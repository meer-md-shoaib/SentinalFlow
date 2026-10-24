"""Simulated response controller + independent verifier.

STRICTLY SIMULATED: no real lockouts, no shell, no network changes. All state
lives in a small JSON file (data/state_store.json) and every mutation persists
there so it can be independently re-read and verified.

Fault injection exists only so tests can prove that "action reports success but
state did not change" is DETECTED, never trusted.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import STATE_STORE_FILE
from schemas import AccountState, ActionResult, ActionKind, VerificationResult


class SimulatorError(Exception):
    """Simulated action could not be executed."""


class StateStore:
    """JSON-backed simulated account state. Writes are atomic (tmp + replace)."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path is not None else STATE_STORE_FILE
        self._data: dict[str, Any] = {"accounts": {}}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and isinstance(raw.get("accounts"), dict):
                    self._data = raw
            except (OSError, json.JSONDecodeError):
                # corrupted store: start empty rather than trust partial data
                self._data = {"accounts": {}}
        self._data.setdefault("accounts", {})

    def account(self, account_id: str) -> AccountState:
        raw = self._data["accounts"].get(account_id)
        if raw is None:
            return AccountState(
                account_id=account_id,
                contained=False,
                flagged_for_investigation=False,
                open_incidents=[],
                escalations=[],
                updated_at=datetime.now(timezone.utc),
            )
        return AccountState.model_validate(raw)

    def save_account(self, state: AccountState) -> None:
        state.updated_at = datetime.now(timezone.utc)
        self._data["accounts"][state.account_id] = state.model_dump(mode="json")
        tmp = self.path.with_suffix(".tmp")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def fresh_read(self, account_id: str) -> AccountState | None:
        """Independent re-read straight from disk (used by the verifier)."""
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            entry = raw.get("accounts", {}).get(account_id)
            return AccountState.model_validate(entry) if entry else None
        except Exception:
            return None


class ResponseSimulator:
    """Executes ONLY allowlisted, simulated actions against the state store."""

    def __init__(self, state_store: StateStore | None = None,
                 faults: dict[str, str] | None = None):
        """faults: action-kind value -> 'silent_fail' (claims success, writes
        nothing) | 'raise' (raises SimulatorError). Used by failure tests."""
        self.store = state_store or StateStore()
        self.faults = dict(faults or {})

    # ------------------------------------------------------------ expected
    @staticmethod
    def expected_state(action: ActionKind, target: str, incident_id: str) -> dict[str, Any]:
        """State facts that must hold after a successful action — the contract
        the verifier checks independently."""
        if action == ActionKind.CONTAIN_ACCOUNT:
            return {
                "contained": True,
                "flagged_for_investigation": True,
                "contained_reason_is_set": True,
                "incident_open": incident_id,
            }
        if action == ActionKind.FLAG_ACCOUNT:
            return {"flagged_for_investigation": True, "incident_open": incident_id}
        if action == ActionKind.CREATE_INCIDENT:
            return {"incident_open": incident_id}
        if action == ActionKind.ESCALATE:
            return {"escalated": incident_id}
        return {}

    # ----------------------------------------------------------- execution
    def execute(
        self,
        action: ActionKind,
        action_id: str,
        target: str,
        incident_id: str,
        reason: str,
    ) -> ActionResult:
        now = datetime.now(timezone.utc)

        # simulated hard failure
        if self.faults.get(action.value) == "raise":
            raise SimulatorError(f"simulated failure executing {action.value}")

        state = self.store.account(target)

        if action == ActionKind.CREATE_INCIDENT:
            if incident_id not in state.open_incidents:
                state.open_incidents.append(incident_id)
        elif action == ActionKind.FLAG_ACCOUNT:
            state.flagged_for_investigation = True
            if incident_id not in state.open_incidents:
                state.open_incidents.append(incident_id)
        elif action == ActionKind.CONTAIN_ACCOUNT:
            state.contained = True
            state.flagged_for_investigation = True
            state.contained_reason = reason[:200]
            state.contained_at = now
            if incident_id not in state.open_incidents:
                state.open_incidents.append(incident_id)
        elif action == ActionKind.ESCALATE:
            if incident_id not in state.escalations:
                state.escalations.append(incident_id)
        elif action == ActionKind.RESPONSE_SUMMARY:
            pass  # read-only
        else:
            raise SimulatorError(f"action {action.value} is not simulated")

        # 'silent_fail' claims success but persists nothing — verifier must catch it
        if self.faults.get(action.value) == "silent_fail":
            return ActionResult(
                action_id=action_id,
                action=action,
                target_account=target,
                status="executed",
                detail="(simulator reported success)",
                executed_at=now,
            )

        self.store.save_account(state)

        return ActionResult(
            action_id=action_id,
            action=action,
            target_account=target,
            status="executed",
            detail=f"simulated {action.value} applied to {target}",
            executed_at=now,
        )


def verify_state(
    state_store: StateStore,
    action: ActionKind,
    action_id: str,
    target: str,
    incident_id: str,
) -> VerificationResult:
    """Independent verification: re-read state from the store and compare with
    the expected contract. Never trusts the action tool's success message."""
    now = datetime.now(timezone.utc)
    expected = ResponseSimulator.expected_state(action, target, incident_id)

    if not expected:  # e.g. response_summary — nothing to verify
        return VerificationResult(
            action_id=action_id,
            status="unverified",
            expected_state={},
            actual_state=None,
            checked_at=now,
            note="action has no state contract; nothing to verify",
        )

    try:
        actual = state_store.fresh_read(target)
    except Exception as exc:  # unreadable state -> unverified, never "verified"
        return VerificationResult(
            action_id=action_id,
            status="unverified",
            expected_state=expected,
            actual_state=None,
            checked_at=now,
            note=f"state could not be read: {exc}",
        )

    if actual is None:
        return VerificationResult(
            action_id=action_id,
            status="failed",
            expected_state=expected,
            actual_state=None,
            checked_at=now,
            note="account state missing after action",
        )

    flat: dict[str, Any] = {
        "contained": actual.contained,
        "flagged_for_investigation": actual.flagged_for_investigation,
        "contained_reason_is_set": actual.contained_reason is not None,
        "incident_open": actual.open_incidents,
        "escalated": actual.escalations,
    }

    checks: list[str] = []
    ok = True
    for key, want in expected.items():
        have = flat.get(key)
        if key in ("incident_open", "escalated"):
            passed = isinstance(have, list) and want in have
        else:
            passed = have == want
        if not passed:
            ok = False
            checks.append(f"{key}: expected {want!r}, got {have!r}")

    return VerificationResult(
        action_id=action_id,
        status="verified" if ok else "failed",
        expected_state=expected,
        actual_state=flat,
        checked_at=now,
        note="" if ok else "; ".join(checks),
    )
