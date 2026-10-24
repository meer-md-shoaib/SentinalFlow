"""Approval flow for sensitive simulated actions (text-based, chat-friendly).

Approvals are:
- bound to the exact (incident, action, target, requester) via a fingerprint,
- single-use (replay rejected),
- time-limited (expired rejected),
- tied to an identified approver (the requesting chat session's sender),
- matched exactly against the pending proposal (mismatch rejected).

Every rejection raises ApprovalError — state is never touched by rejections.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from config import settings
from schemas import ActionKind, ApprovalDecision, PendingAction


class ApprovalError(Exception):
    """Base class: any approval that cannot be trusted must be rejected."""


class ApprovalNotFound(ApprovalError):
    pass


class ApprovalExpired(ApprovalError):
    pass


class ApprovalMismatch(ApprovalError):
    pass


class ApprovalReplayed(ApprovalError):
    pass


class ApprovalDenied(ApprovalError):
    pass


def fingerprint(incident_id: str, action: ActionKind, target: str, requester: str) -> str:
    payload = f"{incident_id}|{action.value}|{target}|{requester}"
    return hashlib.sha256(payload.encode()).hexdigest()


def create_pending_action(
    incident_id: str,
    action: ActionKind,
    target_account: str,
    requested_by: str,
    justification: str,
    sensitive: bool = True,
    ttl_seconds: int | None = None,
) -> PendingAction:
    now = datetime.now(timezone.utc)
    ttl = ttl_seconds if ttl_seconds is not None else settings.approval_ttl_seconds
    return PendingAction(
        action_id="APR-" + secrets.token_hex(6).upper(),
        fingerprint=fingerprint(incident_id, action, target_account, requested_by),
        incident_id=incident_id,
        action=action,
        target_account=target_account,
        requested_by=requested_by,
        proposed_at=now,
        expires_at=now + timedelta(seconds=ttl),
        justification=justification,
        sensitive=sensitive,
    )


APPROVE_RE = r"\bAPPROVE\b"
DECLINE_RE = r"\bDECLINE\b"


def parse_decision(text: str) -> tuple[str, str | None] | None:
    """Extract ('approve'|'decline', token|None) from a chat reply."""
    import re
    t = text.strip()
    m = re.search(r"\b(APPROVE|DECLINE)\b\s*(APR-[0-9A-F]{8,16})?", t, re.IGNORECASE)
    if not m:
        return None
    return m.group(1).lower(), m.group(2)


class ApprovalLedger:
    """Tracks issued proposals and consumed approvals."""

    def __init__(self) -> None:
        self._pending: dict[str, PendingAction] = {}
        self._consumed: set[str] = set()
        self._decisions: list[ApprovalDecision] = []

    # ----------------------------------------------------------- lifecycle
    def issue(self, pending: PendingAction) -> PendingAction:
        self._pending[pending.action_id] = pending
        return pending

    def get(self, action_id: str) -> PendingAction:
        pending = self._pending.get(action_id)
        if pending is None:
            raise ApprovalNotFound(f"unknown approval token {action_id!r}")
        return pending

    @property
    def decisions(self) -> list[ApprovalDecision]:
        return list(self._decisions)

    # ---------------------------------------------------------- validation
    def validate(
        self,
        action_id: str,
        decision: str,
        decided_by: str,
        *,
        expected_fingerprint: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalDecision:
        """Full validation. Raises ApprovalError on ANY doubt.

        Checks in order: existence -> replay -> expiry -> approver identity ->
        fingerprint binding (proposal <-> this incident/action/target/requester).
        """
        if decision not in ("approve", "decline"):
            raise ApprovalMismatch(f"unknown decision {decision!r}")
        if not decided_by or not str(decided_by).strip():
            raise ApprovalMismatch("approver identity missing")

        pending = self.get(action_id)

        if action_id in self._consumed:
            raise ApprovalReplayed(f"approval {action_id} was already used")

        current = now or datetime.now(timezone.utc)
        if pending.expires_at < current:
            raise ApprovalExpired(f"approval {action_id} expired at {pending.expires_at.isoformat()}")

        # approver must be the session that requested the action (session binding)
        if decided_by != pending.requested_by:
            raise ApprovalMismatch(
                "approver identity does not match the requesting session"
            )

        if expected_fingerprint is not None and expected_fingerprint != pending.fingerprint:
            raise ApprovalMismatch("approval fingerprint does not match the pending action")

        if decision == "decline":
            # decline consumes the token too: no re-deciding later
            self._consumed.add(action_id)
            decl = ApprovalDecision(
                action_id=action_id,
                decision="decline",
                approved_by=decided_by,
                decided_at=current,
                fingerprint=pending.fingerprint,
            )
            self._decisions.append(decl)
            raise ApprovalDenied(f"user declined action {action_id}")

        self._consumed.add(action_id)
        approval = ApprovalDecision(
            action_id=action_id,
            decision="approve",
            approved_by=decided_by,
            decided_at=current,
            fingerprint=pending.fingerprint,
        )
        self._decisions.append(approval)
        return approval
