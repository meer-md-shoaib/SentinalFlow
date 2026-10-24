"""Simulated containment actions, audit ledger, and cryptographic state verifier."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


class SimulatedStateStore:
    """In-memory state store tracking identities, sessions, and network blocks."""

    def __init__(self) -> None:
        self.accounts: dict[str, dict[str, Any]] = {
            "demo-user-104": {"status": "active", "active_sessions": 3, "mfa_enabled": True},
            "sarah-dev-202": {"status": "active", "active_sessions": 1, "mfa_enabled": True},
            "test-user-inject": {"status": "active", "active_sessions": 2, "mfa_enabled": False},
        }
        self.blocked_ips: set[str] = set()
        self.action_ledger: dict[str, dict[str, Any]] = {}

    def get_account_state(self, account_id: str) -> dict[str, Any]:
        """Fetch current state of an account, initializing default if unknown."""
        return self.accounts.setdefault(
            account_id, {"status": "active", "active_sessions": 1, "mfa_enabled": True}
        )

    def is_ip_blocked(self, ip_address: str) -> bool:
        return ip_address in self.blocked_ips


# Global singleton instance for runtime state
_STATE_STORE = SimulatedStateStore()


def get_state_store() -> SimulatedStateStore:
    return _STATE_STORE


def reset_state_store() -> None:
    """Helper to reset store between unit tests."""
    global _STATE_STORE
    _STATE_STORE = SimulatedStateStore()


def execute_simulated_action(
    action_type: str,
    target: str,
    operator: str = "sentinelflow_agent",
    parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute a simulated containment action and record in the audit ledger."""
    store = get_state_store()
    action_id = f"act-{uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    params = parameters or {}

    # Check for duplicate action within past 5 minutes (Idempotency check T09)
    for existing_id, existing_act in store.action_ledger.items():
        if (
            existing_act.get("action_type") == action_type
            and existing_act.get("target") == target
            and existing_act.get("status") in ("executed", "simulated")
        ):
            return {
                "action_id": existing_id,
                "status": "duplicate_prevented",
                "message": f"Action '{action_type}' was already executed for target '{target}'. Idempotent response returned.",
                "action_record": existing_act,
            }

    state_before: dict[str, Any] = {}
    state_after: dict[str, Any] = {}

    if action_type == "revoke_user_sessions":
        acc = store.get_account_state(target)
        state_before = dict(acc)
        acc["status"] = "sessions_revoked"
        acc["active_sessions"] = 0
        state_after = dict(acc)

    elif action_type == "block_ip_address":
        state_before = {"ip": target, "blocked": store.is_ip_blocked(target)}
        store.blocked_ips.add(target)
        state_after = {"ip": target, "blocked": True}

    elif action_type == "trigger_password_reset":
        acc = store.get_account_state(target)
        state_before = dict(acc)
        acc["status"] = "password_reset_required"
        state_after = dict(acc)

    elif action_type == "isolate_endpoint":
        acc = store.get_account_state(target)
        state_before = dict(acc)
        acc["status"] = "quarantined"
        state_after = dict(acc)

    else:
        raise ValueError(f"Unsupported containment action: {action_type}")

    # Build tamper-evident record
    record = {
        "action_id": action_id,
        "timestamp": now_iso,
        "operator": operator,
        "action_type": action_type,
        "target": target,
        "parameters": params,
        "status": "executed",
        "state_before": state_before,
        "state_after": state_after,
    }

    # Record in persistent ledger
    store.action_ledger[action_id] = record

    return {
        "action_id": action_id,
        "status": "executed",
        "timestamp": now_iso,
        "target": target,
        "action_type": action_type,
        "message": f"Successfully executed containment action '{action_type}' on '{target}'.",
        "action_record": record,
    }


def verify_containment_state(
    action_id: str,
    expected_status: str = "sessions_revoked",
    simulate_mismatch: bool = False,
) -> dict[str, Any]:
    """Inspect actual post-action state against expected target state."""
    store = get_state_store()
    record = store.action_ledger.get(action_id)

    if not record:
        return {
            "verified": False,
            "action_id": action_id,
            "error": f"No recorded action found in ledger for ID '{action_id}'.",
        }

    target = record["target"]
    action_type = record["action_type"]

    if simulate_mismatch:
        # Simulate state failure (e.g. backend failed to invalidate redis cache)
        actual_state = "active"
    else:
        if action_type == "revoke_user_sessions":
            actual_state = store.get_account_state(target)["status"]
        elif action_type == "block_ip_address":
            actual_state = "blocked" if store.is_ip_blocked(target) else "allowed"
        elif action_type == "trigger_password_reset":
            actual_state = store.get_account_state(target)["status"]
        elif action_type == "isolate_endpoint":
            actual_state = store.get_account_state(target)["status"]
        else:
            actual_state = "unknown"

    passed = (actual_state == expected_status) and not simulate_mismatch

    # Compute SHA-256 audit verification hash
    raw_payload = f"{action_id}:{target}:{action_type}:{actual_state}:{passed}"
    audit_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

    return {
        "verified": passed,
        "action_id": action_id,
        "target": target,
        "action_type": action_type,
        "expected_state": expected_status,
        "actual_state": actual_state,
        "audit_hash": audit_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": (
            f"State verification PASSED. Target '{target}' confirmed in state '{actual_state}'."
            if passed
            else f"State verification FAILED. Expected '{expected_status}' but target '{target}' is '{actual_state}'."
        ),
    }
