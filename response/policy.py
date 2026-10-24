"""Policy engine — allowlist + approval requirements, independent of any LLM.

decide() answers one question: is this action allowed right now, and why?
It never mutates state. Every decision is recorded for audit.
"""

from __future__ import annotations

from datetime import datetime, timezone

from schemas import ActionKind, ApprovalDecision, PolicyDecision

# The complete set of actions this agent may ever perform (all simulated).
ALLOWLIST: dict[ActionKind, bool] = {
    ActionKind.CREATE_INCIDENT: False,   # value: requires approval
    ActionKind.FLAG_ACCOUNT: False,
    ActionKind.CONTAIN_ACCOUNT: True,    # sensitive -> approval required
    ActionKind.ESCALATE: False,
    ActionKind.RESPONSE_SUMMARY: False,
}


def requires_approval(action: ActionKind) -> bool:
    return ALLOWLIST.get(action, True)  # unknown actions default to "approval required"


def decide(
    action: ActionKind,
    approval: ApprovalDecision | None,
    *,
    incident_id: str,
    target_account: str,
    requested_by: str,
    expected_fingerprint: str,
    incident_open: bool = True,
    reason_for_denial: str | None = None,
) -> PolicyDecision:
    now = datetime.now(timezone.utc)

    label = getattr(action, "value", str(action))

    def _deny(reason: str) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            action=action if isinstance(action, ActionKind) else ActionKind.RESPONSE_SUMMARY,
            requires_approval=requires_approval(action),
            reason=reason,
            decided_at=now,
        )

    # 1) allowlist — unknown/undocumented actions are never allowed
    if not isinstance(action, ActionKind) or action not in ALLOWLIST:
        return _deny(f"action {label!r} is not allowlisted")

    # 2) external denial (e.g. user declined) short-circuits everything
    if reason_for_denial:
        return _deny(reason_for_denial)

    # 3) incident must still be open/valid at decision time
    if not incident_open:
        return _deny("incident is no longer open; refusing to act")

    # 4) approval binding for sensitive actions
    if requires_approval(action):
        if approval is None:
            return _deny("explicit approval required for this action; none provided")
        if approval.fingerprint != expected_fingerprint:
            return _deny(
                "approval fingerprint does not match this incident/action/target"
            )
        if approval.decision != "approve":
            return _deny("approval decision was not 'approve'")
        if approval.action_id == "":
            return _deny("approval token missing")

    return PolicyDecision(
        allowed=True,
        action=action,
        requires_approval=requires_approval(action),
        reason=(
            "allowed: action is allowlisted and approval requirements are satisfied"
            if requires_approval(action)
            else "allowed: non-sensitive allowlisted action"
        ),
        decided_at=now,
    )
