"""Security policies, MITRE ATT&CK mapping, and Human-in-the-Loop authorization gate."""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


# Allowlisted containment actions
ALLOWED_CONTAINMENT_ACTIONS = {
    "revoke_user_sessions",
    "block_ip_address",
    "isolate_endpoint",
    "trigger_password_reset",
}

# High-impact actions that mandate human approval
HIGH_IMPACT_ACTIONS = {
    "revoke_user_sessions",
    "block_ip_address",
    "isolate_endpoint",
    "trigger_password_reset",
}

# Valid approval tokens recognized for human-in-the-loop decisions
VALID_APPROVAL_TOKENS = {
    "APPROVED_BY_ANALYST",
    "AUTO_CONTAIN_STAGING",
    "CARD_ACTION_APPROVE",
}


class RiskAssessment(BaseModel):
    """Deterministic evaluation of security findings."""
    risk_level: Literal["low", "medium", "high", "critical"]
    risk_score: int = Field(ge=0, le=100)
    mitre_tactics: list[str]
    evidence: list[str]
    recommended_action: str
    requires_human_approval: bool
    summary: str


def evaluate_incident_risk(events: list[dict[str, Any]], target: str) -> RiskAssessment:
    """Deterministically analyze log events using explicit rules and MITRE ATT&CK mapping."""
    if not events:
        return RiskAssessment(
            risk_level="low",
            risk_score=0,
            mitre_tactics=[],
            evidence=["No matching authentication or access records found in the specified window."],
            recommended_action="none",
            requires_human_approval=False,
            summary=f"No activity found for target '{target}'. Insufficient data to warrant containment.",
        )

    evidence: list[str] = []
    mitre: list[str] = []
    
    # 1. Count failed login events
    failed_logins = [e for e in events if e.get("event_type") == "login_failed"]
    num_failures = len(failed_logins)
    has_repeated_failures = num_failures >= 3
    
    if num_failures >= 5:
        evidence.append(f"High-frequency brute force: {num_failures} consecutive failed logins recorded.")
        mitre.append("T1110 - Brute Force (Credential Guessing)")
    elif num_failures >= 3:
        evidence.append(f"Elevated authentication failures: {num_failures} failed logins observed.")
        mitre.append("T1110 - Brute Force")

    # 2. Check for successful login following failed attempts (credential crack / valid accounts)
    login_successes = [e for e in events if e.get("event_type") == "login_success"]
    has_success_after_failure = False
    
    if login_successes and num_failures > 0:
        # Check if successful login happened from same IP as failure
        fail_ips = {e.get("ip_address") for e in failed_logins}
        for s in login_successes:
            if s.get("ip_address") in fail_ips:
                has_success_after_failure = True
                evidence.append(
                    f"Successful authentication on IP {s.get('ip_address')} immediately following failed brute-force burst."
                )
                mitre.append("T1078 - Valid Accounts (Compromised Credentials)")
                break

    # 3. Check for sensitive privilege queries or MFA bypass probes
    sensitive_ops = [e for e in events if e.get("event_type") == "sensitive_operation"]
    has_privileged_probe = False
    for op in sensitive_ops:
        has_privileged_probe = True
        evidence.append(
            f"Privilege escalation probe detected: '{op.get('reason')}' targeting '{op.get('resource')}'."
        )
        mitre.append("T1068 - Exploitation for Privilege Escalation")
        mitre.append("T1556 - Modify Authentication Process (MFA Bypass)")

    # 4. Geolocation / Baseline anomaly
    locations = {e.get("location") for e in events if e.get("location")}
    has_anomalous_location = any("Romania" in loc or "Bucharest" in loc or "Frankfurt" in loc for loc in locations)
    if has_anomalous_location:
        loc_str = ", ".join(locations)
        evidence.append(f"Geographic anomaly detected: Login activity originating from unfamiliar location ({loc_str}).")
        mitre.append("T1078.004 - Cloud Administration / External Identity Anomaly")

    # Deduplicate MITRE tactics
    unique_mitre = list(dict.fromkeys(mitre))

    # Calculate deterministic risk score: R = min(100, 30F + 25S + 35P + 10B)
    score = 0
    if num_failures >= 5:
        score += 30
    elif num_failures >= 3:
        score += 15

    if has_success_after_failure:
        score += 25
    elif login_successes and has_anomalous_location:
        score += 15

    if has_privileged_probe:
        score += 35

    if has_anomalous_location:
        score += 10

    score = min(100, score)

    # Classify risk level
    if score >= 85:
        level = "critical"
        rec_action = "revoke_user_sessions"
        requires_approval = True
    elif score >= 60:
        level = "high"
        rec_action = "revoke_user_sessions"
        requires_approval = True
    elif score >= 30:
        level = "medium"
        rec_action = "trigger_password_reset"
        requires_approval = True
    else:
        level = "low"
        rec_action = "none"
        requires_approval = False
        if not evidence:
            evidence.append("All observed authentication events conform to normal corporate baselines.")

    summary = (
        f"Incident assessment for {target}: Risk {level.upper()} (Score {score}/100). "
        f"Correlated {len(evidence)} suspicious indicators across {len(events)} events."
    )

    return RiskAssessment(
        risk_level=level,  # type: ignore[arg-type]
        risk_score=score,
        mitre_tactics=unique_mitre,
        evidence=evidence,
        recommended_action=rec_action,
        requires_human_approval=requires_approval,
        summary=summary,
    )


def authorize_action(
    action: str,
    target: str,
    approval_token: str | None,
    risk_score: int,
) -> tuple[bool, str]:
    """Policy Gate: Enforces strict authorization before permitting any containment action."""
    if action not in ALLOWED_CONTAINMENT_ACTIONS:
        return False, f"Action '{action}' is not in the permitted allowlist: {sorted(ALLOWED_CONTAINMENT_ACTIONS)}."

    if not target:
        return False, "Target identifier is missing. Containment cannot proceed."

    # If action is high-impact, human approval is mandatory
    if action in HIGH_IMPACT_ACTIONS:
        if not approval_token or approval_token not in VALID_APPROVAL_TOKENS:
            return (
                False,
                f"Action '{action}' requires explicit human analyst approval. Provide a valid approval token or approve via interactive card.",
            )

    return True, f"Action '{action}' authorized under security policy for target '{target}'."
