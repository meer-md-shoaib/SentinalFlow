"""SentinelFlow Controller: Core orchestrator binding intent, tools, risk analysis, policy, and verification."""

from __future__ import annotations

from typing import Any
from security.input_validation import parse_and_validate_request, ValidationError, detect_prompt_injection
from security.policies import (
    evaluate_incident_risk,
    authorize_action,
    ALLOWED_CONTAINMENT_ACTIONS,
    RiskAssessment,
)
from tools.log_search import search_logs, LogSearchError
from tools.simulated_response import (
    execute_simulated_action,
    verify_containment_state,
    get_state_store,
)


class SentinelFlowController:
    """Manages the full lifecycle of security incident investigation and response."""

    def __init__(self) -> None:
        self.state_store = get_state_store()

    def process_investigation_request(
        self,
        intent: str = "investigate_suspicious_logins",
        target: str = "demo-user-104",
        time_window_minutes: int = 60,
        requested_action: str | None = None,
        approval_token: str | None = None,
        simulate_tool_failure: bool = False,
        simulate_verify_mismatch: bool = False,
    ) -> dict[str, Any]:
        """Execute the 5-stage SentinelFlow workflow: Understand -> Investigate -> Assess -> Respond -> Verify."""
        # 1. UNDERSTAND & VALIDATE
        try:
            req = parse_and_validate_request(
                intent=intent,
                target=target,
                time_window_minutes=time_window_minutes,
                requested_action=requested_action,
                approval_token=approval_token,
            )
        except (ValueError, ValidationError) as val_err:
            return {
                "status": "failed",
                "error_stage": "input_validation",
                "risk_level": "low",
                "risk_score": 0,
                "evidence": [],
                "message": f"Malformed request: {val_err}",
                "action": None,
                "verification": None,
            }

        # 2. INVESTIGATE (Tool Execution)
        try:
            search_result = search_logs(
                account_id=req.target,
                time_window_minutes=req.time_window_minutes,
                simulate_failure=simulate_tool_failure,
            )
        except LogSearchError as search_err:
            return {
                "status": "failed",
                "error_stage": "log_search",
                "risk_level": "unknown",
                "risk_score": 0,
                "evidence": [],
                "message": f"Security log retrieval failed: {search_err}",
                "action": None,
                "verification": None,
            }

        events = search_result.get("events", [])

        # Scan ingested log records for indirect prompt injection attempts (T05)
        for ev in events:
            for k, v in ev.items():
                if isinstance(v, str) and detect_prompt_injection(v):
                    note = f"Indirect prompt injection neutralized in log field '{k}' of event '{ev.get('event_id')}': treated as untrusted data."
                    if note not in req.sanitization_notes:
                        req.sanitization_notes.append(note)

        # Check for zero records (T03)
        if not events:
            return {
                "status": "insufficient_data",
                "target": req.target,
                "risk_level": "low",
                "risk_score": 0,
                "mitre_tactics": [],
                "evidence": [f"No telemetry logs found for target '{req.target}' in the last {req.time_window_minutes} minutes."],
                "message": f"Insufficient data: zero events matched target '{req.target}'. No automated action warranted.",
                "action": None,
                "verification": None,
            }

        # 3. ASSESS (Deterministic MITRE ATT&CK Risk Scoring)
        assessment: RiskAssessment = evaluate_incident_risk(events, req.target)

        # 4. RESPOND (Policy Gate & Remediation)
        action_payload: dict[str, Any] | None = None
        verification_payload: dict[str, Any] | None = None
        status = "needs_confirmation"

        # Determine target action
        action_to_take = req.requested_action or (
            assessment.recommended_action if assessment.risk_level in ("high", "critical") else None
        )

        if action_to_take and action_to_take in ALLOWED_CONTAINMENT_ACTIONS:
            # Policy Gate Check
            is_authorized, auth_reason = authorize_action(
                action=action_to_take,
                target=req.target,
                approval_token=req.approval_token,
                risk_score=assessment.risk_score,
            )

            if is_authorized:
                # Execute permitted action
                exec_res = execute_simulated_action(
                    action_type=action_to_take,
                    target=req.target,
                    operator="sentinelflow_agent",
                )
                action_payload = exec_res

                # 5. VERIFY (State check & cryptographic audit receipt)
                action_id = exec_res.get("action_id", "")
                expected_state = "sessions_revoked" if action_to_take == "revoke_user_sessions" else "blocked"
                
                verification_payload = verify_containment_state(
                    action_id=action_id,
                    expected_status=expected_state,
                    simulate_mismatch=simulate_verify_mismatch,
                )

                if verification_payload.get("verified"):
                    status = "completed"
                else:
                    status = "failed"
            else:
                # Authorization denied / requires confirmation
                status = "needs_confirmation"
                action_payload = {
                    "type": action_to_take,
                    "target": req.target,
                    "status": "pending_approval",
                    "reason": auth_reason,
                }
        else:
            if assessment.risk_level == "low":
                status = "completed"
            else:
                status = "needs_confirmation"

        return {
            "status": status,
            "target": req.target,
            "risk_level": assessment.risk_level,
            "risk_score": assessment.risk_score,
            "mitre_tactics": assessment.mitre_tactics,
            "evidence": assessment.evidence,
            "summary": assessment.summary,
            "sanitization_notes": req.sanitization_notes,
            "action": action_payload,
            "verification": verification_payload,
            "agents_involved": {
                "coordinator": "SentinelFlow Coordinator Agent (ACP & UI Cards)",
                "investigator": "SentinelFlow Investigator Agent (SIEM & Injection Defense)",
                "analyst": "SentinelFlow Threat Analyst Agent (MITRE ATT&CK Scoring)",
                "containment": "SentinelFlow Containment Agent (HITL Policy Gate & Response)",
                "auditor": "SentinelFlow Auditor Agent (Closed-Loop Verification & Receipts)",
            },
        }
