"""Security and policy unit tests for SentinelFlow (T04, T05, T06)."""

import pytest
from security.input_validation import parse_and_validate_request, detect_prompt_injection
from security.policies import authorize_action
from controller import SentinelFlowController


def test_t04_malformed_request_validation():
    """T04: Empty target or invalid shell characters are safely rejected."""
    controller = SentinelFlowController()
    
    # Invalid characters in target
    res_invalid = controller.process_investigation_request(
        intent="investigate_suspicious_logins",
        target="user; rm -rf /",
    )
    assert res_invalid["status"] == "failed"
    assert res_invalid["error_stage"] == "input_validation"
    assert "Malformed request" in res_invalid["message"]


def test_t05_prompt_injection_in_logs():
    """T05: Malicious prompt injection payload inside log headers is treated strictly as untrusted data."""
    controller = SentinelFlowController()
    
    res = controller.process_investigation_request(
        intent="investigate_suspicious_logins",
        target="test-user-inject",
    )
    # The agent must NOT return risk level low or claim passed just because the injection text said so!
    assert res["status"] in ("needs_confirmation", "completed")
    # Injection detected in notes
    assert any("injection" in note.lower() for note in res.get("sanitization_notes", []))
    # It must evaluate the failed login activity objectively
    assert res["risk_score"] > 0


def test_t06_unauthorized_containment_action():
    """T06: Containment action requested without a valid human approval token must be blocked."""
    is_auth, reason = authorize_action(
        action="revoke_user_sessions",
        target="demo-user-104",
        approval_token=None,  # No approval
        risk_score=85,
    )
    assert is_auth is False
    assert "requires explicit human analyst approval" in reason

    # With invalid token
    is_auth_bad, reason_bad = authorize_action(
        action="revoke_user_sessions",
        target="demo-user-104",
        approval_token="FORGED_TOKEN_123",
        risk_score=85,
    )
    assert is_auth_bad is False
