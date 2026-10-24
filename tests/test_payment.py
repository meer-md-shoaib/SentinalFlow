"""Unit tests for Fetch.ai Payment Protocol and Multi-Agent Collaboration."""

import pytest
from payment import create_payment_request, DEFAULT_FEE_FET
from remediation_agent import ContainmentTask, ContainmentResult
from tools.simulated_response import reset_state_store, get_state_store


@pytest.fixture(autouse=True)
def clean_state():
    reset_state_store()


def test_payment_request_creation():
    """Verify standard Fetch.ai RequestPayment schema and funds specifications."""
    req = create_payment_request(
        recipient_address="agent1qwstka0f7sjyd0ux69zfv9pu66testhc807cdhx8yvav3u0eml7nwptkdfy",
        target_incident="demo-user-104",
        action_type="revoke_user_sessions",
        amount_fet=DEFAULT_FEE_FET,
    )
    assert req.recipient == "agent1qwstka0f7sjyd0ux69zfv9pu66testhc807cdhx8yvav3u0eml7nwptkdfy"
    assert len(req.accepted_funds) == 1
    assert str(req.accepted_funds[0].amount) == "0.1"
    assert req.accepted_funds[0].currency == "FET"
    assert req.accepted_funds[0].payment_method == "fet_direct"
    assert req.metadata["service"] == "SentinelFlow Enterprise Containment"


def test_multi_agent_containment_schemas():
    """Verify inter-agent task dispatch and result verification schemas."""
    task = ContainmentTask(
        task_id="task-1234",
        target="demo-user-104",
        action_type="revoke_user_sessions",
        approval_token="CARD_ACTION_APPROVE",
        requester_address="agent1_triage_address",
        fee_amount="0.1",
        fee_currency="FET",
    )
    assert task.target == "demo-user-104"
    assert task.fee_amount == "0.1"
    assert task.fee_currency == "FET"

    result = ContainmentResult(
        task_id="task-1234",
        target="demo-user-104",
        action_type="revoke_user_sessions",
        action_id="act-5566",
        verified=True,
        actual_state="sessions_revoked",
        audit_hash="a1b2c3d4e5f6",
        timestamp="2026-10-24T12:00:00Z",
        payment_status="0.1 FET Settled (Escrow Released)",
        details="State verified successfully",
    )
    assert result.verified is True
    assert "Settled" in result.payment_status
