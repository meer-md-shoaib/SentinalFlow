"""Tests for SentinelFlow Fetch.ai Multi-Agent System (MAS).

Validates that all 5 specialized agents instantiate correctly as native Fetch.ai Agents,
register with the Bureau, and process inter-agent message payloads.
"""

import pytest
from uagents import Agent, Bureau

from agents.models import (
    InvestigateTelemetryRequest,
    InvestigateTelemetryResponse,
    ThreatAnalysisRequest,
    ThreatAnalysisResponse,
    ContainmentActionRequest,
    ContainmentActionResponse,
    VerificationRequest,
    VerificationResponse,
)
from agents.investigator import investigator_agent, perform_investigation
from agents.analyst import analyst_agent
from agents.containment import containment_agent
from agents.auditor import auditor_agent
from agents.coordinator import coordinator_agent
from agents.bureau import create_sentinelflow_bureau
from tools.simulated_response import reset_state_store, execute_simulated_action


@pytest.fixture(autouse=True)
def clean_state():
    reset_state_store()


def test_agent_instances_are_fetchai_uagents():
    """Verify all 5 specialized agents are valid Fetch.ai Agent instances with unique addresses."""
    agents = [
        coordinator_agent,
        investigator_agent,
        analyst_agent,
        containment_agent,
        auditor_agent,
    ]
    for ag in agents:
        assert isinstance(ag, Agent), f"{ag.name} must be a native Fetch.ai Agent"
        assert ag.address.startswith("agent1"), f"{ag.name} address must start with agent1"

    # Ensure all agents have distinct addresses
    addresses = [ag.address for ag in agents]
    assert len(addresses) == len(set(addresses)), "All 5 agents must have distinct Fetch.ai addresses"


def test_bureau_contains_all_specialized_agents():
    """Verify that the Bureau correctly registers all 5 specialized Fetch.ai agents."""
    bureau = create_sentinelflow_bureau()
    assert isinstance(bureau, Bureau)
    bureau_agents = bureau._agents
    assert len(bureau_agents) == 5
    agent_names = [a.name for a in bureau_agents]
    assert any("Coordinator" in n or "SecOps" in n or "sentinel" in n.lower() for n in agent_names)
    assert any("Investigator" in n for n in agent_names)
    assert any("Analyst" in n for n in agent_names)
    assert any("Containment" in n for n in agent_names)
    assert any("Auditor" in n for n in agent_names)


def test_investigator_agent_telemetry_and_injection_defense():
    """Verify Investigator Agent searches telemetry and sanitizes prompt injections."""
    events, notes, success, err = perform_investigation("test-user-inject")
    assert success is True
    assert err is None
    assert len(events) >= 1
    # Check injection defense
    assert any("prompt injection neutralized" in n.lower() for n in notes)


def test_analyst_agent_mitre_scoring():
    """Verify Analyst Agent receives telemetry and computes MITRE ATT&CK risk score."""
    from security.policies import evaluate_incident_risk
    events, _, _, _ = perform_investigation("demo-user-104")
    assessment = evaluate_incident_risk(events, "demo-user-104")
    assert assessment.risk_level in ("high", "critical")
    assert assessment.risk_score >= 80
    assert any("T1110" in t for t in assessment.mitre_tactics)


def test_containment_agent_policy_enforcement():
    """Verify Containment Agent rejects unauthorized actions without token, permits with token."""
    from security.policies import authorize_action
    # Without token
    auth1, reason1 = authorize_action("revoke_user_sessions", "demo-user-104", approval_token=None, risk_score=85)
    assert auth1 is False
    assert "requires explicit human analyst approval" in reason1

    # With valid token
    auth2, reason2 = authorize_action("revoke_user_sessions", "demo-user-104", approval_token="APPROVED_BY_ANALYST", risk_score=85)
    assert auth2 is True


def test_auditor_agent_state_verification_and_receipt():
    """Verify Auditor Agent checks post-containment system state and issues SHA-256 receipts."""
    from tools.simulated_response import verify_containment_state
    # Execute action
    exec_res = execute_simulated_action("revoke_user_sessions", "demo-user-104")
    act_id = exec_res["action_id"]

    # Verify state
    ver_res = verify_containment_state(action_id=act_id, expected_status="sessions_revoked")
    assert ver_res["verified"] is True
    assert len(ver_res["audit_hash"]) == 64  # SHA-256 hex string
