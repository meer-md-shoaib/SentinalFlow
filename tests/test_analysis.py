"""Unit tests for SentinelFlow log search, risk scoring, and evidence correlation (T01, T02, T03)."""

import pytest
from tools.log_search import search_logs
from security.policies import evaluate_incident_risk
from controller import SentinelFlowController


def test_t01_normal_investigation_demo_user():
    """T01: Verify that a valid investigation query finds matching records and assembles evidence."""
    controller = SentinelFlowController()
    res = controller.process_investigation_request(
        intent="investigate_suspicious_logins",
        target="demo-user-104",
        time_window_minutes=60,
    )
    assert res["status"] in ("needs_confirmation", "completed")
    assert res["target"] == "demo-user-104"
    assert len(res["evidence"]) > 0
    assert res["risk_score"] > 50


def test_t02_known_suspicious_pattern():
    """T02: Flag brute-force burst, geographic anomaly, and privilege probe with MITRE mapping."""
    logs_res = search_logs(account_id="demo-user-104")
    events = logs_res["events"]
    assert len(events) >= 8

    assessment = evaluate_incident_risk(events, "demo-user-104")
    assert assessment.risk_level in ("high", "critical")
    assert assessment.risk_score >= 75
    assert any("T1110" in t for t in assessment.mitre_tactics)
    assert any("T1078" in t for t in assessment.mitre_tactics)
    assert assessment.requires_human_approval is True


def test_t03_no_matching_records():
    """T03: Query for unknown user returns insufficient_data without fabricating evidence."""
    controller = SentinelFlowController()
    res = controller.process_investigation_request(
        intent="investigate_suspicious_logins",
        target="unknown-user-999",
    )
    assert res["status"] == "insufficient_data"
    assert res["risk_score"] == 0
    assert "No telemetry logs found" in res["evidence"][0]
    assert res["action"] is None
