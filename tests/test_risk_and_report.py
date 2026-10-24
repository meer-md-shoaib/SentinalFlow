"""Milestone C tests: deterministic risk engine + incident report."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from investigation import LogStore, correlate_events, search_logs
from reporting import build_report, render_report
from risk import assess_risk, incident_id_for, severity_for_score
from schemas import Severity

W_START = datetime(2026, 10, 20, 0, 0, tzinfo=timezone.utc)
W_END = datetime(2026, 10, 21, 0, 0, tzinfo=timezone.utc)
ATTACK_START = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)
ATTACK_END = datetime(2026, 10, 20, 11, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def store() -> LogStore:
    return LogStore()


def _assess(s: LogStore, account: str, start, end):
    outcome = search_logs(s, account, start, end)
    corr = correlate_events(outcome.events)
    return assess_risk(outcome, corr, baseline=s.baseline), outcome, corr


# ------------------------------------------------------------- scenarios
def test_suspicious_account_scores_high_with_rules(store):
    a, outcome, corr = _assess(store, "A104", ATTACK_START, ATTACK_END)
    fired = {h.rule_id for h in a.rule_hits}
    assert {"R1", "R2", "R3", "R4", "R5"} <= fired, fired
    assert "R6" in fired, "baseline anomaly should fire for 203.0.113.50"
    assert a.severity in (Severity.HIGH, Severity.CRITICAL)
    assert a.score >= 7
    assert a.baseline_applied is True
    assert a.evidence_ids, "evidence ids must flow into the assessment"
    assert "E-1011" in a.evidence_ids
    # explanation names rules; disclaims probability
    assert "R2" in a.explanation and "not a probability" in a.explanation
    assert a.recommended_next_step.startswith("Simulated containment")


def test_benign_travel_scores_informational(store):
    a, _, _ = _assess(store, "A107", W_START, W_END)
    assert a.severity in (Severity.INFORMATIONAL, Severity.LOW), a.explanation
    assert a.score <= 1
    fired = {h.rule_id for h in a.rule_hits}
    assert "R1" not in fired and "R2" not in fired and "R3" not in fired
    assert not a.recommended_next_step.startswith("Simulated containment")


def test_normal_account_stays_low(store):
    a, _, _ = _assess(store, "A118", W_START, W_END)
    assert a.severity in (Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM)
    assert a.severity != Severity.HIGH and a.severity != Severity.CRITICAL
    assert not a.recommended_next_step.startswith("Simulated containment")


def test_no_matching_logs_explicit_behavior(store):
    a, outcome, _ = _assess(store, "A901", W_START, W_END)
    assert outcome.empty
    assert a.severity == Severity.INFORMATIONAL
    assert a.score == 0
    assert "evidence gap" in a.explanation.lower() or "no matching events" in a.explanation.lower()
    assert a.missing_information == ["no events in window"]


def test_uncertainty_and_missing_info_reported(store):
    a, _, _ = _assess(store, "A104", ATTACK_START, ATTACK_END)
    assert any("missing telemetry" in u or "missing telemetry" in u.lower()
               for u in a.uncertainties) or any(
        "telemetry" in u.lower() for u in a.uncertainties
    )
    assert any("instruction-like" in u for u in a.uncertainties), (
        "prompt-injection content must be surfaced as uncertainty"
    )


# ----------------------------------------------------------- determinism
def test_assessment_deterministic(store):
    a1, _, _ = _assess(store, "A104", ATTACK_START, ATTACK_END)
    a2, _, _ = _assess(store, "A104", ATTACK_START, ATTACK_END)
    strip = lambda a: {**a.model_dump(), "assessed_at": None}
    assert strip(a1) == strip(a2)
    assert a1.deterministic is True


def test_incident_id_deterministic_per_window():
    s = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)
    e = datetime(2026, 10, 20, 11, 0, tzinfo=timezone.utc)
    assert incident_id_for("A104", s, e) == incident_id_for("A104", s, e)
    assert incident_id_for("A104", s, e) != incident_id_for("A107", s, e)


def test_severity_thresholds():
    assert severity_for_score(0) == Severity.INFORMATIONAL
    assert severity_for_score(1) == Severity.LOW
    assert severity_for_score(4) == Severity.MEDIUM
    assert severity_for_score(7) == Severity.HIGH
    assert severity_for_score(15) == Severity.CRITICAL


def test_baseline_missing_is_skipped_not_guessed(store):
    outcome = search_logs(store, "A104", ATTACK_START, ATTACK_END)
    corr = correlate_events(outcome.events)
    from risk.rules import BaselineStore
    a = assess_risk(outcome, corr, baseline=BaselineStore(None))
    assert a.baseline_applied is False
    assert not any(h.rule_id == "R6" for h in a.rule_hits if h.weight > 0)
    assert any("baseline" in u.lower() for u in a.uncertainties), (
        "absent baseline must produce an uncertainty note"
    )


# ------------------------------------------------------------- report
def test_report_sections_complete(store):
    a, outcome, corr = _assess(store, "A104", ATTACK_START, ATTACK_END)
    tl = __import__("investigation").generate_incident_timeline(outcome.events)
    rep = build_report(a, tl, corr, audit_reference="AUDIT-TEST-1")
    text = render_report(rep)
    for marker in (
        "1. Incident ID", "2. Account & window", "3. Severity", "4. Timeline",
        "5. Evidence IDs", "6. Observed facts", "7. Missing evidence",
        "8. Recommended response", "9. Approval status", "10. Action result",
        "11. Verification result", "12. Audit reference",
    ):
        assert marker in text, f"missing section marker: {marker}"
    assert rep.status == "complete"
    assert rep.evidence_ids
    # observed facts are concrete, inferences are labeled
    assert any("consecutive failed logins" in f for f in rep.observed_facts)
    assert all(x.startswith("[inference") for x in rep.inferred_conclusions)
    # injection payload may appear only as sanitized quoted evidence
    assert "ADMIN OVERRIDE GRANTED" in text or "untrusted" in text.lower()
    assert "\n\n\n" not in text


def test_report_injection_never_rendered_as_instruction(store):
    a, outcome, corr = _assess(store, "A104", ATTACK_START, ATTACK_END)
    tl = __import__("investigation").generate_incident_timeline(outcome.events)
    rep = build_report(a, tl, corr, audit_reference="AUDIT-TEST-2")
    # timeline entry for E-1011 must be flagged untrusted
    flagged = [t for t in rep.timeline if t.event_id == "E-1011"]
    assert flagged and flagged[0].untrusted_detail_flagged is True
    # report recommends the deterministic response regardless of payload text
    assert rep.recommended_response.startswith("Simulated containment")
