"""Milestone B tests: synthetic data, search_logs, correlation, evidence,
timeline, and failure handling (malformed, duplicates, injection, timeouts)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from investigation import (
    InvalidRequestError,
    LogStore,
    ToolFailure,
    ToolTimeout,
    correlate_events,
    generate_incident_timeline,
    retrieve_evidence,
    search_logs,
)
from schemas import Event

W_START = datetime(2026, 10, 20, 0, 0, tzinfo=timezone.utc)
W_END = datetime(2026, 10, 21, 0, 0, tzinfo=timezone.utc)
ATTACK_START = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)
ATTACK_END = datetime(2026, 10, 20, 11, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def store() -> LogStore:
    return LogStore()


# ------------------------------------------------------------ dataset shape
def test_dataset_loads_with_quarantine_and_duplicates(store):
    # all valid events loaded, malformed quarantined (never used as evidence)
    assert len(store.events) >= 26
    assert len(store.quarantined) == 3, [q.reason for q in store.quarantined]
    reasons = " ".join(q.reason for q in store.quarantined)
    assert "event_id" in reasons or "event_id" in str(store.quarantined[0].raw)
    assert "timestamp" in reasons
    assert "event_type" in reasons
    # duplicate event_id collapsed
    assert store.duplicate_event_ids == ["E-1007"]
    ids = [e.event_id for e in store.events]
    assert ids.count("E-1007") == 1


def test_all_dataset_ips_are_reserved_documentation_ranges(store):
    import ipaddress
    reserved = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]
    for ev in store.events:
        if ev.source_ip is None:
            continue
        ip = ipaddress.ip_address(ev.source_ip)
        assert any(ip in net for net in reserved), f"non-reserved IP {ev.source_ip}"


def test_suspicious_chain_present(store):
    out = search_logs(store, "A104", ATTACK_START, ATTACK_END)
    types = [e.event_type for e in out.events]
    assert types.count("auth_failure") >= 5
    assert "auth_success" in types
    sensitive = [e for e in out.events if e.is_sensitive_operation]
    assert sensitive, "expected sensitive operations after login"


def test_benign_travel_scenario_present(store):
    out = search_logs(store, "A107", W_START, W_END)
    assert not out.empty
    corr = correlate_events(out.events)
    assert not corr.failed_login_streaks
    assert not corr.success_after_failures
    assert len(corr.benign_signals) >= 2


# ------------------------------------------------------------ empty / errors
def test_no_matching_logs_explicit_empty(store):
    out = search_logs(store, "A901", W_START, W_END)
    assert out.empty is True
    assert out.events == []
    assert out.total_matched == 0


def test_missing_account_identifier_rejected(store):
    with pytest.raises(InvalidRequestError):
        search_logs(store, "", W_START, W_END)


def test_invalid_account_format_rejected(store):
    with pytest.raises(InvalidRequestError):
        search_logs(store, "DROP TABLE accounts", W_START, W_END)


def test_invalid_time_window_rejected(store):
    with pytest.raises(InvalidRequestError):
        search_logs(store, "A104", W_END, W_START)  # reversed
    with pytest.raises(InvalidRequestError):
        search_logs(store, "A104", W_START, W_START + timedelta(days=999))  # too wide
    with pytest.raises(InvalidRequestError):
        search_logs(store, "A104", "not-a-date", W_END)  # malformed


def test_log_search_timeout_simulated():
    s = LogStore(faults={"A104": "timeout"})
    with pytest.raises(ToolTimeout):
        search_logs(s, "A104", W_START, W_END)


def test_log_search_error_simulated():
    s = LogStore(faults={"A104": "error"})
    with pytest.raises(ToolFailure):
        search_logs(s, "A104", W_START, W_END)


# -------------------------------------------------------------- time zones
def test_timezone_handling_naive_interpreted_as_utc(store):
    naive_start = datetime(2026, 10, 20, 0, 0)      # no tzinfo
    out = search_logs(store, "A118", naive_start, datetime(2026, 10, 21))
    assert out.total_matched >= 4
    aware_out = search_logs(store, "A118", W_START, W_END)
    assert out.total_matched == aware_out.total_matched


def test_window_filters_correctly(store):
    narrow = search_logs(
        store, "A104",
        datetime(2026, 10, 20, 9, 12, tzinfo=timezone.utc),
        datetime(2026, 10, 20, 9, 18, tzinfo=timezone.utc),
    )
    assert all(
        datetime(2026, 10, 20, 9, 12, tzinfo=timezone.utc)
        <= e.timestamp
        <= datetime(2026, 10, 20, 9, 18, tzinfo=timezone.utc)
        for e in narrow.events
    )
    assert len(narrow.events) >= 6


# ------------------------------------------------------------- correlation
def test_correlate_finds_streak_success_and_sensitive(store):
    out = search_logs(store, "A104", ATTACK_START, ATTACK_END)
    corr = correlate_events(out.events)
    assert corr.account_id == "A104"
    assert corr.failed_login_streaks
    assert corr.failed_login_streaks[0]["count"] >= 5
    assert corr.success_after_failures
    sa = corr.success_after_failures[0]
    assert sa["success_event_id"] == "E-1010"
    assert sa["prior_failure_count"] >= 5
    assert corr.sensitive_operations
    sensitive_ids = {s["event_id"] for s in corr.sensitive_operations}
    assert {"E-1011", "E-1012", "E-1013"} <= sensitive_ids
    assert corr.privilege_changes
    # telemetry gaps surfaced, not hidden
    assert any("missing device_id" in g for g in corr.telemetry_gaps)
    assert any("missing source_ip" in g for g in corr.telemetry_gaps)


def test_correlate_deterministic(store):
    out = search_logs(store, "A104", ATTACK_START, ATTACK_END)
    a = correlate_events(out.events)
    b = correlate_events(list(reversed(out.events)))
    assert a.model_dump() == b.model_dump()


def test_correlate_empty_input(store):
    corr = correlate_events([])
    assert corr.total_events == 0
    assert corr.failed_login_streaks == []


# ------------------------------------------------------------ prompt injection
def test_prompt_injection_flagged_not_obeyed(store):
    out = search_logs(store, "A104", ATTACK_START, ATTACK_END)
    corr = correlate_events(out.events)
    assert "E-1011" in corr.injection_suspected_ids
    ev = store.get_by_id("E-1011")
    assert ev is not None and ev.prompt_injection_suspected
    # payload neutralized: no newlines/control chars can break report framing
    assert "\n" not in ev.detail and "\r" not in ev.detail
    # and the timeline marks it as untrusted instead of replaying it raw
    tl = generate_incident_timeline([ev])
    assert tl[0].untrusted_detail_flagged is True


# ------------------------------------------------------------- evidence
def test_retrieve_evidence_roundtrip(store):
    bundle = retrieve_evidence(store, ["E-1010", "E-1011", "E-1013"])
    assert [e.event_id for e in bundle.found] == ["E-1010", "E-1011", "E-1013"]
    assert bundle.missing_ids == []


def test_retrieve_evidence_never_invents(store):
    bundle = retrieve_evidence(store, ["E-1010", "E-9999"])
    assert bundle.missing_ids == ["E-9999"]
    assert [e.event_id for e in bundle.found] == ["E-1010"]


def test_retrieve_evidence_rejects_malformed_ids(store):
    with pytest.raises(InvalidRequestError):
        retrieve_evidence(store, ["'; DROP TABLE evidence; --"])
    with pytest.raises(InvalidRequestError):
        retrieve_evidence(store, "E-1010")  # not a list


# ------------------------------------------------------------- timeline
def test_timeline_chronological_with_evidence_ids(store):
    out = search_logs(store, "A104", ATTACK_START, ATTACK_END)
    tl = generate_incident_timeline(out.events)
    assert tl, "timeline must not be empty for matching window"
    assert [t.timestamp for t in tl] == sorted(t.timestamp for t in tl)
    assert all(t.event_id.startswith("E-") for t in tl)
    # summaries contain no raw control characters
    assert all("\n" not in t.summary and "\r" not in t.summary for t in tl)


def test_malformed_event_rejected_by_schema():
    with pytest.raises(Exception):
        Event.model_validate({"event_id": "E-1", "timestamp": "2026-10-20T00:00:00Z",
                              "account_id": "A1", "event_type": "nonsense"})
    with pytest.raises(Exception):
        Event.model_validate({"event_id": "bad", "timestamp": "2026-10-20T00:00:00Z",
                              "account_id": "A104", "event_type": "auth_success"})
