"""correlation, evidence retrieval, and timeline tools — pure deterministic
functions over validated events. Evidence IDs are preserved end to end.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from config import settings
from investigation.log_store import InvalidRequestError, LogStore
from schemas import (
    EVENT_ID_RE,
    SENSITIVE_ACTIONS,
    CorrelationResult,
    EvidenceBundle,
    Event,
    TimelineEntry,
    sanitize_untrusted,
)

FAILURE_STREAK_GAP = timedelta(minutes=10)
LOOKBACK_SUCCESS = timedelta(minutes=15)
LOOKBACK_BENIGN = timedelta(minutes=60)
MIN_FAILURES_FOR_STREAK = 3
MIN_FAILURES_BEFORE_SUCCESS = 3

_MAX_TIMELINE = 200


def correlate_events(events: list[Event]) -> CorrelationResult:
    """Deterministic correlation of authentication and audit events.

    Pure function of the evidence: same input always yields same output.
    """
    if not events:
        return CorrelationResult(account_id="", total_events=0, tool_calls_used=1)

    if not all(isinstance(e, Event) for e in events):
        raise TypeError("correlate_events requires validated Event objects")

    ordered = sorted(events, key=lambda e: e.timestamp)
    account = ordered[0].account_id

    streaks: list[dict] = []
    current: dict | None = None
    for ev in ordered:
        if ev.event_type != "auth_failure":
            if current and current["count"] >= MIN_FAILURES_FOR_STREAK:
                streaks.append(current)
            current = None
            continue
        key = (ev.source_ip, ev.device_id)
        if (
            current is not None
            and current["_key"] == key
            and ev.timestamp - current["_last"] <= FAILURE_STREAK_GAP
        ):
            current["count"] += 1
            current["event_ids"].append(ev.event_id)
            current["_last"] = ev.timestamp
            current["end"] = ev.timestamp.isoformat()
        else:
            if current and current["count"] >= MIN_FAILURES_FOR_STREAK:
                streaks.append(current)
            current = {
                "_key": key,
                "_last": ev.timestamp,
                "source_ip": ev.source_ip,
                "device_id": ev.device_id,
                "count": 1,
                "start": ev.timestamp.isoformat(),
                "end": ev.timestamp.isoformat(),
                "event_ids": [ev.event_id],
            }
    if current and current["count"] >= MIN_FAILURES_FOR_STREAK:
        streaks.append(current)
    for s in streaks:
        s.pop("_key", None)
        s.pop("_last", None)

    success_after: list[dict] = []
    benign: list[dict] = []
    for ev in ordered:
        if ev.event_type != "auth_success":
            continue
        window_start = ev.timestamp - LOOKBACK_SUCCESS
        prior_failures = [
            f
            for f in ordered
            if f.event_type == "auth_failure" and window_start <= f.timestamp < ev.timestamp
        ]
        same_source = [f for f in prior_failures if f.source_ip == ev.source_ip]
        if len(prior_failures) >= MIN_FAILURES_BEFORE_SUCCESS:
            success_after.append(
                {
                    "success_event_id": ev.event_id,
                    "timestamp": ev.timestamp.isoformat(),
                    "source_ip": ev.source_ip,
                    "device_id": ev.device_id,
                    "prior_failure_count": len(prior_failures),
                    "same_source_failure_count": len(same_source),
                    "event_ids": [f.event_id for f in prior_failures] + [ev.event_id],
                }
            )
        else:
            benign_window = ev.timestamp - LOOKBACK_BENIGN
            recent_failures = [
                f
                for f in ordered
                if f.event_type == "auth_failure"
                and benign_window <= f.timestamp < ev.timestamp
            ]
            if not recent_failures:
                benign.append(
                    {
                        "success_event_id": ev.event_id,
                        "timestamp": ev.timestamp.isoformat(),
                        "source_ip": ev.source_ip,
                        "device_id": ev.device_id,
                        "note": "first-try success, no recent failures",
                    }
                )

    sensitive = [
        {
            "event_id": ev.event_id,
            "timestamp": ev.timestamp.isoformat(),
            "action_type": ev.action_type,
            "source_ip": ev.source_ip,
            "device_id": ev.device_id,
            "privilege_level": ev.privilege_level,
        }
        for ev in ordered
        if ev.event_type in ("audit_action", "audit_config")
        and ev.action_type in SENSITIVE_ACTIONS
    ]

    priv_changes = [s for s in sensitive if s["action_type"] == "privilege_escalation"]

    gaps: list[str] = []
    for ev in ordered:
        if ev.device_id is None:
            gaps.append(f"{ev.event_id}: missing device_id")
        if ev.source_ip is None:
            gaps.append(f"{ev.event_id}: missing source_ip")

    injections = [ev.event_id for ev in ordered if ev.prompt_injection_suspected]

    return CorrelationResult(
        account_id=account,
        failed_login_streaks=streaks,
        success_after_failures=success_after,
        sensitive_operations=sensitive,
        privilege_changes=priv_changes,
        telemetry_gaps=gaps,
        benign_signals=benign,
        injection_suspected_ids=injections,
        total_events=len(ordered),
        tool_calls_used=1,
    )


def retrieve_evidence(store: LogStore, event_ids: list[str]) -> EvidenceBundle:
    """Fetch full records for the given evidence IDs. Never invents events:
    unknown IDs are reported in missing_ids."""
    if not isinstance(event_ids, list) or not all(
        isinstance(x, str) for x in event_ids
    ):
        raise InvalidRequestError("event_ids must be a list of strings")
    if len(event_ids) > settings.max_evidence_ids:
        raise InvalidRequestError(
            f"too many evidence ids (max {settings.max_evidence_ids})"
        )
    for eid in event_ids:
        if not EVENT_ID_RE.match(eid):
            raise InvalidRequestError(f"malformed evidence id {eid!r}")

    found: list[Event] = []
    missing: list[str] = []
    seen: set[str] = set()
    for eid in event_ids:
        if eid in seen:
            continue
        seen.add(eid)
        ev = store.get_by_id(eid)
        if ev is None:
            missing.append(eid)
        else:
            found.append(ev)
    return EvidenceBundle(found=found, missing_ids=missing)


_CATEGORY = {
    "auth_success": "authentication success",
    "auth_failure": "authentication failure",
    "auth_logout": "session end",
    "audit_action": "audit action",
    "audit_config": "configuration change",
}


def generate_incident_timeline(events: list[Event]) -> list[TimelineEntry]:
    """Observed-facts timeline in UTC order. Summaries never restate untrusted
    detail text as instructions — detail is quoted and flagged when suspicious."""
    if not all(isinstance(e, Event) for e in events):
        raise TypeError("timeline requires validated Event objects")

    ordered = sorted(events, key=lambda e: e.timestamp)
    truncated = False
    if len(ordered) > _MAX_TIMELINE:
        ordered = ordered[:_MAX_TIMELINE]
        truncated = True

    entries: list[TimelineEntry] = []
    for ev in ordered:
        parts = [_CATEGORY[ev.event_type]]
        if ev.source_ip:
            parts.append(f"from {ev.source_ip}")
        if ev.device_id:
            parts.append(f"device {ev.device_id}")
        if ev.action_type:
            parts.append(f"action={ev.action_type}")
        if ev.detail:
            parts.append(f'("{sanitize_untrusted(ev.detail)}")')
        if truncated:
            parts.append("[timeline truncated]")
        entries.append(
            TimelineEntry(
                timestamp=ev.timestamp,
                event_id=ev.event_id,
                category=_CATEGORY[ev.event_type],
                summary=" ".join(parts),
                untrusted_detail_flagged=ev.prompt_injection_suspected,
            )
        )
    return entries


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
