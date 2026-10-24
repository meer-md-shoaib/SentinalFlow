"""Deterministic risk assessment: rules -> severity + explanation.

The score is a transparent sum of rule weights. It is NOT a probability of
compromise and must never be presented as one.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from investigation.log_store import BaselineStore, LogStore
from risk.rules import RuleContext, evaluate_rules
from schemas import (
    CorrelationResult,
    Event,
    Indicator,
    RiskAssessment,
    SearchOutcome,
    Severity,
)

# severity thresholds over the deterministic point total
_THRESHOLDS = (
    (15, Severity.CRITICAL),
    (7, Severity.HIGH),
    (4, Severity.MEDIUM),
    (1, Severity.LOW),
)


def severity_for_score(score: int) -> Severity:
    for minimum, sev in _THRESHOLDS:
        if score >= minimum:
            return sev
    return Severity.INFORMATIONAL


def incident_id_for(account_id: str, start: datetime, end: datetime) -> str:
    """Deterministic incident id — identical (account, window) => same id,
    which also underpins duplicate-request handling."""
    key = f"{account_id}|{start.isoformat()}|{end.isoformat()}"
    return "INC-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper()


def assess_risk(
    outcome: SearchOutcome,
    correlation: CorrelationResult,
    events: list[Event] | None = None,
    baseline: BaselineStore | None = None,
) -> RiskAssessment:
    request = outcome.request
    incident_id = incident_id_for(
        request.account_id, request.start_time, request.end_time
    )
    effective_events = events if events is not None else outcome.events

    # explicit empty-evidence behavior: nothing to score, stated plainly
    if not effective_events:
        return RiskAssessment(
            incident_id=incident_id,
            account_id=request.account_id,
            window_start=request.start_time,
            window_end=request.end_time,
            severity=Severity.INFORMATIONAL,
            score=0,
            rule_hits=[],
            indicators=[],
            evidence_ids=[],
            explanation=(
                "No matching events were found in the requested window, so no "
                "risk indicators could be evaluated. This is an evidence gap, "
                "not a clean bill of health."
            ),
            uncertainties=[
                "No telemetry for this account/window — verify account id and "
                "time window, or treat missing logs as its own concern."
            ],
            missing_information=["no events in window"],
            recommended_next_step=(
                "Verify the account identifier and time window; if correct, "
                "investigate why telemetry is absent."
            ),
            baseline_applied=False,
            assessed_at=datetime.now(timezone.utc),
        )

    ctx = RuleContext(
        events=effective_events,
        correlation=correlation,
        baseline=baseline or BaselineStore(None),
        window_start=request.start_time,
        window_end=request.end_time,
    )
    hits = evaluate_rules(ctx)
    score = sum(h.weight for h in hits if not h.rationale.startswith("EVALUATION ERROR"))
    severity = severity_for_score(score)
    baseline_applied = any(h.rule_id == "R6" for h in hits)

    evidence_ids: list[str] = []
    for h in hits:
        for eid in h.evidence_ids:
            if eid not in evidence_ids:
                evidence_ids.append(eid)

    uncertainties: list[str] = []
    missing: list[str] = []
    if correlation.telemetry_gaps:
        uncertainties.append(
            f"{len(correlation.telemetry_gaps)} event(s) missing telemetry "
            "fields: " + "; ".join(correlation.telemetry_gaps)
        )
        missing.append("device/source fields absent on some events")
    if not baseline or not baseline.available:
        uncertainties.append(
            "No baseline data available — baseline anomaly rules were not applied."
        )
        missing.append("baseline profile")
    elif not baseline_applied and not baseline.allowed_source_prefixes(request.account_id):
        uncertainties.append(
            f"No baseline entry for {request.account_id} — baseline rules skipped."
        )
        missing.append(f"baseline for {request.account_id}")
    for h in hits:
        if h.rationale.startswith("EVALUATION ERROR"):
            uncertainties.append(f"Rule {h.rule_id} failed to evaluate; score may be understated.")
            missing.append(f"rule {h.rule_id} result")
    if correlation.injection_suspected_ids:
        uncertainties.append(
            "Log field(s) "
            + ", ".join(correlation.injection_suspected_ids)
            + " contain instruction-like text (treated strictly as untrusted data)."
        )
    if outcome.warnings:
        uncertainties.extend(outcome.warnings)

    indicators = [
        Indicator(
            name=h.name,
            detail=h.rationale,
            evidence_ids=h.evidence_ids,
        )
        for h in hits
        if h.weight > 0
    ]

    # explanation: purely mechanical summary of triggered rules
    if any(h.weight > 0 for h in hits):
        parts = [
            f"{h.rule_id} {h.name} (+{h.weight}): {h.rationale}"
            for h in hits
            if h.weight > 0
        ]
        explanation = (
            f"Deterministic rule total {score} points -> {severity.value}. "
            + " | ".join(parts)
            + ". Points are transparent rule weights, not a probability of compromise."
        )
    else:
        explanation = (
            "No risk rule fired in this window (score 0, informational). "
            "This reflects the available evidence only."
        )

    recommended = _recommendation(severity, correlation)

    return RiskAssessment(
        incident_id=incident_id,
        account_id=request.account_id,
        window_start=request.start_time,
        window_end=request.end_time,
        severity=severity,
        score=score,
        rule_hits=hits,
        indicators=indicators,
        evidence_ids=evidence_ids,
        explanation=explanation,
        uncertainties=uncertainties,
        missing_information=missing,
        recommended_next_step=recommended,
        baseline_applied=baseline_applied,
        deterministic=True,
        assessed_at=datetime.now(timezone.utc),
    )


def _recommendation(severity: Severity, corr: CorrelationResult) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return (
            "Simulated containment recommended: temporarily contain account "
            "(requires explicit approval before any action). Also open an "
            "incident record and escalate to the on-call analyst."
        )
    if severity == Severity.MEDIUM:
        return (
            "Flag the account for investigation and increase monitoring; "
            "re-run the investigation with an extended window."
        )
    if severity == Severity.LOW:
        return "Record the finding and monitor; containment is not indicated."
    return "No response action indicated; record the outcome."


def default_baseline(store: LogStore) -> BaselineStore:
    return store.baseline
