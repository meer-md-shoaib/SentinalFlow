"""Incident report: structured 12-section output, rendered for ASI:One chat.

Sections follow the spec: id, account/window, severity+rationale, timeline,
evidence ids, observed vs inferred, missing evidence/uncertainty, recommended
response, approval status, action result, verification result, audit ref.
"""

from __future__ import annotations

from datetime import datetime, timezone

from schemas import (
    CorrelationResult,
    IncidentReport,
    RiskAssessment,
    Severity,
    TimelineEntry,
    sanitize_untrusted,
)


def _observed_facts(corr: CorrelationResult) -> list[str]:
    facts: list[str] = []
    for s in corr.failed_login_streaks:
        facts.append(
            f"{s['count']} consecutive failed logins from {s['source_ip']} "
            f"between {s['start']} and {s['end']} "
            f"(evidence: {', '.join(s['event_ids'])})"
        )
    for e in corr.success_after_failures:
        facts.append(
            f"Successful login {e['success_event_id']} at {e['timestamp']} from "
            f"{e['source_ip']} after {e['prior_failure_count']} recent failures "
            "(evidence: " + ", ".join(e["event_ids"]) + ")"
        )
    for op in corr.sensitive_operations:
        facts.append(
            f"Sensitive operation '{op['action_type']}' at {op['timestamp']} from "
            f"{op['source_ip']} (evidence: {op['event_id']})"
        )
    for b in corr.benign_signals:
        facts.append(
            f"First-try successful login {b['success_event_id']} at {b['timestamp']} "
            f"from {b['source_ip']} with no recent failures (evidence: benign)"
        )
    for g in corr.telemetry_gaps:
        facts.append(f"Telemetry gap: {g}")
    if corr.injection_suspected_ids:
        facts.append(
            "Instruction-like text found in log field(s) "
            + ", ".join(corr.injection_suspected_ids)
            + " — recorded as untrusted data only, not acted upon"
        )
    if not facts:
        facts.append("No notable events observed in the requested window.")
    return facts


def _inferred_conclusions(assessment: RiskAssessment) -> list[str]:
    if not any(h.weight > 0 for h in assessment.rule_hits):
        return ["No pattern-based conclusions drawn; no rule fired."]
    return [
        f"[inference, rule {h.rule_id}] {h.rationale}"
        for h in assessment.rule_hits
        if h.weight > 0
    ]


def build_report(
    assessment: RiskAssessment,
    timeline: list[TimelineEntry],
    correlation: CorrelationResult,
    *,
    approval_status: str = "not requested",
    action_result: str | None = None,
    verification_result: str | None = None,
    audit_reference: str,
    status: str = "complete",
    extra_notes: list[str] | None = None,
) -> IncidentReport:
    uncertainties = list(assessment.uncertainties)
    if extra_notes:
        uncertainties.extend(extra_notes)

    return IncidentReport(
        incident_id=assessment.incident_id,
        account_id=assessment.account_id,
        window_start=assessment.window_start,
        window_end=assessment.window_end,
        severity=assessment.severity,
        severity_rationale=assessment.explanation,
        timeline=timeline,
        evidence_ids=assessment.evidence_ids,
        observed_facts=_observed_facts(correlation),
        inferred_conclusions=_inferred_conclusions(assessment),
        missing_evidence_and_uncertainty=uncertainties,
        recommended_response=assessment.recommended_next_step,
        approval_status=approval_status,
        action_result=action_result,
        verification_result=verification_result,
        audit_reference=audit_reference,
        status=status,
    )


def render_report(report: IncidentReport) -> str:
    """Human-readable markdown for chat. Every line derives from validated
    deterministic output — no model-generated facts."""
    sev = report.severity.value.upper()
    lines: list[str] = [
        f"## Incident Report — {report.incident_id}",
        f"Status: {report.status}",
        "",
        f"**1. Incident ID:** {report.incident_id}",
        f"**2. Account & window:** {report.account_id} | "
        f"{report.window_start.isoformat()} → {report.window_end.isoformat()} (UTC)",
        f"**3. Severity:** {sev}",
        f"Rationale: {sanitize_untrusted(report.severity_rationale)}",
        "",
        "**4. Timeline (observed events):**",
    ]
    if not report.timeline:
        lines.append("  (no events in window)")
    for i, entry in enumerate(report.timeline, 1):
        flag = " ⚠ untrusted-content-flagged" if entry.untrusted_detail_flagged else ""
        lines.append(
            f"  {i}. {entry.timestamp.isoformat()} {entry.event_id} — "
            f"{sanitize_untrusted(entry.summary)}{flag}"
        )
    lines += [
        "",
        "**5. Evidence IDs:** " + (", ".join(report.evidence_ids) or "(none)"),
        "",
        "**6. Observed facts vs inferred conclusions:**",
        "  Observed:",
    ]
    lines += [f"  - {sanitize_untrusted(f)}" for f in report.observed_facts]
    lines.append("  Inferred:")
    lines += [f"  - {sanitize_untrusted(f)}" for f in report.inferred_conclusions]
    lines += [
        "",
        "**7. Missing evidence & uncertainty:**",
    ]
    lines += [f"  - {sanitize_untrusted(u)}" for u in report.missing_evidence_and_uncertainty] or [
        "  - (none noted)"
    ]
    lines += [
        "",
        f"**8. Recommended response:** {sanitize_untrusted(report.recommended_response)}",
        f"**9. Approval status:** {report.approval_status}",
        f"**10. Action result:** {report.action_result or 'no action taken'}",
        f"**11. Verification result:** {report.verification_result or 'n/a'}",
        f"**12. Audit reference:** {report.audit_reference}",
        "",
        "_All conclusions are deterministic rule output; the score is not a "
        "probability of compromise. All log content is untrusted data._",
    ]
    return "\n".join(lines)
