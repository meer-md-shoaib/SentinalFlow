"""Named, deterministic risk rules.

Every rule is a pure function of validated evidence + optional baseline.
No probabilistic claims: weights are transparent points, not probabilities.
Baseline rules run ONLY when baseline data exists for the account.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime

from investigation.log_store import BaselineStore
from schemas import CorrelationResult, Event, RuleHit


@dataclass
class RuleContext:
    events: list[Event]
    correlation: CorrelationResult
    baseline: BaselineStore
    window_start: object
    window_end: object


@dataclass
class Rule:
    rule_id: str
    name: str
    weight: int
    evaluate: object  # fn(ctx) -> RuleHit | None
    sensitive: bool = False
    description: str = ""


def _hit(rule: Rule, evidence_ids: list[str], rationale: str) -> RuleHit:
    return RuleHit(
        rule_id=rule.rule_id,
        name=rule.name,
        weight=rule.weight,
        evidence_ids=list(dict.fromkeys(evidence_ids)),
        rationale=rationale,
    )


# ----------------------------------------------------------------- rules
def _r1(ctx: RuleContext) -> RuleHit | None:
    streaks = ctx.correlation.failed_login_streaks
    qualifying = [s for s in streaks if s["count"] >= 5]
    if not qualifying:
        return None
    ids: list[str] = []
    for s in qualifying:
        ids.extend(s["event_ids"])
    counts = ", ".join(str(s["count"]) for s in qualifying)
    return _hit(R1, ids, f"{counts} consecutive failed logins observed in window")


def _r2(ctx: RuleContext) -> RuleHit | None:
    entries = ctx.correlation.success_after_failures
    if not entries:
        return None
    ids: list[str] = []
    for e in entries:
        ids.extend(e["event_ids"])
    n = entries[0]["prior_failure_count"]
    return _hit(
        R2, ids,
        f"successful login at {entries[0]['timestamp']} followed {n} failures "
        "within 15 minutes",
    )


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _r3(ctx: RuleContext) -> RuleHit | None:
    """Sensitive operation executed from a source that authenticated right
    after repeated failures (unusual authentication)."""
    unusual_sources: dict[str, datetime] = {}
    for e in ctx.correlation.success_after_failures:
        unusual_sources.setdefault(e["source_ip"], _ts(e["timestamp"]))
    if not unusual_sources or not ctx.correlation.sensitive_operations:
        return None
    ids: list[str] = []
    matched_actions: list[str] = []
    for op in ctx.correlation.sensitive_operations:
        if (
            op["source_ip"] in unusual_sources
            and _ts(op["timestamp"]) > unusual_sources[op["source_ip"]]
        ):
            ids.append(op["event_id"])
            matched_actions.append(str(op["action_type"]))
    if not ids:
        return None
    return _hit(
        R3, ids,
        "sensitive operation(s) ["
        + ", ".join(matched_actions)
        + "] executed from the source that authenticated after repeated failures",
    )


def _r4(ctx: RuleContext) -> RuleHit | None:
    changes = ctx.correlation.privilege_changes
    if not changes:
        return None
    ids = [c["event_id"] for c in changes]
    return _hit(R4, ids, "privilege level escalated during the window")


def _r5(ctx: RuleContext) -> RuleHit | None:
    disables = [
        op for op in ctx.correlation.sensitive_operations
        if op["action_type"] == "mfa_disable"
    ]
    if not disables:
        return None
    ids = [op["event_id"] for op in disables]
    return _hit(R5, ids, "multi-factor authentication disabled during the window")


def _r6(ctx: RuleContext) -> RuleHit | None:
    """Baseline source anomaly — only when baseline data exists."""
    if not ctx.baseline.available:
        return None
    prefixes = ctx.baseline.allowed_source_prefixes(ctx.correlation.account_id or "")
    if not prefixes:
        return None
    networks = []
    for p in prefixes:
        try:
            networks.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            continue
    if not networks:
        return None
    anomalous: list[Event] = []
    for ev in ctx.events:
        if ev.event_type not in ("auth_success", "auth_failure") or not ev.source_ip:
            continue
        ip = ipaddress.ip_address(ev.source_ip)
        if not any(ip in net for net in networks):
            anomalous.append(ev)
    if not anomalous:
        return None
    ids = [e.event_id for e in anomalous]
    ips = sorted({str(e.source_ip) for e in anomalous})
    return _hit(
        R6, ids,
        f"authentication event(s) from source(s) outside the known baseline: "
        f"{', '.join(ips)}",
    )


def _r7(ctx: RuleContext) -> RuleHit | None:
    """Missing telemetry — uncertainty, zero score."""
    gaps = ctx.correlation.telemetry_gaps
    if not gaps:
        return None
    ids = [g.split(":", 1)[0] for g in gaps]
    return _hit(R7, ids, f"{len(gaps)} event(s) have missing telemetry fields")


def _r8(ctx: RuleContext) -> RuleHit | None:
    """Conflicting benign signal — uncertainty, zero score."""
    suspicious_marks = ctx.correlation.success_after_failures
    if not suspicious_marks:
        return None
    last_suspicious = max(_ts(e["timestamp"]) for e in suspicious_marks)
    later_benign = [
        b for b in ctx.correlation.benign_signals
        if _ts(b["timestamp"]) > last_suspicious
    ]
    if not later_benign:
        return None
    ids = [b["success_event_id"] for b in later_benign]
    return _hit(
        R8, ids,
        "later successful login(s) from benign-looking sources conflict with the "
        "suspicious chain (compromised session may have ended, or attacker still active)",
    )


R1 = Rule("R1", "repeated_authentication_failures", 2, _r1, description="≥5 consecutive failed logins")
R2 = Rule("R2", "login_success_after_failures", 3, _r2, description="success follows repeated failures")
R3 = Rule("R3", "sensitive_operation_after_unusual_auth", 3, _r3, description="sensitive op from unusual source")
R4 = Rule("R4", "privilege_escalation", 2, _r4, description="privilege level changed")
R5 = Rule("R5", "security_control_disabled", 2, _r5, description="MFA/other control disabled")
R6 = Rule("R6", "baseline_source_anomaly", 1, _r6, description="auth outside known baseline (baseline required)")
R7 = Rule("R7", "telemetry_gaps", 0, _r7, description="missing fields — uncertainty only")
R8 = Rule("R8", "conflicting_benign_signal", 0, _r8, description="conflicting evidence — uncertainty only")

ALL_RULES: tuple[Rule, ...] = (R1, R2, R3, R4, R5, R6, R7, R8)


def evaluate_rules(ctx: RuleContext) -> list[RuleHit]:
    """Run all rules in fixed order; deterministic for identical input."""
    hits: list[RuleHit] = []
    for rule in ALL_RULES:
        try:
            hit = rule.evaluate(ctx)
        except Exception:
            # A crashing rule must not take down the assessment; it is recorded
            # as an uncertainty by the caller via rule_error flagging.
            hit = None
            hits.append(
                RuleHit(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    weight=0,
                    evidence_ids=[],
                    rationale=f"EVALUATION ERROR: rule {rule.rule_id} failed to run",
                )
            )
            continue
        if hit is not None:
            hits.append(hit)
    return hits
