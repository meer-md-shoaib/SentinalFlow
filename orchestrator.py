"""SentinelFlow orchestrator: staged, bounded investigation -> response workflow.

Stages (kept distinct per spec):
  parse -> search -> correlate -> assess -> recommend -> (auto: non-sensitive
  record actions) -> approval request -> validate approval -> revalidate ->
  execute simulated action -> independent verification -> report.

The LLM (ASI:One model) is used ONLY to classify intent and extract parameters.
Every security decision — risk, authorization, execution, verification — is
deterministic code with strict validation. Failures at any critical stage
produce a FAILED/PARTIAL status, never a fabricated "complete".
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from config import AUDIT_LOG_FILE, settings
from investigation import (
    InvalidRequestError,
    LogStore,
    ToolFailure,
    ToolTimeout,
    correlate_events,
    generate_incident_timeline,
    get_store,
    search_logs,
)
from llm import Intent, IntentResult, fallback_classify
from reporting import build_report, render_report
from response import (
    ApprovalDenied,
    ApprovalError,
    ApprovalLedger,
    ApprovalReplayed,
    ResponseSimulator,
    StateStore,
    create_pending_action,
    decide,
    parse_decision,
    verify_state,
)
from risk import assess_risk
from schemas import (
    ActionKind,
    CorrelationResult,
    IncidentReport,
    InvestigationRequest,
    RiskAssessment,
    SearchOutcome,
    Severity,
    TimelineEntry,
)

MAX_TEXT_IN = 4000
_CACHE_MAX = 64


@dataclass
class ChatReply:
    text: str
    status: str  # complete | partial | failed | info
    report: IncidentReport | None = None
    assessment: RiskAssessment | None = None


@dataclass
class InvestigationRecord:
    outcome: SearchOutcome
    correlation: CorrelationResult
    assessment: RiskAssessment
    timeline: list[TimelineEntry]
    report: IncidentReport
    session: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class Orchestrator:
    def __init__(
        self,
        store: LogStore | None = None,
        simulator: ResponseSimulator | None = None,
        ledger: ApprovalLedger | None = None,
        llm: Any | None = None,
        audit_path: Path | None = None,
    ):
        self.store = store or get_store()
        self.sim = simulator or ResponseSimulator(StateStore())
        self.ledger = ledger or ApprovalLedger()
        self.llm = llm  # None => purely deterministic keyword parsing
        self.audit_path = audit_path or AUDIT_LOG_FILE

        self._sessions: dict[str, dict[str, str]] = {}
        self._investigations: dict[str, InvestigationRecord] = {}
        self._cache: OrderedDict[str, str] = OrderedDict()
        self._audit_seq = 0
        self._audit_memory: list[dict[str, Any]] = []
        self._tool_calls = 0

        # default window = dataset's own span (deterministic, data-driven)
        if self.store.events:
            first = self.store.events[0].timestamp
            last = self.store.events[-1].timestamp
            self._default_window = (first, last)
        else:
            now = datetime.now(timezone.utc)
            self._default_window = (now - timedelta(days=1), now)

    # ================================================================ entry
    def handle_message(
        self, text: str, sender: str = "chat-user", session_id: str | None = None
    ) -> ChatReply:
        session = session_id or sender
        raw = (text or "").strip()
        self._tool_calls = 0

        if not raw:
            return ChatReply(text=self._help_text(), status="info")
        if len(raw) > MAX_TEXT_IN:
            raw = raw[:MAX_TEXT_IN]

        self._audit("message_received", session=session, length=len(raw))

        try:
            intent_res = self._classify(raw)
        except Exception as exc:  # classification must never kill the flow
            self._audit("classify_error", session=session, error=str(exc)[:200])
            intent_res = fallback_classify(raw)

        try:
            if intent_res.intent == Intent.INVESTIGATE:
                return self._cmd_investigate(intent_res, raw, session)
            if intent_res.intent == Intent.APPROVE:
                return self._cmd_decision(raw, "approve", session)
            if intent_res.intent == Intent.DECLINE:
                return self._cmd_decision(raw, "decline", session)
            if intent_res.intent == Intent.STATUS:
                return self._cmd_status(session)
            if intent_res.intent == Intent.HELP:
                return ChatReply(text=self._help_text(), status="info")
            return ChatReply(
                text=(
                    "I didn't understand that. Try: `Investigate account A104 "
                    "from 2026-10-20T00:00:00Z to 2026-10-21T00:00:00Z` "
                    "or type `help`."
                ),
                status="info",
            )
        except Exception as exc:  # absolute last resort: honest failure
            self._audit("unhandled_error", session=session, error=str(exc)[:300])
            return ChatReply(
                text=(
                    "SentinelFlow hit an unexpected internal error and stopped. "
                    "The investigation is NOT complete. No actions were taken. "
                    f"({type(exc).__name__})"
                ),
                status="failed",
            )

    # ========================================================= classification
    def _classify(self, text: str) -> IntentResult:
        if self.llm is not None:
            res = self.llm.classify(text)   # client itself falls back on API failure
            if isinstance(res, IntentResult):
                return res
            return IntentResult.model_validate(res)
        return fallback_classify(text)

    # ============================================================ investigate
    def _cmd_investigate(
        self, res: IntentResult, text: str, session: str
    ) -> ChatReply:
        # ---- stage 1: parse + validate parameters
        if not res.account_id:
            return ChatReply(
                text=(
                    "I need an account id in the format `A###` (e.g. `A104`). "
                    "Example: `Investigate account A104 from 2026-10-20T00:00:00Z "
                    "to 2026-10-21T00:00:00Z`"
                ),
                status="info",
            )

        start, end = self._resolve_window(res)
        request = InvestigationRequest(
            account_id=res.account_id,
            start_time=start,
            end_time=end,
            requested_by=session,
            session_id=session,
        )

        # ---- duplicate request handling (idempotent)
        key = hashlib.sha256(
            f"{session}|{request.account_id}|{request.start_time}|{request.end_time}".encode()
        ).hexdigest()
        if key in self._cache:
            self._audit("duplicate_request", session=session, key=key[:12])
            return ChatReply(
                text=self._cache[key]
                + "\n\n_(duplicate request: the original investigation is returned "
                "unchanged; no new work was performed)_",
                status="complete",
                report=None,
            )

        # ---- stage 2: search logs
        try:
            self._spend_tool_call()
            outcome = search_logs(
                self.store, request.account_id, request.start_time, request.end_time
            )
        except InvalidRequestError as exc:
            return ChatReply(text=f"Invalid investigation request: {exc}", status="info")
        except ToolTimeout as exc:
            self._audit("search_timeout", session=session, error=str(exc))
            return ChatReply(
                text=(
                    f"INVESTIGATION FAILED — log search timed out ({exc}). "
                    "No risk assessment was produced and no actions were taken. "
                    "Nothing is reported as complete."
                ),
                status="failed",
            )
        except ToolFailure as exc:
            self._audit("search_failure", session=session, error=str(exc))
            return ChatReply(
                text=(
                    f"INVESTIGATION FAILED — log backend error ({exc}). "
                    "No actions were taken."
                ),
                status="failed",
            )

        # ---- stage 3: correlate (output validated; malformed => failure)
        try:
            self._spend_tool_call()
            corr_raw = correlate_events(outcome.events)
            payload = corr_raw.model_dump() if hasattr(corr_raw, "model_dump") else corr_raw
            correlation = CorrelationResult.model_validate(payload)
        except ValidationError as exc:
            self._audit("correlation_malformed", session=session, error=str(exc)[:200])
            return ChatReply(
                text=(
                    "INVESTIGATION FAILED — the correlation tool returned malformed "
                    f"output and was rejected by schema validation. No actions were "
                    "taken. Details: {first error}".replace(
                        "{first error}", str(exc.errors()[0].get("msg", ""))[:150]
                    )
                ),
                status="failed",
            )
        except Exception as exc:
            self._audit("correlation_error", session=session, error=str(exc)[:200])
            return ChatReply(
                text=f"INVESTIGATION FAILED — correlation error ({type(exc).__name__}). "
                "No actions were taken.",
                status="failed",
            )

        # ---- stage 4: deterministic risk assessment
        try:
            self._spend_tool_call()
            assessment = assess_risk(
                outcome, correlation, baseline=self.store.baseline
            )
            RiskAssessment.model_validate(assessment.model_dump())
        except Exception as exc:
            self._audit("risk_engine_failure", session=session, error=str(exc)[:300])
            return ChatReply(
                text=(
                    f"INVESTIGATION FAILED — risk engine error ({type(exc).__name__}). "
                    "Evidence was retrieved but NO severity, recommendation, or action "
                    "is being reported. Treat this investigation as incomplete."
                ),
                status="failed",
            )

        # ---- timeline (stage 4b)
        try:
            timeline = generate_incident_timeline(outcome.events)
            for t in timeline:
                TimelineEntry.model_validate(t.model_dump())
        except Exception as exc:
            self._audit("timeline_error", session=session, error=str(exc)[:200])
            return ChatReply(
                text=f"INVESTIGATION FAILED — timeline generation error "
                f"({type(exc).__name__}). No actions were taken.",
                status="failed",
            )

        # ---- stage 5: proportional, policy-checked response actions
        action_notes: list[str] = []
        verify_notes: list[str] = []
        approval_status = "not required at this severity"
        pending_prompt = ""

        if assessment.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
            auto_actions = [
                (ActionKind.CREATE_INCIDENT, "open incident record"),
                (ActionKind.FLAG_ACCOUNT, "flag account for investigation"),
            ]
            for action, reason in auto_actions:
                fp = _fp(assessment.incident_id, action, request.account_id, session)
                decision = decide(
                    action, None,
                    incident_id=assessment.incident_id,
                    target_account=request.account_id,
                    requested_by=session,
                    expected_fingerprint=fp,
                )
                self._audit_policy(decision, session)
                if not decision.allowed:
                    action_notes.append(f"{action.value}: rejected ({decision.reason})")
                    continue
                try:
                    self._spend_tool_call()
                    result = self.sim.execute(
                        action, f"AUTO-{assessment.incident_id}", request.account_id,
                        assessment.incident_id, reason,
                    )
                    action_notes.append(f"{action.value}: {result.status}")
                    check = verify_state(
                        self.sim.store, action, result.action_id,
                        request.account_id, assessment.incident_id,
                    )
                    verify_notes.append(f"{action.value}: {check.status}")
                    self._audit(
                        "action_executed",
                        session=session, action=action.value,
                        incident=assessment.incident_id, verification=check.status,
                    )
                except Exception as exc:
                    action_notes.append(f"{action.value}: failed ({type(exc).__name__})")
                    self._audit("action_failed", session=session, action=action.value,
                                error=str(exc)[:200])

        # ---- stage 6: sensitive action => explicit authorization required
        if assessment.severity in (Severity.HIGH, Severity.CRITICAL):
            pending = create_pending_action(
                incident_id=assessment.incident_id,
                action=ActionKind.CONTAIN_ACCOUNT,
                target_account=request.account_id,
                requested_by=session,
                justification=(
                    f"severity={assessment.severity.value}, score={assessment.score} "
                    f"({', '.join(h.rule_id for h in assessment.rule_hits if h.weight > 0)})"
                ),
            )
            self.ledger.issue(pending)
            self._sessions[session] = {
                "pending": pending.action_id,
                "incident": assessment.incident_id,
            }
            approval_status = (
                f"PENDING — containment requires your explicit approval "
                f"(token {pending.action_id}, expires "
                f"{pending.expires_at.strftime('%H:%M:%S')}Z)"
            )
            pending_prompt = (
                "\n\n---\n**Authorization required.** Proposed simulated action: "
                f"`temporarily contain account {request.account_id}` "
                f"(incident {assessment.incident_id}).\n"
                f"Justification: {pending.justification}\n\n"
                f"To authorize, reply exactly: **APPROVE {pending.action_id}**\n"
                f"To refuse, reply exactly: **DECLINE {pending.action_id}**\n"
                "_No action will be taken without your approval. The token expires "
                "and can be used only once._"
            )
            self._audit(
                "approval_requested",
                session=session, token=pending.action_id,
                incident=assessment.incident_id, target=request.account_id,
                expires=pending.expires_at.isoformat(),
            )

        # ---- stage 10: report
        audit_ref = self._audit(
            "investigation_completed",
            session=session,
            incident=assessment.incident_id,
            severity=assessment.severity.value,
            score=assessment.score,
            events=len(outcome.events),
        )
        report = build_report(
            assessment, timeline, correlation,
            approval_status=approval_status,
            action_result="; ".join(action_notes) if action_notes else None,
            verification_result="; ".join(verify_notes) if verify_notes else None,
            audit_reference=audit_ref,
            status="complete",
            extra_notes=[] if outcome.events else ["no events in window"],
        )
        text = render_report(report) + pending_prompt

        self._investigations[assessment.incident_id] = InvestigationRecord(
            outcome=outcome, correlation=correlation, assessment=assessment,
            timeline=timeline, report=report, session=session,
        )
        self._cache[key] = text
        while len(self._cache) > _CACHE_MAX:
            self._cache.popitem(last=False)

        return ChatReply(text=text, status="complete", report=report,
                         assessment=assessment)

    # ======================================================= approve / decline
    def _cmd_decision(self, text: str, fallback: str, session: str) -> ChatReply:
        parsed = parse_decision(text) or (fallback, None)
        decision, token = parsed

        if token is None:
            ctx = self._sessions.get(session, {})
            token = ctx.get("pending")
            if not token:
                return ChatReply(
                    text=(
                        "There is no pending action for this conversation. "
                        "Provide the token: `APPROVE <token>` or `DECLINE <token>`."
                    ),
                    status="info",
                )

        # ---- stage 7: validate approval (binding, expiry, replay, identity)
        try:
            pending = self.ledger.get(token)
            approval = self.ledger.validate(
                token, decision, decided_by=session,
                expected_fingerprint=pending.fingerprint,
            )
        except ApprovalDenied as exc:
            self._audit("approval_declined", session=session, token=token)
            self._release_pending(session, token)
            return ChatReply(
                text=(
                    f"Approval declined. No action was taken and state was not "
                    f"modified ({exc}). You can request a new investigation at any time."
                ),
                status="info",
            )
        except ApprovalError as exc:
            self._audit("approval_rejected", session=session, token=token,
                        error=str(exc)[:200])
            return ChatReply(
                text=(
                    f"Approval REJECTED: {exc}. No action was executed and no state "
                    "was modified."
                ),
                status="info",
            )

        self._audit(
            "approval_granted", session=session, token=token,
            incident=pending.incident_id, target=pending.target_account,
            fingerprint=pending.fingerprint[:16],
        )

        # ---- policy revalidation immediately before execution
        record = self._investigations.get(pending.incident_id)
        if record is None:
            return self._reject_after_approval(
                session, token, "incident is unknown to this session"
            )
        fp = _fp(pending.incident_id, pending.action, pending.target_account, session)
        policy = decide(
            pending.action, approval,
            incident_id=pending.incident_id,
            target_account=pending.target_account,
            requested_by=session,
            expected_fingerprint=fp,
        )
        self._audit_policy(policy, session)
        if not policy.allowed:
            return self._reject_after_approval(session, token, policy.reason)

        # re-verify the action is still warranted (state/severity revalidation)
        try:
            fresh = assess_risk(
                record.outcome, record.correlation, baseline=self.store.baseline
            )
        except Exception as exc:
            return self._reject_after_approval(
                session, token, f"revalidation failed ({type(exc).__name__})"
            )
        if fresh.severity not in (Severity.HIGH, Severity.CRITICAL):
            return self._reject_after_approval(
                session, token,
                f"severity is now {fresh.severity.value}; containment no longer warranted",
            )

        # ---- stage 8: execute the simulated action
        try:
            result = self.sim.execute(
                pending.action, pending.action_id, pending.target_account,
                pending.incident_id, pending.justification,
            )
        except Exception as exc:
            self._audit("action_failed", session=session, token=token,
                        error=str(exc)[:200])
            return ChatReply(
                text=(
                    f"Simulated action FAILED ({type(exc).__name__}): {exc}. "
                    "The action did not complete."
                ),
                status="failed",
            )

        # ---- stage 9: independent verification (never trust the tool's claim)
        check = verify_state(
            self.sim.store, pending.action, pending.action_id,
            pending.target_account, pending.incident_id,
        )
        self._audit(
            "verification", session=session, token=token, status=check.status,
            note=check.note[:200],
        )

        updated = record.report.model_copy(update={
            "approval_status": (
                f"APPROVED by {session} at "
                f"{approval.decided_at.isoformat()} (token {token})"
            ),
            "action_result": f"{pending.action.value}: {result.status}",
            "verification_result": (
                f"{pending.action.value}: {check.status}"
                + (f" — {check.note}" if check.note else "")
            ),
        })
        record.report = updated
        self._sessions.pop(session, None)

        verdict = {
            "verified": "VERIFIED — the state change was independently confirmed.",
            "failed": "VERIFICATION FAILED — the expected state change was NOT found. "
                      "Do not treat the action as effective.",
            "unverified": "UNVERIFIED — state could not be independently checked.",
        }[check.status]

        return ChatReply(
            text=(
                f"**Action executed and checked.**\n{verdict}\n\n"
                + render_report(updated)
            ),
            status="complete" if check.status == "verified" else "failed",
            report=updated,
            assessment=record.assessment,
        )

    def _reject_after_approval(
        self, session: str, token: str, reason: str
    ) -> ChatReply:
        self._audit("policy_rejected_after_approval", session=session,
                    token=token, reason=reason[:200])
        return ChatReply(
            text=(
                f"Approval was received but the action was REJECTED by policy "
                f"immediately before execution: {reason}. No state was modified."
            ),
            status="info",
        )

    # ============================================================== status/help
    def _cmd_status(self, session: str) -> ChatReply:
        ctx = self._sessions.get(session)
        if not ctx:
            return ChatReply(
                text="No pending action or active investigation in this conversation.",
                status="info",
            )
        pending = None
        try:
            pending = self.ledger.get(ctx["pending"])
        except Exception:
            pass
        if pending is None:
            return ChatReply(text="No pending action.", status="info")
        return ChatReply(
            text=(
                f"Pending: `{pending.action.value}` on {pending.target_account} "
                f"(incident {pending.incident_id}). Token {pending.action_id}, "
                f"expires {pending.expires_at.isoformat()}. "
                f"Reply APPROVE {pending.action_id} or DECLINE {pending.action_id}."
            ),
            status="info",
        )

    def _help_text(self) -> str:
        return (
            "**SentinelFlow** — evidence-driven security investigation agent.\n"
            "Commands:\n"
            "- `Investigate account A104 from 2026-10-20T00:00:00Z to "
            "2026-10-21T00:00:00Z` — full investigation + risk assessment\n"
            "- `APPROVE <token>` / `DECLINE <token>` — decide a proposed "
            "simulated action\n"
            "- `STATUS` — show the pending proposal\n"
            "- `help` — this message\n"
            "All actions are simulated; nothing touches real systems."
        )

    # ================================================================ helpers
    def _resolve_window(self, res: IntentResult) -> tuple[datetime, datetime]:
        d_start, d_end = self._default_window
        start = _parse_ts(res.start_time) if res.start_time else None
        end = _parse_ts(res.end_time) if res.end_time else None
        if start and end:
            return start, end
        if start and not end:
            return start, min(start + timedelta(days=1), d_end) if start < d_end else start + timedelta(days=1)
        if end and not start:
            return end - timedelta(days=1), end
        return d_start, d_end

    def _spend_tool_call(self) -> None:
        self._tool_calls += 1
        if self._tool_calls > settings.max_tool_calls_per_request:
            raise ToolFailure("tool call budget exceeded for this request")

    def _release_pending(self, session: str, token: str) -> None:
        ctx = self._sessions.get(session)
        if ctx and ctx.get("pending") == token:
            self._sessions.pop(session, None)

    def _audit_policy(self, decision, session: str) -> None:
        self._audit(
            "policy_decision",
            session=session, allowed=decision.allowed,
            action=decision.action.value, reason=decision.reason[:200],
        )

    def _audit(self, event: str, **payload: Any) -> str:
        self._audit_seq += 1
        entry = {
            "seq": self._audit_seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **payload,
        }
        ref = f"AUD-{self._audit_seq:06d}"
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            self._audit_memory.append({**entry, "file_error": str(exc)[:120]})
        return ref


# ------------------------------------------------------------------ module
def _fp(incident_id: str, action: ActionKind, target: str, requester: str) -> str:
    return hashlib.sha256(
        f"{incident_id}|{action.value}|{target}|{requester}".encode()
    ).hexdigest()


def _parse_ts(value: str) -> datetime:
    v = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


_orchestrator: Orchestrator | None = None


def get_orchestrator(llm: Any | None = None) -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator(llm=llm)
    return _orchestrator
