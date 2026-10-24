"""SentinelFlow structured schemas (Pydantic v2).

Strict validation for everything that enters the system: log events, requests,
assessments, approvals, actions, verification, and the incident report.
Untrusted text fields are bounded and normalized at validation time.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

ACCOUNT_RE = re.compile(r"^A\d{3,4}$")
EVENT_ID_RE = re.compile(r"^E-\d{4}$")
MAX_WINDOW_DAYS = 31
MAX_TEXT = 500

EVENT_TYPES = (
    "auth_success",
    "auth_failure",
    "auth_logout",
    "audit_action",
    "audit_config",
)

SENSITIVE_ACTIONS = (
    "data_export",
    "privilege_escalation",
    "mfa_disable",
    "permission_grant",
    "config_change",
)

PRIVILEGE_LEVELS = ("user", "admin", "superadmin")


# --------------------------------------------------------------- helpers
def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        # Naive timestamps are interpreted as UTC (documented behavior).
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def sanitize_untrusted(text: str) -> str:
    """Neutralize untrusted log text for display: no control chars, bounded,
    and never rendered as instructions."""
    text = text.replace("\r", " ").replace("\n", " ").replace("\x00", "")
    text = re.sub(r"[\x01-\x1f\x7f]", "", text)
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT] + "…[truncated]"
    return text


# ------------------------------------------------------------- log events
class Event(BaseModel):
    """One synthetic security event. All fields validated strictly."""

    model_config = {"extra": "forbid"}

    event_id: str
    timestamp: datetime
    account_id: str
    event_type: str
    source_ip: str | None = None
    device_id: str | None = None
    authentication_result: str | None = None
    privilege_level: str | None = None
    action_type: str | None = None
    detail: str = ""

    @field_validator("event_id")
    @classmethod
    def _valid_event_id(cls, v: str) -> str:
        if not EVENT_ID_RE.match(v):
            raise ValueError(f"event_id must match E-#### (got {v!r})")
        return v

    @field_validator("account_id")
    @classmethod
    def _valid_account(cls, v: str) -> str:
        if not ACCOUNT_RE.match(v):
            raise ValueError(f"invalid account_id {v!r}")
        return v

    @field_validator("timestamp")
    @classmethod
    def _valid_ts(cls, v: datetime) -> datetime:
        return _ensure_utc(v)

    @field_validator("event_type")
    @classmethod
    def _valid_type(cls, v: str) -> str:
        if v not in EVENT_TYPES:
            raise ValueError(f"unknown event_type {v!r}")
        return v

    @field_validator("source_ip")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        if v is None:
            return None
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"invalid source_ip {v!r}")
        return v

    @field_validator("authentication_result")
    @classmethod
    def _valid_auth_result(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in ("success", "failure"):
            raise ValueError(f"authentication_result must be success|failure, got {v!r}")
        return v

    @field_validator("privilege_level")
    @classmethod
    def _valid_priv(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in PRIVILEGE_LEVELS:
            raise ValueError(f"invalid privilege_level {v!r}")
        return v

    @field_validator("detail", "device_id", "action_type")
    @classmethod
    def _bound_text(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return sanitize_untrusted(v)

    @model_validator(mode="after")
    def _auth_consistency(self) -> "Event":
        if self.event_type == "auth_failure" and self.authentication_result != "failure":
            raise ValueError("auth_failure requires authentication_result='failure'")
        if self.event_type == "auth_success" and self.authentication_result != "success":
            raise ValueError("auth_success requires authentication_result='success'")
        return self

    @property
    def is_sensitive_operation(self) -> bool:
        return self.action_type in SENSITIVE_ACTIONS

    @property
    def prompt_injection_suspected(self) -> bool:
        markers = (
            "ignore all previous", "ignore previous", "system prompt",
            "you are now", "disregard", "maintenance mode",
            "api key", "override granted",
        )
        low = self.detail.lower()
        return any(m in low for m in markers)


class QuarantinedRecord(BaseModel):
    """A raw record that failed validation — kept for audit, never used as evidence."""

    index: int
    reason: str
    raw: dict[str, Any] | str


# ------------------------------------------------------------- requests
class InvestigationRequest(BaseModel):
    account_id: str
    start_time: datetime
    end_time: datetime
    requested_by: str = "chat-user"
    session_id: str | None = None

    @field_validator("account_id")
    @classmethod
    def _account(cls, v: str) -> str:
        v = v.strip().upper()
        if not ACCOUNT_RE.match(v):
            raise ValueError(
                f"invalid account_id {v!r}: expected format A### (e.g. A104)"
            )
        return v

    @field_validator("start_time", "end_time")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return _ensure_utc(v)

    @model_validator(mode="after")
    def _window(self) -> "InvestigationRequest":
        if self.end_time <= self.start_time:
            raise ValueError("end_time must be after start_time")
        span = (self.end_time - self.start_time).total_seconds()
        if span > MAX_WINDOW_DAYS * 86400:
            raise ValueError(f"time window exceeds {MAX_WINDOW_DAYS} days")
        return self


# ------------------------------------------------------------ investigation
class SearchOutcome(BaseModel):
    request: InvestigationRequest
    events: list[Event]
    total_matched: int
    truncated: bool = False
    empty: bool = False
    warnings: list[str] = []


class TimelineEntry(BaseModel):
    timestamp: datetime
    event_id: str
    category: str  # observed label only, no inference
    summary: str
    untrusted_detail_flagged: bool = False


class CorrelationResult(BaseModel):
    account_id: str
    failed_login_streaks: list[dict[str, Any]] = []
    success_after_failures: list[dict[str, Any]] = []
    sensitive_operations: list[dict[str, Any]] = []
    privilege_changes: list[dict[str, Any]] = []
    telemetry_gaps: list[str] = []
    benign_signals: list[dict[str, Any]] = []
    injection_suspected_ids: list[str] = []
    total_events: int = 0
    tool_calls_used: int = 0


class EvidenceBundle(BaseModel):
    found: list[Event] = []
    missing_ids: list[str] = []


# ------------------------------------------------------------------ risk
class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Indicator(BaseModel):
    name: str
    detail: str
    evidence_ids: list[str] = []


class RuleHit(BaseModel):
    rule_id: str
    name: str
    weight: int
    evidence_ids: list[str] = []
    rationale: str


class RiskAssessment(BaseModel):
    incident_id: str
    account_id: str
    window_start: datetime
    window_end: datetime
    severity: Severity
    score: int  # deterministic points, explicitly NOT a probability
    rule_hits: list[RuleHit] = []
    indicators: list[Indicator] = []
    evidence_ids: list[str] = []
    explanation: str
    uncertainties: list[str] = []
    missing_information: list[str] = []
    recommended_next_step: str
    baseline_applied: bool = False
    deterministic: bool = True
    assessed_at: datetime


# --------------------------------------------------------------- response
class ActionKind(str, Enum):
    CREATE_INCIDENT = "create_incident"
    FLAG_ACCOUNT = "flag_account"
    CONTAIN_ACCOUNT = "contain_account"
    ESCALATE = "escalate"
    RESPONSE_SUMMARY = "response_summary"


class PendingAction(BaseModel):
    action_id: str  # one-time approval token
    fingerprint: str  # sha256(incident|action|target|requester)
    incident_id: str
    action: ActionKind
    target_account: str
    requested_by: str
    proposed_at: datetime
    expires_at: datetime
    justification: str
    sensitive: bool = True

    @property
    def expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


class ApprovalDecision(BaseModel):
    action_id: str
    decision: str  # "approve" | "decline"
    approved_by: str
    decided_at: datetime
    fingerprint: str


class ActionResult(BaseModel):
    action_id: str
    action: ActionKind
    target_account: str
    status: str  # "executed" | "rejected" | "failed"
    detail: str
    executed_at: datetime


class VerificationResult(BaseModel):
    action_id: str
    status: str  # "verified" | "failed" | "unverified"
    expected_state: dict[str, Any]
    actual_state: dict[str, Any] | None
    checked_at: datetime
    note: str = ""


class AccountState(BaseModel):
    account_id: str
    contained: bool = False
    flagged_for_investigation: bool = False
    contained_reason: str | None = None
    contained_at: datetime | None = None
    open_incidents: list[str] = []
    escalations: list[str] = []
    updated_at: datetime


class PolicyDecision(BaseModel):
    allowed: bool
    action: ActionKind
    requires_approval: bool
    reason: str
    decided_at: datetime


# ----------------------------------------------------------------- report
class IncidentReport(BaseModel):
    incident_id: str
    account_id: str
    window_start: datetime
    window_end: datetime
    severity: Severity
    severity_rationale: str
    timeline: list[TimelineEntry]
    evidence_ids: list[str]
    observed_facts: list[str]
    inferred_conclusions: list[str]
    missing_evidence_and_uncertainty: list[str]
    recommended_response: str
    approval_status: str
    action_result: str | None = None
    verification_result: str | None = None
    audit_reference: str
    status: str  # "complete" | "partial" | "failed"
