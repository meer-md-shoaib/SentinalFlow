"""Pydantic message schemas for communication between specialized SentinelFlow agents."""

from __future__ import annotations
from typing import Any

try:
    from uagents import Model
except ImportError:
    from pydantic import BaseModel as Model  # Fallback for static typing / testing without uagents


class InvestigateTelemetryRequest(Model):
    """Dispatched by Coordinator to InvestigatorAgent to query SIEM logs."""
    target: str
    time_window_minutes: int = 60
    simulate_failure: bool = False


class InvestigateTelemetryResponse(Model):
    """Returned by InvestigatorAgent containing retrieved and sanitized telemetry."""
    target: str
    events: list[dict[str, Any]]
    sanitization_notes: list[str]
    success: bool
    error_message: str | None = None


class ThreatAnalysisRequest(Model):
    """Dispatched to AnalystAgent to evaluate MITRE ATT&CK tactics & score risk."""
    target: str
    events: list[dict[str, Any]]


class ThreatAnalysisResponse(Model):
    """Returned by AnalystAgent with deterministic risk assessment."""
    target: str
    risk_level: str
    risk_score: int
    mitre_tactics: list[str]
    evidence: list[str]
    recommended_action: str | None = None
    summary: str


class ContainmentActionRequest(Model):
    """Dispatched to ContainmentAgent to enforce policy & execute remediation."""
    action_type: str
    target: str
    risk_score: int
    approval_token: str | None = None
    operator: str = "sentinelflow_containment_agent"


class ContainmentActionResponse(Model):
    """Returned by ContainmentAgent with action execution status."""
    authorized: bool
    executed: bool
    action_id: str | None = None
    target: str
    action_type: str
    status: str
    reason: str
    timestamp: str


class VerificationRequest(Model):
    """Dispatched to AuditorAgent to independently inspect post-containment state."""
    action_id: str
    expected_status: str
    simulate_mismatch: bool = False


class VerificationResponse(Model):
    """Returned by AuditorAgent with cryptographic audit receipt and verified state."""
    verified: bool
    action_id: str
    expected_status: str
    actual_status: str
    audit_receipt_hash: str
    timestamp: str
    summary: str
