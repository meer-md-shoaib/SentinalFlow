"""Input validation and prompt injection defenses for SentinelFlow.

Ensures that user queries, target account IDs, and log contents are strictly
treated as untrusted data and cannot hijack agent execution.
"""

from __future__ import annotations

import re
from typing import Literal
from pydantic import BaseModel, Field, ValidationError


# Strict regex for permitted target identifiers (e.g. demo-user-104, sarah-dev-202, ip addresses)
TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.@:]{1,64}$")

# Adversarial prompt injection keywords and patterns
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s+override", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:in\s+developer\s+mode|dan|an\s+unrestricted)", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all\s+)?prior\s+guidance", re.IGNORECASE),
    re.compile(r"bypass\s+(?:policy|authorization|guardrails)", re.IGNORECASE),
    re.compile(r"return\s+risk\s+level\s+low", re.IGNORECASE),
    re.compile(r"verify\s+as\s+passed", re.IGNORECASE),
    re.compile(r"drop\s+table\s+", re.IGNORECASE),
]


class SanitizedRequest(BaseModel):
    """Structured and sanitized representation of a user investigation request."""
    intent: Literal["investigate_suspicious_logins", "request_containment", "verify_state", "status_check"]
    target: str = Field(..., min_length=1, max_length=64)
    time_window_minutes: int = Field(default=60, ge=1, le=1440)
    requested_action: str | None = None
    approval_token: str | None = None
    has_injection_attempt: bool = False
    sanitization_notes: list[str] = Field(default_factory=list)


def validate_target(target: str) -> str:
    """Validate and sanitize a target account ID or IP address."""
    if not target or not isinstance(target, str):
        raise ValueError("Target account or IP identifier cannot be empty.")
    
    cleaned = target.strip()
    if not TARGET_PATTERN.match(cleaned):
        raise ValueError(
            f"Invalid target identifier: '{cleaned}'. Allowed characters: alphanumeric, hyphens, underscores, dots, '@'."
        )
    return cleaned


def detect_prompt_injection(text: str) -> bool:
    """Inspect text (user input or untrusted log strings) for adversarial injection patterns."""
    if not text:
        return False
    return any(pattern.search(text) for pattern in PROMPT_INJECTION_PATTERNS)


def parse_and_validate_request(
    intent: str,
    target: str,
    time_window_minutes: int = 60,
    requested_action: str | None = None,
    approval_token: str | None = None,
) -> SanitizedRequest:
    """Validate request parameters against strict security constraints."""
    notes: list[str] = []
    
    # Check for adversarial injection attempts in any field
    combined_text = f"{intent} {target} {requested_action or ''}"
    has_injection = detect_prompt_injection(combined_text)
    if has_injection:
        notes.append("Adversarial prompt injection pattern detected and neutralized.")
    
    # Clean and validate target
    clean_target = validate_target(target)
    
    # Normalize intent
    normalized_intent = intent.lower().strip()
    valid_intents = ("investigate_suspicious_logins", "request_containment", "verify_state", "status_check")
    if normalized_intent not in valid_intents:
        # Map common variations
        if "contain" in normalized_intent or "revoke" in normalized_intent or "block" in normalized_intent:
            normalized_intent = "request_containment"
        elif "verify" in normalized_intent or "audit" in normalized_intent:
            normalized_intent = "verify_state"
        elif "status" in normalized_intent:
            normalized_intent = "status_check"
        else:
            normalized_intent = "investigate_suspicious_logins"
            
    return SanitizedRequest(
        intent=normalized_intent,  # type: ignore[arg-type]
        target=clean_target,
        time_window_minutes=max(1, min(time_window_minutes, 1440)),
        requested_action=requested_action.strip() if requested_action else None,
        approval_token=approval_token.strip() if approval_token else None,
        has_injection_attempt=has_injection,
        sanitization_notes=notes,
    )
