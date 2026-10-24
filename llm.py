"""Thin, fail-soft client for the ASI:One model API.

Deliberately limited: the model is only ever asked to (a) classify a request
into a fixed set of intents and (b) rephrase already-computed, deterministic
results for chat readability. It never scores risk, never authorizes actions,
and its output is always validated against strict schemas.

Any model failure degrades to deterministic rule-based behavior.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

import httpx
from pydantic import BaseModel, Field, ValidationError

from config import settings


class Intent(str, Enum):
    INVESTIGATE = "investigate"
    STATUS = "status"
    APPROVE = "approve"
    DECLINE = "decline"
    HELP = "help"
    UNKNOWN = "unknown"


class IntentResult(BaseModel):
    intent: Intent
    account_id: str | None = Field(default=None, pattern=r"^A\d{3,4}$")
    start_time: str | None = None  # ISO-8601 UTC
    end_time: str | None = None


_INTENT_PROMPT = """You classify a user's message for a cybersecurity investigation agent.
Reply with ONLY a JSON object, no prose, matching exactly:
{"intent": "investigate"|"status"|"approve"|"decline"|"help"|"unknown",
 "account_id": "A104" or null,
 "start_time": "ISO-8601 UTC datetime or null",
 "end_time": "ISO-8601 UTC datetime or null"}
Rules: account ids look like A104. "approve"/"accept/yes, go ahead" about a pending
action = approve. "decline/no/cancel/reject" = decline. If the user asks to check,
review, investigate, look into an account = investigate.
Message: {message}"""


class ASI1Client:
    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 model: str | None = None, timeout: float | None = None):
        self.base_url = (base_url or settings.asi1_base_url).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.asi1_api_key
        self.model = model or settings.asi1_model
        self.timeout = timeout or settings.llm_timeout_seconds

    # ------------------------------------------------------------------ core
    def _chat(self, prompt: str, *, system: str | None = None) -> str:
        """Single chat completion call. Raises on any failure (callers degrade)."""
        if not self.api_key:
            raise RuntimeError("ASI1_API_KEY not configured")
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {"model": self.model, "messages": messages}
        resp = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    # ---------------------------------------------------------------- intent
    def classify(self, message: str) -> IntentResult:
        """Best-effort intent classification. Falls back to keyword rules."""
        message = message.strip()[:4000]  # bounded input
        try:
            raw = self._chat(_INTENT_PROMPT.format(message=message))
            obj = _extract_json(raw)
            return IntentResult.model_validate(obj)
        except Exception:
            return _fallback_classify(message)

    # ------------------------------------------------------------ rephrasing
    def explain_report(self, report_text: str) -> str | None:
        """Optional: ask the model to keep a report verbatim-faithful but chattier.

        Returns None on any failure so the caller uses the deterministic text.
        The prompt forbids adding, removing, or altering any fact.
        """
        try:
            return self._chat(
                "Rephrase the following incident report for a chat window. "
                "Keep EVERY fact, id, timestamp and section label identical. "
                "Do not add information. Output plain text only.\n\n" + report_text,
                system="You are a formatting assistant. You never add or remove facts.",
            )
        except Exception:
            return None


# --------------------------------------------------------------- helpers
def _extract_json(text: str) -> dict[str, Any]:
    """Pull the first JSON object out of a model reply (tolerates code fences)."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in reply")
    return json.loads(text[start:end + 1])


def _fallback_classify(message: str) -> IntentResult:
    """Deterministic keyword fallback when the model is unavailable."""
    low = message.lower()
    if any(w in low for w in ("approve", "accept", "yes, go ahead", "confirm")):
        return IntentResult(intent=Intent.APPROVE)
    if any(w in low for w in ("decline", "cancel", "reject", "no, do not")):
        return IntentResult(intent=Intent.DECLINE)
    if "help" in low or low.strip() in ("?", "start"):
        return IntentResult(intent=Intent.HELP)
    for word in ("investigate", "check", "review", "look into", "assess", "scan"):
        if word in low:
            acct = _find_account(message)
            start, end = _find_window(message)
            return IntentResult(
                intent=Intent.INVESTIGATE, account_id=acct,
                start_time=start, end_time=end,
            )
    return IntentResult(intent=Intent.UNKNOWN)


def _find_account(text: str) -> str | None:
    import re
    m = re.search(r"\bA\d{3,4}\b", text)
    return m.group(0) if m else None


def _find_window(text: str) -> tuple[str | None, str | None]:
    import re
    # e.g. "2026-03-01T00:00:00Z" or "2026-03-01 00:00"
    pat = r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?Z?)"
    found = re.findall(pat, text)
    if len(found) >= 2:
        return found[0], found[1]
    if len(found) == 1:
        return found[0], None
    return None, None


# Public name used by the orchestrator (deterministic, model-free parsing).
fallback_classify = _fallback_classify
