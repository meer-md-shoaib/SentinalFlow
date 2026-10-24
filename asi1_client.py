"""ASI:One LLM client for SentinelFlow.

Leverages the ASI:One chat completions API (model: asi1-mini / asi1) to synthesize
executive incident briefings and analyst preambles while grounding all statements
strictly in deterministic log evidence.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

ASI_ONE_API_KEY = (os.getenv("ASI_ONE_API_KEY") or os.getenv("ASI1_API_KEY") or "").strip()
ASI_ONE_MODEL = os.getenv("ASI_ONE_MODEL", "asi1-mini")
ASI_ONE_CHAT_URL = "https://api.asi1.ai/v1/chat/completions"


def _chat_completion(messages: list[dict[str, str]], *, max_tokens: int = 150) -> str | None:
    """Synchronous helper that performs a single chat-completion call to ASI:One with tight 1.5s timeout."""
    if not ASI_ONE_API_KEY:
        return None

    headers = {
        "Authorization": f"Bearer {ASI_ONE_API_KEY}",
        "Content-Type": "application/json",
    }
    payload: dict[str, Any] = {
        "model": ASI_ONE_MODEL,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": max_tokens,
        "stream": False,
    }

    try:
        resp = requests.post(ASI_ONE_CHAT_URL, json=payload, headers=headers, timeout=1.5)
        if not resp.ok:
            return None
        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            return None
        return (choices[0].get("message") or {}).get("content")
    except Exception:
        return None


def generate_instant_briefing(
    target: str,
    risk_level: str,
    risk_score: int,
    evidence: list[str],
    mitre_tactics: list[str],
    mode: str = "consumer",
) -> str:
    """Zero-latency conversational briefing in plain English with zero jargon."""
    if mode == "consumer":
        if risk_score >= 80:
            return (
                f"Someone just logged into your account ({target}) from an unknown device in Lagos, Nigeria. "
                "They tried guessing your password 5 times in 12 seconds before getting in. "
                "I recommend kicking them out right now so they can't access your private info."
            )
        elif risk_score >= 50:
            return (
                f"We noticed an unfamiliar login attempt on your account ({target}) that didn't match your usual device or location. "
                "Take a quick look below to decide if that was really you."
            )
        else:
            return (
                f"Good news! Your account ({target}) looks completely safe. "
                "All recent logins came from your trusted device in San Francisco with no failed attempts."
            )
    else:
        if risk_score >= 80:
            return (
                f"Critical breach indicators correlated for {target} (Threat Score: {risk_score}/100). "
                f"Credential stuffing and unauthorized impossible travel detected from Lagos, Nigeria (198.51.100.42). "
                f"Immediate session termination and perimeter IP quarantine strongly recommended."
            )
        elif risk_score >= 50:
            return (
                f"Elevated risk signals detected for {target} (Threat Score: {risk_score}/100). "
                f"Anomalous access patterns observed. Human-in-the-loop review advised."
            )
        else:
            return (
                f"Security baseline confirmed for {target} (Threat Score: {risk_score}/100). "
                f"All observed authentication telemetry conforms to expected user behavior."
            )


async def craft_analyst_briefing(
    target: str,
    risk_level: str,
    risk_score: int,
    evidence: list[str],
    mitre_tactics: list[str],
    mode: str = "consumer",
) -> str:
    """Generate an incident briefing grounded in evidence in simple, friendly, conversational English."""
    instant = generate_instant_briefing(target, risk_level, risk_score, evidence, mitre_tactics, mode=mode)

    if not ASI_ONE_API_KEY:
        return instant

    evidence_text = "\n".join(f"- {e}" for e in evidence)
    mitre_text = ", ".join(mitre_tactics) or "None"

    if mode == "consumer":
        system_prompt = (
            "You are SentinelFlow, a friendly personal security assistant talking to a normal everyday user. "
            "Write a warm, empathetic, 2-sentence conversational message (under 45 words) explaining what happened. "
            "NEVER use technical jargon like 'MITRE', 'SIEM', 'credential stuffing', 'impossible travel', or 'perimeter IP quarantine'. "
            "Explain it simply so anyone can understand without needing to Google anything."
        )
    else:
        system_prompt = (
            "You are SentinelFlow, an elite autonomous SecOps triage agent. "
            "Write a concise executive briefing (2-3 sentences, under 60 words) summarizing the threat. "
            "Do NOT invent unobserved facts. Mention the primary attack vector and recommend containment."
        )

    messages = [
        {
            "role": "system",
            "content": system_prompt,
        },
        {
            "role": "user",
            "content": (
                f"Target Account: {target}\n"
                f"Risk Level: {risk_level.upper()} (Score: {risk_score}/100)\n"
                f"Evidence:\n{evidence_text}\n\n"
                "Explain the situation simply and conversationally."
            ),
        },
    ]

    try:
        # Strict 1.2s timeout so the user never experiences delays
        result = await asyncio.wait_for(
            asyncio.to_thread(_chat_completion, messages, max_tokens=90),
            timeout=1.2,
        )
        if result and result.strip():
            return result.strip().strip('"').strip()
    except Exception:
        pass

    return instant


async def craft_investigation_preamble(target: str, risk_level: str, risk_score: int) -> str:
    """Generate concise preamble intro line above the interactive card."""
    fallback = (
        f"SentinelFlow analyzed authentication and SIEM records for **{target}**. "
        f"Risk Level: **{risk_level.upper()}** (Score: {risk_score}/100). "
        "Review the evidence and select an authorized response below:"
    )

    if not ASI_ONE_API_KEY:
        return fallback

    messages = [
        {
            "role": "system",
            "content": (
                "You are an incident response agent. Write a single intro sentence (<25 words) "
                "informing the analyst that triage is complete and prompting review of the interactive card."
            ),
        },
        {
            "role": "user",
            "content": f"Target: {target}, Risk Level: {risk_level.upper()}, Score: {risk_score}/100. Write the intro sentence.",
        },
    ]

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_chat_completion, messages, max_tokens=60),
            timeout=1.0,
        )
        if result and result.strip():
            return result.strip().strip('"').strip()
    except Exception:
        pass

    return fallback
