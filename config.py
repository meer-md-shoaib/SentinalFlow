"""SentinelFlow configuration — all secrets come from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

DATA_DIR = PROJECT_ROOT / "data"
EVENTS_FILE = DATA_DIR / "synthetic_events.json"
STATE_STORE_FILE = DATA_DIR / "state_store.json"
AUDIT_LOG_FILE = PROJECT_ROOT / "logs" / "audit.jsonl"


@dataclass(frozen=True)
class Settings:
    # ASI:One model API (OpenAI-compatible). Used ONLY for intent parsing and
    # phrasing — never for risk scoring, authorization, or action decisions.
    asi1_base_url: str = field(
        default_factory=lambda: os.getenv("ASI1_BASE_URL", "https://api.asi1.ai/v1")
    )
    asi1_api_key: str = field(
        default_factory=lambda: os.getenv("ASI1_API_KEY", "")
    )
    asi1_model: str = field(default_factory=lambda: os.getenv("ASI1_MODEL", "asi1"))

    # Agent / platform
    agent_port: int = field(
        default_factory=lambda: int(os.getenv("AGENT_PORT", "8081"))
    )
    agentverse_mailbox_key: str = field(
        default_factory=lambda: os.getenv("AGENTVERSE_MAILBOX_KEY", "")
    )
    agent_seed: str = field(default_factory=lambda: os.getenv("AGENT_SEED", ""))

    # Bounded execution limits (security requirements)
    llm_timeout_seconds: float = 20.0
    tool_timeout_seconds: float = 5.0
    max_search_results: int = 500
    max_evidence_ids: int = 100
    approval_ttl_seconds: int = 600  # approvals expire after 10 minutes
    max_tool_calls_per_request: int = 25

    @property
    def llm_available(self) -> bool:
        return bool(self.asi1_api_key)


settings = Settings()
