"""Synthetic log store: strict load-time validation, dedupe, quarantine,
fault injection for failure-path testing, and baseline loading.

Malformed records are quarantined (kept for audit, never used as evidence).
Duplicate event_ids are collapsed to the first occurrence and reported.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from config import EVENTS_FILE, settings
from schemas import Event, QuarantinedRecord


class ToolTimeout(Exception):
    """A tool exceeded its time budget (simulated or real)."""


class ToolFailure(Exception):
    """A tool failed to produce output."""


class InvalidRequestError(Exception):
    """Request parameters failed validation."""


class BaselineStore:
    """Known-good activity baseline per account. If absent, baseline rules
    must be skipped (never assumed)."""

    def __init__(self, data: dict[str, Any] | None):
        self._accounts: dict[str, Any] = (data or {}).get("accounts", {})

    @classmethod
    def load(cls, path: Path) -> "BaselineStore":
        if not path.exists():
            return cls(None)
        try:
            return cls(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            return cls(None)

    @property
    def available(self) -> bool:
        return bool(self._accounts)

    def allowed_source_prefixes(self, account_id: str) -> list[str] | None:
        entry = self._accounts.get(account_id)
        if not entry:
            return None
        prefixes = entry.get("allowed_source_prefixes")
        return list(prefixes) if prefixes else None


class LogStore:
    def __init__(
        self,
        events_file: Path | None = None,
        baseline_file: Path | None = None,
        faults: dict[str, str] | None = None,
    ):
        """faults: mapping account_id -> 'timeout' | 'error' used to simulate
        log-search failures in tests and demos. Empty in normal operation."""
        self.events_file = events_file or EVENTS_FILE
        self.faults = dict(faults or {})
        self.events: list[Event] = []
        self.quarantined: list[QuarantinedRecord] = []
        self.duplicate_event_ids: list[str] = []
        self._by_id: dict[str, Event] = {}
        self._by_account: dict[str, list[Event]] = {}
        self.baseline = BaselineStore.load(
            baseline_file or (self.events_file.parent / "baseline.json")
        )
        self._load()

    # ------------------------------------------------------------------ load
    def _load(self) -> None:
        try:
            raw = json.loads(self.events_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ToolFailure(f"cannot read event dataset: {exc}") from exc

        records = raw.get("events") if isinstance(raw, dict) else None
        if not isinstance(records, list):
            raise ToolFailure("dataset malformed: expected {'events': [...]}")

        seen: set[str] = set()
        for idx, rec in enumerate(records):
            try:
                event = Event.model_validate(rec)
            except ValidationError as exc:
                reasons = "; ".join(
                    f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
                    for e in exc.errors()
                )
                self.quarantined.append(
                    QuarantinedRecord(index=idx, reason=reasons, raw=_safe_raw(rec))
                )
                continue
            if event.event_id in seen:
                self.duplicate_event_ids.append(event.event_id)
                continue
            seen.add(event.event_id)
            self.events.append(event)

        self.events.sort(key=lambda e: e.timestamp)
        for event in self.events:
            self._by_id[event.event_id] = event
            self._by_account.setdefault(event.account_id, []).append(event)

    # ----------------------------------------------------------------- query
    def get_by_id(self, event_id: str) -> Event | None:
        return self._by_id.get(event_id)

    def accounts(self) -> list[str]:
        return sorted(self._by_account)

    def range(
        self, account_id: str, start, end
    ) -> list[Event]:
        """Time-ordered events for an account within [start, end], both UTC."""
        return [
            e
            for e in self._by_account.get(account_id, [])
            if start <= e.timestamp <= end
        ]

    def check_fault(self, account_id: str) -> None:
        """Raise the configured simulated fault for this account, if any."""
        mode = self.faults.get(account_id)
        if mode == "timeout":
            raise ToolTimeout(f"log search timed out for account {account_id}")
        if mode == "error":
            raise ToolFailure(f"log backend error for account {account_id}")


def _safe_raw(rec: Any) -> dict[str, Any] | str:
    if isinstance(rec, dict):
        return {str(k): str(v)[:200] for k, v in rec.items()}
    return str(rec)[:300]


_default_store: LogStore | None = None


def get_store(faults: dict[str, str] | None = None) -> LogStore:
    """Default store instance (fresh read when faults are specified)."""
    global _default_store
    if faults is not None:
        return LogStore(faults=faults)
    if _default_store is None:
        _default_store = LogStore()
    return _default_store
