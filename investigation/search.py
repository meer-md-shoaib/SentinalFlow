"""search_logs — deterministic, bounded log search over the synthetic dataset.

Signature: search_logs(store, account_id, start_time, end_time)
- Strict parameter validation (format, order, max window).
- UTC-normalized comparison; naive inputs interpreted as UTC.
- Bounded result size; explicit empty-result flag.
- Raises InvalidRequestError / ToolTimeout / ToolFailure — never invents data.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from config import settings
from investigation.log_store import InvalidRequestError, LogStore
from schemas import InvestigationRequest, SearchOutcome


def search_logs(
    store: LogStore,
    account_id: str,
    start_time: datetime | str,
    end_time: datetime | str,
) -> SearchOutcome:
    # 1) strict validation of the request envelope
    try:
        request = InvestigationRequest(
            account_id=account_id,
            start_time=start_time,  # type: ignore[arg-type]
            end_time=end_time,      # type: ignore[arg-type]
        )
    except ValidationError as exc:
        msgs = "; ".join(
            " ".join(str(x) for x in e["msg"].split()) for e in exc.errors()
        )
        raise InvalidRequestError(msgs) from exc

    # 2) simulated/real log backend failure
    store.check_fault(request.account_id)

    # 3) bounded retrieval, deterministic order (timestamp asc)
    matched = store.range(request.account_id, request.start_time, request.end_time)
    total = len(matched)
    truncated = total > settings.max_search_results
    if truncated:
        matched = matched[: settings.max_search_results]

    warnings: list[str] = []
    if store.quarantined:
        warnings.append(
            f"{len(store.quarantined)} malformed record(s) quarantined at load; "
            "excluded from evidence"
        )
    if store.duplicate_event_ids:
        warnings.append(
            f"{len(store.duplicate_event_ids)} duplicate event_id(s) collapsed: "
            + ", ".join(sorted(set(store.duplicate_event_ids)))
        )
    if truncated:
        warnings.append(
            f"results truncated to {settings.max_search_results} events"
        )

    return SearchOutcome(
        request=request,
        events=matched,
        total_matched=total,
        truncated=truncated,
        empty=(total == 0),
        warnings=warnings,
    )
