"""SentinelFlow Investigator Agent: Specialized in SIEM telemetry queries & log sanitization."""

from __future__ import annotations

import os
import asyncio

# Ensure active event loop for Python 3.12+
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

from uagents import Agent, Context

from agents.models import InvestigateTelemetryRequest, InvestigateTelemetryResponse
from tools.log_search import search_logs, LogSearchError
from security.input_validation import detect_prompt_injection

INVESTIGATOR_PORT = int(os.getenv("INVESTIGATOR_PORT", "8001"))
INVESTIGATOR_SEED = os.getenv("INVESTIGATOR_SEED", "sentinelflow-investigator-agent-seed-2026")

investigator_agent = Agent(
    name="SentinelFlow Investigator Agent",
    seed=INVESTIGATOR_SEED,
    port=INVESTIGATOR_PORT,
    endpoint=[f"http://127.0.0.1:{INVESTIGATOR_PORT}/submit"],
)


def perform_investigation(
    target: str,
    time_window_minutes: int = 60,
    simulate_failure: bool = False,
) -> tuple[list[dict], list[str], bool, str | None]:
    """Execute deterministic log search and scan raw records for prompt injections."""
    sanitization_notes: list[str] = []
    try:
        search_result = search_logs(
            account_id=target,
            time_window_minutes=time_window_minutes,
            simulate_failure=simulate_failure,
        )
    except LogSearchError as err:
        return [], sanitization_notes, False, str(err)

    events = search_result.get("events", [])
    for ev in events:
        for k, v in ev.items():
            if isinstance(v, str) and detect_prompt_injection(v):
                note = f"Indirect prompt injection neutralized in log field '{k}' of event '{ev.get('event_id')}': treated as untrusted data."
                if note not in sanitization_notes:
                    sanitization_notes.append(note)

    return events, sanitization_notes, True, None


@investigator_agent.on_message(model=InvestigateTelemetryRequest)
async def handle_investigation(ctx: Context, sender: str, msg: InvestigateTelemetryRequest):
    """Handle telemetry investigation dispatch from Coordinator."""
    ctx.logger.info(f"🔎 Investigator received query for target '{msg.target}' from {sender}")
    events, notes, success, error_msg = perform_investigation(
        target=msg.target,
        time_window_minutes=msg.time_window_minutes,
        simulate_failure=msg.simulate_failure,
    )

    response = InvestigateTelemetryResponse(
        target=msg.target,
        events=events,
        sanitization_notes=notes,
        success=success,
        error_message=error_msg,
    )
    await ctx.send(sender, response)
    ctx.logger.info(f"✅ Investigator returned {len(events)} telemetry events to {sender}")


if __name__ == "__main__":
    investigator_agent.run()
