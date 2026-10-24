"""SentinelFlow Auditor Agent: Specialized in Closed-Loop State Verification & Cryptographic Auditing."""

from __future__ import annotations

import os
import asyncio

# Ensure active event loop for Python 3.12+
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

from uagents import Agent, Context

from agents.models import VerificationRequest, VerificationResponse
from tools.simulated_response import verify_containment_state

AUDITOR_PORT = int(os.getenv("AUDITOR_PORT", "8004"))
AUDITOR_SEED = os.getenv("AUDITOR_SEED", "sentinelflow-auditor-agent-seed-2026")

auditor_agent = Agent(
    name="SentinelFlow Auditor Agent",
    seed=AUDITOR_SEED,
    port=AUDITOR_PORT,
    endpoint=[f"http://127.0.0.1:{AUDITOR_PORT}/submit"],
)


@auditor_agent.on_message(model=VerificationRequest)
async def handle_verification(ctx: Context, sender: str, msg: VerificationRequest):
    """Independently verify actual post-containment system state and issue cryptographic audit receipt."""
    ctx.logger.info(f"🔍 Auditor verifying action '{msg.action_id}' expecting status '{msg.expected_status}' from {sender}")

    verification_payload = verify_containment_state(
        action_id=msg.action_id,
        expected_status=msg.expected_status,
        simulate_mismatch=msg.simulate_mismatch,
    )

    response = VerificationResponse(
        verified=verification_payload.get("verified", False),
        action_id=verification_payload.get("action_id", msg.action_id),
        expected_status=verification_payload.get("expected_status", msg.expected_status),
        actual_status=verification_payload.get("actual_status", "unknown"),
        audit_receipt_hash=verification_payload.get("audit_receipt_hash", ""),
        timestamp=verification_payload.get("timestamp", ""),
        summary=verification_payload.get("summary", ""),
    )
    await ctx.send(sender, response)
    ctx.logger.info(f"📜 Verification result: verified={response.verified}, receipt={response.audit_receipt_hash[:12]}...")


if __name__ == "__main__":
    auditor_agent.run()
