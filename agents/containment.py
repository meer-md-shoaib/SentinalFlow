"""SentinelFlow Containment Agent: Specialized in Policy Gating & SecOps Incident Remediation."""

from __future__ import annotations

import os
import asyncio

# Ensure active event loop for Python 3.12+
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

from uagents import Agent, Context

from agents.models import ContainmentActionRequest, ContainmentActionResponse
from security.policies import authorize_action, ALLOWED_CONTAINMENT_ACTIONS
from tools.simulated_response import execute_simulated_action

CONTAINMENT_PORT = int(os.getenv("CONTAINMENT_PORT", "8003"))
CONTAINMENT_SEED = os.getenv("CONTAINMENT_SEED", "sentinelflow-containment-agent-seed-2026")

containment_agent = Agent(
    name="SentinelFlow Containment Agent",
    seed=CONTAINMENT_SEED,
    port=CONTAINMENT_PORT,
    endpoint=[f"http://127.0.0.1:{CONTAINMENT_PORT}/submit"],
)


@containment_agent.on_message(model=ContainmentActionRequest)
async def handle_containment_action(ctx: Context, sender: str, msg: ContainmentActionRequest):
    """Enforce strict Human-in-the-Loop policy gate before executing containment."""
    ctx.logger.info(f"🛡️ Containment agent evaluating action '{msg.action_type}' for '{msg.target}' from {sender}")

    if msg.action_type not in ALLOWED_CONTAINMENT_ACTIONS:
        response = ContainmentActionResponse(
            authorized=False,
            executed=False,
            action_id=None,
            target=msg.target,
            action_type=msg.action_type,
            status="rejected",
            reason=f"Action '{msg.action_type}' is not in allowed containment actions whitelist.",
            timestamp="",
        )
        await ctx.send(sender, response)
        return

    # Check authorization token & policy gate
    is_authorized, auth_reason = authorize_action(
        action=msg.action_type,
        target=msg.target,
        approval_token=msg.approval_token,
        risk_score=msg.risk_score,
    )

    if not is_authorized:
        ctx.logger.warning(f"⛔ Containment rejected: {auth_reason}")
        response = ContainmentActionResponse(
            authorized=False,
            executed=False,
            action_id=None,
            target=msg.target,
            action_type=msg.action_type,
            status="pending_approval",
            reason=auth_reason,
            timestamp="",
        )
        await ctx.send(sender, response)
        return

    # Execute authorized containment
    exec_res = execute_simulated_action(
        action_type=msg.action_type,
        target=msg.target,
        operator=msg.operator,
    )

    response = ContainmentActionResponse(
        authorized=True,
        executed=exec_res.get("success", False),
        action_id=exec_res.get("action_id"),
        target=msg.target,
        action_type=msg.action_type,
        status="executed",
        reason=auth_reason,
        timestamp=exec_res.get("timestamp", ""),
    )
    await ctx.send(sender, response)
    ctx.logger.info(f"⚡ Containment executed successfully: action_id={exec_res.get('action_id')}")


if __name__ == "__main__":
    containment_agent.run()
