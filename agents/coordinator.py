"""SentinelFlow Coordinator Agent: Frontline SecOps Orchestrator interfacing with ASI:One."""

from __future__ import annotations

import os
import asyncio

# Ensure active event loop for Python 3.12+
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

from uagents import Agent, Context

from chat_proto import chat_proto
from agents.investigator import investigator_agent
from agents.analyst import analyst_agent
from agents.containment import containment_agent
from agents.auditor import auditor_agent

import uagents.config

# Accelerate Mailbox polling to 250ms (4x faster message pickup from ASI:One)
uagents.config.MAILBOX_POLL_INTERVAL_SECONDS = 0.25

COORDINATOR_PORT = int(os.getenv("AGENT_PORT", "8081"))
COORDINATOR_SEED = os.getenv("AGENT_SEED_PHRASE") or os.getenv("AGENT_SEED", "sentinelflow_challenge_master_seed_2026")
AGENT_NAME = os.getenv("AGENT_NAME", "sentinalflow")
AGENT_ENDPOINT = os.getenv("AGENT_ENDPOINT", "")
MAILBOX_KEY = os.getenv("AGENTVERSE_MAILBOX_KEY", "")
USE_MAILBOX = bool(MAILBOX_KEY) or os.getenv("AGENT_MAILBOX", "False").lower() in ("true", "1", "yes")

agent_kwargs = {
    "name": AGENT_NAME,
    "seed": COORDINATOR_SEED,
    "port": COORDINATOR_PORT,
}
if MAILBOX_KEY:
    agent_kwargs["mailbox"] = f"{MAILBOX_KEY}@https://agentverse.ai"
elif AGENT_ENDPOINT:
    agent_kwargs["endpoint"] = [AGENT_ENDPOINT]

coordinator_agent = Agent(**agent_kwargs)

# Attach Agent Chat Protocol (ACP) for ASI:One discovery and dynamic cards
coordinator_agent.include(chat_proto, publish_manifest=True)


@coordinator_agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("=" * 65)
    ctx.logger.info(f"🛡️  SentinelFlow Coordinator Initialized: {coordinator_agent.name}")
    ctx.logger.info(f"📍 Coordinator Address: {coordinator_agent.address}")
    ctx.logger.info(f"👥 Multi-Agent Swarm Connected:")
    ctx.logger.info(f"   - 🔎 Investigator Agent : {investigator_agent.address}")
    ctx.logger.info(f"   - 🧠 Analyst Agent      : {analyst_agent.address}")
    ctx.logger.info(f"   - 🛡️ Containment Agent  : {containment_agent.address}")
    ctx.logger.info(f"   - 📜 Auditor Agent      : {auditor_agent.address}")
    ctx.logger.info(f"🌐 Protocol: Agent Chat Protocol (ACP) Published")
    ctx.logger.info(f"📬 Mailbox Enabled: {USE_MAILBOX}")
    ctx.logger.info("=" * 65)


if __name__ == "__main__":
    coordinator_agent.run()
