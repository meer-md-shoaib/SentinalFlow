"""SentinelFlow: Autonomous SecOps Incident Investigation & Response Multi-Agent System (MAS).

Built exclusively on Fetch.ai uAgents and Agent Chat Protocol (ACP).
Features a collaborative swarm of 5 specialized Fetch.ai agents:
  1. Coordinator Agent  (Orchestrator & ASI:One ACP interface)
  2. Investigator Agent (Deterministic SIEM & Telemetry search)
  3. Threat Analyst Agent (MITRE ATT&CK Risk Scoring 0-100)
  4. Containment Agent  (Human-in-the-Loop Policy Gate & Remediation)
  5. Auditor Agent      (Closed-Loop State Verification & SHA-256 Receipts)
"""

from __future__ import annotations

import sys
import asyncio

# Ensure UTF-8 output on Windows consoles
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure active event loop on MainThread for Python 3.12+ compatibility
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

from dotenv import load_dotenv

load_dotenv()

import uagents.config

# Accelerate Mailbox polling to 250ms (4x faster message pickup from ASI:One)
uagents.config.MAILBOX_POLL_INTERVAL_SECONDS = 0.25

from agents.coordinator import coordinator_agent
from agents.bureau import create_sentinelflow_bureau

# Primary coordinator agent reference
agent = coordinator_agent

if __name__ == "__main__":
    if "--standalone" in sys.argv:
        print("🛡️  Starting SentinelFlow Coordinator Agent in Standalone mode...")
        coordinator_agent.run()
    else:
        print("=" * 65)
        print("🛡️  Starting SentinelFlow Multi-Agent System (Fetch.ai uAgents)")
        print("   1. Coordinator Agent  -> ASI:One Interface & ACP Dispatch")
        print("   2. Investigator Agent -> SIEM Log Search & Injection Defense")
        print("   3. Analyst Agent      -> MITRE ATT&CK Risk Scoring (0-100)")
        print("   4. Containment Agent  -> HITL Policy Gate & State Remediation")
        print("   5. Auditor Agent      -> Closed-Loop State Inspection & Receipts")
        print("=" * 65)
        bureau = create_sentinelflow_bureau()
        bureau.run()
