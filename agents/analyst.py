"""SentinelFlow Analyst Agent: Specialized in MITRE ATT&CK risk assessment & threat scoring."""

from __future__ import annotations

import os
import asyncio

# Ensure active event loop for Python 3.12+
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

from uagents import Agent, Context

from agents.models import ThreatAnalysisRequest, ThreatAnalysisResponse
from security.policies import evaluate_incident_risk, RiskAssessment

ANALYST_PORT = int(os.getenv("ANALYST_PORT", "8002"))
ANALYST_SEED = os.getenv("ANALYST_SEED", "sentinelflow-analyst-agent-seed-2026")

analyst_agent = Agent(
    name="SentinelFlow Threat Analyst Agent",
    seed=ANALYST_SEED,
    port=ANALYST_PORT,
    endpoint=[f"http://127.0.0.1:{ANALYST_PORT}/submit"],
)


@analyst_agent.on_message(model=ThreatAnalysisRequest)
async def handle_threat_analysis(ctx: Context, sender: str, msg: ThreatAnalysisRequest):
    """Handle threat analysis dispatch from Coordinator using deterministic MITRE ATT&CK rules."""
    ctx.logger.info(f"🧠 Analyst assessing threat for target '{msg.target}' from {sender}")
    assessment: RiskAssessment = evaluate_incident_risk(events=msg.events, target=msg.target)

    response = ThreatAnalysisResponse(
        target=msg.target,
        risk_level=assessment.risk_level,
        risk_score=assessment.risk_score,
        mitre_tactics=assessment.mitre_tactics,
        evidence=assessment.evidence,
        recommended_action=assessment.recommended_action,
        summary=assessment.summary,
    )
    await ctx.send(sender, response)
    ctx.logger.info(f"📊 Analyst computed risk score {assessment.risk_score} ({assessment.risk_level}) for {msg.target}")


if __name__ == "__main__":
    analyst_agent.run()
