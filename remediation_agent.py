"""SentinelVault: Specialized Remediation, Audit Verifier & Payment Escrow Agent.

Collaborates with SentinelFlow (Agent 1) to execute authorized containment actions,
charge enterprise containment fees via Fetch.ai Payment Protocol, and generate
tamper-evident SHA-256 audit receipts.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

from dotenv import load_dotenv
from uagents import Agent, Context, Model, Protocol

load_dotenv()

from payment import payment_proto, DEFAULT_FEE_FET
from security.policies import authorize_action
from tools.simulated_response import execute_simulated_action, verify_containment_state


# Shared Agent-to-Agent (A2A) message schemas
class ContainmentTask(Model):
    task_id: str
    target: str
    action_type: str
    approval_token: str
    requester_address: str
    fee_amount: str = DEFAULT_FEE_FET
    fee_currency: str = "FET"


class ContainmentResult(Model):
    task_id: str
    target: str
    action_type: str
    action_id: str
    verified: bool
    actual_state: str
    audit_hash: str
    timestamp: str
    payment_status: str
    details: str


remediation_proto = Protocol(name="SentinelRemediationProtocol", version="1.0.0")


@remediation_proto.on_message(model=ContainmentTask)
async def handle_containment_task(ctx: Context, sender: str, msg: ContainmentTask):
    """Handle containment execution delegated from SentinelFlow Triage Agent."""
    ctx.logger.info(f"🛡️  [SentinelVault] Received ContainmentTask from {sender} for {msg.target} ({msg.action_type})")

    # 1. Authorization check
    is_auth, auth_reason = authorize_action(
        action=msg.action_type,
        target=msg.target,
        approval_token=msg.approval_token,
        risk_score=90,
    )

    if not is_auth:
        ctx.logger.warning(f"❌ [SentinelVault] Unauthorized action request from {sender}: {auth_reason}")
        await ctx.send(
            sender,
            ContainmentResult(
                task_id=msg.task_id,
                target=msg.target,
                action_type=msg.action_type,
                action_id="unauthorized",
                verified=False,
                actual_state="unchanged",
                audit_hash="none",
                timestamp=datetime.now(timezone.utc).isoformat(),
                payment_status="rejected",
                details=auth_reason,
            ),
        )
        return

    # 2. Execute containment
    exec_res = execute_simulated_action(
        action_type=msg.action_type,
        target=msg.target,
        operator=f"sentinel_vault_agent:{ctx.agent.address}",
    )
    action_id = exec_res.get("action_id", f"act-{uuid4().hex[:6]}")

    # 3. Verify state
    expected_state = "sessions_revoked" if msg.action_type == "revoke_user_sessions" else "blocked"
    verification = verify_containment_state(
        action_id=action_id,
        expected_status=expected_state,
        simulate_mismatch=False,
    )

    verified = bool(verification.get("verified"))
    actual_state = str(verification.get("actual_state", "unknown"))
    audit_hash = str(verification.get("audit_hash", ""))
    details = str(verification.get("details", ""))

    ctx.logger.info(
        f"✅ [SentinelVault] Remediation executed for {msg.target}. "
        f"State: {actual_state}. Verified: {verified}. Fee: {msg.fee_amount} {msg.fee_currency}"
    )

    # 4. Reply to Agent 1 with cryptographic proof and payment status
    await ctx.send(
        sender,
        ContainmentResult(
            task_id=msg.task_id,
            target=msg.target,
            action_type=msg.action_type,
            action_id=action_id,
            verified=verified,
            actual_state=actual_state,
            audit_hash=audit_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            payment_status=f"{msg.fee_amount} {msg.fee_currency} Settled (Escrow Released)",
            details=details,
        ),
    )


# Agent 2 definition
remediation_agent = Agent(
    name=os.getenv("REMEDIATION_AGENT_NAME", "SentinelVault Remediation Agent"),
    seed=os.getenv("REMEDIATION_AGENT_SEED", "sentinelvault-remediation-agent-seed-2026"),
    port=int(os.getenv("REMEDIATION_AGENT_PORT", "8001")),
    mailbox=False,  # Runs locally or inside Bureau alongside Agent 1
)

# Attach Payment Protocol and Inter-Agent Remediation Protocol
remediation_agent.include(payment_proto)
remediation_agent.include(remediation_proto)


@remediation_agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("=" * 60)
    ctx.logger.info(f"🔐 SentinelVault Remediation Agent Initialized")
    ctx.logger.info(f"📍 Agent Address: {remediation_agent.address}")
    ctx.logger.info(f"💰 Payment Protocol: Active ({DEFAULT_FEE_FET} FET per verified incident)")
    ctx.logger.info("=" * 60)


if __name__ == "__main__":
    remediation_agent.run()
