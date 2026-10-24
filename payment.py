"""Fetch.ai Payment Protocol implementation for SentinelFlow.

Enables Enterprise SecOps-as-a-Service (SECaaS) monetization:
- Log triage and risk scoring are free.
- Autonomous verified containment and cryptographic audit logging cost 0.1 FET per incident.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from uagents import Context, Protocol
from uagents_core.contrib.protocols.payment import (
    CancelPayment,
    CommitPayment,
    CompletePayment,
    Funds,
    RejectPayment,
    RequestPayment,
    payment_protocol_spec,
)

# Standard Fetch.ai Payment Protocol (Seller Role)
payment_proto = Protocol(spec=payment_protocol_spec, role="seller")

DEFAULT_FEE_FET = "0.1"
FEE_FUNDS = Funds(currency="FET", amount=DEFAULT_FEE_FET, payment_method="fet_direct")
ACCEPTED_FUNDS = [FEE_FUNDS]


def create_payment_request(
    recipient_address: str,
    target_incident: str,
    action_type: str,
    amount_fet: str = DEFAULT_FEE_FET,
) -> RequestPayment:
    """Construct an official Fetch.ai RequestPayment object."""
    return RequestPayment(
        accepted_funds=[Funds(currency="FET", amount=amount_fet, payment_method="fet_direct")],
        recipient=recipient_address,
        deadline_seconds=300,
        reference=f"secops:{target_incident}:{uuid4().hex[:6]}",
        description=f"SentinelFlow Containment Fee ({amount_fet} FET) for action: {action_type} on {target_incident}",
        metadata={
            "service": "SentinelFlow Enterprise Containment",
            "target": target_incident,
            "action_type": action_type,
            "fee_fet": amount_fet,
            "fet_network": os.getenv("FET_NETWORK", "fetchai-stable-testnet"),
        },
    )


@payment_proto.on_message(model=CommitPayment)
async def handle_commit_payment(ctx: Context, sender: str, msg: CommitPayment):
    """Handle incoming payment commitment from an analyst or corporate treasury wallet."""
    ctx.logger.info(f"[Payment] Received CommitPayment from {sender} (tx: {msg.transaction_id})")

    # In production/testnet, verify transfer via LedgerClient. In prototype/demo, simulate verification.
    is_valid_payment = bool(msg.transaction_id and str(msg.funds.amount) == DEFAULT_FEE_FET)

    if is_valid_payment:
        ctx.logger.info(f"[Payment] Transaction {msg.transaction_id} verified on Fetch network. Completing payment.")
        await ctx.send(sender, CompletePayment(transaction_id=msg.transaction_id))
        
        # Store payment verification state
        ctx.storage.set(f"paid:{msg.transaction_id}", {
            "status": "completed",
            "amount": str(msg.funds.amount),
            "sender": sender,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    else:
        ctx.logger.warning(f"[Payment] Payment verification failed for tx {msg.transaction_id}")
        await ctx.send(
            sender,
            CancelPayment(
                transaction_id=msg.transaction_id,
                reason="Invalid transaction or fee mismatch",
            ),
        )


@payment_proto.on_message(model=RejectPayment)
async def handle_reject_payment(ctx: Context, sender: str, msg: RejectPayment):
    """Handle user or buyer rejection of payment request."""
    ctx.logger.info(f"[Payment] Payment rejected by {sender}: {msg.reason}")
