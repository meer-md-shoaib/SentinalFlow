"""ASI:One Interactive Cards builder using Fetch.ai dynamic element-tree primitives.

Implements Card A (Risk Assessment), Card B (Response Approval),
Card C (Post-Remediation Cryptographic Verification Receipt),
Card D (Forensic Telemetry Deep Dive), and Card E (Welcome & Discovery).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from uagents_core.contrib.protocols.chat import (
    ChatMessage,
    MetadataContent,
    TextContent,
)

CARD_PROTOCOL_VERSION = "1"
SENTINELFLOW_SOURCE = "sentinelflow_ui"


def _card_metadata(card_payload: dict[str, Any], card_kind: str = "custom") -> MetadataContent:
    """Wrap an element-tree payload dict into an ACP MetadataContent block."""
    return MetadataContent(
        type="metadata",
        metadata={
            "card_protocol_version": CARD_PROTOCOL_VERSION,
            "requires_card_interaction": "true",
            "card_kind": card_kind,
            "card_payload": json.dumps(card_payload),
        },
    )


def build_risk_assessment_card(
    target: str,
    risk_level: str,
    risk_score: int,
    evidence: list[str],
    mitre_tactics: list[str],
    summary: str,
    event_details: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Generate Card A: Comprehensive Incident Risk Assessment Card.
    
    Displays:
    - High-visibility risk badge & severity score (e.g., HIGH RISK 85/100)
    - Target identity & account details
    - Correlated suspicious login evidence
    - MITRE ATT&CK framework mapping
    - Recommended remediation next steps
    """
    badge_variant = "error" if risk_level in ("critical", "high") else ("warning" if risk_level == "medium" else "success")
    details = event_details or {
        "Target Account": target,
        "Threat Origin": "Lagos, Nigeria (198.51.100.42)",
        "Baseline Origin": "San Francisco, US (192.168.1.50)",
        "Compromise Vector": "Credential Stuffing & Impossible Travel",
        "Investigation Window": "Past 60 minutes",
    }

    evidence_items = [{"type": "text", "value": f"• {e}", "style": "body"} for e in evidence]
    mitre_badges = [{"type": "badge", "label": t, "variant": "info"} for t in mitre_tactics]
    detail_items = [{"type": "text", "value": f"{k}: {v}", "style": "body"} for k, v in details.items()]

    section: dict[str, Any] = {
        "type": "section",
        "title": "SentinelFlow Risk Assessment",
        "subtitle": f"Target: {target} | Risk Score: {risk_score}/100",
        "children": [
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "badge",
                        "label": f"{risk_level.upper()} RISK",
                        "variant": badge_variant,
                    },
                    {
                        "type": "badge",
                        "label": f"RISK SCORE: {risk_score}/100",
                        "variant": "info",
                    },
                    {
                        "type": "badge",
                        "label": f"TARGET: {target}",
                        "variant": "default",
                    },
                ],
            },
            {
                "type": "heading",
                "value": "Executive Threat Briefing",
                "level": 3,
            },
            {
                "type": "text",
                "value": summary,
                "style": "body",
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Account & Telemetry Details",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": detail_items,
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Correlated Suspicious Login Evidence",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": evidence_items or [{"type": "text", "value": "No anomalous signals detected.", "style": "muted"}],
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "MITRE ATT&CK Framework Mapping",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "row",
                "gap": 6,
                "children": mitre_badges or [{"type": "badge", "label": "None", "variant": "info"}],
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Recommended Next Steps",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": [
                    {"type": "text", "value": "1. Invalidate all active OAuth/JWT user sessions across devices.", "style": "body"},
                    {"type": "text", "value": "2. Quarantine malicious ingress IP 198.51.100.42 at security perimeter.", "style": "body"},
                    {"type": "text", "value": "3. Enforce mandatory hardware MFA re-registration upon re-login.", "style": "muted"},
                ],
            },
        ],
    }

    return {"root": section}


def build_response_approval_card(
    target: str,
    risk_level: str = "critical",
    proposed_action: str = "revoke_user_sessions",
    malicious_ip: str = "198.51.100.42",
    fee: str = "0.1 FET",
) -> dict[str, Any]:
    """Generate Card B: Response Approval Card (Human-in-the-Loop Policy Gate).
    
    Presents the proposed remediation action, scope, and impact, and lets the analyst:
    - Approve session revocation (Primary action)
    - Reject the action / dismiss alert
    - Request more information (deep-dive forensic telemetry)
    - Block ingress attacker IP
    """
    section: dict[str, Any] = {
        "type": "section",
        "title": "SentinelFlow Response Approval",
        "subtitle": f"Target: {target} | Proposed Action: Session Revocation",
        "children": [
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "badge",
                        "label": "GATE: HUMAN APPROVAL REQUIRED",
                        "variant": "warning",
                    },
                    {
                        "type": "badge",
                        "label": f"SECaaS FEE: {fee}",
                        "variant": "info",
                    },
                    {
                        "type": "badge",
                        "label": "POLICY: SAFE AUTOMATION",
                        "variant": "default",
                    },
                ],
            },
            {
                "type": "heading",
                "value": "Review Proposed Containment Action & Impact",
                "level": 3,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": [
                    {
                        "type": "text",
                        "value": f"• Primary Action: Invalidate all active sessions for {target}",
                        "style": "body",
                    },
                    {
                        "type": "text",
                        "value": "• Impact: Terminates 3 active tokens (1 suspicious, 2 legit). User must re-authenticate with hardware MFA.",
                        "style": "body",
                    },
                    {
                        "type": "text",
                        "value": f"• Perimeter Action: Quarantine attacker IP {malicious_ip} at ingress firewall.",
                        "style": "body",
                    },
                    {
                        "type": "text",
                        "value": f"• Payment Settlement: {fee} committed to remediation escrow via Fetch.ai Payment Protocol.",
                        "style": "muted",
                    },
                ],
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Choose Analyst Decision",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "button",
                        "label": f"Approve Session Revocation ({fee})",
                        "primary": True,
                        "action": {
                            "selection": {
                                "action": "approve_containment",
                                "target": target,
                                "action_type": "revoke_user_sessions",
                                "token": "CARD_ACTION_APPROVE",
                                "fee": fee,
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "Reject the Action",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "dismiss_incident",
                                "target": target,
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "Request More Information",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "request_more_info",
                                "target": target,
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": f"Block Attacker IP ({fee})",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "approve_containment",
                                "target": malicious_ip,
                                "action_type": "block_ip_address",
                                "token": "CARD_ACTION_APPROVE",
                                "fee": fee,
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                ],
            },
        ],
    }
    return {"root": section}


def build_verification_receipt_card(
    action_id: str,
    target: str,
    action_type: str,
    actual_state: str,
    audit_hash: str,
    timestamp: str,
    payment_status: str = "0.1 FET Settled (Fetch.ai Escrow)",
) -> dict[str, Any]:
    """Generate Card C: Post-containment verified receipt card with cryptographic SHA-256 hash."""
    section: dict[str, Any] = {
        "type": "section",
        "title": "Incident Containment Verified",
        "subtitle": f"Action ID: {action_id}",
        "children": [
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "badge",
                        "label": "STATUS: VERIFIED & AUDITED",
                        "variant": "success",
                    },
                    {
                        "type": "badge",
                        "label": payment_status,
                        "variant": "info",
                    },
                ],
            },
            {
                "type": "heading",
                "value": "Remediation Execution Record",
                "level": 3,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": [
                    {"type": "text", "value": f"Action: {action_type}", "style": "body"},
                    {"type": "text", "value": f"Target: {target}", "style": "body"},
                    {"type": "text", "value": f"Post-Remediation State: {actual_state} (0 active tokens)", "style": "body"},
                    {"type": "text", "value": f"Execution Timestamp: {timestamp}", "style": "muted"},
                    {"type": "text", "value": f"Payment Protocol: {payment_status}", "style": "muted"},
                ],
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Cryptographic Audit Receipt (SHA-256)",
                "level": 4,
            },
            {
                "type": "text",
                "value": audit_hash,
                "style": "code",
            },
        ],
    }
    return {"root": section}


def build_forensic_details_card(
    target: str,
    risk_score: int,
    evidence: list[str],
    raw_logs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate Card D: Deep-Dive Forensic Telemetry Card when analyst requests more info."""
    log_rows: list[dict[str, Any]] = []
    if raw_logs:
        for log in raw_logs[:5]:
            ts = log.get("timestamp", "N/A")
            event = log.get("event_type", "auth_event")
            ip = log.get("ip_address", "N/A")
            loc = log.get("location", "N/A")
            status = log.get("status", "unknown")
            log_rows.append({
                "type": "text",
                "value": f"[{ts}] {event.upper()} ({status}) | IP: {ip} | Loc: {loc}",
                "style": "code",
            })
    else:
        for e in evidence:
            log_rows.append({"type": "text", "value": f"• {e}", "style": "body"})

    section: dict[str, Any] = {
        "type": "section",
        "title": f"Forensic Telemetry: {target}",
        "subtitle": f"SIEM Log Correlator | Risk Score: {risk_score}/100",
        "children": [
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {"type": "badge", "label": "FORENSIC LOG AUDIT", "variant": "info"},
                    {"type": "badge", "label": f"SCORE: {risk_score}/100", "variant": "error" if risk_score >= 80 else "warning"},
                ],
            },
            {
                "type": "heading",
                "value": "Raw Authentication Audit Trail",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": log_rows or [{"type": "text", "value": "No raw telemetry logs available.", "style": "muted"}],
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Proceed with Containment Authorization",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "button",
                        "label": "Approve Session Revocation (0.1 FET)",
                        "primary": True,
                        "action": {
                            "selection": {
                                "action": "approve_containment",
                                "target": target,
                                "action_type": "revoke_user_sessions",
                                "token": "CARD_ACTION_APPROVE",
                                "fee": "0.1 FET",
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "Reject the Action",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "dismiss_incident",
                                "target": target,
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                ],
            },
        ],
    }
    return {"root": section}


def build_welcome_card() -> dict[str, Any]:
    """Generate Card E: Welcome & Capabilities Card for onboarding any user in ASI:One."""
    section: dict[str, Any] = {
        "type": "section",
        "title": "Welcome to SentinelFlow SecOps Agent",
        "subtitle": "Your Personal Security Guard against Hackers & Unauthorized Logins",
        "children": [
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {"type": "badge", "label": "STATUS: ONLINE", "variant": "success"},
                    {"type": "badge", "label": "1-TAP RESCUE", "variant": "info"},
                    {"type": "badge", "label": "NO TECH JARGON", "variant": "default"},
                ],
            },
            {
                "type": "heading",
                "value": "How I Keep You Safe",
                "level": 3,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": [
                    {"type": "text", "value": "🔍 Instant Account Scan: Checks recent logins to catch hackers trying to guess your password.", "style": "body"},
                    {"type": "text", "value": "🔒 1-Tap Kick Out: Instantly logs out intruders across all phones & computers with one tap.", "style": "body"},
                    {"type": "text", "value": "🛡️ Block Hacker Devices: Prevents the intruder from trying to log in again.", "style": "body"},
                    {"type": "text", "value": "🧾 Digital Safety Receipt: Verifiable proof showing your account was rescued.", "style": "muted"},
                ],
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Tap Any Option to Start (Or Just Type 1-4)",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "button",
                        "label": "🚨 1. Scan My Account (Free)",
                        "primary": True,
                        "action": {
                            "selection": {
                                "action": "investigate_target",
                                "target": "demo-user-104",
                                "mode": "consumer",
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "🔒 2. Kick Out Intruder (0.1 FET)",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "approve_containment",
                                "target": "demo-user-104",
                                "action_type": "revoke_user_sessions",
                                "token": "CARD_ACTION_APPROVE",
                                "fee": "0.1 FET",
                                "mode": "consumer",
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "📜 3. Login History",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "request_more_info",
                                "target": "demo-user-104",
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "🔍 4. Check Safe User",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "investigate_target",
                                "target": "sarah-dev-92",
                                "mode": "consumer",
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                ],
            },
        ],
    }
    return {"root": section}


def build_risk_assessment_message(
    preamble: str,
    target: str,
    risk_level: str,
    risk_score: int,
    evidence: list[str],
    mitre_tactics: list[str],
    summary: str,
    event_details: dict[str, str] | None = None,
) -> ChatMessage:
    """Create ChatMessage with text preamble and Card A (Risk Assessment)."""
    card_dict = build_risk_assessment_card(
        target=target,
        risk_level=risk_level,
        risk_score=risk_score,
        evidence=evidence,
        mitre_tactics=mitre_tactics,
        summary=summary,
        event_details=event_details,
    )
    return ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=[
            TextContent(type="text", text=preamble),
            _card_metadata(card_dict, card_kind="custom"),
        ],
    )


def build_response_approval_message(
    preamble: str,
    target: str,
    risk_level: str = "critical",
    proposed_action: str = "revoke_user_sessions",
    malicious_ip: str = "198.51.100.42",
    fee: str = "0.1 FET",
) -> ChatMessage:
    """Create ChatMessage with Card B (Response Approval)."""
    card_dict = build_response_approval_card(
        target=target,
        risk_level=risk_level,
        proposed_action=proposed_action,
        malicious_ip=malicious_ip,
        fee=fee,
    )
    return ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=[
            TextContent(type="text", text=preamble),
            _card_metadata(card_dict, card_kind="review"),
        ],
    )


def build_verification_message(
    preamble: str,
    action_id: str,
    target: str,
    action_type: str,
    actual_state: str,
    audit_hash: str,
    timestamp: str,
    payment_status: str = "0.1 FET Settled (Fetch.ai Escrow)",
) -> ChatMessage:
    """Create ChatMessage with text preamble and verified audit card."""
    card_dict = build_verification_receipt_card(
        action_id=action_id,
        target=target,
        action_type=action_type,
        actual_state=actual_state,
        audit_hash=audit_hash,
        timestamp=timestamp,
        payment_status=payment_status,
    )
    return ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=[
            TextContent(type="text", text=preamble),
            _card_metadata(card_dict, card_kind="custom"),
        ],
    )


def build_forensic_details_message(
    preamble: str,
    target: str,
    risk_score: int,
    evidence: list[str],
    raw_logs: list[dict[str, Any]] | None = None,
) -> ChatMessage:
    """Create ChatMessage with deep-dive forensic log card."""
    card_dict = build_forensic_details_card(
        target=target,
        risk_score=risk_score,
        evidence=evidence,
        raw_logs=raw_logs,
    )
    return ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=[
            TextContent(type="text", text=preamble),
            _card_metadata(card_dict, card_kind="detail"),
        ],
    )


def build_welcome_message(preamble: str) -> ChatMessage:
    """Create ChatMessage with welcome card."""
    card_dict = build_welcome_card()
    return ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=[
            TextContent(type="text", text=preamble),
            _card_metadata(card_dict, card_kind="custom"),
        ],
    )


# =====================================================================
# REAL-WORLD CONSUMER "EMERGENCY LOCK" CARDS SUITE
# =====================================================================

def build_consumer_alert_card(
    target: str,
    risk_score: int = 85,
    location: str = "Lagos, Nigeria",
    device: str = "Linux / Unauthorized Browser",
    summary: str | None = None,
    fee: str = "0.1 FET (~$0.12)",
) -> dict[str, Any]:
    """Generate Card: Consumer Account Security Alert (Plain English, Zero Jargon)."""
    default_summary = (
        f"Someone just logged into your account ({target}) from an unknown device in {location}. "
        "They attempted to enter your password 5 times in 12 seconds before gaining access."
    )
    section: dict[str, Any] = {
        "type": "section",
        "title": "🚨 Account Security Alert",
        "subtitle": f"Unauthorized access detected for {target}",
        "children": [
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {"type": "badge", "label": "HIGH RISK", "variant": "error"},
                    {"type": "badge", "label": f"LOCATION: {location.upper()}", "variant": "warning"},
                    {"type": "badge", "label": f"THREAT SCORE: {risk_score}/100", "variant": "info"},
                ],
            },
            {
                "type": "heading",
                "value": "What Happened?",
                "level": 3,
            },
            {
                "type": "text",
                "value": summary or default_summary,
                "style": "body",
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Suspicious Login Details",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": [
                    {"type": "text", "value": f"• Protected Account: {target}", "style": "body"},
                    {"type": "text", "value": f"• Where Intruder Logged In: {location}", "style": "body"},
                    {"type": "text", "value": f"• Intruder Device: {device}", "style": "body"},
                    {"type": "text", "value": "• Your Normal Location: San Francisco, USA", "style": "muted"},
                ],
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Recommended Immediate Action",
                "level": 4,
            },
            {
                "type": "text",
                "value": "Don't worry — I can immediately kick out the intruder and log your account out of all other devices.",
                "style": "body",
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Take Action in 1 Tap",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "button",
                        "label": f"🔒 Kick Out Intruder ({fee})",
                        "primary": True,
                        "action": {
                            "selection": {
                                "action": "approve_containment",
                                "target": target,
                                "action_type": "revoke_user_sessions",
                                "token": "CARD_ACTION_APPROVE",
                                "fee": "0.1 FET",
                                "mode": "consumer",
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "✅ That Was Me (Safe)",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "it_was_me",
                                "target": target,
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "📜 Show Login Details",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "request_more_info",
                                "target": target,
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                ],
            },
        ],
    }
    return {"root": section}


def build_consumer_lockdown_card(
    target: str,
    fee: str = "0.1 FET (~$0.12)",
) -> dict[str, Any]:
    """Generate Card: 1-Tap Emergency Account Lockdown (Consumer Pay-per-Rescue)."""
    section: dict[str, Any] = {
        "type": "section",
        "title": "🛡️ 1-Tap Emergency Account Lockdown",
        "subtitle": f"Kick out intruders and secure {target}",
        "children": [
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {"type": "badge", "label": "1-TAP RESCUE", "variant": "success"},
                    {"type": "badge", "label": f"FEE: {fee}", "variant": "info"},
                    {"type": "badge", "label": "INSTANT PROTECTION", "variant": "default"},
                ],
            },
            {
                "type": "heading",
                "value": "What Lockdown Will Do",
                "level": 3,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": [
                    {"type": "text", "value": "✅ Instantly logs out all phones, laptops, and web browsers so no one can access your data.", "style": "body"},
                    {"type": "text", "value": "✅ Locks out the intruder immediately.", "style": "body"},
                    {"type": "text", "value": "✅ Blocks the attacker's device from attempting any further logins.", "style": "body"},
                    {"type": "text", "value": f"✅ Small protection fee ({fee}, ~$0.10) charged only on successful rescue.", "style": "muted"},
                ],
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Choose Action",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "button",
                        "label": f"🔒 Kick Out Intruder ({fee})",
                        "primary": True,
                        "action": {
                            "selection": {
                                "action": "approve_containment",
                                "target": target,
                                "action_type": "revoke_user_sessions",
                                "token": "CARD_ACTION_APPROVE",
                                "fee": "0.1 FET",
                                "mode": "consumer",
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "✅ That Was Me (Safe)",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "it_was_me",
                                "target": target,
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "📜 Show Login Details",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "request_more_info",
                                "target": target,
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                ],
            },
        ],
    }
    return {"root": section}


def build_consumer_safety_certificate_card(
    target: str,
    action_id: str,
    audit_hash: str,
    timestamp: str,
    fee: str = "0.1 FET (~$0.12)",
) -> dict[str, Any]:
    """Generate Card: Personal Safety Certificate & Verification Receipt for everyday users."""
    section: dict[str, Any] = {
        "type": "section",
        "title": "✅ Account Successfully Secured!",
        "subtitle": f"Protection Certificate • {target}",
        "children": [
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {"type": "badge", "label": "STATUS: SECURED & SAFE", "variant": "success"},
                    {"type": "badge", "label": f"{fee} Settled", "variant": "info"},
                    {"type": "badge", "label": "0 INTRUDERS REMAINING", "variant": "default"},
                ],
            },
            {
                "type": "heading",
                "value": "What Was Done",
                "level": 3,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": [
                    {"type": "text", "value": f"• Protected Account: {target}", "style": "body"},
                    {"type": "text", "value": "• Logins Terminated: Intruder in Nigeria has been kicked out of all devices", "style": "body"},
                    {"type": "text", "value": "• Hacker Device Blocked: Attacker IP 198.51.100.42 blocked from trying again", "style": "body"},
                    {"type": "text", "value": f"• Time Secured: {timestamp}", "style": "muted"},
                ],
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Digital Safety Receipt (Proof of Security)",
                "level": 4,
            },
            {
                "type": "text",
                "value": audit_hash,
                "style": "code",
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Important Next Steps For You",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": [
                    {"type": "text", "value": "1. Reset your password right now from your own trusted device.", "style": "body"},
                    {"type": "text", "value": "2. Enable Two-Factor Authentication (2FA) using an authenticator app.", "style": "body"},
                    {"type": "text", "value": "3. Your account is now safe. You can scan again anytime.", "style": "muted"},
                ],
            },
            {"type": "divider"},
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "button",
                        "label": "🔍 Scan Account Again",
                        "primary": True,
                        "action": {
                            "selection": {
                                "action": "investigate_target",
                                "target": target,
                                "mode": "consumer",
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "🏠 Main Menu",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "welcome",
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                ],
            },
        ],
    }
    return {"root": section}


def build_consumer_alert_message(
    preamble: str,
    target: str,
    risk_score: int = 85,
    location: str = "Lagos, Nigeria",
    device: str = "Linux / Unauthorized Browser",
    summary: str | None = None,
) -> ChatMessage:
    """Create ChatMessage with Consumer Alert Card."""
    card_dict = build_consumer_alert_card(
        target=target,
        risk_score=risk_score,
        location=location,
        device=device,
        summary=summary,
    )
    return ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=[
            TextContent(type="text", text=preamble),
            _card_metadata(card_dict, card_kind="custom"),
        ],
    )


def build_consumer_lockdown_message(
    preamble: str,
    target: str,
    fee: str = "0.1 FET (~$0.12)",
) -> ChatMessage:
    """Create ChatMessage with Consumer Lockdown Card."""
    card_dict = build_consumer_lockdown_card(target=target, fee=fee)
    return ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=[
            TextContent(type="text", text=preamble),
            _card_metadata(card_dict, card_kind="review"),
        ],
    )


def build_consumer_safety_certificate_message(
    preamble: str,
    target: str,
    action_id: str,
    audit_hash: str,
    timestamp: str,
    fee: str = "0.1 FET (~$0.12)",
) -> ChatMessage:
    """Create ChatMessage with Consumer Safety Certificate."""
    card_dict = build_consumer_safety_certificate_card(
        target=target,
        action_id=action_id,
        audit_hash=audit_hash,
        timestamp=timestamp,
        fee=fee,
    )
    return ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=[
            TextContent(type="text", text=preamble),
            _card_metadata(card_dict, card_kind="custom"),
        ],
    )

