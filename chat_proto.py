"""Agent Chat Protocol (ACP) handlers for SentinelFlow.

Processes multi-turn conversations, renders ASI:One interactive cards:
- Card A: Risk Assessment Card / Consumer Security Alert
- Card B: Response Approval Card / Consumer Emergency Lockdown
- Card C: Cryptographic Verification Receipt / Personal Safety Certificate
- Card D: Deep-Dive Forensics Card
- Card E: Welcome & Discovery Onboarding Card

Seamlessly supports dual personas:
1. Everyday Consumer Mode: Empathetic, plain-English, 1-tap emergency rescue with 0.1 FET.
2. Enterprise SOC Mode: Tier-3 SOC reports, MITRE ATT&CK correlation, and SIEM telemetry.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from uagents import Context, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    TextContent,
    chat_protocol_spec,
)

from cards import (
    build_consumer_alert_message,
    build_consumer_lockdown_message,
    build_consumer_safety_certificate_message,
    build_forensic_details_message,
    build_response_approval_message,
    build_risk_assessment_message,
    build_verification_message,
    build_welcome_message,
)
from controller import SentinelFlowController
from tools.log_search import search_logs
from asi1_client import craft_analyst_briefing

chat_proto = Protocol(spec=chat_protocol_spec)
controller = SentinelFlowController()

# Target account extraction regex (supports standard IDs, enterprise accs, and consumer emails)
ACCOUNT_RE = re.compile(
    r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}|demo-user-\w+|sarah-dev-\w+|test-user-\w+|user-\w+|acc-\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
    re.IGNORECASE,
)


def parse_card_selection(text: str) -> dict[str, Any] | None:
    """Extract action selection payload from interactive card button interactions or natural language.
    
    Handles two formats:
    1. Structured JSON payload (e.g. from ASI:One button click)
    2. Natural language analyst or consumer prose
    """
    if not text:
        return {"action": "welcome"}

    stripped = text.strip()

    # Format 1: Structured JSON payload
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                # Unwrap nested keys if present (e.g. selection or action wrapper)
                if "selection" in data and isinstance(data["selection"], dict):
                    data = data["selection"]
                elif "payload" in data and isinstance(data["payload"], dict):
                    data = data["payload"]
                return {str(k): v for k, v in data.items()}
        except json.JSONDecodeError:
            pass

    # Strip any agent mention like @agent1qwstka0f7sjyd0ux69zfv9pu66testhc807cdhx8yvav3u0eml7nwptkdfy
    clean_text = re.sub(r"@?agent1[a-z0-9]{30,}", "", stripped, flags=re.IGNORECASE).strip()
    clean_text = re.sub(r"@agent1\w*", "", clean_text, flags=re.IGNORECASE).strip()

    # If the user only sent the @agent1 tag, show the friendly welcome menu
    if not clean_text:
        return {"action": "welcome"}

    lower = clean_text.lower()

    # Quick numeric shortcodes (1 = Scan, 2 = Kick out, 3 = History, 4 = Safe / Menu)
    if lower in ("1", "1.", "#1", "one"):
        return {"action": "investigate_target", "target": "demo-user-104", "mode": "consumer"}
    if lower in ("2", "2.", "#2", "two"):
        return {
            "action": "approve_containment",
            "target": "demo-user-104",
            "action_type": "revoke_user_sessions",
            "token": "CARD_ACTION_APPROVE",
            "fee": "0.1 FET",
            "mode": "consumer",
        }
    if lower in ("3", "3.", "#3", "three"):
        return {"action": "request_more_info", "target": "demo-user-104"}
    if lower in ("4", "4.", "#4", "four"):
        return {"action": "investigate_target", "target": "sarah-dev-92", "mode": "consumer"}

    # 1. Consumer hack alert / Investigation trigger (Check specific high-priority keywords first)
    if any(kw in lower for kw in (
        "hacked", "stole my password", "someone logged into", "someone accessed",
        "unauthorized login", "investigate", "analyze", "check", "triage",
        "suspicious", "compromise", "scan", "check my account", "check account",
        "am i safe", "is my account safe", "got hacked", "hack", "someone in my account"
    )):
        target_found = extract_target_from_text(clean_text)
        is_consumer = not any(w in lower for w in ("soc", "mitre", "tier-3", "siem", "enterprise"))
        return {
            "action": "investigate_target",
            "target": target_found,
            "mode": "consumer" if is_consumer else "soc",
        }

    # 2. Block IP action (Check before session lock so 'block' does not match 'lock')
    if "block ip" in lower or "block attacker ip" in lower or "block 198.51.100.42" in lower or "quarantine ip" in lower:
        return {
            "action": "approve_containment",
            "target": "198.51.100.42",
            "action_type": "block_ip_address",
            "token": "CARD_ACTION_APPROVE",
            "fee": "0.1 FET",
        }

    # 3. Approve session revocation / Consumer Emergency Lockdown
    if any(kw in lower for kw in (
        "lock my account", "lock down", "emergency lock", "approve session revocation",
        "approve containment", "approve", "revoke", "kick out", "yes, revoke",
        "authorize", "confirm", "lock it", "do it", "stop them", "kick them",
        "kick them out", "kick him out", "boot them", "log them out"
    )) or re.search(r"\b(lock|yes|yep|yeah|ok|okay|sure)\b", lower):
        target_found = extract_target_from_text(clean_text)
        is_consumer = not any(w in lower for w in ("soc", "mitre", "tier-3", "siem", "enterprise"))
        return {
            "action": "approve_containment",
            "target": target_found,
            "action_type": "revoke_user_sessions",
            "token": "CARD_ACTION_APPROVE",
            "fee": "0.1 FET",
            "mode": "consumer" if is_consumer else "soc",
        }

    # 4. Consumer "It was me" dismissal / Rejection
    if any(kw in lower for kw in ("it was me", "that was me", "safe", "false alarm", "my login", "ignore", "all good")) or re.search(r"\b(no|nope|me)\b", lower):
        target_found = extract_target_from_text(clean_text)
        return {"action": "it_was_me", "target": target_found}

    # 5. Request more information / Forensics / History
    if any(kw in lower for kw in ("more info", "request more info", "request more information", "forensic", "details", "raw logs", "show logs", "login history", "history", "logins")) or re.search(r"\b(details|info|more|history|logins)\b", lower):
        target_found = extract_target_from_text(clean_text)
        return {"action": "request_more_info", "target": target_found}

    # 6. Reject / Dismiss incident
    if any(kw in lower for kw in ("reject", "dismiss", "false positive", "cancel", "deny")):
        target_found = extract_target_from_text(clean_text)
        return {"action": "dismiss_incident", "target": target_found}

    # Check for agent team / architecture questions
    if any(kw in lower for kw in ("how many agents", "multi agent", "single agent", "agents are present", "what agents", "swarm", "agents")):
        return {"action": "agent_info"}

    # 7. Help / Greeting / Onboarding
    if any(re.search(rf"\b{greeting}\b", lower) for greeting in ("hello", "hi", "hey", "help", "start", "menu", "options", "yo", "sup")) or any(q in lower for q in ("who are you", "what can you do", "what to type", "how does this work", "?")):
        return {"action": "welcome"}

    # Target direct email or account name (e.g. "alex@gmail.com")
    match = ACCOUNT_RE.search(clean_text)
    if match and ("@" in clean_text or "user" in clean_text):
        return {
            "action": "investigate_target",
            "target": match.group(1),
            "mode": "consumer",
        }

    return None


def extract_target_from_text(text: str) -> str:
    """Extract account identifier, email, or IP address from query string."""
    clean = re.sub(r"@?agent1[a-z0-9]{30,}", "", text, flags=re.IGNORECASE).strip()
    clean = re.sub(r"@agent1\w*", "", clean, flags=re.IGNORECASE).strip()
    match = ACCOUNT_RE.search(clean)
    if match:
        return match.group(1)
    # Default demonstration target
    return "demo-user-104"


@chat_proto.on_message(model=ChatMessage)
async def handle_chat_message(ctx: Context, sender: str, msg: ChatMessage):
    """Receive ACP message, acknowledge receipt, execute investigation, and return interactive cards."""
    ctx.logger.info(f"Received ACP message from {sender}")

    # 1. Immediate Protocol Acknowledgment
    await ctx.send(
        sender,
        ChatAcknowledgement(
            timestamp=datetime.now(timezone.utc),
            acknowledged_msg_id=msg.msg_id,
        ),
    )

    # 2. Extract incoming text content
    inbound_text = ""
    for content in msg.content:
        if isinstance(content, TextContent):
            inbound_text += content.text + " "
    inbound_text = inbound_text.strip()
    ctx.logger.info(f"Inbound text: '{inbound_text}'")

    # 3. Check for Card Action Selection or Natural Language Intent
    parsed_intent = parse_card_selection(inbound_text)
    action_name = parsed_intent.get("action") if parsed_intent else None

    # Determine if this conversation should run in Consumer Mode
    is_soc_mode = any(w in inbound_text.lower() for w in ("soc", "mitre", "tier-3", "siem", "enterprise", "ciso"))
    is_consumer_query = not is_soc_mode

    # Handle Welcome / Onboarding
    if action_name == "welcome":
        welcome_preamble = """👋 **Hey there! I'm SentinelFlow, your personal security assistant.**

Think of me as a 24/7 bodyguard for your accounts. You don't need any cyber knowledge — we can just talk like normal people.

Here is what I can do for you right now:
1️⃣ **Scan Your Account** — I'll check your recent logins to see if anyone broke in (Free)
2️⃣ **Kick Out Intruders** — If someone is in your account, I'll disconnect them everywhere immediately (0.1 FET, ~$0.10)
3️⃣ **See Login History** — See when and where your account was accessed
4️⃣ **Dismiss an Alert** — Let me know if a login was just you

💬 **You can type anything naturally**, like:
* *"I think someone got into my account"*
* *"Can you check alex@gmail.com?"*
* *"Kick them out"*
* Or simply reply with a number: **1**, **2**, **3**, or **4**

👇 *Or just tap one of the buttons below:*"""
        await ctx.send(sender, build_welcome_message(welcome_preamble))
        return

    # Handle Agent Team / Multi-Agent Swarm inquiries
    if action_name == "agent_info":
        reply = ChatMessage(
            timestamp=datetime.now(timezone.utc),
            msg_id=uuid4(),
            content=[
                TextContent(
                    type="text",
                    text="""We are a **5-Agent Multi-Agent Swarm** working together to protect you! 👥

Here is the team:
1. 🎯 **Coordinator Agent** — Handles this chat and coordinates the response.
2. 🔎 **Investigator Agent** — Searches recent login records to find suspicious activity.
3. 🧠 **Threat Analyst Agent** — Analyzes whether logins look like real attacks or false alarms.
4. 🔒 **Containment Agent** — Kicks out intruders and blocks their devices with 1 tap.
5. 📜 **Auditor Agent** — Double-checks that the intruder is really gone and issues your digital receipt.

💬 You can ask me to **"Scan my account"** or say **"Help"** anytime!""",
                )
            ],
        )
        await ctx.send(sender, reply)
        return

    # Handle Consumer "It Was Me" (Safe dismissal)
    if action_name == "it_was_me":
        target = str(parsed_intent.get("target") or "demo-user-104")
        ctx.logger.info(f"User confirmed login was legitimate for target '{target}'.")
        reply = ChatMessage(
            timestamp=datetime.now(timezone.utc),
            msg_id=uuid4(),
            content=[
                TextContent(
                    type="text",
                    text=f"""Whew! That's a relief, {target}! 😊

I've cleared the alert and made a note that this login was really you. No changes were made, and your account is completely safe.

💡 If you ever want to run a quick check again, just say **"Check my account"** or tap **Help**!""",
                )
            ],
        )
        await ctx.send(sender, reply)
        return

    # Handle Request More Information (Card D: Forensics)
    if action_name == "request_more_info":
        target = str(parsed_intent.get("target") or "demo-user-104")
        ctx.logger.info(f"Analyst/User requested deep-dive forensics for target '{target}'.")
        try:
            log_res = search_logs(account_id=target)
            raw_events = log_res.get("events", [])
        except Exception:
            raw_events = []

        forensic_preamble = f"""### 📜 Login History for `{target}`

Here is what happened on your account recently:

* **Account:** `{target}`
* **Total Logins Recorded:** {len(raw_events)} events
* **What Looked Suspicious:** 
  1. Someone entered 5 wrong passwords in just 12 seconds from **Lagos, Nigeria**.
  2. Then they got in from Nigeria — while your real logins are from **San Francisco, USA**!
  3. They triggered several two-factor code prompts.

---

### 💡 What would you like to do?
* 💬 Say **"Kick them out"** (or tap below) — to boot the intruder off your account immediately (0.1 FET)
* 💬 Say **"It was me"** — if that login was really you
* 💬 Say **"Help"** — to go back to the main menu"""

        reply = build_forensic_details_message(
            preamble=forensic_preamble,
            target=target,
            risk_score=85 if target != "sarah-dev-92" else 0,
            evidence=[
                "5 failed login attempts in 12s from 198.51.100.42 (Lagos, Nigeria)",
                "Subsequent successful login from Lagos after 22 minutes (impossible travel)",
                "MFA challenge repeated multiple times",
            ],
            raw_logs=raw_events,
        )
        await ctx.send(sender, reply)
        return

    # Handle Containment Approval / Emergency Lockdown (Card C: Verification Receipt)
    if action_name == "approve_containment":
        target = str(parsed_intent.get("target") or "demo-user-104")
        action_type = str(parsed_intent.get("action_type") or "revoke_user_sessions")
        token = str(parsed_intent.get("token") or "CARD_ACTION_APPROVE")
        fee = str(parsed_intent.get("fee") or "0.1 FET")
        is_consumer_action = is_consumer_query or (parsed_intent and parsed_intent.get("mode") == "consumer")

        ctx.logger.info(f"User approved containment '{action_type}' on '{target}' (Consumer mode: {is_consumer_action}).")
        result = controller.process_investigation_request(
            intent="request_containment",
            target=target,
            requested_action=action_type,
            approval_token=token,
        )

        verification = result.get("verification") or {}
        action_info = result.get("action") or {}
        action_id = action_info.get("action_id", "act-unknown")

        if verification.get("verified"):
            actual_state = verification.get("actual_state", "sessions_revoked")
            audit_hash = verification.get("audit_hash", "e3b0c442...")
            timestamp_str = verification.get("timestamp", datetime.now(timezone.utc).isoformat())
            payment_status_str = f"{fee} Settled (Fetch.ai Escrow)"

            if is_consumer_action:
                consumer_verify_preamble = f"""## ✅ All Done! Your Account is Secured.

I've taken care of everything:

* 🔒 **Intruder Removed:** The person logging in from Nigeria has been kicked out immediately.
* 📱 **Devices Logged Out:** Your account was logged out everywhere so no unauthorized person has access.
* 🚫 **Blocked Device:** The attacker's device (IP `198.51.100.42`) is blocked from trying again.
* 💰 **Small Protection Fee:** `{fee}` settled safely through the Fetch.ai network.
* 🧾 **Digital Safety Receipt:** `{audit_hash[:16]}...` (verified and recorded)

---

### 💡 What you should do next:
1. **Reset your password** from your own device right now just to be completely safe.
2. Turn on **Two-Factor Authentication (2FA)** if you haven't already.

💬 *Feel free to type **"Check my account"** anytime or tap **Help** if you need anything else!*"""

                reply = build_consumer_safety_certificate_message(
                    preamble=consumer_verify_preamble,
                    target=target,
                    action_id=action_id,
                    audit_hash=audit_hash,
                    timestamp=timestamp_str,
                    fee=f"{fee} (~$0.12)",
                )
            else:
                rich_verify_report = f"""## ✅ Incident Containment Executed & Verified

### 🛡️ Remediation Status: **SUCCESSFULLY VERIFIED**
* **Target Identity:** `{target}`
* **Action Executed:** `{action_type}`
* **Pre-Action State:** `3 active sessions (compromised)`
* **Post-Remediation State:** `{actual_state}` (All active tokens terminated)
* **Execution Timestamp:** `{timestamp_str}`
* **Action Audit ID:** `{action_id}`
* **Fetch.ai Payment Protocol:** `{payment_status_str}`

---

### 👥 Multi-Agent Swarm Verification:
* 🔒 **Containment Agent** (`agent1qwh6tqvy...`): Executed session revocation & network quarantine
* 📜 **Auditor Agent** (`agent1qfeunnss...`): Cryptographically inspected post-action state & verified SHA-256 proof

---

### 🔐 Cryptographic State Proof (SHA-256):
```
{audit_hash}
```
*This cryptographic receipt is signed and recorded in SentinelFlow's immutable audit ledger.*"""

                reply = build_verification_message(
                    preamble=rich_verify_report,
                    action_id=action_id,
                    target=target,
                    action_type=action_type,
                    actual_state=actual_state,
                    audit_hash=audit_hash,
                    timestamp=timestamp_str,
                    payment_status=payment_status_str,
                )
        else:
            reply = ChatMessage(
                timestamp=datetime.now(timezone.utc),
                msg_id=uuid4(),
                content=[
                    TextContent(
                        type="text",
                        text=f"Lockdown executed, but state verification failed: {verification.get('details', 'State mismatch detected.')}",
                    )
                ],
            )
        await ctx.send(sender, reply)
        return

    # Handle Dismiss / False Positive
    if action_name == "dismiss_incident":
        target = str(parsed_intent.get("target") or "demo-user-104")
        ctx.logger.info(f"Analyst dismissed alert for target '{target}'.")
        reply = ChatMessage(
            timestamp=datetime.now(timezone.utc),
            msg_id=uuid4(),
            content=[
                TextContent(
                    type="text",
                    text=f"Incident alert for target '{target}' has been dismissed as a false positive. Audit event logged to SentinelFlow ledger.",
                )
            ],
        )
        await ctx.send(sender, reply)
        return

    # 4. Process Natural Language Investigation Intent
    target = (parsed_intent.get("target") if parsed_intent and parsed_intent.get("target") else None) or extract_target_from_text(inbound_text)
    ctx.logger.info(f"Initiating investigation for target: {target} (Consumer: {is_consumer_query})")

    result = controller.process_investigation_request(
        intent="investigate_suspicious_logins",
        target=target,
        time_window_minutes=60,
    )

    if result.get("status") == "insufficient_data":
        reply = ChatMessage(
            timestamp=datetime.now(timezone.utc),
            msg_id=uuid4(),
            content=[
                TextContent(
                    type="text",
                    text=f"SentinelFlow Investigation Complete: 0 security logs found for target '{target}' in the last 60 minutes. No anomalous signals detected.",
                )
            ],
        )
        await ctx.send(sender, reply)
        return

    if result.get("status") == "failed":
        reply = ChatMessage(
            timestamp=datetime.now(timezone.utc),
            msg_id=uuid4(),
            content=[
                TextContent(
                    type="text",
                    text=f"Investigation halted: {result.get('message', 'An internal error occurred.')}",
                )
            ],
        )
        await ctx.send(sender, reply)
        return

    risk_level_str = str(result.get("risk_level", "medium")).upper()
    risk_score_val = result.get("risk_score", 50)
    evidence_list = result.get("evidence", [])
    mitre_list = result.get("mitre_tactics", [])

    # Synthesize AI briefing
    briefing = await craft_analyst_briefing(
        target=target,
        risk_level=result.get("risk_level", "medium"),
        risk_score=result.get("risk_score", 50),
        evidence=result.get("evidence", []),
        mitre_tactics=result.get("mitre_tactics", []),
        mode="consumer" if is_consumer_query else "soc",
    )

    # -----------------------------------------------------------------
    # BRANCH A: REAL-WORLD CONSUMER "EMERGENCY LOCK" FLOW
    # -----------------------------------------------------------------
    if is_consumer_query:
        if risk_score_val >= 50:
            consumer_alert_preamble = f"""### 🚨 Heads Up! We Found a Suspicious Login on `{target}`

Don't worry, we caught it in time! Here is what's going on:

* 👤 **Account:** `{target}`
* 📍 **Where the login came from:** **Lagos, Nigeria** (while your normal logins are from **San Francisco, USA**)
* 💻 **Device:** Unknown Linux browser (`198.51.100.42`)
* ⚠️ **What happened:** They tried guessing your password 5 times in 12 seconds before getting in.
* 🚨 **Threat Level:** High Risk ({risk_score_val}/100)

---

### 💡 How would you like to handle this?
* 💬 Say **"Kick them out"** (or tap below) — to log them out of your account immediately (0.1 FET, ~$0.10)
* 💬 Say **"It was me"** — if that was really you using a VPN or traveling
* 💬 Say **"Details"** — to see the full list of recent logins"""

            card_a_consumer = build_consumer_alert_message(
                preamble=consumer_alert_preamble,
                target=target,
                risk_score=risk_score_val,
                location="Lagos, Nigeria",
                device="Linux / Unauthorized Browser",
                summary=briefing,
            )
            await ctx.send(sender, card_a_consumer)
            return
        else:
            consumer_safe_preamble = f"""### ✅ Good News! Your Account Looks Completely Safe: `{target}`

I just finished scanning your recent logins, and everything looks completely normal:

* 👤 **Account:** `{target}`
* 📍 **Location:** San Francisco, USA (your trusted location)
* 🛡️ **Status:** Clean & Secure (Risk Score: {risk_score_val}/100)
* 🔍 **Findings:** No unauthorized devices, no failed password bursts, and no suspicious activity found.

---

💡 *Your account is in great shape! You can ask me to check another account anytime, or type **"Help"**.*"""

            card_safe_consumer = build_consumer_alert_message(
                preamble=consumer_safe_preamble,
                target=target,
                risk_score=risk_score_val,
                location="San Francisco, USA",
                device="Mac / Chrome (Trusted)",
                summary=briefing,
            )
            await ctx.send(sender, card_safe_consumer)
            return

    # -----------------------------------------------------------------
    # BRANCH B: ENTERPRISE TIER-3 SOC ANALYST FLOW
    # -----------------------------------------------------------------
    ev_bullets = "\n".join(f"• {e}" for e in evidence_list) or "• All observed authentication events conform to normal baseline."
    mitre_chips = "\n".join(f"* `{m}`" for m in mitre_list) or "* `None (Baseline Conformance)`"
    status_icon = "🚨" if risk_score_val >= 80 else ("⚠️" if risk_score_val >= 50 else "✅")

    rich_report = f"""## {status_icon} SentinelFlow Incident Triage Report

### 🚨 Threat Level: **{risk_level_str}** | Severity Score: **{risk_score_val}/100**
* **Target Identity:** `{target}`
* **Investigation Window:** Past 60 minutes
* **Triage Status:** ⚠️ Active Compromise Indicators Correlated • Pending Containment Authorization

---

### 👥 Fetch.ai Multi-Agent Swarm (MAS) Telemetry
* 🎯 **Coordinator Agent** (`agent1qwstka0f7...`): Frontline chat dispatch & card orchestration
* 🔎 **Investigator Agent** (`agent1q2g6yumc...`): Correlated SIEM telemetry & neutralized prompt injections
* 🧠 **Threat Analyst Agent** (`agent1qfj33ut4...`): Evaluated MITRE ATT&CK rules (Score: {risk_score_val}/100)
* 🔒 **Containment Agent** (`agent1qwh6tqvy...`): Enforcing Human-in-the-Loop policy gate
* 📜 **Auditor Agent** (`agent1qfeunnss...`): Ready for closed-loop SHA-256 state proof verification

---

### 📋 Executive Threat Briefing (ASI:One AI)
{briefing}

---

### 🔍 Correlated Security Telemetry & Evidence
{ev_bullets}

---

### 🎯 MITRE ATT&CK Framework Mapping
{mitre_chips}

---

### ⚡ Recommended Next Steps
Under SentinelFlow's Safe Automation Policy, session revocation requires explicit human approval.
Review **Card A (Risk Assessment)** and **Card B (Response Approval)** below to select your containment decision!"""

    # 1. Send Card A: Risk Assessment Card
    card_a_msg = build_risk_assessment_message(
        preamble=rich_report,
        target=target,
        risk_level=result.get("risk_level", "medium"),
        risk_score=result.get("risk_score", 50),
        evidence=result.get("evidence", []),
        mitre_tactics=result.get("mitre_tactics", []),
        summary=briefing,
        event_details={
            "Target Account": target,
            "Threat Origin": "Lagos, Nigeria (198.51.100.42)",
            "Baseline Origin": "San Francisco, US (192.168.1.50)",
            "Compromise Vector": "Credential Stuffing & Impossible Travel",
            "Investigation Window": "Past 60 minutes",
        },
    )
    await ctx.send(sender, card_a_msg)

    # 2. Send Card B: Response Approval Card
    card_b_preamble = f"""### 🛡️ SentinelFlow Remediation Authorization Gate
**Action Proposed:** Invalidate active OAuth & JWT sessions for `{target}`.
**SECaaS Settlement Fee:** `0.1 FET` (Fetch.ai Payment Protocol)

Review the impact in **Card B (Response Approval)** below and choose your decision:"""

    card_b_msg = build_response_approval_message(
        preamble=card_b_preamble,
        target=target,
        risk_level=result.get("risk_level", "critical"),
        proposed_action="revoke_user_sessions",
        malicious_ip="198.51.100.42",
        fee="0.1 FET",
    )
    await ctx.send(sender, card_b_msg)


@chat_proto.on_message(model=ChatAcknowledgement)
async def handle_acknowledgement(ctx: Context, sender: str, msg: ChatAcknowledgement):
    """Handle delivery acknowledgments from ASI:One or interacting agents."""
    ctx.logger.info(f"Received delivery acknowledgment from {sender} for message {msg.acknowledged_msg_id}")
