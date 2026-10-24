# SentinelFlow Architecture & Security Specifications

## 1. System Overview
**SentinelFlow** is an autonomous cybersecurity incident investigation and response agent built on the Fetch.ai and ASI:One ecosystem. It bridges the gap between natural language security intent and deterministic, verified containment actions.

```
                    +------------------------------------------+
                    |                 ASI:One                  |
                    |   (Conversational & Dynamic Cards UI)    |
                    +--------------------+---------------------+
                                         |
                                         | Agent Chat Protocol (ACP)
                                         v
                    +--------------------+---------------------+
                    |           Agentverse Mailbox             |
                    |       (Almanac Registry Discovery)       |
                    +--------------------+---------------------+
                                         |
                                         v
                    +------------------------------------------+
                    |             SentinelFlow Agent           |
                    |           (uAgents Runtime / ACP)        |
                    +--------------------+---------------------+
                                         |
                     +-------------------+-------------------+
                     |                                       |
                     v                                       v
    +--------------------------------+      +--------------------------------+
    |   Input Validation & Injection  |      |   ASI:One Interactive Cards    |
    |          Sanitization          |      |  (Element-Tree Card Builders)  |
    +----------------+---------------+      +--------------------------------+
                     |
                     v
    +--------------------------------+
    |     SentinelFlow Controller     |
    +----------------+---------------+
                     |
         +-----------+-----------+
         |                       |
         v                       v
+-----------------+     +-----------------+
|   Log Search    |     |   MITRE ATT&CK  |
|  Deterministic  |     |   Risk Engine   |
|   SIEM Query    |     |  (Score 0-100)  |
+--------+--------+     +--------+--------+
         |                       |
         +-----------+-----------+
                     |
                     v
        +-------------------------+
        |   Policy & Approval     |
        |   Authorization Gate    |
        +------------+------------+
                     |
         [Authorized | by Analyst]
                     v
        +-------------------------+
        |  Simulated Containment  |
        |   (State Transitions)   |
        +------------+------------+
                     |
                     v
        +-------------------------+
        |  Closed-Loop Verifier   |
        | (State Check + SHA-256) |
        +-------------------------+
```

---

## 2. Component Specifications

### 2.1 Agent Chat Protocol (ACP) Runtime (`agent.py` & `chat_proto.py`)
- Standardized under `uagents_core.contrib.protocols.chat`.
- Emits immediate `ChatAcknowledgement` for sub-second delivery tracking.
- Distinguishes between text queries and button actions via `parse_card_selection`.
- Publishes ACP manifest to Agentverse for immediate discovery in ASI:One.

### 2.2 Security Input Validation (`security/input_validation.py`)
- Sanitizes incoming target identifiers using strict allowlist regex `^[a-zA-Z0-9_\-\.@:]{1,64}$`.
- Scans user prompts and raw ingested log fields for indirect prompt injection keywords (`system override`, `ignore previous instructions`, `bypass policy`).
- Neutralizes injection attempts and tags them in `sanitization_notes`.

### 2.3 Deterministic Risk Engine (`security/policies.py`)
- Evaluates telemetry signals against MITRE ATT&CK:
  - **T1110:** Brute Force authentication bursts.
  - **T1078:** Valid Accounts (successful logins following brute-force bursts from anomalous IPs).
  - **T1068 / T1556:** Privilege escalation and MFA bypass attempts.
  - **T1078.004:** Cloud admin and geographic baseline anomalies.
- Calculates deterministic risk score $R \in [0, 100]$:
  $$R = \min(100, 30F + 25S + 35P + 10B)$$

### 2.4 Human-in-the-Loop Policy Gate (`security/policies.py`)
- Enforces strict separation of duties: AI reasoning can recommend containment, but **cannot self-authorize**.
- High-impact operations (`revoke_user_sessions`, `block_ip_address`, `isolate_endpoint`, `trigger_password_reset`) require a valid approval token generated exclusively through interactive analyst confirmation.

### 2.5 Simulated Containment & Verification Engine (`tools/simulated_response.py`)
- Maintains an in-memory and persistent state store.
- Guarantees idempotency (prevents redundant duplicate actions).
- Performs independent post-action validation: checks if actual state transitioned to `sessions_revoked` or `blocked`.
- Produces a tamper-evident cryptographic SHA-256 audit hash binding `action_id`, `target`, `action_type`, `actual_state`, and `timestamp`.

### 2.6 Dynamic Interactive UI (`cards.py`)
- Generates compliant ASI:One element-tree layouts:
  - **Risk Assessment Card:** Visual threat level badges, MITRE tactics chips, correlated evidence list, and one-tap action buttons.
  - **Verification Receipt Card:** Cryptographic audit stamp, status confirmation, and post-remediation telemetry.
