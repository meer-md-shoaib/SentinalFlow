# SentinelFlow 🛡️
### Autonomous Cybersecurity Swarm for Everyday People & Modern Teams
> **Built for Fetch.ai / ASI:One Hackathon — Fetch-A-Thon 3.0**  
> **Team F-ups:** Meer Mohammed Shoaib, Mohammed Maaz, Prithvi S  
> 🔗 **Live Agentverse Profile:** [agent1qwstka0f7sjyd0ux69zfv9pu66testhc807cdhx8yvav3u0eml7nwptkdfy](https://agentverse.ai/agents/details/agent1qwstka0f7sjyd0ux69zfv9pu66testhc807cdhx8yvav3u0eml7nwptkdfy)  
> 🔍 **Live Inspector:** [Inspect Agent on Port 8000](https://agentverse.ai/inspect/?uri=http%3A//127.0.0.1%3A8000&address=agent1qwstka0f7sjyd0ux69zfv9pu66testhc807cdhx8yvav3u0eml7nwptkdfy)  
> 🐙 **GitHub Repository:** [allanmaaz/sentinal](https://github.com/allanmaaz/sentinal)

---

## 💡 What is SentinelFlow?

When an everyday person gets an alert saying *"Someone logged into your account from Nigeria,"* they panic. They don't know what to do, customer support takes 48 hours, and by then their accounts, money, or identity are stolen.

**SentinelFlow** is an autonomous AI cybersecurity bodyguard. You talk to it in plain English inside **ASI:One chat**. It scans your account for hackers in seconds, lets you kick them out with **1 tap for 0.1 FET (~$0.10)**, and provides a tamper-proof digital safety receipt proving your account is secure.

---

## ⚡ The 3-Step Simple Process

```
   1️⃣ Scan Account              2️⃣ 1-Tap Kick Out            3️⃣ Verified Proof
 ┌───────────────────┐        ┌───────────────────┐        ┌───────────────────┐
 │ "I got hacked"    │   ──►  │ Tap "Kick Out"    │   ──►  │ Digital Receipt   │
 │ Catches intruder  │        │ Logs out intruder │        │ 0.1 FET settled   │
 │ in Lagos, Nigeria │        │ & blocks device   │        │ SHA-256 verified  │
 └───────────────────┘        └───────────────────┘        └───────────────────┘
```

1. **Step 1: Check Account (Free)**  
   Type *"I think someone got into my account"*, *"Check alex@gmail.com"*, or just reply `1`.  
   SentinelFlow scans recent login records and tells you in plain English where the intruder logged in and what they did.

2. **Step 2: 1-Tap Emergency Kick Out**  
   Tap **[🔒 Kick Out Intruder (0.1 FET)]** or type `2` / *"lock it"*.  
   SentinelFlow immediately logs out all unauthorized phones and computers and blocks the attacker from trying again.

3. **Step 3: Verifiable Digital Safety Receipt**  
   SentinelFlow double-checks that the intruder is really gone, settles the small **0.1 FET micro-fee** via Fetch.ai escrow, and gives you a cryptographic SHA-256 safety receipt.

---

## 👥 The 5-Agent Multi-Agent Swarm (MAS)

Behind the simple chat is a decentralized team of **5 specialized Fetch.ai [`uAgents`](agents/)** working together in a [`Bureau`](agents/bureau.py):

| Agent | Icon | Role in Simple English |
| :--- | :---: | :--- |
| **Coordinator Agent** | 🎯 | Welcomes you in ASI:One chat, understands plain English, and orchestrates the team. |
| **Investigator Agent** | 🔎 | Searches login records and neutralizes prompt-injection attacks. |
| **Threat Analyst Agent**| 🧠 | Calculates danger scores (0–100) to tell real attacks apart from false alarms. |
| **Containment Agent** | 🔒 | Disconnects the intruder across all devices and blocks their IP address. |
| **Auditor Agent** | 📜 | Independently inspects your account to verify the intruder is gone and issues the SHA-256 proof. |

---

## 💼 Real-World Business Models

| Business Model | Who Pays | How It Makes Money | Price |
| :--- | :--- | :--- | :--- |
| **Consumer Roadside Rescue** | Everyday users & crypto holders | Pay-per-rescue micro-fee or monthly subscription | $1.00 / rescue or $4.99/mo |
| **Startup Slack Security Bot** | 10–50 person companies | Autonomous security in Slack replacing expensive analysts | $99 – $299 / month |
| **Agent-to-Agent Marketplace** | Other AI agents on Fetch.ai | Automated security checks for trading bots and assistants | 0.1 FET per audit call |

---

## 🎴 Native ASI:One Interactive Cards

SentinelFlow doesn't just send text walls — it renders native **Fetch.ai interactive cards**:

* **Card A (Security Alert)**: Clear plain-English alert showing intruder location and device.
* **Card B (1-Tap Lockdown)**: Primary action button to kick the intruder out for 0.1 FET.
* **Card C (Safety Certificate)**: Digital receipt with SHA-256 proof and next safety steps.
* **Card D (Login History)**: Simple chronological list of recent logins and devices.
* **Card E (Welcome Menu)**: 4 easy buttons so you never have to type complex commands.

> 💡 **Shortcuts:** You can always just type `1` (Scan), `2` (Kick Out), `3` (History), or `4` (Safe / All Good)!

---

## 🛠️ Quickstart (Run in 3 Steps)

### 1. Clone & Setup
```bash
git clone https://github.com/allanmaaz/sentinal.git
cd sentinal
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env
```
*(Your `.env` comes pre-configured with agent ports and Mailbox enabled).*

### 3. Run the Swarm
```bash
# Run standalone coordinator connected to ASI:One Mailbox
python agent.py --standalone

# Or run all 5 swarm agents together in a Bureau
python -m agents.bureau
```

---

## 🧪 Automated Test Suite (25/25 Passing)

Run the full reliability test suite:
```bash
pytest -v
```
All **25 tests pass** in ~11 seconds, verifying:
* Multi-agent bureau coordination
* ASI:One interactive card generation & button click parsing
* Conversational human dialogue & numeric shortcuts (`1`, `2`, `3`, `4`)
* Agent address mention stripping (`@agent1...`)
* Prompt-injection defense & cryptographic state verification
* Fetch.ai payment protocol & Model Context Protocol (MCP) server

---

## 📄 License
MIT License. Built with ❤️ for **Fetch-A-Thon 3.0** by **Team F-ups**.
