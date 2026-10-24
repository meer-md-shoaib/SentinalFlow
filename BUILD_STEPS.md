# SentinelFlow — Build Steps (execute in order)

Working plan for the SentinelFlow prototype (ASI:One Agent Challenge).
Execute steps **top to bottom**, one at a time. After each step: run its
verification, record actual results, only then mark it done.

Legend: `[ ]` pending, `[x]` done, `[!]` blocked (needs credentials/manual action).

---

## Step 0 — Scaffold & plan (this file)
- [x] Create `BUILD_STEPS.md` (this file)
- [x] Create `.gitignore` (must ignore `.env`, `__pycache__`, `.pytest_cache`, etc.)
- [x] Create `.env.example` with placeholders only
- [x] Create `.env` locally (real key lives only here, never in code)
- [x] Create `requirements.txt`

**Verify:** files exist; `git check-ignore .env` confirms `.env` is ignored.

## Step 1 — Milestone 1 (local part): ASI:One model connectivity
- [x] Write `config.py` (env-driven settings: ASI1 base URL, model `asi1`, key)
- [x] Write `llm.py` — thin, fail-soft client for the ASI:One API (used only for
      intent parsing + explanation phrasing; never for security decisions)
- [x] Verify with a real API call that the key + model work
- [x] Record exact model id / endpoint behavior in `docs/PLATFORM.md`

**Verify:** script prints a real model reply; failure modes captured.

## Step 2 — Milestone 2: Synthetic data + investigation tools
- [x] `data/synthetic_events.json` — fictional events covering: repeated failed
      logins, success-after-failures, suspicious privileged op, benign travel /
      new-device, normal activity, missing telemetry, duplicates, malformed
      records, prompt-injection payload in a log field, `198.51.100.x`/`203.0.113.x` IPs
- [x] `schemas.py` — Pydantic models (Event, InvestigationRequest, Assessment…)
- [x] `investigation/log_store.py` — loading, validation, malformed-record quarantine
- [x] `investigation/search.py` — `search_logs(account_id, start_time, end_time)` strict
      validation, UTC handling, bounded results, empty-result behavior
- [x] `investigation/correlation.py` — `correlate_events`, `retrieve_evidence`,
      `generate_incident_timeline`

**Verify:** `pytest tests/test_investigation.py` (21 passed).

## Step 3 — Milestone 3: Deterministic risk engine + report
- [x] `risk/rules.py` — named rules (R1..Rn), explicit triggers
- [x] `risk/assessment.py` — deterministic scoring → severity, rule ids, evidence ids,
      explanation, uncertainty, recommended next step (explicitly NOT a probability)
- [x] `reporting/incident_report.py` — 12-section structured report, chat-readable

**Verify:** `pytest tests/test_risk_and_report.py` (11 passed).

## Step 4 — Milestone 4: Authorization + simulated response + verification
- [x] `response/policy.py` — action allowlist, determinism, policy decision records
- [x] `response/approval.py` — approval bound to (incident, target, action, requester,
      expiry, one-time token); replay/mismatch/decline/expiry handling
- [x] `response/simulator.py` — simulated account state store (JSON-backed), only
      simulated actions (incident record, flag, temporary containment, escalation)
- [x] `response/verifier.py` — independent state read-back; verified / failed / unverified

**Verify:** `pytest tests/test_authorization.py` (16 passed; total 48 tests passing).

## Step 5 — Milestone 5: Multi-Agent Architecture (Fetch.ai uAgents Bureau)
- [x] `orchestrator.py` — staged workflow engine coordinating parse → investigate →
      assess → recommend → request approval → validate → execute → verify → report
- [ ] Multi-Agent Bureau setup (`uagents.Bureau`):
      1. `GatewayAgent`: External ACP / ASI:One chat interface, session & approval token dispatcher
      2. `InvestigatorAgent`: Dispatched log query & correlation specialist
      3. `RiskPolicyAgent`: Deterministic scoring (R1..Rn) & authorization validator
      4. `ResponseVerifierAgent`: State execution & independent read-back verification
- [ ] Text-based approval flow inside chat (`APPROVE <token>` / `DECLINE`)

**Verify:** `pytest tests/test_orchestrator.py tests/test_agent_chat.py` +
agent starts locally and answers a chat request.

## Step 6 — Milestone 5b: Full test suite + failure handling
- [ ] All 17 required scenarios from the spec covered under `tests/`
- [ ] Run full `pytest`, capture real output into `docs/TEST_RESULTS.md`

**Verify:** full suite green (or honest list of failures).

## Step 7 — Milestone 6 (part 1): Documentation
- [ ] `README.md` (problem, solution, architecture, workflow, setup, env vars,
      security controls, tests, example investigation, limitations)
- [ ] `docs/PLATFORM.md` — exact Agentverse + ASI:One steps incl. manual actions

## Step 8 — Milestone 1 (remote part): Agentverse + ASI:One registration [MANUAL/BLOCKED]
- [ ] **User action required:** Agentverse account + agent registration
- [ ] **User action required:** mailbox / ASI:One discovery verification
- [ ] End-to-end message through ASI:One chat → SentinelFlow → reply
- [ ] Record real endpoints/URLs here (never fabricated)

---

## Environment decisions (sensible defaults, chosen to move fast)
- **Python 3.13**, Pydantic v2, pytest, httpx, uAgents (chat protocol), python-dotenv.
- **Model:** ASI:One `asi1` via `ASI1_BASE_URL` (OpenAI-compatible) — used only to
  interpret intent/explain, never to make authorization or risk decisions.
- **Deterministic core**: every security decision comes from code + rules, not the LLM.
- **All simulated state** in `data/state_store.json` (gitignored at runtime, sample shipped).
