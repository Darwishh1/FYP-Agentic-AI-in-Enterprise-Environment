# Agentic AI Security Monitor

Final Year Project — Computer Engineering (AI Honours), UCSI University
Author: Mahmoud Ashraf Mahmoud · Supervisor: Mr. Adi Ong · Industry co-op: Sparke Labs Sdn. Bhd.
Repo: `hazem-sparkelabs/agentic-security-monitor` (private)

A runtime security monitor for multi-agent LLM systems. A simulated enterprise
(HR, Finance, DevOps, Customer Service) runs on LangGraph; every tool invocation
is forced through a single enforcement gate that evaluates the call against a
declarative policy and a layered detection stack, then passes, annotates, or
blocks it. A red-team suite drives attack scenarios through the same engine and
reports Detection Rate, False Positive Rate, and OWASP tagging accuracy.

---

## Why this exists

Agentic systems fail differently from single-model chatbots. The interesting
attack surface is not the prompt, it is the *sequence of tool calls* an agent
makes once it has been compromised: schema hopping, delegation abuse, payment
redirection, slow exfiltration. Prompt-level guardrails do not see any of that.
This project instruments the tool layer instead and asks whether behavioural
detection catches what input filtering misses.

---

## Architecture

```
User query
    │
    ▼
orchestrator (LLM, Gemini Flash) ──── emits a routing keyword
    │
    ├──► hr_agent
    ├──► finance_agent
    ├──► devops_agent
    └──► customer_service_agent
              │
              ▼
      guarded_tool_call()          ← single enforcement choke point
              │
              ├─► SecurityMonitor.enforce_policy()   [Layer 3, rule-based]
              │       └─► policy.yaml
              │
              ├─► CONTAIN ? block, log a BLOCKED ToolCallRecord
              └─► else    ? execute via TOOL_REGISTRY, log a SUCCESS record
                             (WARN / ALERT annotate the result, do not block)
              │
              ▼
      logs/tool_calls.jsonl        ← the detection corpus
```

Every tool ever executed goes through `TOOL_REGISTRY` inside `guarded_tool_call`.
That is deliberate: one auditable place, no side doors.

### Detection layers

| Layer | Method | Purpose | Status |
|-------|--------|---------|--------|
| 1 | Isolation Forest | Point anomalies on per-call feature vectors | **Not built** |
| 2 | LSTM Autoencoder | Sequence anomalies over sliding windows | **Not built** |
| 3 | Rule engine | Deterministic policy enforcement | **Built** |
| 4 | LLM-as-judge | Semantic intent over raw tool args | **Not built** |

Layers fuse into a composite anomaly score with WARN / ALERT / CONTAIN cutoffs.
Only Layer 3 exists today, so the current pipeline is single-layer and the
"triple/quad-layer" language in the older docs is aspirational, not descriptive.

### Rule set (Layer 3, `security_monitor.py`)

| ID | Trigger | Verdict | OWASP |
|----|---------|---------|-------|
| RB-000 | Unknown / rogue agent identity | CONTAIN | ASI10 |
| RB-001 | DB schema outside the agent's whitelist | CONTAIN | ASI03 |
| RB-002 | Tool not whitelisted for the agent | CONTAIN | ASI02 |
| RB-003 | Payment above the role limit | CONTAIN | ASI02 |
| RB-004 | Call rate above the per-minute cap | ALERT | ASI02 |
| RB-005 | Instruction-like text in tool arguments | CONTAIN | ASI01 |
| RB-006 | High-privilege op outside allowed hours | WARN | ASI03 |

`enforce_policy` collects all findings and returns the single most severe one.
Only CONTAIN blocks execution.

---

## Repo layout

```
graph.py              Canonical StateGraph + guarded_tool_call. Single source of truth.
app.py                CLI runner. Compiles the graph with an on-disk SqliteSaver.
simulation_graph.py   Deprecated re-export shim. Do not add logic here.
state.py              EnterpriseState typed session state.
security_monitor.py   Layer 3 rule engine.
policy.yaml           Declarative per-agent policy (tools, schemas, limits, hours).
mock_tools.py         The 8 mock tool implementations + contains_instruction_pattern.
logging_schema.py     ToolCallRecord (19 fields) + hashing/timestamp helpers.
event_logger.py       Appends to logs/tool_calls.jsonl, exposes load_all().
attack_context.py     contextvars-based red-team ground-truth labelling.
demo.py               Narrated ANSI console demo for supervisor meetings.
red_team/
  base_attack.py      BaseAttackScenario, AgentAction, AttackResult.
  scenarios.py        6 attacks + 2 benign controls.
  runner.py           Runs the suite, prints DR / FPR / OWASP coverage.
fyp_build_tracker.jsx React build tracker (phases, statuses, glossary, notes).
```

### Tools available to agents

`db_query`, `execute_shell`, `send_email`, `call_payment_api`, `read_file`,
`write_file`, `create_ticket`, `escalate_to_human`.

---

## Running it

```powershell
# Windows / PowerShell, Python 3.11+
pip install -r requirements.txt
# .env needs GOOGLE_API_KEY; LLM_MODEL defaults to gemini-3.1-flash-lite

python app.py                  # full graph, persistent session (thread cli-session-1)
python demo.py --fast          # supervisor demo over the rule engine, no LLM cost
python -m red_team.runner      # red-team suite + evaluation metrics
langgraph dev                  # LangGraph Studio, uses the module-level `graph`
```

`app.py` resumes from `checkpoints.sqlite` on the same thread id. Delete the db
to start clean.

---

## What is done

- LangGraph scaffold, four agent nodes, orchestrator with conditional routing.
- `guarded_tool_call` as the sole enforcement gate, pre-call (checked *before*
  the tool runs, not after).
- Layer 3 rule engine, RB-000 to RB-006, severity-ordered findings.
- `policy.yaml` loaded at monitor construction as the enforcement source.
- `ToolCallRecord` schema and JSONL corpus with a replay loader.
- SqliteSaver checkpointing on a stable thread id.
- Red-team framework: base class, 6 attacks, 2 benign controls, runner with
  Detection Rate, FPR, OWASP tag accuracy, per-category coverage.
- Console demo with boxed verdict output driven by real `enforce_policy` calls.
- React build tracker with phase collapsing, status cycling, glossary popovers,
  inline notes, import/export, persistent storage.

## What is next

Build order is dependency-driven, not preference-driven:

1. **Baseline traffic generator** — a benign corpus large enough to fit on. The
   only corpus today is whatever `demo.py` and the red-team runner appended,
   which is attack-heavy and tiny. Must not consult the ruleset while
   generating, or Layer 1 learns the rules instead of the behaviour.
2. **Feature extractor** — the 8 feature fields out of `ToolCallRecord`.
3. **Isolation Forest (Layer 1)** — trained benign-only. Establish baseline FPR.
4. **Score fusion** — composite score + tier calibration.
5. **LSTM Autoencoder (Layer 2)** and **semantic LLM judge (Layer 4)** in
   parallel once fusion exists.
6. **Scenario expansion** — 6 implemented against a 24+ target. Confirmed gaps:
   ASI08 cascading failures, ASI09 human-agent trust exploitation.
7. **Policy linter** — dead rules, conflicts, escalation paths, schema validation.
8. **Comparative evaluation** — Promptfoo and DeepTeam adapters, anchored to
   AgentDojo and Agent Security Bench.

---

## Known issues — read before trusting anything

These are tracked deliberately rather than quietly fixed, because several of
them are thesis-relevant limitations, not just bugs.

**Methodological (these affect whether results are defensible):**

- `base_attack.py` derives the ground-truth `is_attack` label from
  `expect_detected`. Those are different things: one is what the input *is*, the
  other is what the monitor *should say* about it. They agree today only because
  no scenario is an attack expected to slip through. This is circular and must be
  separated before any headline number is reported.
- Scenarios hit the detection engine directly and never touch the orchestrator.
  Prompt-injection results scored only against the `contains_instruction_pattern`
  regex are not defensible — the regex is both the attack target and the judge.
- `set_attack_label` is never called anywhere; `graph.py` imports only
  `get_attack_label`. So `is_attack` is always false outside the red-team classes.
- Layer 3 returns a *categorical* status while the design doc defines
  WARN/ALERT/CONTAIN as cutoffs on a *continuous* score. Same tier names, two
  meanings. One of them has to give at fusion time.
- With 6 attacks and 2 controls, precision/recall/F1 denominators are too small
  to report honestly. Expand the suite first, then compute them.
- The Layer 4 judge reads attacker-controlled argument text, which makes it an
  injection target itself. Needs hardening and an explicit mention in the thesis.

**Code / config drift:**

- `policy.yaml` declares `shell_whitelist` and `can_delegate_to`; no rule reads
  either. `delegation_source` is logged but never checked. Delegation depth is
  uncapped.
- `security_monitor.py` imports `contains_instruction_pattern` from
  `mock_tools.py`, so the rule engine depends on the tool mocks. Should move into
  a detection package.
- Shell whitelist, network-pattern blocks, and path-traversal guards are still
  hardcoded in `mock_tools.py` instead of living in the policy file.

**Doc vs code discrepancies (repo is authoritative):**

- D-001 is tagged ASI02 in code, ASI05 in the knowledge base. F-002 is ASI10 in
  code, listed under both ASI07 and ASI10 in the doc.
- Rule ids diverge: code has RB-000 (rogue identity) and defines RB-002 as tool
  whitelist; the doc has no RB-000 and defines RB-002 as shell exec with network
  reach.
- `policy.yaml` carries `privilege_level` per agent and RB-006 reads it; the
  documented schema omits it. The doc is wrong here.
- Orchestrator is Gemini Flash in code; some KB sections still say Claude Sonnet.
- "Triple-layer" language persists in places that should say four layers.
- One reference (Wang et al. 2024, *Attacking and Defending Multi-Agent Systems*)
  is likely hallucinated and needs replacing with a verified source. The KB has a
  history of this — verify every citation before submission.
- MITRE ATLAS technique IDs are deliberately recorded at **tactic level only**.
  Do not attach an `AML.T` id without checking it against the live matrix.

**Sync warning:** the indexed repo state does not include the planner-driven
`graph.py` rewrite, `normal_traffic.py`, or the sliding-window RB-004 redesign
that were developed in session. Either those are unpushed, or the project index
is stale. Reconcile before treating this README as current.

---

## Model stack

| Role | Model |
|------|-------|
| Orchestrator / routing | Gemini Flash (`LLM_MODEL`, default `gemini-3.1-flash-lite`) |
| Semantic judge (Layer 4) | Claude Sonnet |
| Red-team adversarial generation | GPT |
| Dev tooling | Claude Code (not part of the deployed system) |

## Evaluation targets

Detection Rate > 85% · False Positive Rate < 5% · OWASP tag accuracy reported per
category. Baselines: Promptfoo, DeepTeam. Benchmarks: AgentDojo, Agent Security
Bench (ASB). Taxonomies: OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10),
MITRE ATLAS.
