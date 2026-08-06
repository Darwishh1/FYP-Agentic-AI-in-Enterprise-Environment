# Agentic AI Security Monitor

**A runtime security monitor for multi-agent LLM systems.**

A simulated enterprise — HR, Finance, DevOps and Customer Service agents — runs on
LangGraph. Every tool invocation is forced through a single enforcement gate that
evaluates the call against a declarative policy, then passes, annotates, or blocks
it. A red-team suite drives attack scenarios through the same engine and reports
Detection Rate, False Positive Rate and OWASP tagging accuracy.

Final Year Project — Computer Engineering (AI Honours), UCSI University
Author: Mahmoud Ashraf Mahmoud · Supervisor: Mr. Adi Ong · Industry co-op: Sparke Labs Sdn. Bhd.

```bash
pip install -r requirements.txt
python -m pytest tests/ -q        # 72 tests, no API key needed
python demo.py --fast             # narrated policy demo, no API key needed
python -m red_team.runner         # attack suite + evaluation metrics
```

---

## Why this exists

Agentic systems fail differently from single-model chatbots. The interesting attack
surface is not the prompt — it is the *sequence of tool calls* an agent makes once it
has been compromised: schema hopping, delegation abuse, payment redirection, slow
exfiltration. Prompt-level guardrails see none of that.

This project instruments the tool layer instead, and asks whether behavioural
detection catches what input filtering misses.

---

## How it works

```
User query
    │
    ▼
orchestrator (LLM) ──────────── routes to a specialist agent
    │
    ├──► hr_agent      ├──► devops_agent
    ├──► finance_agent └──► customer_service_agent
    │
    ▼
guarded_tool_call()                    ← the only way to reach a tool
    │
    ├─► SecurityMonitor.enforce_policy()  ─── policy.yaml
    │
    ├─► CONTAIN → block, log a BLOCKED record
    └─► else    → execute, log a SUCCESS record
    │              (WARN and ALERT annotate; they do not block)
    ▼
logs/tool_calls.jsonl                  ← the detection corpus
```

Every tool that ever executes goes through `TOOL_REGISTRY` inside
`guarded_tool_call`. That is deliberate: one auditable place, no side doors. The gate
emits exactly one `ToolCallRecord` per call whether it passed or was blocked — a
property covered by tests, because a gate that skipped records on the block path
would delete precisely the positives the detection layers need.

### Rule set

Layer 3 (`security_monitor.py`) evaluates a call against `policy.yaml` and returns
the single most severe finding. Only `CONTAIN` blocks execution.

| ID | Trigger | Verdict | OWASP |
|----|---------|---------|-------|
| RB-000 | Unknown / rogue agent identity | CONTAIN | ASI10 |
| RB-001 | DB schema outside the agent's whitelist | CONTAIN | ASI03 |
| RB-002 | Tool not whitelisted for the agent | CONTAIN | ASI02 |
| RB-003 | Payment above the role limit | CONTAIN | ASI02 |
| RB-004 | Call rate above the windowed cap | ALERT | ASI02 |
| RB-005 | Instruction-like text in tool arguments | CONTAIN | ASI01 |
| RB-006 | High-privilege op outside allowed hours | WARN | ASI03 |

### Detection layers

| Layer | Method | Purpose | Status |
|-------|--------|---------|--------|
| 1 | Isolation Forest | Point anomalies on per-call feature vectors | Not built |
| 2 | LSTM autoencoder | Sequence anomalies over sliding windows | Not built |
| 3 | **Rule engine** | Deterministic policy enforcement | **Built** |
| 4 | LLM-as-judge | Semantic intent over raw tool arguments | Not built |

Layers are designed to fuse into a composite anomaly score. **Only Layer 3 exists
today**, so the current pipeline is single-layer — any "multi-layer" language in
older project documents is aspirational, not descriptive.

---

## Status

Honest summary: **the enforcement and evaluation scaffolding is real and tested; the
machine-learning detection layers are not built yet.**

**Built and covered by tests**

- LangGraph scaffold, four agent nodes, orchestrator routing, agent-to-agent
  delegation with a depth cap.
- Two interchangeable planners behind one protocol: a seeded `ScriptedPlanner`
  (deterministic, free) and an `LLMPlanner`. Selected with `PLANNER_MODE`.
- `guarded_tool_call` as the sole enforcement gate, checked *before* the tool runs.
- Layer 3 rule engine, RB-000 to RB-006, severity-ordered findings.
- `ToolCallRecord` schema, JSONL corpus, replay loader, SQLite checkpointing.
- Red-team framework: 6 attacks and 2 benign controls, with metrics.
- Benign traffic generator; ~3,900 calibration and ~3,900 holdout records generated.
- 72 tests. Their sensitivity was verified by mutation — seven deliberate faults were
  seeded into the rule engine one at a time and all seven were caught.

**Not built**

Isolation Forest, LSTM autoencoder, semantic judge, score fusion, policy linter,
adaptive-attacker rounds, external benchmark adapters.

### About the current numbers

The suite reports 100 % detection and 0 % false positives. **Neither figure should be
quoted as a result yet**, and the tooling says so where it prints them:

- Six attacks, each written against a specific rule. That measures self-consistency,
  not capability.
- Only two benign controls. The ~3,900-record benign corpus has not been scored yet.
- The no-monitor baseline reads 0 %, but *by construction*: scenarios call the
  detection engine directly and never pass through the orchestrating LLM, so with the
  rule engine disabled nothing in the path could refuse anything. Until scenarios run
  end-to-end, the "marginal contribution" of the monitor is not measurable.
- Precision, recall and F1 are deliberately **not** computed. With 6 attacks and 2
  controls the denominators are too small to be honest.

---

## Running it

Python 3.12. For the LLM path, put `GOOGLE_API_KEY` in a `.env` file;
`LLM_MODEL` defaults to `gemini-3.1-flash-lite`.

```bash
pip install -r requirements.txt

python -m pytest tests/ -q      # test suite                      (no API key)
python demo.py --fast           # narrated policy demo            (no API key)
python -m red_team.runner       # attack suite + metrics          (no API key)
python -m red_team.baseline     # monitor-on vs monitor-off       (no API key)
python normal_traffic.py        # generate benign corpus + FPR    (no API key)

python app.py                   # full graph, persistent session  (needs API key)
langgraph dev                   # LangGraph Studio                (needs API key)
```

Most of the project runs without an API key, because the rule engine is
deterministic and the default planner is seeded.

`app.py` resumes from `checkpoints.sqlite` on a fixed thread id; delete the file to
start clean.

| Variable | Default | Purpose |
|----------|---------|---------|
| `LLM_MODEL` | `gemini-3.1-flash-lite` | Model for orchestration and planning |
| `PLANNER_MODE` | `scripted` | `scripted` or `llm` |
| `PLANNER_SEED` | `42` | Seed for the scripted planner |
| `MAX_DELEGATION_DEPTH` | `3` | Agent-to-agent delegation cap |
| `SIM_HOUR` | *(unset)* | Pin the simulated clock, for reproducible RB-006 |
| `SIM_TIME_DEFAULT_INCREMENT` | `2.0` | Seconds each tool call advances the sim clock |

---

## Repo layout

```
graph.py              Canonical StateGraph + guarded_tool_call. Single source of truth.
agent_runtime.py      Planner protocol, ScriptedPlanner, LLMPlanner.
app.py                CLI runner. Compiles the graph with an on-disk SqliteSaver.
state.py              EnterpriseState typed session state.
security_monitor.py   Layer 3 rule engine.
policy.yaml           Declarative per-agent policy: tools, schemas, limits, hours.
mock_tools.py         The 8 mock tool implementations.
logging_schema.py     ToolCallRecord (19 fields) + hashing and timestamp helpers.
event_logger.py       Appends to logs/tool_calls.jsonl, exposes load_all().
attack_context.py     Scoped red-team ground-truth labelling.
normal_traffic.py     Benign corpus generator + false-positive harness.
demo.py               Narrated console demo for supervisor meetings.
simulation_graph.py   Deprecated re-export shim. Do not add logic here.
red_team/
  base_attack.py      BaseAttackScenario, AgentAction, AttackResult.
  scenarios.py        6 attacks + 2 benign controls.
  runner.py           Runs the suite, prints the confusion matrix and metrics.
  baseline.py         No-monitor control condition.
tests/                72 tests: rule engine, enforcement gate, labelling, tracker.
build tracker.html    Standalone build tracker. Open it directly in a browser.
```

Agents have access to `db_query`, `execute_shell`, `send_email`, `call_payment_api`,
`read_file`, `write_file`, `create_ticket` and `escalate_to_human`.

---

## Known issues — read before trusting any number

Tracked openly rather than quietly fixed, because several are thesis-relevant
limitations rather than bugs. Two earlier entries in this section have since been
closed and removed: the ground-truth label is no longer derived from the expectation
it is checked against, and red-team labelling is now actually applied at runtime.

**Methodological — these affect whether results are defensible**

- Scenarios hit the detection engine directly and never touch the orchestrator.
  Prompt-injection results scored only against the `contains_instruction_pattern`
  regex are not defensible: the regex is both the attack target and the judge.
  **This is the current highest-priority item** — it also blocks the no-monitor
  baseline from measuring anything.
- Layer 3 returns a *categorical* status, while the design defines
  WARN/ALERT/CONTAIN as cutoffs on a *continuous* score. Same tier names, two
  meanings. One has to give at fusion time.
- With 6 attacks and 2 controls, precision/recall/F1 denominators are too small to
  report honestly. Expand the suite first.
- A future Layer 4 judge would read attacker-controlled argument text, making it an
  injection target itself. Needs hardening when built.

**Code and config drift**

- `policy.yaml` declares `shell_whitelist` and `can_delegate_to`; no rule reads
  either, and `delegation_source` is logged but never checked.
- Delegation depth *is* capped (`MAX_DELEGATION_DEPTH`), but the cap lives in the
  graph and the planner rather than the rule engine, so exceeding it produces no
  finding and no record. The monitor cannot see it happen.
- `security_monitor.py` imports `contains_instruction_pattern` from `mock_tools.py`,
  so the rule engine depends on the tool mocks. Should move to a detection package.
- Shell whitelist, network-pattern blocks and path-traversal guards are still
  hardcoded in `mock_tools.py` instead of living in the policy file.

**Documentation vs code — the repo is authoritative**

- D-001 is tagged ASI02 in code, ASI05 in the project knowledge base. F-002 is ASI10
  in code, listed under both ASI07 and ASI10 in the docs.
- Rule ids diverge: the code has RB-000 (rogue identity) and defines RB-002 as tool
  whitelist; older docs have no RB-000 and define RB-002 differently.
- `policy.yaml` carries `privilege_level` per agent and RB-006 reads it; the
  documented schema omits it. The doc is wrong here.
- One reference (Wang et al. 2024, *Attacking and Defending Multi-Agent Systems*) is
  likely hallucinated and needs replacing with a verified source. Verify every
  citation before submission.
- MITRE ATLAS techniques are recorded at **tactic level only**, deliberately. Do not
  attach an `AML.T` identifier without checking it against the live matrix.

---

## Evaluation plan

Targets: Detection Rate > 85 %, False Positive Rate < 5 %, OWASP tag accuracy
reported per category. Comparison systems: Promptfoo, DeepTeam. External benchmarks:
AgentDojo, Agent Security Bench. Taxonomies: OWASP Top 10 for Agentic Applications
(ASI01–ASI10) and MITRE ATLAS.

Build order is dependency-driven:

1. **Run scenarios end-to-end through the graph.** Restores the LLM to the attack
   path, makes the baseline a real experiment, and makes injection results
   defensible.
2. **Score the existing benign corpus** and record the rule engine's false-positive
   rate. Already generated, no model cost.
3. **Isolation Forest (Layer 1)**, trained benign-only, with a measured FPR.
4. **Score fusion** and tier calibration.
5. **LSTM autoencoder (Layer 2)** and **semantic judge (Layer 4)**.
6. **Scenario expansion** — 6 implemented against a 24+ target. Confirmed gaps:
   ASI08 cascading failures, ASI09 human-agent trust exploitation.
7. **Policy linter** — dead rules, conflicts, escalation paths, schema validation.
8. **Comparative evaluation** against the systems above.

Progress is tracked in `build tracker.html`, which opens directly in a browser with
no server or build step.
