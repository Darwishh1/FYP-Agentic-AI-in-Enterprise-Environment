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
python -m pytest tests/ -q        # test suite, no API key needed
python demo.py --fast             # narrated policy demo, no API key needed
python -m red_team.runner         # attack suite + evaluation metrics

# Layer 1 end to end (about a minute, no API key)
python normal_traffic.py --all            # benign train / calib / holdout through the real graph
python -m red_team.behavioural            # behavioural attack traces
python -m detection.train                 # -> models/layer1_iforest.joblib
python -m detection.evaluate --seed-sweep 5   # -> reports/layer1/results.md
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
logs/*.jsonl                           ← one corpus file per source
```

Agents loop: after a tool call the agent keeps the turn until it finishes,
delegates, or exhausts its step budget. The gate can also run in **observe mode**
(`use_components(enforce=False)`): rules run and their verdict is recorded on the
record, but nothing is blocked. Detector corpora are generated that way so a call
Layer 3 would have contained still has real volume, and so Layer 1 and Layer 3 can
be scored on identical calls.

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
| 1 | **Isolation Forest** | Behavioural anomalies per call, with session context | **Built, shadow mode** |
| 2 | LSTM autoencoder | Sequence anomalies over sliding windows | Not built |
| 3 | **Rule engine** | Deterministic policy enforcement | **Built** |
| 4 | LLM-as-judge | Semantic intent over raw tool arguments | Not built |

Layers are designed to fuse into a composite anomaly score. Layers 1 and 3 exist.
Layer 1 runs in **shadow mode**: if `models/layer1_iforest.joblib` exists, the gate
writes `l1_score` (0 to 1) on every record and never consults it for enforcement.
Fusion is not built, so there is still no composite score.

### Layer 1 in one paragraph

18 features per call (`detection/features.py`), computed online from the call and
the calls before it in the session: per-role rarity of the tool, schema, hour,
target and payee; volume, amount and text length as robust z-scores against the
same role and tool; windowed call rate, tool diversity and entropy over recent
calls; sandbox-refusal share; delegation depth; cumulative session volume. Never
Layer 3's verdict, never labels, never latency. Trained on benign traffic only;
no `contamination` parameter. The raw score is calibrated on a separate benign
split, so the call threshold (q=0.99) means about 1% of benign calls exceed it,
and a separate session threshold (q=0.95) is calibrated on session maxima. Full
rationale in the module docstrings; every design iteration and its numbers in
`reports/layer1/DEVELOPMENT.md`.

**Current results** (`reports/layer1/results.md`; 5-seed means; benign holdout of
1,000 sessions; 8 behavioural scenarios x 40 sessions, all policy-compliant by
design):

| | Layer 1 | Layer 3 |
|---|---:|---:|
| Benign FPR per call | 0.9% | 6.5% |
| Benign FPR per session | 4.7% | 13.5% |
| Behavioural attack sessions caught | ~56% | ~10% |
| Caught by Layer 1 and not Layer 3 | ~179 of 320 | |

Strong on night-time HR work, delegation pivots into payouts, bulk dumps, data
staging and secret harvesting with whitelisted commands. Weak on salami payments
to new payees, low-and-slow paginated extraction, and anything outside the
training range (it cannot tell a 75k payment from the benign cluster at the
limit). Blind to content (instruction text in arguments) and to mimicry. The
misses and their mechanisms are listed in `DEVELOPMENT.md`; they are the honest
case for Layers 2 and 4.

**These are development numbers.** The detector was iterated against this attack
set, the attack traces are scripted, and benign and attack traffic come from the
same simulator. They show detector sensitivity in a synthetic enterprise, not a
field detection rate. Freeze the design and evaluate on newly written scenarios
before quoting final results.

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
- One benign workload model (`workload.py`) shared by the scripted planner and the
  corpus generator; benign sessions run through the real graph, gate and mock
  tools (about 15 calls per session). Train 1,500 / calib 1,000 / holdout 1,000
  sessions, separate seeds.
- Observe mode, one corpus file per source (`event_logger.CORPUS`).
- 13 behavioural attack traces (`red_team/behavioural.py`), run as sessions with
  benign cover traffic; only the attack calls carry the attack label.
- Layer 1 Isolation Forest: features, training, calibration, evaluation against
  Layer 3 on the same calls, shadow scoring in the gate.
- 112 tests. `test_layer1.py` checks the properties that make a Layer 1 number
  defensible (no leakage from Layer 3 or labels, no look-ahead, live scoring
  equals offline scoring, benign-only training, calibration).

**Not built**

LSTM autoencoder, semantic judge, score fusion, policy linter, adaptive-attacker
rounds, external benchmark adapters.

### About the current numbers

The suite reports 100 % detection and 0 % false positives. **Neither figure should be
quoted as a result yet**, and the tooling says so where it prints them:

- Six attacks, each written against a specific rule. That measures self-consistency,
  not capability.
- Only two benign controls in this suite. The benign corpus *has* now been scored:
  Layer 3 runs at about 6.5% per-call / 13.5% per-session FPR on it (below).
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
python normal_traffic.py --all  # benign corpus splits + Layer 3 FPR (no API key)
python -m red_team.behavioural  # behavioural attack traces       (no API key)
python -m detection.train       # train Layer 1                   (no API key)
python -m detection.evaluate    # Layer 1 vs Layer 3              (no API key)

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
| `LAYER1_MODEL` | `models/layer1_iforest.joblib` | Layer 1 model for shadow scoring |
| `LAYER1_SHADOW` | `1` | `0` disables Layer 1 shadow scoring in the gate |

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
workload.py           The one benign workload model (tool mix, arguments, hours, long tail).
normal_traffic.py     Benign corpus generator (through the real graph) + Layer 3 FPR report.
detection/
  patterns.py         Injection heuristic used by RB-005.
  features.py         Layer 1 features, online and offline from one code path.
  isolation_forest.py Layer1Detector (fit, calibrate, score, save) + ShadowScorer.
  train.py            python -m detection.train
  evaluate.py         python -m detection.evaluate
reports/layer1/       results.md, results.json, DEVELOPMENT.md (iteration log).
demo.py               Narrated console demo for supervisor meetings.
simulation_graph.py   Deprecated re-export shim. Do not add logic here.
red_team/
  base_attack.py      BaseAttackScenario, AgentAction, AttackResult.
  scenarios.py        6 attacks + 2 benign controls.
  runner.py           Runs the suite, prints the confusion matrix and metrics.
  baseline.py         No-monitor control condition.
  behavioural.py      13 behavioural attack traces, run as sessions in observe mode.
tests/                rule engine, enforcement gate, ground truth, baseline, end to end,
                      foundation (corpus + gate regressions), layer1 (detector contract),
                      tracker html.
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

**Closed in the Layer 1 branch**

- Benign corpus bypassed the gate (own volume, own privilege strings, no
  delegation): now generated through the real graph.
- Every graph session ended after one tool call: agents now loop.
- Scripted e2e "attack" runs could be persisted with an attack label although the
  plan never read the attack text: refused now.
- Red-team and benign records shared `logs/tool_calls.jsonl`: one file per source.
- `ToolCallRecord` had no simulated hour or time: added (`sim_hour`,
  `sim_time_seconds`, `delegation_depth`, `enforcement_mode`, `planner`, `l1_score`).
- Mock DB volume ignored query shape: point lookups, aggregates, filters, full
  scans and LIMIT now behave differently.
- `security_monitor.py` imported its injection heuristic from `mock_tools.py`:
  moved to `detection/patterns.py`.

**Policy findings from the benign FPR harness** (findings, not tuned away)

- *Fixed:* `customer_service_agent` carried a 500 refund limit but
  `call_payment_api` was not whitelisted, so RB-002 contained every refund and the
  limit was dead config. All 235 CONTAIN false positives in the old corpus were
  refunds.
- *Open:* RB-006 judges the **executing** role's hours. When DevOps (24/7)
  delegates to Finance at night, Finance trips the after-hours rule. Most of
  Layer 3's benign false positives are this. Whether that is correct is a policy
  decision, and a thesis point about rules that ignore delegation context.
- *Open:* RB-004's finance payment cap (5 per 60 s) fires on busy but legitimate
  payment runs.

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
- Test *count* is not test *sensitivity*. Nothing here establishes that the suite
  would fail if a rule were subtly wrong — no mutation testing or coverage
  measurement has been committed. Until one of those exists, "the tests pass" means
  the asserted cases hold, and nothing stronger.
- A future Layer 4 judge would read attacker-controlled argument text, making it an
  injection target itself. Needs hardening when built.

**Code and config drift**

- `policy.yaml` declares `shell_whitelist` and `can_delegate_to`; no rule reads
  either, and `delegation_source` is logged but never checked.
- Delegation depth *is* capped (`MAX_DELEGATION_DEPTH`), but the cap lives in the
  graph and the planner rather than the rule engine, so exceeding it produces no
  finding and no record. The monitor cannot see it happen.
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
2. ~~Score the benign corpus~~ done: Layer 3 FPR measured, two policy findings.
3. ~~Isolation Forest (Layer 1)~~ built, shadow mode. Next for it: evaluate on
   scenarios written after the design freeze.
4. **Score fusion** and tier calibration.
5. **LSTM autoencoder (Layer 2)** and **semantic judge (Layer 4)**.
6. **Scenario expansion** — 6 implemented against a 24+ target. Confirmed gaps:
   ASI08 cascading failures, ASI09 human-agent trust exploitation.
7. **Policy linter** — dead rules, conflicts, escalation paths, schema validation.
8. **Comparative evaluation** against the systems above.

Progress is tracked in `build tracker.html`, which opens directly in a browser with
no server or build step.
