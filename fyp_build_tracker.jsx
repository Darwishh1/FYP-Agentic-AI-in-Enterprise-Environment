import React, { useState, useEffect, useMemo, useRef } from "react";
import {
  Lock,
  Search,
  X,
  Plus,
  Trash2,
  Pencil,
  ChevronDown,
  ChevronRight,
  Copy,
  RotateCcw,
  BookOpen,
} from "lucide-react";

/* ============================================================================
   SEED_DATA — hand-editable. Every task label is plain text only.

   Edit this file, never 'build tracker.html' — that one is generated from here by
   build_tracker_html.py. Bump seedVersion below so a live board picks the edit up
   instead of ignoring it, then rebuild:  python build_tracker_html.py
   ==========================================================================*/

const SEED_DATA = {
  // Bump this whenever you hand-edit SEED_DATA. On hydrate, a stored board with a
  // different seedVersion is merged against the seed rather than ignored: labels and
  // inferred flags come from the seed, status and note stay yours. Without this, editing
  // the seed did nothing to an already-hydrated board and the only way to pick up an edit
  // was WIPE AND RESEED, which threw away every note.
  seedVersion: 5,

  phases: [
    {
      id: "P0",
      name: "Foundation",
      blurb: "LangGraph env, agent scaffolding, mock tool APIs",
      deps: [],
      tasks: [
        { id: "p0-1", label: "Stand up the LangGraph environment and project scaffold", status: "done", note: "", inferred: false },
        { id: "p0-2", label: "Make graph.py the single source of truth for the StateGraph topology", status: "done", note: "Verified: simulation_graph.py and agent_studio/graph.py are now re-export shims only.", inferred: false },
        { id: "p0-3", label: "Define EnterpriseState as the typed session state", status: "done", note: "", inferred: false },
        { id: "p0-4", label: "Implement the mock tool APIs behind a single TOOL_REGISTRY", status: "done", note: "Counted 8 entries in TOOL_REGISTRY: db_query, execute_shell, send_email, call_payment_api, read_file, write_file, create_ticket, escalate_to_human. Matches the seed.", inferred: false },
        { id: "p0-5", label: "Route every tool invocation through guarded_tool_call as the single choke point", status: "done", note: "", inferred: false },
      ],
    },
    {
      id: "P1",
      name: "Enterprise Simulation",
      blurb: "4 agent roles, planner layer, delegation, logging, checkpointing",
      deps: ["P0"],
      tasks: [
        { id: "p1-1", label: "Build the four agent nodes: hr, finance, devops, customer_service", status: "done", note: "", inferred: false },
        { id: "p1-2", label: "Route from the orchestrator by conditional edge on a keyword verdict", status: "done", note: "route_decision parses ROUTE_TO_HR / FINANCE / DEVOPS / CS out of the message text.", inferred: false },
        { id: "p1-3", label: "Define the ToolCallRecord logging schema", status: "done", note: "Counted 19 dataclass fields in logging_schema.py. Matches the seed.", inferred: false },
        { id: "p1-4", label: "Append every record to a JSONL corpus with a replay loader", status: "done", note: "EventLogger writes logs/tool_calls.jsonl and exposes load_all().", inferred: false },
        { id: "p1-5", label: "Persist sessions with an on-disk checkpointer on a stable thread id", status: "done", note: "SqliteSaver + THREAD_ID cli-session-1, so re-running app.py resumes.", inferred: false },
        { id: "p1-6", label: "Ship the narrated console demo over the rule engine", status: "done", note: "demo.py runs scenarios from the red-team classes through enforce_policy and prints a verdict block plus a summary table.", inferred: false },
        { id: "p1-7", label: "Split the agent decision layer out behind a Planner protocol", status: "done", note: "Was missing from the board entirely. agent_runtime.py defines a Planner protocol with two interchangeable implementations: ScriptedPlanner (seeded random.Random, per-role weighted _WORKLOAD, free and deterministic) and LLMPlanner (JSON-only output contract, validates tool name and delegation target, degrades to finish on any exception). Selected by the PLANNER_MODE env var, scripted by default.", inferred: false },
        { id: "p1-8", label: "Make delegation a real graph edge rather than a logged field", status: "done", note: "Also missing from the board. graph.py has agent-to-agent conditional edges, state.py carries delegation_path and delegation_depth, and a steps_remaining budget bounds the run. Note this is the mechanism only. Whether a delegation is permitted is still unchecked, which is task p4-6.", inferred: false },
        { id: "p1-9", label: "Keep the LLM planner free of safety prompting", status: "done", note: "My addition, but it is a deliberate choice already visible in agent_runtime.py. The planner is not told to behave, so what gets measured is the monitor rather than the base model's own reluctance. This is the same argument as the no-monitor baseline in p7-5, and the two need to stay consistent.", inferred: true },
      ],
    },
    {
      id: "P2",
      name: "Detection Engine v1",
      blurb: "Rule layer and corpus done. Isolation Forest not started.",
      deps: ["P1"],
      tasks: [
        { id: "p2-1", label: "Build the rule engine with RB-000 through RB-006", status: "done", note: "Counted 7 rules in security_monitor.py: RB-000 rogue identity, RB-001 schema, RB-002 tool whitelist, RB-003 payment, RB-004 rate, RB-005 injected instructions, RB-006 after-hours high privilege.", inferred: false },
        { id: "p2-2", label: "Return the most severe finding under WARN / ALERT / CONTAIN tiers", status: "done", note: "Only CONTAIN blocks. WARN and ALERT annotate an allowed call.", inferred: false },
        { id: "p2-3", label: "Build the Isolation Forest layer as its own module", status: "todo", note: "", inferred: false },
        { id: "p2-4", label: "Engineer the 8 feature vector fields out of ToolCallRecord", status: "todo", note: "", inferred: false },
        { id: "p2-5", label: "Generate a normal-operation corpus large enough to fit on", status: "done", note: "Board was stale here. normal_traffic.py exists and has been run: logs/tool_calls_calibration.jsonl holds 3941 records and logs/tool_calls_holdout.jsonl holds 3975, all is_attack false. Calibration and holdout are exactly the split the Isolation Forest needs, so p2-3 is no longer blocked on data.", inferred: false },
        { id: "p2-8", label: "Write down the measured benign false positive rate of the rule engine", status: "todo", note: "normal_traffic.py prints overall, per-role, per-rule and per-severity FPR, but the number is not recorded anywhere, so no document can cite it. Run it and commit the output. If it comes back exactly 0.0, treat that as a warning rather than a result: it would suggest the workload generator was implicitly shaped by the ruleset it is meant to be independent of. normal_traffic.py already prints a warning in that case.", inferred: false },
        { id: "p2-6", label: "Establish the Isolation Forest baseline false positive rate", status: "todo", note: "Distinct from p2-8. That one measures the rule engine, this one measures the statistical layer, and the comparison between them is the point.", inferred: false },
        { id: "p2-7", label: "Move contains_instruction_pattern out of mock_tools into the detection package", status: "todo", note: "Evidenced: security_monitor.py imports contains_instruction_pattern from mock_tools, so the rule engine depends on the tool mocks. The judgement that this is worth untangling is mine, not the repo's.", inferred: true },
      ],
    },
    {
      id: "P3",
      name: "Detection Engine v2",
      blurb: "LSTM autoencoder, score fusion, tier thresholds",
      deps: ["P2"],
      tasks: [
        { id: "p3-1", label: "Build the LSTM autoencoder over a sliding window of feature vectors", status: "todo", note: "", inferred: false },
        { id: "p3-2", label: "Threshold on reconstruction error fitted to a held-out normal set", status: "todo", note: "", inferred: false },
        { id: "p3-3", label: "Implement score fusion into a composite anomaly score", status: "todo", note: "", inferred: false },
        { id: "p3-4", label: "Calibrate the tier cutoffs against the fused score", status: "todo", note: "", inferred: false },
        { id: "p3-5", label: "Reconcile the numeric tiers with the rule engine categorical tiers", status: "todo", note: "Conflict I am flagging, not one the repo states: enforce_policy returns a categorical status, while the design doc defines WARN / ALERT / CONTAIN as cutoffs on a continuous score. Something has to give or the same tier name means two things.", inferred: true },
        { id: "p3-6", label: "Build a per-layer ablation harness so each layer contribution is measurable", status: "todo", note: "", inferred: false },
      ],
    },
    {
      id: "P4",
      name: "Policy Engine",
      blurb: "policy.yaml plus enforcement done. Linter not started.",
      deps: ["P1"],
      tasks: [
        { id: "p4-1", label: "Declare per-agent tools, schemas, payment limits, rate caps and hours in YAML", status: "done", note: "", inferred: false },
        { id: "p4-2", label: "Load the policy file as the enforcement source at monitor construction", status: "done", note: "", inferred: false },
        { id: "p4-3", label: "Migrate the enforcement hardcoded in mock_tools into the policy file", status: "todo", note: "Shell whitelist, network pattern block and path-traversal guards. Discrepancy worth recording: the policy file already declares shell_whitelist for devops_agent, but no rule in the rule engine ever reads it, so that key is currently decorative.", inferred: false },
        { id: "p4-4", label: "Build the policy linter for dead rules, conflicts, escalation paths and schema", status: "todo", note: "", inferred: false },
        { id: "p4-5", label: "Reconcile the live policy file against the design doc policy schema", status: "todo", note: "The live file adds privilege_level per agent; the documented schema omits it. RB-006 reads that key, so the doc is the one that is wrong.", inferred: false },
        { id: "p4-6", label: "Enforce can_delegate_to as a rule in the rule engine", status: "todo", note: "Split from the old combined task, because half of it turned out to be done. Still open: can_delegate_to is declared for all four agents in policy.yaml and read by nothing, and delegation_source is logged but never checked. This wants to be an actual RB rule so that a refused delegation produces a finding and a record, rather than being silently clamped.", inferred: false },
        { id: "p4-7", label: "Cap delegation depth", status: "done", note: "Other half of the old p4-6. Correction to an earlier version of this note, which put the constant in the wrong file: MAX_DELEGATION_DEPTH is defined in graph.py, defaults to 3 and is overridable by an env var of the same name. graph.py pushes it into the context as max_delegation_depth, both planners in agent_runtime.py check it before proposing a delegation, and graph.py re-checks it while routing. Caveat unchanged and worth keeping in view: the cap lives in the graph and the planner, not in policy.yaml and not in the rule engine, so exceeding it produces no finding and no ToolCallRecord. The monitor cannot see it happen. Note that README.md still lists delegation depth as uncapped, which is wrong.", inferred: false },
      ],
    },
    {
      id: "P5",
      name: "Scenario Suite",
      blurb: "Framework and runner done. Coverage is the gap.",
      deps: ["P4"],
      tasks: [
        { id: "p5-1", label: "Build the scenario base class, action record and result record", status: "done", note: "", inferred: false },
        { id: "p5-2", label: "Run the whole suite and print a per-scenario verdict table", status: "done", note: "", inferred: false },
        { id: "p5-3", label: "Add an end-to-end path that runs through the real graph and LLM", status: "todo", note: "Confirmed in the code comments: scenarios target the detection engine directly and never touch the orchestrator. Prompt-injection results scored only against the contains_instruction_pattern regex are not defensible. Now the critical path rather than one item among eight. Three separate things are already built and waiting on it: the ground-truth label plumbing reads a contextvar guarded_tool_call already honours, the no-monitor baseline in p7-5 cannot measure anything until the LLM is back in the path, and RB-005 needs to be scored against something other than the regex that defines it. Nothing downstream of this produces a defensible number until it lands.", inferred: false, pinned: true },
        { id: "p5-4", label: "Wire the attack label into the end-to-end path, or delete the module", status: "done", note: "Kept, not deleted. attack_context now exposes an attack_label context manager that resets via contextvar tokens instead of clearing to the default, and base_attack.run wraps the whole execution in it and reads the label back out for the record. Today only enforce_policy is inside that scope, but guarded_tool_call already reads the same contextvar, so when p5-3 routes scenarios through the real graph the labelling needs no further wiring. Covered by tests/test_enforcement_gate.py.", inferred: false },
        { id: "p5-5", label: "Stop deriving the ground-truth label from the expectation flag", status: "done", note: "is_attack and expect_detected are now separate fields, declared explicitly on every scenario, and a test fails if either is left to inherit. Metrics and the JSONL record both partition on is_attack. The output is unchanged today, exactly as predicted, because the two agreed. What changed is that a missed attack is now expressible: tests/test_ground_truth.py builds one and asserts that partitioning on the expectation instead would report 100 percent where the truth is 50.", inferred: true },
        { id: "p5-6", label: "Reconcile rule ids between the rule engine and the design doc", status: "todo", note: "Code has RB-000 rogue identity and defines RB-002 as tool whitelist. The doc has no RB-000 and defines RB-002 as shell exec with network reach. Confirmed on both sides.", inferred: false },
        { id: "p5-7", label: "Reconcile OWASP tags between the scenario classes and the design doc", status: "todo", note: "Discrepancy found while reading, not in the seed: the code tags D-001 as ASI02, the doc maps D-001 to ASI05 Unexpected Code Execution. F-002 is ASI10 in code but listed under both ASI07 and ASI10 in the doc.", inferred: false },
        { id: "p5-8", label: "Split the scenario file into a package, one file per OWASP category", status: "todo", note: "", inferred: false },
      ],
    },
    {
      id: "P6",
      name: "Semantic Layer",
      blurb: "LLM-based fourth layer, ablation study",
      deps: ["P3"],
      tasks: [
        { id: "p6-1", label: "Build the semantic layer as an LLM-as-judge over the raw tool arguments", status: "todo", note: "The record already keeps args_raw unredacted specifically for this layer.", inferred: false },
        { id: "p6-2", label: "Design the judge prompt and pin its output contract", status: "todo", note: "", inferred: false },
        { id: "p6-3", label: "Run the ablation study with and without the semantic layer", status: "todo", note: "", inferred: false },
        { id: "p6-4", label: "Measure semantic layer latency and cost per tool call", status: "todo", note: "", inferred: false },
        { id: "p6-5", label: "Harden the judge against being prompt injected by the text it is judging", status: "todo", note: "My addition. The layer reads attacker-controlled argument text, so it is itself an injection target and the thesis will get asked about it.", inferred: true },
      ],
    },
    {
      id: "P7",
      name: "Comparative Evaluation",
      blurb: "Core metrics exist in the runner. Adapters and baseline missing.",
      deps: ["P5"],
      tasks: [
        { id: "p7-1", label: "Compute detection rate, false positive rate and OWASP tag accuracy", status: "done", note: "All three confirmed in the runner, with per-scenario table output.", inferred: false },
        { id: "p7-2", label: "Break coverage down per OWASP category across attack scenarios", status: "done", note: "", inferred: false },
        { id: "p7-3", label: "Extract the inline metrics from the runner into an evaluation module", status: "todo", note: "", inferred: false },
        { id: "p7-4", label: "Add precision, recall and F1 alongside detection rate", status: "todo", note: "None of the three exist today. With 6 attacks and 2 benign controls the denominators are too small to report anyway.", inferred: false },
        { id: "p7-5", label: "Run a no-monitor baseline to measure marginal detection contribution", status: "blocked", note: "Harness built and running: red_team/baseline.py runs the suite twice, control against a NullMonitor and treatment against the real one, and prints both columns with the delta. run_suite now takes an injected monitor, and the control run is not logged so it cannot contaminate the training corpus. Blocked, not done, and this is the finding: the measured baseline is 0.0 percent, but that is a property of the harness rather than a result. Scenarios call enforce_policy directly and never touch the orchestrator, so with the rule engine disabled nothing in the path can refuse anything, and the delta is just the detection rate restated. Quoting it as a 100 percent marginal contribution would be circular. It becomes a real experiment the moment p5-3 puts the LLM back in the path, which is why this now depends on p5-3. The module prints that caveat itself so the number cannot be lifted out of context.", inferred: false },
        { id: "p7-6", label: "Build the AgentDojo adapter", status: "todo", note: "", inferred: false },
        { id: "p7-7", label: "Build the Agent Security Bench adapter", status: "todo", note: "", inferred: false },
        { id: "p7-8", label: "Run Promptfoo and DeepTeam over the same scenarios and build the comparison matrix", status: "todo", note: "", inferred: false },
      ],
    },
    {
      id: "P8",
      name: "Adaptive Rounds",
      blurb: "3-round adaptive attacker protocol, ADR metric",
      deps: ["P7"],
      tasks: [
        { id: "p8-1", label: "Implement the three-round adaptive rounds protocol", status: "todo", note: "", inferred: false },
        { id: "p8-2", label: "Feed each round detection verdicts back into the next attacker round", status: "todo", note: "", inferred: false },
        { id: "p8-3", label: "Define and compute ADR", status: "todo", note: "", inferred: false },
        { id: "p8-4", label: "Freeze the defence across rounds so the delta is attributable", status: "todo", note: "", inferred: false },
        { id: "p8-5", label: "Cap and log attacker token spend per round", status: "todo", note: "My addition. An adaptive attacker loop is the single easiest way to burn the API budget by accident.", inferred: true },
      ],
    },
    {
      id: "P9",
      name: "Results and Repro",
      blurb: "eval tables, figures, seed-locked repro scripts",
      deps: ["P8"],
      tasks: [
        { id: "p9-1", label: "Add a test suite with coverage on the rule engine and the enforcement gate", status: "done", note: "57 tests in tests/, run with pytest -q. Pass case and trip case for every rule RB-000 to RB-006, plus boundary cases that aggregate metrics would hide: the RB-003 limit is inclusive, the RB-006 hour window is half-open, and the RB-004 per-tool cap must beat the per-agent fallback. Gate tests assert the contract that matters most, exactly one record per call whether passed or blocked, and that a CONTAIN really does stop the tool running. Rules are tested against a fixture policy rather than the live policy.yaml, so tuning payment limits while calibrating FPR cannot silently weaken a test. Checked by mutation rather than assumed: seven deliberate breaks to security_monitor.py, including the RB-003 boundary flip and inverting RB-005, were all caught. pytest 9.1.1 pinned in requirements.txt.", inferred: false },
        { id: "p9-2", label: "Write seed-locked repro scripts so every number regenerates from a clean checkout", status: "todo", note: "", inferred: false },
        { id: "p9-3", label: "Pin dependency versions and record the model id used for each run", status: "todo", note: "The model id is read from an env var with a default, so a run is not currently self-describing.", inferred: false },
        { id: "p9-4", label: "Generate the eval tables from the JSONL corpus rather than by hand", status: "todo", note: "", inferred: false },
        { id: "p9-5", label: "Generate the ROC curve and a confusion matrix per attack family", status: "todo", note: "", inferred: false },
        { id: "p9-6", label: "Freeze a corpus snapshot next to the published results", status: "todo", note: "My addition. Results that cite a log file which keeps getting appended to are not reproducible.", inferred: true },
      ],
    },
  ],

  counters: [
    { id: "cat-a", code: "A", label: "ASI01 Agent Goal Hijack", done: 1, target: 5, gap: false },
    { id: "cat-b", code: "B", label: "ASI03 Identity and Privilege Abuse", done: 1, target: 5, gap: false },
    { id: "cat-c", code: "C", label: "ASI03 / ASI02 combined outcomes", done: 0, target: 5, gap: false },
    { id: "cat-d", code: "D", label: "ASI02 Tool Misuse and Exploitation", done: 3, target: 5, gap: false },
    { id: "cat-e", code: "E", label: "ASI06 Memory and Context Poisoning", done: 0, target: 4, gap: false },
    { id: "cat-f", code: "F", label: "ASI04 Supply Chain / ASI10 Rogue Agents", done: 1, target: 4, gap: false },
    { id: "cat-n", code: "N", label: "Benign controls, false positive baseline", done: 2, target: null, gap: false },
    { id: "cat-g8", code: "—", label: "ASI08 Cascading Agent Failures", done: 0, target: 1, gap: true },
    { id: "cat-g9", code: "—", label: "ASI09 Human-Agent Trust Exploitation", done: 0, target: 1, gap: true },
  ],

  hygiene: [
    { id: "kb-1", label: "Refresh the stale health note on the knowledge base", status: "todo", note: "Confirmed stale. The note still lists the Isolation Forest and LSTM autoencoder citations as unverified. The lit review has already verified both: Liu, Ting and Zhou 2008 ICDM, and Malhotra et al. 2016 arXiv:1607.00148 with the year corrected from 2015.", inferred: false },
    { id: "kb-2", label: "Rewrite the model stack sections to the decided stack", status: "todo", note: "Worse than the seed said. The doc still lists Claude Haiku for triage, Claude Sonnet for orchestration and semantic, and Gemini 3.5 Flash as red team. Decided stack: GPT-5.6 Sol attacks, Gemini 3 Flash orchestrates and runs semantic, Gemini 3.1 Flash-Lite triages, Claude Code is development tooling only. The code already runs Flash-Lite.", inferred: false },
    { id: "kb-3", label: "Redraw the architecture diagram to match the decided stack", status: "todo", note: "Still shows Claude Sonnet as orchestrator and Claude Haiku as triage.", inferred: false },
    { id: "kb-4", label: "Delete the jailbreak-resistance justification and replace it", status: "todo", note: "Confirmed present, phrased as alignment-trained and less susceptible to jailbreak. Replace with vendor separation, cost, and a measured baseline.", inferred: false },
    { id: "kb-5", label: "Enable Gemini API billing", status: "todo", note: "Free tier throttles to 5-15 requests per minute, which makes any real run useless, and free-tier data may be trained on.", inferred: false },
    { id: "kb-6", label: "Run the adversarial generator capability spike before scaling the suite", status: "todo", note: "", inferred: false },
    { id: "kb-7", label: "Verify that AgentLAB exists or re-anchor the semantic layer to a real source", status: "todo", note: "Did not surface anywhere in the indexed project knowledge. Treat as unverified until you find the primary source.", inferred: false },
    { id: "kb-8", label: "Cross-check every AML.T identifier against the live MITRE ATLAS matrix", status: "todo", note: "The code records tactic level only and says so explicitly, which is the correct conservative choice. The doc is where the loose technique ids live, including one row that already carries a confirm-the-name warning.", inferred: false },
    { id: "kb-9", label: "Verify the ATLAS tactic and technique counts before quoting them", status: "todo", note: "Two documents in the project both quote roughly 16 tactics and 84 techniques. They agree with each other, which is not the same as being right.", inferred: false },
    { id: "kb-10", label: "Re-pull live pricing from all three providers before any cost figure ships", status: "todo", note: "", inferred: false },
    { id: "kb-11", label: "Keep the standalone HTML tracker generated from the JSX, never hand-edited", status: "done", note: "There were two copies of this board: this file, and 'build tracker.html', which embeds the same app inside a script type=text/babel block with React, Babel and Tailwind inlined so it runs offline. They were maintained by hand in parallel, which is the same failure as the old graph.py fork that p0-2 fixed. build_tracker_html.py now generates the HTML from this file and takes --check for CI. It was validated by regenerating the pre-existing HTML from the pre-existing JSX and confirming a byte-for-byte match before any new content went in. tests/test_tracker_sync.py fails if the two drift in either direction, and was itself checked by editing each side in turn and confirming it caught both.", inferred: false },
  ],

  collapsed: { P0: true, P1: true },
  unlocked: [],
  cleared: [],
};

/* ============================================================================
   GLOSSARY — one plain sentence per term. Hand-editable.
   ==========================================================================*/

const GLOSSARY = {
  LangGraph: "A framework for building LLM applications as an explicit graph of nodes and edges, so control flow is something you declare rather than something that emerges from prompting.",
  orchestrator: "The node that reads an incoming request and decides which specialist agent should handle it.",
  "conditional edge": "A graph edge whose destination is chosen at runtime by a function, which is how the orchestrator routes to one agent instead of another.",
  checkpointer: "A storage backend that saves graph state after each step, so a session can be paused, resumed, or replayed instead of starting over.",
  "enforcement gate": "The wrapper that every tool call must pass through, where the policy check happens before the tool actually runs.",
  "choke point": "A deliberate single place in the code that all of a certain kind of traffic must pass through, which is what makes it auditable.",
  "Isolation Forest": "An unsupervised anomaly detector that isolates unusual points by random splitting, on the logic that weird points get separated from the rest in fewer cuts.",
  "LSTM autoencoder": "A neural network that compresses a sequence and then tries to rebuild it, trained only on normal sequences so it fails loudly on abnormal ones.",
  "reconstruction error": "The gap between what an autoencoder was given and what it managed to rebuild, used as the anomaly signal.",
  "score fusion": "Combining the outputs of several detectors into one number, usually as a weighted sum.",
  "composite anomaly score": "The single fused number that the statistical, sequential, rule and semantic layers all feed into.",
  "WARN / ALERT / CONTAIN": "The three escalating verdicts above PASS: log it, log and throttle it, or block the call outright.",
  "false positive rate": "The share of legitimate operations that the monitor wrongly flags as attacks.",
  "detection rate": "The share of actual attacks that the monitor correctly flags.",
  precision: "Of everything the monitor flagged, the share that really was an attack.",
  recall: "Of all the attacks that happened, the share the monitor caught. Same quantity as detection rate, different name by convention.",
  F1: "The harmonic mean of precision and recall, used when you want one number that punishes being bad at either.",
  "behavioural baselining": "Learning what an agent normally does so that departures from that pattern can be measured rather than guessed at.",
  "feature vector": "The fixed list of numbers extracted from one event that a detector actually consumes.",
  "YAML policy engine": "A system where the security rules live in a readable configuration file rather than in code, so they can be audited without reading Python.",
  "policy linter": "A checker that reads the policy file and reports rules that can never fire, rules that contradict each other, and paths that grant more privilege than intended.",
  "least privilege": "Giving each agent only the tools, data and limits it needs for its own job and nothing more.",
  "delegation depth": "How many hops a task has travelled from agent to agent, capped so a request cannot be laundered through a chain into higher privilege.",
  "human-in-the-loop": "A design where certain actions stop and wait for a person to approve them before proceeding.",
  "supervisor gating": "The specific human-in-the-loop step where a risky action is escalated to a person instead of executed.",
  "prompt injection": "Text that is supposed to be data but gets read as instructions. Direct injection comes from the user, indirect injection comes from content the agent fetched, such as a document or an email.",
  "indirect prompt injection": "Prompt injection delivered through content the agent retrieved rather than typed by the user, which is the harder case because the attack surface scales with everything the agent reads.",
  "schema hopping": "An agent reaching into a database schema outside its own whitelist, such as HR querying finance.",
  "OWASP Top 10 for Agentic Applications": "The 2026 industry list of the ten most significant security risks specific to autonomous agent systems, coded ASI01 through ASI10.",
  ASI01: "Agent Goal Hijack. The agent gets redirected away from the objective it was given.",
  ASI02: "Tool Misuse and Exploitation. The agent uses a tool it has access to in a way it should not.",
  ASI03: "Identity and Privilege Abuse. The agent acts with authority it was never granted.",
  ASI04: "Agentic Supply Chain Vulnerabilities. Risk arriving through third-party tools, plugins or servers the agent trusts.",
  ASI05: "Unexpected Code Execution. The agent runs code or commands that were never meant to run.",
  ASI06: "Memory and Context Poisoning. Bad content is planted in the agent's memory or retrieval store so it corrupts later decisions.",
  ASI07: "Insecure Inter-Agent Communication. Messages between agents are unauthenticated or tamperable.",
  ASI08: "Cascading Agent Failures. One agent's bad output becomes another agent's trusted input, and the error propagates.",
  ASI09: "Human-Agent Trust Exploitation. The agent's credibility with a person is used to make the person do something harmful.",
  ASI10: "Rogue Agents. An unregistered or compromised agent operating inside the system.",
  "MITRE ATLAS": "A public knowledge base of real-world adversary behaviour against AI systems, structured like MITRE ATT&CK.",
  "tactic versus technique": "A tactic is what the adversary is trying to achieve, such as privilege escalation. A technique is the specific method used to get there. Tactics are hard to get wrong, technique ids are easy to get wrong.",
  "AML.T identifier": "The identifier format for a MITRE ATLAS technique. Never cite one from memory, because the matrix changes and wrong ids are the classic way to lose credibility in a write-up.",
  AgentDojo: "An external benchmark for evaluating whether agents can be steered off task by injected instructions while still doing real work.",
  "Agent Security Bench": "An external benchmark suite for agent attacks and defences, used here as an outside anchor so results are not self-graded.",
  Promptfoo: "An open-source red-teaming and evaluation tool for LLM applications, used here as a comparison system.",
  DeepTeam: "An open-source red-teaming framework with a MITRE ATLAS module, used here as the second comparison system.",
  "ablation study": "Turning one component off and re-running everything, to find out how much that component was actually contributing.",
  "adaptive rounds": "A protocol where the attacker sees whether it was caught and revises its approach for the next round, instead of firing the same fixed attacks forever.",
  ADR: "Adaptive Degradation Rate. How much detection performance drops once the attacker has been allowed to learn from the defence.",
  "LLM-as-judge": "Using a language model to grade or classify something, here to decide whether a tool call looks malicious in context.",
  "red team": "The side building and running attacks.",
  "blue team": "The side building and running the defence. Keeping these on different vendors' models avoids a system quietly grading its own homework.",
  "benign control": "A completely legitimate operation deliberately included in the test suite, so that flagging it counts as a measurable false positive.",
  "ground-truth label": "The recorded fact of whether an event really was an attack, independent of what the monitor said about it.",
  "no-monitor baseline": "The same attack suite run with the monitor switched off, which tells you what the base model refuses on its own.",
  "marginal detection contribution": "How much detection the monitor adds over that no-monitor baseline. This is the only number that actually belongs to the monitor.",
  ToolCallRecord: "The structured record emitted for every tool call, passed or blocked, which forms the corpus every detection layer is trained and evaluated on.",
  JSONL: "A file format with one complete JSON object per line, which makes an append-only log both streamable and trivially parseable.",
  "rule engine": "The deterministic layer that checks a request against explicit written rules and returns a verdict with no ambiguity and no model call.",
  "sliding window": "A fixed-length span of consecutive events that moves forward one step at a time, which is how sequence models see a stream.",
  "confusion matrix": "The four-cell table of caught, missed, wrongly flagged and correctly ignored, from which most other metrics are derived.",
  "ROC curve": "A plot of detection rate against false positive rate across every possible threshold, used to compare detectors without picking a threshold first.",
  "seed-locked": "Every random choice fixed to a recorded seed, so re-running the experiment reproduces the same numbers rather than similar ones.",
};

/* ============================================================================
   Helpers
   ==========================================================================*/

const STATUS_ORDER = ["todo", "active", "blocked", "done"];

const STATUS_META = {
  todo: { label: "TODO", dot: "bg-neutral-600", text: "text-neutral-400", ring: "border-neutral-700" },
  active: { label: "ACTIVE", dot: "bg-cyan-400", text: "text-cyan-300", ring: "border-cyan-700" },
  blocked: { label: "BLOCKED", dot: "bg-red-500", text: "text-red-300", ring: "border-red-800" },
  done: { label: "DONE", dot: "bg-emerald-500", text: "text-emerald-300", ring: "border-emerald-800" },
};

const escapeRx = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const TERM_RX = new RegExp(
  "(?<![A-Za-z0-9])(" +
    Object.keys(GLOSSARY)
      .sort((a, b) => b.length - a.length)
      .map(escapeRx)
      .join("|") +
    ")(?![A-Za-z0-9])",
  "gi"
);

const TERM_LOOKUP = Object.keys(GLOSSARY).reduce((acc, k) => {
  acc[k.toLowerCase()] = k;
  return acc;
}, {});

const uid = () => "u" + Math.random().toString(36).slice(2, 9);

const STORAGE_KEY = "fyp_tracker_state";

/* Merge one task list.

   Precedence, and the reasoning, because this is the one decision in the file that
   can lose work: the seed wins on label, inferred AND status. The stored board wins
   on note. A seedVersion bump is a deliberate act by the same person who clicks the
   status dots, and the usual reason to bump is that a status in the seed was wrong,
   so a merge that preserved stored status would refuse to deliver the correction it
   was written for. Notes are the expensive artifact, they are typed prose that exists
   nowhere else, so they are never overwritten.

   The cost: a status you cycled in the UI since the last bump is reverted to whatever
   the seed says. Keep the seed honest and bump deliberately. Tasks you added in the UI
   have uid ids the seed will never contain, so they survive untouched at the tail. */
const mergeTasks = (seedTasks, storedTasks) => {
  const stored = new Map((storedTasks || []).map((t) => [t.id, t]));
  const merged = seedTasks.map((s) => {
    const prev = stored.get(s.id);
    stored.delete(s.id);
    // No stored counterpart means this task is new in the seed. Take it whole.
    if (!prev) return { ...s };
    // Keep a note the seed does not supply. If both have one, the seed's is the
    // considered version, so it wins and the typed one is appended rather than lost.
    let note = s.note;
    if (prev.note && prev.note !== s.note) note = s.note ? s.note + "\n\n---\n" + prev.note : prev.note;
    return { ...s, note };
  });
  // Whatever is left in `stored` was added in the UI. Keep it, at the end.
  return merged.concat(Array.from(stored.values()));
};

/* Reconcile a stored board against the seed. Only runs when seedVersion moved,
   so the normal path stays a plain read. */
const mergeBoard = (seed, stored) => {
  const storedPhases = new Map((stored.phases || []).map((p) => [p.id, p]));
  const phases = seed.phases.map((sp) => {
    const prev = storedPhases.get(sp.id);
    storedPhases.delete(sp.id);
    return { ...sp, tasks: mergeTasks(sp.tasks, prev ? prev.tasks : []) };
  });
  phases.push(...Array.from(storedPhases.values()));

  const storedCounters = new Map((stored.counters || []).map((c) => [c.id, c]));
  const counters = seed.counters.map((sc) => {
    const prev = storedCounters.get(sc.id);
    storedCounters.delete(sc.id);
    // Counters are hand-tallied, so the stored numbers are the real ones.
    if (!prev) return { ...sc };
    return { ...sc, done: prev.done, target: prev.target };
  });
  counters.push(...Array.from(storedCounters.values()));

  const hygiene = mergeTasks(seed.hygiene, stored.hygiene);

  // Drop cleared entries whose task no longer exists, and refresh the rest so a
  // relabelled task does not show its old wording in the cleared panel.
  const labels = new Map();
  phases.forEach((p) => p.tasks.forEach((t) => labels.set(t.id, t.label)));
  hygiene.forEach((t) => labels.set(t.id, t.label));
  const cleared = (stored.cleared || [])
    .filter((c) => labels.has(c.id))
    .map((c) => ({ id: c.id, label: labels.get(c.id) }));

  return {
    seedVersion: seed.seedVersion,
    phases,
    counters,
    hygiene,
    collapsed: stored.collapsed || seed.collapsed,
    unlocked: stored.unlocked || [],
    cleared,
  };
};

/* ============================================================================
   Component
   ==========================================================================*/

export default function FypBuildTracker() {
  const [board, setBoard] = useState(null);
  const [hydrated, setHydrated] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [popover, setPopover] = useState(null); // { key, anchor }
  const [openNote, setOpenNote] = useState(null);
  const [editing, setEditing] = useState(null); // { id, value }
  const [drafts, setDrafts] = useState({});
  const [drawer, setDrawer] = useState(false);
  const [drawerQuery, setDrawerQuery] = useState("");
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [confirmReset, setConfirmReset] = useState(false);
  const [toast, setToast] = useState("");
  const rootRef = useRef(null);

  /* ---- hydrate ---- */
  useEffect(() => {
    let alive = true;
    (async () => {
      let next = null;
      try {
        // window.storage only exists in the Claude artifact host. Anywhere else this
        // throws, the board falls back to the seed, and the persist effect below will
        // surface loadError. The board is then ephemeral for that session.
        const res = await window.storage.get(STORAGE_KEY);
        if (res && res.value) next = JSON.parse(res.value);
      } catch (err) {
        // Reading a key that was never written also throws. That is the first-run path.
        next = null;
      }
      if (!alive) return;
      if (!next || !next.phases) {
        setBoard(structuredClone(SEED_DATA));
      } else if (next.seedVersion !== SEED_DATA.seedVersion) {
        // Seed moved under a live board. Merge instead of discarding either side.
        setBoard(mergeBoard(SEED_DATA, next));
      } else {
        setBoard(next);
      }
      setHydrated(true);
    })();
    return () => {
      alive = false;
    };
  }, []);

  /* ---- persist whole board under one key ---- */
  useEffect(() => {
    if (!hydrated || !board) return;
    (async () => {
      try {
        const res = await window.storage.set(STORAGE_KEY, JSON.stringify(board));
        if (!res) setLoadError("Board did not save. Export a copy before you close this.");
        else setLoadError("");
      } catch (err) {
        setLoadError("Board did not save. Export a copy before you close this.");
      }
    })();
  }, [board, hydrated]);

  /* ---- close popover on outside click ---- */
  useEffect(() => {
    const onDown = (e) => {
      if (!e.target.closest || !e.target.closest("[data-pop]")) setPopover(null);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, []);

  const flash = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(""), 2200);
  };

  /* ---- derived ---- */
  const stats = useMemo(() => {
    if (!board) return { done: 0, total: 0, pct: 0 };
    let done = 0;
    let total = 0;
    board.phases.forEach((p) =>
      p.tasks.forEach((t) => {
        total += 1;
        if (t.status === "done") done += 1;
      })
    );
    return { done, total, pct: total ? Math.round((done / total) * 100) : 0 };
  }, [board]);

  const phaseStat = (p) => {
    const total = p.tasks.length;
    const done = p.tasks.filter((t) => t.status === "done").length;
    return { done, total, pct: total ? Math.round((done / total) * 100) : 0 };
  };

  const focusPhaseId = useMemo(() => {
    if (!board) return null;
    const partial = board.phases.find((p) => {
      const s = phaseStat(p);
      return s.done > 0 && s.done < s.total;
    });
    return partial ? partial.id : null;
  }, [board]);

  const isLocked = (p) => {
    if (!board) return false;
    if (board.unlocked.includes(p.id)) return false;
    if (p.tasks.some((t) => t.status === "done")) return false;
    return p.deps.some((d) => {
      const dep = board.phases.find((x) => x.id === d);
      if (!dep) return false;
      const s = phaseStat(dep);
      return s.done < s.total;
    });
  };

  /* Pinned tasks jump the queue from anywhere on the board.
     Needed because phase order is not the same as build order. The dependency graph
     says P2 is next, but the tasks that actually gate everything downstream sit in P5,
     P7 and P9: if ground truth and the no-monitor baseline are wrong, every number a
     later phase produces has to be regenerated. Without a pin there is no way to say
     that on a board whose focus is "first partially complete phase". */
  const nextActions = useMemo(() => {
    if (!board) return [];
    const out = [];
    const seen = new Set();
    const push = (p, t) => {
      if (seen.has(t.id) || t.status === "done" || t.status === "blocked") return;
      seen.add(t.id);
      out.push({ phase: p.id, task: t });
    };

    board.phases.forEach((p) => p.tasks.forEach((t) => t.pinned && push(p, t)));

    if (focusPhaseId) {
      const idx = board.phases.findIndex((p) => p.id === focusPhaseId);
      const pool = [board.phases[idx], board.phases[idx + 1]].filter(Boolean);
      ["active", "todo"].forEach((st) =>
        pool.forEach((p) => p.tasks.forEach((t) => t.status === st && push(p, t)))
      );
    }
    return out.slice(0, 3);
  }, [board, focusPhaseId]);

  /* ---- mutations ---- */
  const mutate = (fn) => setBoard((b) => (b ? fn(structuredClone(b)) : b));

  const cycleStatus = (listKey, phaseId, taskId) =>
    mutate((b) => {
      const list = listKey === "hygiene" ? b.hygiene : b.phases.find((p) => p.id === phaseId).tasks;
      const t = list.find((x) => x.id === taskId);
      const next = STATUS_ORDER[(STATUS_ORDER.indexOf(t.status) + 1) % STATUS_ORDER.length];
      t.status = next;
      if (next === "done") {
        b.cleared = [{ id: t.id, label: t.label }, ...b.cleared.filter((c) => c.id !== t.id)].slice(0, 5);
      } else {
        b.cleared = b.cleared.filter((c) => c.id !== t.id);
      }
      return b;
    });

  const setNote = (listKey, phaseId, taskId, value) =>
    mutate((b) => {
      const list = listKey === "hygiene" ? b.hygiene : b.phases.find((p) => p.id === phaseId).tasks;
      list.find((x) => x.id === taskId).note = value;
      return b;
    });

  const renameTask = (listKey, phaseId, taskId, value) =>
    mutate((b) => {
      const list = listKey === "hygiene" ? b.hygiene : b.phases.find((p) => p.id === phaseId).tasks;
      list.find((x) => x.id === taskId).label = value;
      return b;
    });

  const deleteTask = (listKey, phaseId, taskId) =>
    mutate((b) => {
      if (listKey === "hygiene") b.hygiene = b.hygiene.filter((x) => x.id !== taskId);
      else {
        const p = b.phases.find((q) => q.id === phaseId);
        p.tasks = p.tasks.filter((x) => x.id !== taskId);
      }
      b.cleared = b.cleared.filter((c) => c.id !== taskId);
      return b;
    });

  const addTask = (listKey, phaseId) => {
    const key = listKey === "hygiene" ? "hygiene" : phaseId;
    const text = (drafts[key] || "").trim();
    if (!text) return;
    mutate((b) => {
      const item = { id: uid(), label: text, status: "todo", note: "", inferred: false };
      if (listKey === "hygiene") b.hygiene.push(item);
      else b.phases.find((p) => p.id === phaseId).tasks.push(item);
      return b;
    });
    setDrafts((d) => ({ ...d, [key]: "" }));
  };

  const toggleCollapse = (id) =>
    mutate((b) => {
      b.collapsed = { ...b.collapsed, [id]: !b.collapsed[id] };
      return b;
    });

  const unlockPhase = (id) =>
    mutate((b) => {
      if (!b.unlocked.includes(id)) b.unlocked.push(id);
      return b;
    });

  const bumpCounter = (id, field, delta) =>
    mutate((b) => {
      const c = b.counters.find((x) => x.id === id);
      if (field === "target" && c.target === null) c.target = Math.max(0, delta);
      else c[field] = Math.max(0, (c[field] || 0) + delta);
      return b;
    });

  const exportBoard = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(board, null, 2));
      flash("Board copied to clipboard as JSON.");
    } catch (err) {
      setImportText(JSON.stringify(board, null, 2));
      setImportOpen(true);
      flash("Clipboard blocked. The JSON is in the box below, copy it from there.");
    }
  };

  const importBoard = () => {
    try {
      const parsed = JSON.parse(importText);
      if (!parsed || !Array.isArray(parsed.phases)) throw new Error("no phases");
      setBoard(parsed);
      setImportOpen(false);
      setImportText("");
      flash("Board replaced from pasted JSON.");
    } catch (err) {
      flash("That is not a valid board. Paste the full JSON including the phases array.");
    }
  };

  /* ---- label rendering with glossary terms ---- */
  const renderLabel = (text, scopeId) => {
    const parts = [];
    let last = 0;
    let m;
    TERM_RX.lastIndex = 0;
    while ((m = TERM_RX.exec(text)) !== null) {
      if (m.index > last) parts.push(text.slice(last, m.index));
      const canonical = TERM_LOOKUP[m[0].toLowerCase()];
      const popKey = scopeId + "::" + m.index;
      parts.push(
        <span key={popKey} className="relative inline-block" data-pop>
          <button
            onClick={() => setPopover(popover && popover.key === popKey ? null : { key: popKey, term: canonical })}
            className="border-b border-dotted border-cyan-500 text-neutral-100 hover:text-cyan-300"
          >
            {m[0]}
          </button>
          {popover && popover.key === popKey ? (
            <span className="absolute left-0 top-6 z-30 block w-72 rounded border border-cyan-800 bg-neutral-900 p-3 shadow-lg">
              <span className="mb-1 block font-mono text-xs uppercase tracking-wide text-cyan-400">{canonical}</span>
              <span className="block text-xs leading-relaxed text-neutral-300">{GLOSSARY[canonical]}</span>
            </span>
          ) : null}
        </span>
      );
      last = m.index + m[0].length;
    }
    if (last < text.length) parts.push(text.slice(last));
    return parts;
  };

  /* ---- task row ---- */
  const renderTask = (t, listKey, phaseId, accent) => {
    const meta = STATUS_META[t.status];
    const isEditing = editing && editing.id === t.id;
    const noteOpen = openNote === t.id;
    return (
      <div
        key={t.id}
        className={
          "group rounded border px-3 py-2 transition-colors " +
          (t.inferred ? "border-dashed " : "border-solid ") +
          (t.status === "done" ? "border-neutral-800 bg-neutral-900" : "border-neutral-800 bg-neutral-900")
        }
      >
        <div className="flex items-start gap-3">
          <button
            onClick={() => cycleStatus(listKey, phaseId, t.id)}
            className={"mt-1 h-3 w-3 shrink-0 rounded-full " + meta.dot}
            title="Cycle status"
          />
          <div className="min-w-0 flex-1">
            {isEditing ? (
              <div className="flex gap-2">
                <input
                  value={editing.value}
                  onChange={(e) => setEditing({ id: t.id, value: e.target.value })}
                  className="w-full rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-sm text-neutral-100"
                />
                <button
                  onClick={() => {
                    renameTask(listKey, phaseId, t.id, editing.value.trim() || t.label);
                    setEditing(null);
                  }}
                  className="rounded border border-cyan-800 px-2 text-xs text-cyan-300"
                >
                  Save
                </button>
                <button onClick={() => setEditing(null)} className="rounded border border-neutral-700 px-2 text-xs text-neutral-400">
                  Cancel
                </button>
              </div>
            ) : (
              <p
                className={
                  "text-sm leading-relaxed " +
                  (t.status === "done" ? "text-neutral-500 line-through" : "text-neutral-200")
                }
              >
                {renderLabel(t.label, t.id)}
              </p>
            )}
            <div className="mt-1 flex flex-wrap items-center gap-3">
              <span className={"font-mono text-xs " + meta.text}>{meta.label}</span>
              {t.pinned ? <span className="font-mono text-xs text-amber-400">pinned, blocks later phases</span> : null}
              {t.inferred ? <span className="font-mono text-xs text-violet-400">inferred, check this</span> : null}
              <button
                onClick={() => setOpenNote(noteOpen ? null : t.id)}
                className={"font-mono text-xs hover:text-neutral-200 " + (t.note ? "text-" + accent + "-400" : "text-neutral-600")}
              >
                {noteOpen ? "hide note" : t.note ? "note" : "+ note"}
              </button>
              <span className="ml-auto hidden gap-2 group-hover:flex">
                <button onClick={() => setEditing({ id: t.id, value: t.label })} className="text-neutral-600 hover:text-neutral-300">
                  <Pencil className="h-3 w-3" />
                </button>
                <button onClick={() => deleteTask(listKey, phaseId, t.id)} className="text-neutral-600 hover:text-red-400">
                  <Trash2 className="h-3 w-3" />
                </button>
              </span>
            </div>
            {noteOpen ? (
              <textarea
                value={t.note}
                onChange={(e) => setNote(listKey, phaseId, t.id, e.target.value)}
                rows={3}
                placeholder="What you found, what is still unresolved."
                className="mt-2 w-full rounded border border-neutral-800 bg-neutral-950 px-2 py-1 font-mono text-xs leading-relaxed text-neutral-300"
              />
            ) : null}
          </div>
        </div>
      </div>
    );
  };

  /* ---- loading ---- */
  if (!hydrated || !board) {
    return (
      <div className="min-h-screen bg-neutral-950 p-8 font-sans">
        <p className="font-mono text-sm text-cyan-400">Loading board…</p>
      </div>
    );
  }

  const ringR = 42;
  const ringC = 2 * Math.PI * ringR;

  return (
    <div ref={rootRef} className="min-h-screen bg-neutral-950 font-sans text-neutral-200">
      <div className="mx-auto max-w-5xl px-4 py-8">
        {/* header */}
        <div className="mb-8 flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="font-mono text-lg tracking-wide text-neutral-100">AGENTIC SECURITY MONITOR</h1>
            <p className="mt-1 text-sm text-neutral-500">Build tracker. Ordering and dependencies only.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setDrawer(true)}
              className="flex items-center gap-2 rounded border border-neutral-700 px-3 py-2 font-mono text-xs text-neutral-300 hover:border-cyan-700 hover:text-cyan-300"
            >
              <BookOpen className="h-3 w-3" /> GLOSSARY
            </button>
            <button
              onClick={exportBoard}
              className="flex items-center gap-2 rounded border border-neutral-700 px-3 py-2 font-mono text-xs text-neutral-300 hover:border-cyan-700 hover:text-cyan-300"
            >
              <Copy className="h-3 w-3" /> EXPORT
            </button>
            <button
              onClick={() => setImportOpen(!importOpen)}
              className="rounded border border-neutral-700 px-3 py-2 font-mono text-xs text-neutral-300 hover:border-cyan-700 hover:text-cyan-300"
            >
              IMPORT
            </button>
            {confirmReset ? (
              <span className="flex gap-2">
                <button
                  onClick={() => {
                    setBoard(structuredClone(SEED_DATA));
                    setConfirmReset(false);
                    flash("Board reset to seed.");
                  }}
                  className="rounded border border-red-800 px-3 py-2 font-mono text-xs text-red-300"
                >
                  WIPE AND RESEED
                </button>
                <button onClick={() => setConfirmReset(false)} className="rounded border border-neutral-700 px-3 py-2 font-mono text-xs text-neutral-400">
                  KEEP
                </button>
              </span>
            ) : (
              <button
                onClick={() => setConfirmReset(true)}
                className="flex items-center gap-2 rounded border border-neutral-700 px-3 py-2 font-mono text-xs text-neutral-400 hover:border-red-800 hover:text-red-300"
              >
                <RotateCcw className="h-3 w-3" /> RESET
              </button>
            )}
          </div>
        </div>

        {loadError ? (
          <div className="mb-4 rounded border border-red-800 bg-neutral-900 px-3 py-2 font-mono text-xs text-red-300">{loadError}</div>
        ) : null}

        {importOpen ? (
          <div className="mb-6 rounded border border-neutral-800 bg-neutral-900 p-4">
            <p className="mb-2 font-mono text-xs text-neutral-400">Paste a full board JSON, then replace.</p>
            <textarea
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              rows={6}
              className="w-full rounded border border-neutral-800 bg-neutral-950 p-2 font-mono text-xs text-neutral-300"
            />
            <div className="mt-2 flex gap-2">
              <button onClick={importBoard} className="rounded border border-cyan-800 px-3 py-1 font-mono text-xs text-cyan-300">
                REPLACE BOARD
              </button>
              <button onClick={() => setImportOpen(false)} className="rounded border border-neutral-700 px-3 py-1 font-mono text-xs text-neutral-400">
                CLOSE
              </button>
            </div>
          </div>
        ) : null}

        {/* top panels */}
        <div className="mb-8 grid gap-4 lg:grid-cols-3">
          <div className="flex items-center gap-5 rounded border border-neutral-800 bg-neutral-900 p-5">
            <svg viewBox="0 0 100 100" className="h-24 w-24 shrink-0">
              <circle cx="50" cy="50" r={ringR} fill="none" stroke="currentColor" strokeWidth="7" className="text-neutral-800" />
              <circle
                cx="50"
                cy="50"
                r={ringR}
                fill="none"
                stroke="currentColor"
                strokeWidth="7"
                strokeLinecap="round"
                className="text-cyan-400"
                style={{
                  strokeDasharray: ringC,
                  strokeDashoffset: ringC * (1 - stats.pct / 100),
                  transform: "rotate(-90deg)",
                  transformOrigin: "50% 50%",
                  transition: "stroke-dashoffset 400ms",
                }}
              />
            </svg>
            <div>
              <p className="font-mono text-3xl text-neutral-100">{stats.pct}%</p>
              <p className="mt-1 font-mono text-xs text-neutral-500">
                {stats.done} / {stats.total} phase tasks
              </p>
              <p className="mt-3 font-mono text-xs text-cyan-400">FOCUS: {focusPhaseId || "none"}</p>
            </div>
          </div>

          <div className="rounded border border-neutral-800 bg-neutral-900 p-5">
            <p className="mb-3 font-mono text-xs tracking-widest text-neutral-500">NEXT 3 ACTIONS</p>
            {nextActions.length === 0 ? (
              <p className="text-sm text-neutral-500">Nothing queued. Start something in the focus phase.</p>
            ) : (
              <ol className="space-y-2">
                {nextActions.map((n, i) => (
                  <li key={n.task.id} className="flex gap-3">
                    <span
                      className={"font-mono text-xs " + (n.task.pinned ? "text-amber-400" : "text-cyan-400")}
                      title={n.task.pinned ? "Pinned. Out of phase order on purpose." : ""}
                    >
                      {n.phase}
                    </span>
                    <span className="text-sm leading-snug text-neutral-300">{renderLabel(n.task.label, "next" + i)}</span>
                  </li>
                ))}
              </ol>
            )}
          </div>

          <div className="rounded border border-neutral-800 bg-neutral-900 p-5">
            <p className="mb-3 font-mono text-xs tracking-widest text-neutral-500">RECENTLY CLEARED</p>
            {board.cleared.length === 0 ? (
              <p className="text-sm text-neutral-500">Nothing cleared yet in this session.</p>
            ) : (
              <ul className="space-y-2">
                {board.cleared.map((c) => (
                  <li key={c.id} className="flex gap-2 text-sm text-neutral-400">
                    <span className="font-mono text-xs text-emerald-500">ok</span>
                    <span className="leading-snug">{c.label}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* phases */}
        <div className="space-y-4">
          {board.phases.map((p) => {
            const s = phaseStat(p);
            const locked = isLocked(p);
            const focused = focusPhaseId === p.id;
            const collapsed = !!board.collapsed[p.id];
            return (
              <div
                key={p.id}
                className={
                  "rounded border bg-neutral-900 transition-colors " +
                  (focused ? "border-cyan-600 shadow-lg " : "border-neutral-800 ") +
                  (locked ? "opacity-50" : "")
                }
              >
                <div className="flex items-center gap-3 px-4 py-3">
                  <button onClick={() => toggleCollapse(p.id)} className="text-neutral-500 hover:text-neutral-200">
                    {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </button>
                  <span className="font-mono text-sm text-cyan-400">{p.id}</span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm text-neutral-100">{p.name}</p>
                    <p className="truncate text-xs text-neutral-500">{p.blurb}</p>
                  </div>
                  {locked ? (
                    <button
                      onClick={() => unlockPhase(p.id)}
                      className="flex items-center gap-1 rounded border border-neutral-700 px-2 py-1 font-mono text-xs text-neutral-400 hover:border-cyan-700 hover:text-cyan-300"
                      title="Dependencies are incomplete. Click to work on it anyway."
                    >
                      <Lock className="h-3 w-3" /> UNLOCK
                    </button>
                  ) : null}
                  <span className="font-mono text-xs text-neutral-500">
                    {s.done}/{s.total}
                  </span>
                </div>
                <div className="mx-4 mb-3 h-1 rounded bg-neutral-800">
                  <div
                    className={"h-1 rounded " + (focused ? "bg-cyan-400" : "bg-violet-500")}
                    style={{ width: s.pct + "%", transition: "width 300ms" }}
                  />
                </div>

                {!collapsed ? (
                  <div className="space-y-2 px-4 pb-4">
                    {p.tasks.map((t) => renderTask(t, "phase", p.id, "cyan"))}

                    {p.id === "P5" ? (
                      <div className="mt-4 rounded border border-neutral-800 bg-neutral-950 p-3">
                        <p className="mb-3 font-mono text-xs tracking-widest text-neutral-500">SCENARIO FAMILIES</p>
                        <div className="space-y-2">
                          {board.counters.map((c) => (
                            <div key={c.id} className="flex items-center gap-3">
                              <span className={"w-5 font-mono text-xs " + (c.gap ? "text-violet-400" : "text-neutral-500")}>{c.code}</span>
                              <span className="min-w-0 flex-1 truncate text-sm text-neutral-300">{renderLabel(c.label, c.id)}</span>
                              <span className="flex items-center gap-1">
                                <button onClick={() => bumpCounter(c.id, "done", -1)} className="rounded border border-neutral-800 px-2 font-mono text-xs text-neutral-500 hover:text-neutral-200">
                                  -
                                </button>
                                <span className="w-12 text-center font-mono text-xs text-neutral-200">
                                  {c.done}/{c.target === null ? "?" : c.target}
                                </span>
                                <button onClick={() => bumpCounter(c.id, "done", 1)} className="rounded border border-neutral-800 px-2 font-mono text-xs text-neutral-500 hover:text-neutral-200">
                                  +
                                </button>
                                <button onClick={() => bumpCounter(c.id, "target", 1)} className="ml-1 rounded border border-neutral-800 px-2 font-mono text-xs text-neutral-600 hover:text-neutral-300" title="Raise target">
                                  t+
                                </button>
                                <button onClick={() => bumpCounter(c.id, "target", -1)} className="rounded border border-neutral-800 px-2 font-mono text-xs text-neutral-600 hover:text-neutral-300" title="Lower target">
                                  t-
                                </button>
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    <div className="flex gap-2 pt-2">
                      <input
                        value={drafts[p.id] || ""}
                        onChange={(e) => setDrafts({ ...drafts, [p.id]: e.target.value })}
                        placeholder="Add a task"
                        className="flex-1 rounded border border-neutral-800 bg-neutral-950 px-2 py-1 text-sm text-neutral-200"
                      />
                      <button
                        onClick={() => addTask("phase", p.id)}
                        className="flex items-center gap-1 rounded border border-neutral-700 px-3 font-mono text-xs text-neutral-400 hover:border-cyan-700 hover:text-cyan-300"
                      >
                        <Plus className="h-3 w-3" /> ADD
                      </button>
                    </div>
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>

        {/* hygiene track */}
        <div className="mt-8 rounded border border-amber-900 bg-neutral-900">
          <div className="flex items-center gap-3 px-4 py-3">
            <button onClick={() => toggleCollapse("HYG")} className="text-neutral-500 hover:text-neutral-200">
              {board.collapsed.HYG ? <ChevronRight className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>
            <span className="font-mono text-sm text-amber-400">KB</span>
            <div className="min-w-0 flex-1">
              <p className="text-sm text-neutral-100">Knowledge base hygiene</p>
              <p className="truncate text-xs text-neutral-500">Not a phase. Runs alongside everything else.</p>
            </div>
            <span className="font-mono text-xs text-neutral-500">
              {board.hygiene.filter((t) => t.status === "done").length}/{board.hygiene.length}
            </span>
          </div>
          {!board.collapsed.HYG ? (
            <div className="space-y-2 px-4 pb-4">
              {board.hygiene.map((t) => renderTask(t, "hygiene", null, "amber"))}
              <div className="flex gap-2 pt-2">
                <input
                  value={drafts.hygiene || ""}
                  onChange={(e) => setDrafts({ ...drafts, hygiene: e.target.value })}
                  placeholder="Add a hygiene task"
                  className="flex-1 rounded border border-neutral-800 bg-neutral-950 px-2 py-1 text-sm text-neutral-200"
                />
                <button
                  onClick={() => addTask("hygiene", null)}
                  className="flex items-center gap-1 rounded border border-neutral-700 px-3 font-mono text-xs text-neutral-400 hover:border-amber-700 hover:text-amber-300"
                >
                  <Plus className="h-3 w-3" /> ADD
                </button>
              </div>
            </div>
          ) : null}
        </div>

        <p className="mt-8 font-mono text-xs text-neutral-700">
          Dotted underline means the word is in the glossary. Dashed border means I inferred it and you should check it.
          Pinned means it jumps the queue regardless of phase order, because something later depends on it being right.
        </p>
      </div>

      {/* glossary drawer */}
      {drawer ? (
        <div className="fixed inset-0 z-40 flex justify-end bg-neutral-950 bg-opacity-80">
          <div className="h-full w-full max-w-md overflow-y-auto border-l border-neutral-800 bg-neutral-900 p-5">
            <div className="mb-4 flex items-center gap-3">
              <Search className="h-4 w-4 text-neutral-600" />
              <input
                value={drawerQuery}
                onChange={(e) => setDrawerQuery(e.target.value)}
                placeholder="Search terms"
                className="flex-1 rounded border border-neutral-800 bg-neutral-950 px-2 py-1 text-sm text-neutral-200"
              />
              <button onClick={() => setDrawer(false)} className="text-neutral-500 hover:text-neutral-200">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="space-y-4">
              {Object.keys(GLOSSARY)
                .filter(
                  (k) =>
                    k.toLowerCase().includes(drawerQuery.toLowerCase()) ||
                    GLOSSARY[k].toLowerCase().includes(drawerQuery.toLowerCase())
                )
                .sort((a, b) => a.localeCompare(b))
                .map((k) => (
                  <div key={k}>
                    <p className="font-mono text-xs uppercase tracking-wide text-cyan-400">{k}</p>
                    <p className="mt-1 text-sm leading-relaxed text-neutral-300">{GLOSSARY[k]}</p>
                  </div>
                ))}
            </div>
          </div>
        </div>
      ) : null}

      {toast ? (
        <div className="fixed bottom-6 left-1/2 z-50 rounded border border-neutral-700 bg-neutral-900 px-4 py-2 font-mono text-xs text-neutral-200">
          {toast}
        </div>
      ) : null}
    </div>
  );
}
