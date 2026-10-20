"""
Benign corpus generator: drives benign sessions through the REAL graph.

What changed, and why it matters for every number downstream
------------------------------------------------------------
This file used to replay its own workload straight into SecurityMonitor. It never
touched guarded_tool_call or mock_tools, so it invented its own byte and row
counts, wrote lower-case privilege strings the gate never emits ("medium",
"low-medium"), never delegated, and ran sessions ~15 calls long while the graph
ran exactly one call per session. A detector trained on it measured 0.8% FPR on
its own holdout and 10.8% on benign traffic through the real gate: it had learned
where the data came from, not what an attack looks like (Arp et al., 2022,
sampling bias).

Now there is one path. Each session is a task handed to the orchestrator, routed
to an agent, planned by a seeded ScriptedPlanner drawing from workload.py, and
executed through guarded_tool_call and mock_tools. Benign traffic, attack traces
and live runs share the gate, the tools, the sim clock and the record schema.

Two jobs, kept separate:
  1. WORKLOAD MODEL  - workload.py. Models the business, never the ruleset.
  2. EXECUTOR        - this file. Runs sessions and reports what the rules said.

Rules run in OBSERVE mode by default (--enforce to change): the verdict is
recorded, nothing is blocked, so every call has real volume. The FPR printed
below is the rule engine's verdict rate on benign traffic either way.

Splits for Layer 1 (different seeds, never mixed):
    python normal_traffic.py --split benign_train   --sessions 1500 --seed 1
    python normal_traffic.py --split benign_calib   --sessions 1000 --seed 2
    python normal_traffic.py --split benign_holdout --sessions 1000 --seed 3
or simply:
    python normal_traffic.py --all
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from collections import Counter

from event_logger import EventLogger, CORPUS

DEFAULT_SPLITS = {
    "benign_train": (1500, 1),
    "benign_calib": (1000, 2),
    "benign_holdout": (1000, 3),
}


def generate(n_sessions: int, seed: int, sink=None, *, enforce: bool = False) -> list:
    """Run *n_sessions* benign sessions through the graph. Returns all records.

    Deterministic for a given seed: the session draws (role, hour, length) and the
    planner share one seed lineage, the sim clock is fixed-increment, and mock_tools
    derive volume from the arguments.
    """
    import graph
    from agent_runtime import ScriptedPlanner
    from workload import ROLES, ROLE_TASKS, draw_session

    rng = random.Random(seed)
    planner = ScriptedPlanner(seed=seed * 7919 + 1)
    records = []
    for i in range(n_sessions):
        role = rng.choice(ROLES)
        hour, n_calls = draw_session(rng, role)
        recs, _ = graph.run_session(
            ROLE_TASKS[role],
            session_id=f"benign-s{seed}-{role}-{i:05d}",
            steps=n_calls + 1,          # the agent spends one step deciding to finish
            sim_hour=hour,
            planner_override=planner,
            enforce=enforce,
            sink=sink,
            layer1_override=None,       # the corpus must not depend on a previous model
        )
        records.extend(recs)
    return records


def report(records: list, label: str, show: int = 10) -> float:
    calls = len(records)
    flagged = [r for r in records if r.policy_status != "PASS"]
    per_role = Counter(r.agent_role for r in records)
    per_role_flag = Counter(r.agent_role for r in flagged)
    sessions = {r.session_id for r in records}
    flagged_sessions = {r.session_id for r in flagged}
    fpr = len(flagged) / calls if calls else 0.0

    print("=" * 88)
    print(f"BENIGN CORPUS [{label}] - RULE ENGINE (LAYER 3) FALSE POSITIVES")
    print("=" * 88)
    print(f"  Sessions                : {len(sessions)}")
    print(f"  Tool calls              : {calls}")
    print(f"  Calls flagged (non-PASS): {len(flagged)}")
    print(f"  Per-call FPR            : {fpr:6.2%}   target < 5%")
    print(f"  Per-session FPR         : {len(flagged_sessions) / max(len(sessions), 1):6.2%}"
          "   (sessions with at least one flag)")
    print()
    print(f"  {'role':<26} {'calls':>8} {'flagged':>9} {'FPR':>8}")
    print(f"  {'-' * 53}")
    for role in sorted(per_role):
        c, f = per_role[role], per_role_flag.get(role, 0)
        print(f"  {role:<26} {c:>8} {f:>9} {f / c:>7.2%}")
    by_rule = Counter(r.rule_ids[0] if r.rule_ids else None for r in flagged)
    if by_rule:
        print("\n  Rules producing the false positives:")
        for rule, n in by_rule.most_common():
            print(f"    {rule or '(none)':<10} {n:>5}")
    for r in flagged[:show]:
        print(f"    {r.session_id:<40} t{r.turn_index:<3} {r.tool_name:<18} "
              f"{r.policy_status:<8} {r.rule_ids[0] if r.rule_ids else '-'}")
    lens = Counter(r.session_id for r in records).values()
    print(f"\n  Session length: min {min(lens)}, mean {sum(lens) / len(lens):.1f}, max {max(lens)}")
    if fpr == 0.0:
        print("  FPR is exactly 0. Do not report that without scrutiny: it usually means")
        print("  the benign traffic never approaches a policy boundary.")
    print("=" * 88)
    return fpr


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate benign corpus splits through the real graph.")
    ap.add_argument("--split", choices=[k for k in CORPUS if k.startswith("benign_")])
    ap.add_argument("--sessions", type=int)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--all", action="store_true", help="Generate train, calib and holdout with default sizes/seeds.")
    ap.add_argument("--enforce", action="store_true", help="Block CONTAIN calls instead of observing.")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    # LLM planner off for corpus generation regardless of the environment.
    os.environ["PLANNER_MODE"] = "scripted"

    jobs = []
    if args.all:
        jobs = [(k, n, s) for k, (n, s) in DEFAULT_SPLITS.items()]
    elif args.split:
        n, s = DEFAULT_SPLITS[args.split]
        jobs = [(args.split, args.sessions or n, args.seed if args.seed is not None else s)]
    else:
        ap.error("pass --split NAME or --all")

    for split, n, seed in jobs:
        path = CORPUS[split]
        if os.path.exists(path):
            os.remove(path)          # a split is regenerated whole, never appended to
        sink = EventLogger(path=path)
        print(f"\nGenerating {split}: {n} sessions, seed {seed} -> {path}")
        recs = generate(n, seed, sink, enforce=args.enforce)
        report(recs, split)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
