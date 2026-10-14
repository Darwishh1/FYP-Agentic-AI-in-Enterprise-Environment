"""Evaluate Layer 1 against Layer 3 on the same calls.

    python -m red_team.behavioural --sessions 40
    python -m detection.evaluate                    # uses models/layer1_iforest.joblib
    python -m detection.evaluate --seed-sweep 5     # retrain 5 forest seeds, report spread

Data
  negatives  benign_holdout (never seen in training or calibration)
  positives  attack_behavioural: is_attack=True calls; sessions containing them
Both corpora are generated in observe mode, so Layer 3's verdict is recorded on
every call (policy_status) without having blocked anything, and the two layers
are compared on identical traffic.

What is reported, and why
  - Benign FPR for each layer, per call and per session, at the calibrated
    operating points. Session FPR is what a SOC experiences.
  - Per-scenario session detection for L1, L3, both, L1-only. "L1-only" on the
    behavioural scenarios is the number that justifies Layer 1 existing.
  - PR-AUC (average precision) per call and per session. PR rather than ROC
    because the classes are imbalanced in deployment and ROC hides that.
    ROC-AUC is printed alongside for comparability with other work.
  - Wilson 95% intervals on detection rates: n=40 sessions per scenario is small.
  - Which features moved: for each scenario, the features where attack calls sit
    furthest from benign holdout (median shift in units of benign IQR). This is
    descriptive, not causal attribution.

Caveats printed with the results, not buried here: the benign traffic and the
attack traces come from the same simulator, so these numbers measure detector
sensitivity to scripted behaviour in a synthetic enterprise, not field accuracy.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import defaultdict

sys.path.insert(0, ".")

import numpy as np  # noqa: E402
from sklearn.metrics import average_precision_score, roc_auc_score  # noqa: E402

from event_logger import EventLogger, CORPUS  # noqa: E402
from detection.features import FEATURE_NAMES  # noqa: E402
from detection.train import DEFAULT_MODEL, load_split, train  # noqa: E402


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _sessions(records, values):
    out = defaultdict(list)
    for r, v in zip(records, values):
        out[r.session_id].append(v)
    return out


def evaluate(det, holdout, attacks, traces_meta) -> dict:
    raw_b, _ = det.score_records(holdout)
    raw_a, _ = det.score_records(attacks)
    X_b = det.featurizer.transform(holdout)
    X_a = det.featurizer.transform(attacks)

    l3_b = np.array([r.policy_status != "PASS" for r in holdout])
    l3_a = np.array([r.policy_status != "PASS" for r in attacks])
    l1_b = det.flag_calls(raw_b)

    # --- benign ----------------------------------------------------------------
    sess_l1_b = det.flag_sessions(holdout, raw_b)
    sess_l3_b = {s: any(v) for s, v in _sessions(holdout, l3_b).items()}
    nb = len(sess_l1_b)
    benign = {
        "calls": len(holdout), "sessions": nb,
        "l1_call_fpr": float(l1_b.mean()),
        "l3_call_fpr": float(l3_b.mean()),
        "l1_session_fpr": sum(sess_l1_b.values()) / nb,
        "l3_session_fpr": sum(sess_l3_b.values()) / nb,
        "either_session_fpr": sum(sess_l1_b[s] or sess_l3_b[s] for s in sess_l1_b) / nb,
    }

    # --- per scenario, session level --------------------------------------------
    sess_l1_a = det.flag_sessions(attacks, raw_a)
    sess_l3_a = {s: any(v) for s, v in _sessions(attacks, l3_a).items()}
    is_atk = np.array([r.is_attack for r in attacks])
    scen_of = {}
    for r in attacks:
        if r.is_attack:
            scen_of[r.session_id] = r.attack_id

    iqr = np.subtract(*np.percentile(X_b, [75, 25], axis=0))
    sd = np.std(X_b, axis=0)
    iqr = np.where(iqr > 0, iqr, np.where(sd > 0, sd, 1.0))   # constant-in-benign: raw units
    med_b = np.median(X_b, axis=0)

    scenarios = []
    for sid, meta in traces_meta.items():
        sess = [s for s, a in scen_of.items() if a == sid]
        if not sess:
            continue
        n = len(sess)
        l1 = sum(sess_l1_a[s] for s in sess)
        l3 = sum(sess_l3_a[s] for s in sess)
        both = sum(sess_l1_a[s] and sess_l3_a[s] for s in sess)
        call_idx = [i for i, r in enumerate(attacks) if r.is_attack and r.attack_id == sid]
        shift = (np.median(X_a[call_idx], axis=0) - med_b) / iqr
        top = np.argsort(-np.abs(shift))[:3]
        scenarios.append({
            "id": sid, "name": meta["name"], "category": meta["category"],
            "known_gap": meta["known_gap"], "sessions": n,
            "l1": l1, "l3": l3, "both": both, "l1_only": l1 - both, "l3_only": l3 - both,
            "either": l1 + l3 - both,
            "l1_rate": l1 / n, "l1_ci": wilson(l1, n),
            "l3_rate": l3 / n, "either_rate": (l1 + l3 - both) / n,
            "l1_call_recall": float(det.flag_calls(raw_a[call_idx]).mean()),
            "top_features": [(FEATURE_NAMES[j], round(float(np.clip(shift[j], -99, 99)), 1)) for j in top],
        })

    # --- threshold-free ----------------------------------------------------------
    y_call = np.r_[np.zeros(len(raw_b)), np.ones(int(is_atk.sum()))]
    s_call = np.r_[raw_b, raw_a[is_atk]]
    beh_ids = {s["id"] for s in scenarios if s["category"] == "behavioural"}
    beh_mask = np.array([r.is_attack and r.attack_id in beh_ids for r in attacks])
    y_beh = np.r_[np.zeros(len(raw_b)), np.ones(int(beh_mask.sum()))]
    s_beh = np.r_[raw_b, raw_a[beh_mask]]

    smax_b = {s: max(v) for s, v in _sessions(holdout, raw_b).items()}
    smax_a = {s: max(v) for s, v in _sessions(attacks, raw_a).items() if s in scen_of}
    beh_sess = [s for s in smax_a if scen_of[s] in beh_ids]
    y_sess = np.r_[np.zeros(len(smax_b)), np.ones(len(beh_sess))]
    s_sess = np.r_[list(smax_b.values()), [smax_a[s] for s in beh_sess]]

    curves = {
        "call_all": {"pr_auc": average_precision_score(y_call, s_call), "roc_auc": roc_auc_score(y_call, s_call),
                     "pos": int(y_call.sum()), "neg": int((1 - y_call).sum())},
        "call_behavioural": {"pr_auc": average_precision_score(y_beh, s_beh), "roc_auc": roc_auc_score(y_beh, s_beh),
                             "pos": int(y_beh.sum()), "neg": int((1 - y_beh).sum())},
        "session_behavioural": {"pr_auc": average_precision_score(y_sess, s_sess),
                                "roc_auc": roc_auc_score(y_sess, s_sess),
                                "pos": int(y_sess.sum()), "neg": int((1 - y_sess).sum())},
    }
    beh = [s for s in scenarios if s["category"] == "behavioural"]
    summary = {
        "behavioural_sessions": sum(s["sessions"] for s in beh),
        "behavioural_l1": sum(s["l1"] for s in beh),
        "behavioural_l3": sum(s["l3"] for s in beh),
        "behavioural_either": sum(s["either"] for s in beh),
        "behavioural_l1_only": sum(s["l1_only"] for s in beh),
    }
    return {"benign": benign, "scenarios": scenarios, "curves": curves, "summary": summary,
            "operating_point": {"q_call": det.q_call, "q_session": det.q_session}}


def print_report(res: dict) -> None:
    b = res["benign"]
    print("=" * 100)
    print("LAYER 1 (Isolation Forest) vs LAYER 3 (rules) — same calls, observe mode")
    print("=" * 100)
    print(f"Benign holdout: {b['calls']} calls, {b['sessions']} sessions "
          f"(operating point q_call={res['operating_point']['q_call']}, q_session={res['operating_point']['q_session']})")
    print(f"  {'':22} {'per call':>10} {'per session':>12}")
    print(f"  {'Layer 1 FPR':22} {b['l1_call_fpr']:>10.2%} {b['l1_session_fpr']:>12.2%}")
    print(f"  {'Layer 3 FPR':22} {b['l3_call_fpr']:>10.2%} {b['l3_session_fpr']:>12.2%}")
    print(f"  {'L1 or L3 FPR':22} {'':>10} {b['either_session_fpr']:>12.2%}")
    print()
    print(f"{'ID':6} {'cat':5} {'n':>3} {'L1':>4} {'L1 95% CI':>13} {'L3':>4} {'both':>5} {'L1only':>7} "
          f"{'either':>7} {'callrec':>8}  top features (median shift / benign IQR)")
    print("-" * 140)
    for s in res["scenarios"]:
        cat = "beh" if s["category"] == "behavioural" else "rule"
        gap = " (known gap)" if s["known_gap"] else ""
        ci = f"[{s['l1_ci'][0]:.0%},{s['l1_ci'][1]:.0%}]"
        feats = ", ".join(f"{f} {v:+}" for f, v in s["top_features"])
        print(f"{s['id']:6} {cat:5} {s['sessions']:>3} {s['l1']:>4} {ci:>13} {s['l3']:>4} {s['both']:>5} "
              f"{s['l1_only']:>7} {s['either']:>7} {s['l1_call_recall']:>8.0%}  {feats}{gap}")
    sm = res["summary"]
    n = sm["behavioural_sessions"]
    print("-" * 140)
    print(f"Behavioural (policy-compliant) sessions: {n}")
    print(f"  Layer 3 alone : {sm['behavioural_l3']:>4}  ({sm['behavioural_l3'] / n:.1%})")
    print(f"  Layer 1 alone : {sm['behavioural_l1']:>4}  ({sm['behavioural_l1'] / n:.1%})")
    print(f"  L1 or L3      : {sm['behavioural_either']:>4}  ({sm['behavioural_either'] / n:.1%})")
    print(f"  caught ONLY by Layer 1: {sm['behavioural_l1_only']}")
    print()
    for k, c in res["curves"].items():
        print(f"  {k:22} PR-AUC {c['pr_auc']:.3f}  ROC-AUC {c['roc_auc']:.3f}   (pos {c['pos']}, neg {c['neg']})")
    print()
    print("Read before quoting: benign and attack traffic come from the same simulator, and the")
    print("attack traces are scripted. These numbers measure detector sensitivity to scripted")
    print("behaviour in a synthetic enterprise. They are not field detection rates. PR-AUC base")
    print("rates differ between rows (see pos/neg), so compare PR-AUC within a row, not across.")
    print("=" * 100)


def write_markdown(res: dict, path: str, sweep: dict | None) -> None:
    b = res["benign"]
    L = ["# Layer 1 evaluation", "",
         "Generated by `python -m detection.evaluate`. Both corpora are generated in observe mode,",
         "so Layer 3's verdict is recorded on every call and both layers are scored on identical traffic.", "",
         "## Benign holdout false positives", "",
         "| | per call | per session |", "|---|---:|---:|",
         f"| Layer 1 | {b['l1_call_fpr']:.2%} | {b['l1_session_fpr']:.2%} |",
         f"| Layer 3 | {b['l3_call_fpr']:.2%} | {b['l3_session_fpr']:.2%} |",
         f"| L1 or L3 | | {b['either_session_fpr']:.2%} |", "",
         f"{b['calls']} calls, {b['sessions']} sessions.", "",
         "## Session detection by scenario", "",
         "| ID | category | n | L1 | L1 95% CI | L3 | both | L1 only | either | top features |",
         "|---|---|---:|---:|---|---:|---:|---:|---:|---|"]
    for s in res["scenarios"]:
        feats = ", ".join(f"`{f}` {v:+}" for f, v in s["top_features"])
        name = s["name"] + (" *(known gap)*" if s["known_gap"] else "")
        L.append(f"| {s['id']} {name} | {s['category']} | {s['sessions']} | {s['l1']} | "
                 f"{s['l1_ci'][0]:.0%}-{s['l1_ci'][1]:.0%} | {s['l3']} | {s['both']} | {s['l1_only']} | "
                 f"{s['either']} | {feats} |")
    sm = res["summary"]
    n = sm["behavioural_sessions"]
    L += ["", "## Behavioural (policy-compliant) scenarios combined", "",
          f"- Layer 3 alone: {sm['behavioural_l3']}/{n} ({sm['behavioural_l3'] / n:.1%})",
          f"- Layer 1 alone: {sm['behavioural_l1']}/{n} ({sm['behavioural_l1'] / n:.1%})",
          f"- Either: {sm['behavioural_either']}/{n} ({sm['behavioural_either'] / n:.1%})",
          f"- Caught only by Layer 1: {sm['behavioural_l1_only']}", "",
          "## Threshold-free", "", "| set | PR-AUC | ROC-AUC | pos | neg |", "|---|---:|---:|---:|---:|"]
    for k, c in res["curves"].items():
        L.append(f"| {k} | {c['pr_auc']:.3f} | {c['roc_auc']:.3f} | {c['pos']} | {c['neg']} |")
    if sweep:
        L += ["", f"## Seed sweep ({sweep['n']} forest seeds, same data)", "",
              "| metric | mean | min | max |", "|---|---:|---:|---:|"]
        for k, v in sweep["metrics"].items():
            L.append(f"| {k} | {v['mean']:.3f} | {v['min']:.3f} | {v['max']:.3f} |")
    L += ["", "## Caveats", "",
          "- Benign traffic and attack traces come from the same simulator; attack traces are scripted.",
          "  These are sensitivity results in a synthetic enterprise, not field detection rates.",
          "- n = 40 sessions per scenario. Use the Wilson intervals, not the point estimates alone.",
          "- 'Top features' is the median shift of attack calls from benign holdout in benign-IQR units.",
          "  It describes what moved; it is not a causal attribution of the forest's decision.",
          "- Layer 3 numbers are for its current policy.yaml, which has known tensions (see README).", ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate Layer 1 against Layer 3.")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--seed-sweep", type=int, default=0, help="Retrain N forest seeds and report spread.")
    ap.add_argument("--out", default=os.path.join("reports", "layer1"))
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    from detection.isolation_forest import Layer1Detector
    from red_team.behavioural import TRACES

    if not os.path.exists(CORPUS["attack_behavioural"]):
        raise SystemExit("attack corpus missing. Run: python -m red_team.behavioural")
    holdout = load_split("benign_holdout")
    attacks = EventLogger.load_all(CORPUS["attack_behavioural"])
    meta = {t.scenario_id: {"name": t.name, "category": t.category, "known_gap": t.known_gap} for t in TRACES}

    if not os.path.exists(args.model):
        raise SystemExit(f"{args.model} missing. Run: python -m detection.train")
    det = Layer1Detector.load(args.model)
    res = evaluate(det, holdout, attacks, meta)
    print_report(res)

    sweep = None
    if args.seed_sweep:
        keys = {
            "l1_session_fpr": lambda r: r["benign"]["l1_session_fpr"],
            "l1_call_fpr": lambda r: r["benign"]["l1_call_fpr"],
            "behavioural_l1_session_rate": lambda r: r["summary"]["behavioural_l1"] / r["summary"]["behavioural_sessions"],
            "behavioural_l1_only": lambda r: r["summary"]["behavioural_l1_only"],
            "session_behavioural_pr_auc": lambda r: r["curves"]["session_behavioural"]["pr_auc"],
            "call_behavioural_pr_auc": lambda r: r["curves"]["call_behavioural"]["pr_auc"],
        }
        vals = defaultdict(list)
        for seed in range(args.seed_sweep):
            r = evaluate(train(seed=seed, verbose=False), holdout, attacks, meta)
            for k, f in keys.items():
                vals[k].append(float(f(r)))
        sweep = {"n": args.seed_sweep,
                 "metrics": {k: {"mean": float(np.mean(v)), "min": float(np.min(v)), "max": float(np.max(v))}
                             for k, v in vals.items()}}
        print(f"\nSeed sweep over {args.seed_sweep} forest seeds:")
        for k, v in sweep["metrics"].items():
            print(f"  {k:32} mean {v['mean']:.3f}  [{v['min']:.3f}, {v['max']:.3f}]")

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as f:
        json.dump({**res, "seed_sweep": sweep}, f, indent=2, default=float)
    write_markdown(res, os.path.join(args.out, "results.md"), sweep)
    print(f"\nWritten: {args.out}/results.json, {args.out}/results.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
