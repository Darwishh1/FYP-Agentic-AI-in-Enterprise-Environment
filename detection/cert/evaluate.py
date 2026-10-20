"""Layer 1 on CERT r4.2: does the per-role behavioural method work on a
recognised insider-threat benchmark it was not designed against?

    python -m detection.cert.prepare  ...                 # once, where the archive is
    python -m detection.cert.evaluate --events data/cert/r42_events.csv.gz

WHAT IS REUSED UNCHANGED
  detection.features.Featurizer and detection.isolation_forest.Layer1Detector:
  same 18 features, same benign-only training, same cross-fitting, same ECDF
  calibration, same q_call / q_session operating points. Nothing in Layer 1 was
  tuned for CERT. The only code added to Layer 1 for this is two optional keys
  (__target__, __text_len__) that let an adapter hand over the "target" and the
  free-text length directly; simulator records never set them.

MAPPING (CERT event -> Layer 1 record)
  user            -> session owner; session = one user-day
  LDAP role       -> agent_role   (per-role baselines, the method under test)
  event type      -> tool_name    logon / logoff / usb_connect / usb_disconnect /
                                  file / email / http
  target          -> logon/logoff: own PC vs other PC (own = the user's modal
                     logon PC); file: extension; email: internal / mixed /
                     external_only; http: host
  email size      -> bytes_returned;  attachments -> rows_returned
  content length  -> free-text length
  timestamp       -> sim_hour, sim_time_seconds (seconds since midnight)
  not applicable  -> schema, payee, amount, sandbox refusals, delegation depth:
                     left at their neutral value, so those features are constant
                     and the forest ignores them.

SPLITS (by user, so no user's habits leak across splits)
  non-insider users  hashed 60 / 20 / 20 into train / calib / holdout
  insiders           only their malicious days are used, as positives. Their
                     other days are excluded: they are neither clean negatives
                     (pre-attack drift is part of several scenarios) nor positives.

REPORTED
  user-day FPR on holdout users at the calibrated q_session (5%) and at 1%;
  malicious-day detection per scenario with Wilson 95% intervals; insider-level
  detection (insider caught on >= 1 malicious day); ROC-AUC and PR-AUC on the
  user-day max anomaly. PR-AUC depends on prevalence, and benign days are
  sub-sampled by prepare.py, so it is reported with the prevalence it was
  computed at and is not comparable to papers that use all days.
  Ablation: the same pipeline with every user given one role ("role_blind"),
  which isolates what per-role conditioning contributes.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import os
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

sys.path.insert(0, ".")

import numpy as np  # noqa: E402
from sklearn.metrics import average_precision_score, roc_auc_score  # noqa: E402

from detection.evaluate import wilson  # noqa: E402
from detection.features import FEATURE_NAMES  # noqa: E402
from detection.isolation_forest import Layer1Detector, _session_max  # noqa: E402

SCENARIOS = {
    "1": "after-hours logons + USB + upload to wikileaks.org, then leaves",
    "2": "job-site browsing, then USB data theft before leaving",
    "3": "disgruntled sysadmin: keylogger via USB, logs in as supervisor, mass email",
}


@dataclass(slots=True)
class CertRecord:
    """The subset of ToolCallRecord that Layer 1 reads."""
    session_id: str
    turn_index: int
    agent_role: str
    tool_name: str
    args_raw: dict
    sim_hour: int
    sim_time_seconds: float
    bytes_returned: int
    rows_returned: int
    is_attack: bool
    user: str = ""
    scenario: str = ""
    schema_accessed: str | None = None
    result_status: str = "SUCCESS"
    delegation_depth: int = 0
    attack_id: str | None = None


def _split_of(user: str) -> str:
    h = int.from_bytes(hashlib.blake2b(user.encode(), digest_size=8).digest(), "big") / 2 ** 64
    return "train" if h < 0.6 else ("calib" if h < 0.8 else "holdout")


def load(events_path: str, role_mode: str = "role") -> dict:
    """-> {"train", "calib", "holdout", "attack"}: lists of CertRecord in session order."""
    ldap = {}
    with open(events_path + ".ldap.csv", newline="") as fh:
        for row in csv.DictReader(fh):
            ldap[row["user"]] = row["role"] or row["functional_unit"] or "unknown"
    insiders = set()
    with open(events_path + ".insiders.csv", newline="") as fh:
        for row in csv.DictReader(fh):
            insiders.add(row["user"].strip())

    rows = []
    logon_pcs: dict = defaultdict(Counter)
    with gzip.open(events_path, "rt", newline="") as fh:
        for r in csv.DictReader(fh):
            rows.append(r)
            if r["tool"] == "logon":
                logon_pcs[r["user"]][r["target"]] += 1
    own_pc = {u: c.most_common(1)[0][0] for u, c in logon_pcs.items()}

    mal_sessions = {r["session"] for r in rows if r["is_attack"] == "1"}
    by_session: dict = defaultdict(list)
    for r in rows:
        by_session[r["session"]].append(r)

    out = {"train": [], "calib": [], "holdout": [], "attack": []}
    for sid in sorted(by_session):
        evs = sorted(by_session[sid], key=lambda r: int(r["secs"]))
        user = evs[0]["user"]
        if user in insiders:
            if sid not in mal_sessions:
                continue
            split = "attack"
        else:
            split = _split_of(user)
        role = "ALL" if role_mode == "role_blind" else ldap.get(user, "unknown")
        scen = next((e["scenario"] for e in evs if e["scenario"]), "")
        for i, e in enumerate(evs):
            target = e["target"]
            if e["tool"] in ("logon", "logoff"):
                target = "own_pc" if target == own_pc.get(user) else "other_pc"
            out[split].append(CertRecord(
                session_id=sid, turn_index=i + 1, agent_role=role, tool_name=e["tool"],
                args_raw={"__target__": target, "__text_len__": int(e["text_len"])},
                sim_hour=int(e["hour"]), sim_time_seconds=float(e["secs"]),
                bytes_returned=int(e["nbytes"]), rows_returned=int(e["nrows"]),
                is_attack=e["is_attack"] == "1", user=user, scenario=scen,
                attack_id=f"CERT-{scen}" if e["is_attack"] == "1" else None))
    return out


def _subsample_sessions(records, max_sessions: int, seed: int):
    sess = sorted({r.session_id for r in records})
    if len(sess) <= max_sessions:
        return records
    keep = set(np.random.default_rng(seed).choice(sess, max_sessions, replace=False))
    return [r for r in records if r.session_id in keep]


def evaluate_once(data: dict, seed: int, max_train_sessions: int) -> dict:
    train = _subsample_sessions(data["train"], max_train_sessions, seed)
    calib, holdout, attack = data["calib"], data["holdout"], data["attack"]
    for r in calib:                          # fit() refuses attack-labelled records,
        assert not r.is_attack               # and so should we
    det = Layer1Detector(seed=seed).fit(train, calib)

    raw_c, _ = det.score_records(calib)
    calib_max = np.array(list(_session_max(calib, raw_c).values()))
    thr = {"q95": det.session_threshold_raw, "q99": float(np.quantile(calib_max, 0.99))}

    raw_h, _ = det.score_records(holdout)
    raw_a, _ = det.score_records(attack)
    neg = _session_max(holdout, raw_h)
    pos = _session_max(attack, raw_a)
    scen_of = {r.session_id: r.scenario for r in attack}
    user_of = {r.session_id: r.user for r in attack}

    res = {"seed": seed, "n_train_sessions": len({r.session_id for r in train}),
           "n_calib_sessions": len(calib_max), "n_holdout_sessions": len(neg),
           "n_attack_sessions": len(pos), "operating_points": {}}
    y = np.r_[np.zeros(len(neg)), np.ones(len(pos))]
    s = np.r_[list(neg.values()), list(pos.values())]
    res["roc_auc"] = float(roc_auc_score(y, s))
    res["pr_auc"] = float(average_precision_score(y, s))
    res["prevalence"] = float(y.mean())
    for name, t in thr.items():
        flagged = {sid: v > t for sid, v in pos.items()}
        per_scen = {}
        for sc in sorted(set(scen_of.values())):
            ids = [sid for sid in pos if scen_of[sid] == sc]
            k = sum(flagged[sid] for sid in ids)
            per_scen[sc] = {"days": len(ids), "detected": k, "rate": k / len(ids),
                            "ci95": wilson(k, len(ids))}
            users = {user_of[sid] for sid in ids}
            caught = {user_of[sid] for sid in ids if flagged[sid]}
            per_scen[sc]["insiders"] = len(users)
            per_scen[sc]["insiders_caught"] = len(caught)
        k_all = sum(flagged.values())
        all_users = set(user_of.values())
        caught_users = {user_of[s_] for s_, f in flagged.items() if f}
        res["operating_points"][name] = {
            "holdout_day_fpr": float(np.mean([v > t for v in neg.values()])),
            "day_detection": k_all / len(pos), "day_ci95": wilson(k_all, len(pos)),
            "insiders": len(all_users), "insiders_caught": len(caught_users),
            "per_scenario": per_scen,
        }

    # which features moved, per scenario (descriptive, same recipe as detection.evaluate)
    X_h = det.featurizer.transform(holdout)
    X_a = det.featurizer.transform(attack)
    med = np.median(X_h, axis=0)
    iqr = np.subtract(*np.percentile(X_h, [75, 25], axis=0))
    sd = np.std(X_h, axis=0)
    iqr = np.where(iqr > 0, iqr, np.where(sd > 0, sd, 1.0))
    moved = {}
    for sc in sorted(set(scen_of.values())):
        idx = [i for i, r in enumerate(attack) if r.is_attack and r.scenario == sc]
        shift = (np.median(X_a[idx], axis=0) - med) / iqr
        top = np.argsort(-np.abs(shift))[:4]
        moved[sc] = [(FEATURE_NAMES[j], round(float(shift[j]), 2)) for j in top]
    res["features_moved"] = moved
    return res


def _mean_sd(xs):
    return float(np.mean(xs)), float(np.std(xs))


def summarise(runs: list[dict]) -> dict:
    out = {"roc_auc": _mean_sd([r["roc_auc"] for r in runs]),
           "pr_auc": _mean_sd([r["pr_auc"] for r in runs]),
           "prevalence": runs[0]["prevalence"], "op": {}}
    for op in runs[0]["operating_points"]:
        ops = [r["operating_points"][op] for r in runs]
        out["op"][op] = {
            "holdout_day_fpr": _mean_sd([o["holdout_day_fpr"] for o in ops]),
            "day_detection": _mean_sd([o["day_detection"] for o in ops]),
            "insiders_caught": _mean_sd([o["insiders_caught"] for o in ops]),
            "insiders": ops[0]["insiders"],
            "per_scenario": {sc: {
                "rate": _mean_sd([o["per_scenario"][sc]["rate"] for o in ops]),
                "days": ops[0]["per_scenario"][sc]["days"],
                "insiders_caught": _mean_sd([o["per_scenario"][sc]["insiders_caught"] for o in ops]),
                "insiders": ops[0]["per_scenario"][sc]["insiders"],
            } for sc in ops[0]["per_scenario"]},
        }
    return out


def _pct(ms):
    return f"{100 * ms[0]:.1f}% ± {100 * ms[1]:.1f}"


def to_markdown(results: dict, meta: dict) -> str:
    L = ["# Layer 1 on CERT r4.2 (insider threat benchmark)", "",
         "Generated by `python -m detection.cert.evaluate`. Layer 1 code and hyperparameters are "
         "the frozen simulator design; nothing was tuned on CERT.", "",
         f"- Benign user-days kept by prepare.py: {meta['keep']:.3f} of all; every malicious day kept.",
         f"- Users: train / calib / holdout split by user hash (60/20/20); insiders contribute malicious days only.",
         f"- Seeds: {meta['seeds']}; training sessions capped at {meta['max_train_sessions']:,} user-days per seed.",
         f"- Sessions per run: {meta['sizes']}.", ""]
    for variant, summ in results.items():
        L += [f"## Variant: `{variant}`", "",
              f"ROC-AUC {summ['roc_auc'][0]:.3f} ± {summ['roc_auc'][1]:.3f} · "
              f"PR-AUC {summ['pr_auc'][0]:.3f} ± {summ['pr_auc'][1]:.3f} "
              f"(at prevalence {100 * summ['prevalence']:.2f}% malicious days)", "",
              "| Operating point | Holdout day FPR | Malicious days caught | Insiders caught |",
              "|---|---:|---:|---:|"]
        for op, o in summ["op"].items():
            label = {"q95": "calibrated 5% (default)", "q99": "calibrated 1%"}[op]
            L.append(f"| {label} | {_pct(o['holdout_day_fpr'])} | {_pct(o['day_detection'])} | "
                     f"{o['insiders_caught'][0]:.1f} / {o['insiders']} |")
        L += ["", "Per scenario at the default operating point:", "",
              "| Scenario | Malicious days | Days caught | Insiders caught |", "|---|---:|---:|---:|"]
        for sc, p in summ["op"]["q95"]["per_scenario"].items():
            L.append(f"| {sc}: {SCENARIOS.get(sc, '')} | {p['days']} | {_pct(p['rate'])} | "
                     f"{p['insiders_caught'][0]:.1f} / {p['insiders']} |")
        L.append("")
    L += ["## Caveats", "",
          "- CERT is synthetic (generated from real case patterns), and it is human activity "
          "(logons, USB, files, email, web), not AI-agent tool calls. This tests whether the "
          "feature design transfers, not the agent monitor itself.",
          "- Per-role baselines are what the method uses. Most CERT work uses per-user baselines, "
          "which are stronger for this data; numbers here are not directly comparable.",
          "- PR-AUC is computed on sub-sampled benign days and is prevalence-dependent.", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate Layer 1 on CERT r4.2")
    ap.add_argument("--events", default=os.path.join("data", "cert", "r42_events.csv.gz"))
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--max-train-sessions", type=int, default=8000)
    ap.add_argument("--keep", type=float, default=1 / 12, help="what prepare.py used (for the report)")
    ap.add_argument("--variants", default="role,role_blind")
    ap.add_argument("--out-dir", default=os.path.join("reports", "layer1", "cert"))
    a = ap.parse_args()

    results, raw, sizes = {}, {}, None
    for variant in a.variants.split(","):
        t0 = time.time()
        data = load(a.events, variant)
        sizes = {k: len({r.session_id for r in v}) for k, v in data.items()}
        print(f"[{variant}] loaded {sum(len(v) for v in data.values()):,} events, sessions {sizes} "
              f"({time.time() - t0:.0f}s)", flush=True)
        runs = []
        for seed in range(a.seeds):
            t1 = time.time()
            r = evaluate_once(data, seed, a.max_train_sessions)
            op = r["operating_points"]["q95"]
            print(f"  seed {seed}: ROC {r['roc_auc']:.3f} PR {r['pr_auc']:.3f} | day FPR "
                  f"{op['holdout_day_fpr']:.3f} detect {op['day_detection']:.3f} insiders "
                  f"{op['insiders_caught']}/{op['insiders']} ({time.time() - t1:.0f}s)", flush=True)
            runs.append(r)
        results[variant] = summarise(runs)
        raw[variant] = runs
    meta = {"keep": a.keep, "seeds": a.seeds, "max_train_sessions": a.max_train_sessions, "sizes": sizes}
    os.makedirs(a.out_dir, exist_ok=True)
    with open(os.path.join(a.out_dir, "results.json"), "w") as fh:
        json.dump({"meta": meta, "summary": results, "runs": raw}, fh, indent=1)
    with open(os.path.join(a.out_dir, "results.md"), "w") as fh:
        fh.write(to_markdown(results, meta))
    print(f"wrote {a.out_dir}/results.md and results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
