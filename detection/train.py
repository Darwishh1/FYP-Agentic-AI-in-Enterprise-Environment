"""Train and calibrate Layer 1.

    python normal_traffic.py --all          # benign_train / benign_calib / benign_holdout
    python -m detection.train               # -> models/layer1_iforest.joblib

Reads benign_train and benign_calib only. The holdout split and every attack
corpus are untouched here, so evaluation numbers are out of sample.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, ".")

from event_logger import EventLogger, CORPUS  # noqa: E402

DEFAULT_MODEL = os.path.join("models", "layer1_iforest.joblib")


def load_split(name: str):
    path = CORPUS[name]
    if not os.path.exists(path):
        raise SystemExit(f"{path} missing. Run: python normal_traffic.py --all")
    return EventLogger.load_all(path)


def train(seed: int = 0, q_call: float = 0.99, q_session: float = 0.95, verbose: bool = True):
    from detection.isolation_forest import Layer1Detector
    train_recs = load_split("benign_train")
    calib_recs = load_split("benign_calib")
    det = Layer1Detector(seed=seed, q_call=q_call, q_session=q_session).fit(train_recs, calib_recs)
    if verbose:
        m = det.meta
        print(f"Layer 1 trained: {m['n_train_calls']} calls / {m['n_train_sessions']} sessions (benign_train)")
        print(f"  calibrated on {m['n_calib_calls']} calls / {m['n_calib_sessions']} sessions (benign_calib)")
        print(f"  call threshold    q={q_call}:    raw anomaly > {det.call_threshold_raw:.4f}")
        print(f"  session threshold q={q_session}: max raw anomaly > {det.session_threshold_raw:.4f}")
    return det


def main() -> int:
    ap = argparse.ArgumentParser(description="Train Layer 1 (Isolation Forest).")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--q-call", type=float, default=0.99)
    ap.add_argument("--q-session", type=float, default=0.95)
    ap.add_argument("--out", default=DEFAULT_MODEL)
    args = ap.parse_args()
    det = train(args.seed, args.q_call, args.q_session)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    det.save(args.out)
    print(f"  saved -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
