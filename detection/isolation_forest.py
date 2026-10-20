"""
Layer 1: Isolation Forest over per-call behavioural features.

Training regime
  - Fit on benign_train only. Never on attack data, never on red-team records.
  - Featurizer frequency tables are part of the model and are fitted on the same
    benign_train split; training vectors are cross-fitted (see features.py).
  - contamination is NOT used. Setting contamination=0.05 asserts that 5% of
    benign traffic is malicious, which is a made-up number. Instead the raw
    anomaly score is calibrated on a separate benign split (benign_calib):
        score(x) = share of calibration calls at least as normal as x   in [0, 1]
    and the alert threshold is a quantile of that distribution. A threshold of
    0.99 therefore means "about 1% of benign calls exceed it", by construction,
    and the holdout split checks whether that holds out of sample.
  - Two operating points, because a SOC alerts on sessions, not calls:
        call level    flag a call if score > q_call         (default 0.99)
        session level flag a session if its max raw anomaly exceeds the
                      q_session quantile of calibration session maxima (0.95)
    A per-call threshold applied per session inflates FPR roughly with session
    length (1 - 0.99^15 is about 14%), which is why the session threshold is
    calibrated separately rather than derived from the call one.

The score is an input to score fusion later, so it is a number in [0, 1], not
just a flag. In the gate it runs in shadow mode: written to the record as
l1_score, never consulted for enforcement.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from detection.features import FEATURE_NAMES, Featurizer, SessionState

MODEL_VERSION = 1


@dataclass
class Layer1Detector:
    n_estimators: int = 300
    max_samples: int = 512
    seed: int = 0
    q_call: float = 0.99
    q_session: float = 0.95

    featurizer: Featurizer | None = None
    forest: IsolationForest | None = None
    calib_call: np.ndarray | None = None        # sorted raw anomaly, calibration calls
    call_threshold_raw: float | None = None
    session_threshold_raw: float | None = None
    meta: dict = field(default_factory=dict)

    # -- fit / calibrate ------------------------------------------------------
    def fit(self, train_records, calib_records) -> "Layer1Detector":
        if any(r.is_attack for r in train_records) or any(r.is_attack for r in calib_records):
            raise ValueError("Layer 1 trains and calibrates on benign records only.")
        X_train = Featurizer.cross_fit_transform(train_records, seed=self.seed)
        self.featurizer = Featurizer().fit(train_records)
        self.forest = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=min(self.max_samples, len(X_train)),
            random_state=self.seed,
        ).fit(X_train)

        a_cal = self.anomaly(self.featurizer.transform(calib_records))
        self.calib_call = np.sort(a_cal)
        self.call_threshold_raw = float(np.quantile(a_cal, self.q_call))
        sess_max = _session_max(calib_records, a_cal)
        self.session_threshold_raw = float(np.quantile(list(sess_max.values()), self.q_session))
        self.meta = {
            "version": MODEL_VERSION,
            "features": list(FEATURE_NAMES),
            "n_train_calls": len(train_records),
            "n_train_sessions": len({r.session_id for r in train_records}),
            "n_calib_calls": len(calib_records),
            "n_calib_sessions": len(sess_max),
        }
        return self

    # -- scoring --------------------------------------------------------------
    def anomaly(self, X: np.ndarray) -> np.ndarray:
        """Raw anomaly: higher is more anomalous (negated sklearn score_samples)."""
        return -self.forest.score_samples(X)

    def calibrated(self, raw: np.ndarray) -> np.ndarray:
        """Map raw anomaly to [0, 1] via the calibration ECDF."""
        return np.searchsorted(self.calib_call, raw, side="right") / len(self.calib_call)

    def score_records(self, records) -> tuple[np.ndarray, np.ndarray]:
        """(raw anomaly, calibrated score) for each record, in the order given."""
        raw = self.anomaly(self.featurizer.transform(records))
        return raw, self.calibrated(raw)

    def flag_calls(self, raw: np.ndarray) -> np.ndarray:
        return raw > self.call_threshold_raw

    def flag_sessions(self, records, raw: np.ndarray) -> dict[str, bool]:
        return {s: m > self.session_threshold_raw for s, m in _session_max(records, raw).items()}

    # -- persistence ----------------------------------------------------------
    def save(self, path: str) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str) -> "Layer1Detector":
        det = joblib.load(path)
        if not isinstance(det, Layer1Detector) or det.meta.get("version") != MODEL_VERSION:
            raise ValueError(f"{path} is not a v{MODEL_VERSION} Layer1Detector; retrain it.")
        return det


def _session_max(records, raw) -> dict[str, float]:
    out: dict[str, float] = defaultdict(lambda: -np.inf)
    for r, a in zip(records, raw):
        out[r.session_id] = max(out[r.session_id], float(a))
    return dict(out)


class ShadowScorer:
    """Online wrapper used by guarded_tool_call. Keeps one SessionState per session
    so a live score is computed exactly the way the offline extractor computes it.

    Process-local: a session resumed from a checkpoint in a new process starts with
    an empty history. Acceptable for shadow mode; fusion will need state in the
    graph checkpoint instead.
    """

    def __init__(self, detector: Layer1Detector, max_sessions: int = 10_000):
        self.det = detector
        self.states: dict[str, SessionState] = {}
        self.max_sessions = max_sessions

    @classmethod
    def load(cls, path: str) -> "ShadowScorer":
        return cls(Layer1Detector.load(path))

    def score_record(self, record) -> float:
        if len(self.states) > self.max_sessions:
            self.states.clear()
        state = self.states.setdefault(record.session_id, SessionState())
        x = self.det.featurizer.vector(state, record)
        raw = self.det.anomaly(x.reshape(1, -1))
        return round(float(self.det.calibrated(raw)[0]), 4)
