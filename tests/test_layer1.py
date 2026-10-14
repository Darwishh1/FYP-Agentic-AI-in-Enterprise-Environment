"""Layer 1 (Isolation Forest) contract tests.

These check properties that make a Layer 1 number defensible, not the number
itself: no leakage from Layer 3 or labels, no look-ahead, live == offline,
benign-only training, calibration that means what it says.
"""
import copy
import dataclasses

import numpy as np
import pytest

import graph
from detection.features import FEATURE_NAMES, Featurizer
from detection.isolation_forest import Layer1Detector, ShadowScorer


@pytest.fixture(scope="module")
def corpora():
    from normal_traffic import generate
    return generate(150, seed=101), generate(80, seed=102)


@pytest.fixture(scope="module")
def detector(corpora):
    train, calib = corpora
    return Layer1Detector(n_estimators=100, seed=0).fit(train, calib)


def test_feature_vector_has_the_declared_width(detector, corpora):
    X = detector.featurizer.transform(corpora[1][:20])
    assert X.shape == (20, len(FEATURE_NAMES))
    assert np.isfinite(X).all()


def test_layer3_verdicts_and_labels_do_not_move_the_features(detector, corpora):
    """Layer 1 must not read Layer 3's verdict, the ground truth, ids, or noise."""
    recs = corpora[1][:200]
    base = detector.featurizer.transform(recs)
    perturbed = []
    for r in recs:
        p = copy.deepcopy(r)
        p.policy_status = "CONTAIN"
        p.rule_ids = ["RB-999"]
        p.owasp_tags = ["ASI99"]
        p.latency_ms = 12345.0
        p.timestamp = "1999-01-01T00:00:00+00:00"
        p.args_hash = "x"
        p.is_attack = True
        p.attack_id = "LEAK"
        p.l1_score = 0.5
        p.enforcement_mode = "enforce"
        if p.result_status == "SUCCESS":
            p.result_status = "BLOCKED"     # a Layer 3 block, not a sandbox refusal
        perturbed.append(p)
    assert np.array_equal(base, detector.featurizer.transform(perturbed))


def test_features_only_look_backwards(detector, corpora):
    """Changing a later call in a session must not change an earlier call's vector."""
    recs = corpora[1]
    sid = max({r.session_id for r in recs}, key=lambda s: sum(r.session_id == s for r in recs))
    sess = sorted([r for r in recs if r.session_id == sid], key=lambda r: r.turn_index)
    assert len(sess) >= 4
    before = detector.featurizer.transform(sess[:3])
    tampered = [*sess[:3], dataclasses.replace(sess[3], bytes_returned=10**9, tool_name="write_file")]
    after = detector.featurizer.transform(tampered)[:3]
    assert np.array_equal(before, after)


def test_live_scorer_matches_offline_scoring(detector, corpora):
    """The shadow scorer in the gate must compute exactly what training computed."""
    recs = sorted(corpora[1][:300], key=lambda r: (r.session_id, r.turn_index))
    _, offline = detector.score_records(recs)
    live = ShadowScorer(detector)
    online = [live.score_record(r) for r in recs]
    assert np.allclose(np.round(offline, 4), online)


def test_training_refuses_attack_records(corpora):
    train, calib = corpora
    bad = [dataclasses.replace(train[0], is_attack=True, attack_id="X")] + train[1:]
    with pytest.raises(ValueError, match="benign"):
        Layer1Detector(n_estimators=10).fit(bad, calib)


def test_calibrated_score_is_a_probability_like_rank(detector, corpora):
    raw, score = detector.score_records(corpora[1])
    assert ((score >= 0) & (score <= 1)).all()
    # On the calibration split itself the call threshold flags ~(1 - q_call).
    assert abs(detector.flag_calls(raw).mean() - (1 - detector.q_call)) < 0.01


def test_save_and_load_round_trip(detector, corpora, tmp_path):
    path = tmp_path / "m.joblib"
    detector.save(str(path))
    again = Layer1Detector.load(str(path))
    a, _ = detector.score_records(corpora[1][:50])
    b, _ = again.score_records(corpora[1][:50])
    assert np.allclose(a, b)


def test_cross_fitting_keeps_routine_novelty_routine(corpora):
    """A refund to a brand-new customer is the norm for CS. In-sample fitting would
    mark every training payee as 'seen' and teach the forest to fear new ones."""
    train, _ = corpora
    X = Featurizer.cross_fit_transform(train)
    i = FEATURE_NAMES.index("payee_surprise")
    cs_refunds = [k for k, r in enumerate(train)
                  if r.agent_role == "customer_service_agent" and r.tool_name == "call_payment_api"]
    if not cs_refunds:
        pytest.skip("no CS refunds drawn in this small corpus")
    assert np.median(X[cs_refunds, i]) < 1.0


# --- shadow mode in the gate ------------------------------------------------------

class _Sink:
    def __init__(self):
        self.records = []

    def log(self, rec):
        self.records.append(rec)


def test_shadow_score_is_written_and_never_enforced(detector, monitor):
    sink = _Sink()
    ctx = {"agent_role": "finance_agent", "session_id": "shadow", "privilege_level": "HIGH"}
    with graph.use_components(monitor_override=monitor, logger_override=sink, sim_hour=10,
                              layer1_override=ShadowScorer(detector)):
        out = graph.guarded_tool_call(ctx, "db_query", resource="finance",
                                      tool_kwargs={"schema": "finance", "query": "SELECT * FROM invoices"})
    rec = sink.records[0]
    assert rec.l1_score is not None and 0.0 <= rec.l1_score <= 1.0
    assert rec.policy_status == "PASS" and rec.result_status == "SUCCESS"
    assert "Returned" in out


def test_a_broken_scorer_cannot_take_the_gate_down(monitor):
    class Broken:
        def score_record(self, rec):
            raise RuntimeError("model file corrupted")

    sink = _Sink()
    ctx = {"agent_role": "finance_agent", "session_id": "broken", "privilege_level": "HIGH"}
    with graph.use_components(monitor_override=monitor, logger_override=sink, sim_hour=10,
                              layer1_override=Broken()):
        graph.guarded_tool_call(ctx, "db_query", resource="finance",
                                tool_kwargs={"schema": "finance", "query": "select 1"})
    assert len(sink.records) == 1 and sink.records[0].l1_score is None
