"""CERT adapter: format handling, labels, splits, and that Layer 1 runs on it."""
import csv
import gzip

import numpy as np
import pytest

from detection.cert import evaluate as ce
from detection.cert import prepare as cp
from detection.features import Featurizer
from tests import cert_fixture


@pytest.fixture(scope="module", params=[True, False], ids=["tar", "folder"])
def prepared(request, tmp_path_factory):
    root = tmp_path_factory.mktemp("cert")
    data, answers, insider = cert_fixture.build(str(root), as_tar=request.param)
    out = str(root / "events.csv.gz")
    counts = cp.prepare(data, answers, out, keep=1.0)
    return out, counts, insider


def test_prepare_reads_everything_and_labels(prepared):
    out, counts, insider = prepared
    assert counts["insiders"] == 1                      # the 5.2 row is filtered out
    assert counts["malicious_events"] == 12
    assert counts["attack_kept"] == 12                  # every answer-key event found
    with gzip.open(out, "rt") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["tool"] for r in rows} >= {"logon", "logoff", "usb_connect", "http", "email"}
    mal = [r for r in rows if r["is_attack"] == "1"]
    assert all(r["user"] == insider and r["scenario"] == "1" for r in mal)
    assert any(r["target"] == "wikileaks.org" for r in mal)
    assert all(r["text_len"].isdigit() for r in rows)   # content never stored
    assert "content" not in rows[0]


def test_headerless_http_parsed(prepared):
    out, _, _ = prepared
    with gzip.open(out, "rt") as fh:
        hosts = {r["target"] for r in csv.DictReader(fh) if r["tool"] == "http"}
    assert "google.com" in hosts and not any("," in h for h in hosts)


def test_sampling_keeps_all_malicious_days(tmp_path):
    data, answers, insider = cert_fixture.build(str(tmp_path))
    out = str(tmp_path / "e.csv.gz")
    counts = cp.prepare(data, answers, out, keep=0.0)   # drop every benign day
    with gzip.open(out, "rt") as fh:
        sessions = {r["session"] for r in csv.DictReader(fh)}
    assert counts["attack_kept"] == 12
    assert sessions and all(s.startswith(insider + "|") for s in sessions)


def test_splits_are_user_disjoint_and_insiders_only_positive(prepared):
    out, _, insider = prepared
    data = ce.load(out)
    users = {k: {r.user for r in v} for k, v in data.items()}
    assert users["attack"] == {insider}
    for a in ("train", "calib", "holdout"):
        assert insider not in users[a]
        assert not any(r.is_attack for r in data[a])
        for b in ("train", "calib", "holdout"):
            if a < b:
                assert not users[a] & users[b]
    # insider's non-malicious days are excluded, not mislabelled as benign
    assert all(any(x.is_attack for x in data["attack"] if x.session_id == r.session_id)
               for r in data["attack"])


def test_role_blind_collapses_roles(prepared):
    out, _, _ = prepared
    assert {r.agent_role for r in ce.load(out, "role_blind")["train"]} == {"ALL"}
    assert len({r.agent_role for r in ce.load(out)["train"]}) > 1


def test_layer1_runs_and_ranks_planted_insider(prepared):
    out, _, _ = prepared
    data = ce.load(out)
    if not data["calib"] or not data["holdout"]:
        pytest.skip("hash split left a split empty on this tiny fixture")
    r = ce.evaluate_once(data, seed=0, max_train_sessions=10_000)
    assert r["n_attack_sessions"] == 3
    assert r["roc_auc"] > 0.9                           # midnight wikileaks upload is not subtle
    assert set(r["operating_points"]) == {"q95", "q99"}


def test_adapter_keys_do_not_change_simulator_features(tmp_path):
    """The two adapter hooks only fire when the keys are present."""
    data, answers, _ = cert_fixture.build(str(tmp_path))
    out = str(tmp_path / "e.csv.gz")
    cp.prepare(data, answers, out, keep=1.0)
    recs = ce.load(out)["train"][:200]
    fz = Featurizer().fit(recs)
    X1 = fz.transform(recs)
    for r in recs:
        r.args_raw["__target__"] = "same-for-all"
    X2 = Featurizer().fit(recs).transform(recs)
    assert not np.allclose(X1, X2)                       # hook is live for adapter records
