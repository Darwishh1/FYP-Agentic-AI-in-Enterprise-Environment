"""Regression tests for the corpus foundation the detection layers stand on.

Each test pins a defect that was found in the repo and fixed (see README "Known
issues" history). If one of these fails, the Layer 1 numbers are not trustworthy
until it is understood.
"""
import json
import os

import pytest

import graph
import mock_tools
from event_logger import EventLogger
from security_monitor import SecurityMonitor
from workload import ROLES, ROLE_TASKS


# --- sessions have length ----------------------------------------------------

def test_agents_loop_so_sessions_have_more_than_one_call():
    """Every session used to end after exactly one tool call (400/400 measured),
    which made every windowed and sequence feature constant."""
    lengths = []
    for i in range(10):
        recs, _ = graph.run_session(ROLE_TASKS["devops_agent"], session_id=f"loop-{i}", steps=8)
        lengths.append(len(recs))
    assert max(lengths) > 1
    assert all(n <= 7 for n in lengths), "the step budget must still bound a session"


@pytest.mark.parametrize("role", ROLES)
def test_role_tasks_route_to_their_role(role):
    """'hr' is a substring of many words; the keyword router must land correctly."""
    from langchain_core.messages import HumanMessage
    from state import new_context
    out = graph.orchestrator_node({"messages": [HumanMessage(content=ROLE_TASKS[role])],
                                   "context": new_context("route-test")})
    assert out["context"]["next_agent"] == role


# --- benign corpus goes through the real gate --------------------------------

@pytest.fixture(scope="module")
def benign_small():
    from normal_traffic import generate
    return generate(12, seed=11)


def test_benign_records_come_from_the_gate(benign_small):
    """The old generator bypassed the gate: lower-case privilege strings, invented
    volume, no sim clock. Measured consequence: 0.8% FPR on its own holdout vs
    10.8% on benign traffic through the real gate."""
    assert benign_small
    assert {r.privilege_level for r in benign_small} <= {"LOW", "MEDIUM", "HIGH"}
    assert all(r.planner == "scripted" for r in benign_small)
    assert all(r.sim_hour is not None and r.sim_time_seconds is not None for r in benign_small)
    assert all(r.enforcement_mode == "observe" for r in benign_small)
    assert not any(r.is_attack for r in benign_small)


def test_benign_volume_is_the_mock_tools_volume(benign_small):
    for r in benign_small:
        if r.tool_name == "db_query" and r.result_status == "SUCCESS":
            expected = mock_tools.estimate_rows(r.args_raw["schema"], r.args_raw["query"])
            assert r.rows_returned == expected
            assert r.bytes_returned == expected * 180


def test_benign_generation_is_deterministic():
    from normal_traffic import generate
    a = generate(5, seed=23)
    b = generate(5, seed=23)
    assert [(r.args_hash, r.bytes_returned, r.sim_hour) for r in a] == \
           [(r.args_hash, r.bytes_returned, r.sim_hour) for r in b]


def test_benign_args_vary():
    """The scripted planner used to emit eight fixed calls, so volume took a
    handful of values. Arguments are now drawn per call."""
    from normal_traffic import generate
    recs = generate(20, seed=5)
    assert len({r.args_hash for r in recs}) > len(recs) // 3


# --- mock volume model ---------------------------------------------------------

def test_full_table_scan_returns_more_than_a_point_lookup():
    dump = mock_tools.estimate_rows("hr", "SELECT * FROM employees")
    point = mock_tools.estimate_rows("hr", "SELECT id, name FROM employees WHERE employee_id = 4411")
    agg = mock_tools.estimate_rows("hr", "SELECT COUNT(*) FROM employees WHERE dept = 'eng'")
    capped = mock_tools.estimate_rows("hr", "SELECT id FROM employees WHERE dept = 'eng' LIMIT 5")
    assert dump == 2000 and point <= 3 and agg == 1 and capped <= 5


# --- observe mode ----------------------------------------------------------------

def test_observe_mode_records_the_verdict_but_executes(monitor):
    captured = []

    class Sink:
        def log(self, rec):
            captured.append(rec)

    ctx = {"agent_role": "finance_agent", "session_id": "obs", "privilege_level": "HIGH"}
    with graph.use_components(monitor_override=monitor, logger_override=Sink(), sim_hour=10, enforce=False):
        out = graph.guarded_tool_call(ctx, "call_payment_api", amount=75000,
                                      tool_kwargs={"amount": 75000, "recipient": "r"})
    assert graph.ENFORCE is True, "observe mode must not leak out of the context manager"
    rec = captured[0]
    assert rec.policy_status == "CONTAIN"
    assert rec.result_status == "SUCCESS" and rec.bytes_returned > 0
    assert rec.enforcement_mode == "observe"
    assert "authorized" in out


# --- schema / storage ---------------------------------------------------------------

def test_old_and_newer_jsonl_both_load(tmp_path):
    old = {"session_id": "s", "turn_index": 1, "timestamp": "t", "agent_role": "hr_agent",
           "privilege_level": "MEDIUM", "delegation_source": None, "tool_name": "db_query",
           "args_raw": {}, "args_hash": "h", "schema_accessed": "hr", "result_status": "SUCCESS",
           "rows_returned": 1, "bytes_returned": 180, "latency_ms": 0.1, "policy_status": "PASS",
           "rule_ids": [], "owasp_tags": [], "is_attack": False, "attack_id": None}
    newer = dict(old, sim_hour=10, some_future_field=123)
    p = tmp_path / "c.jsonl"
    p.write_text(json.dumps(old) + "\n" + json.dumps(newer) + "\n", encoding="utf-8")
    recs = EventLogger.load_all(str(p))
    assert recs[0].sim_hour is None and recs[1].sim_hour == 10


# --- policy finding -------------------------------------------------------------------

def test_customer_service_refunds_are_whitelisted_and_capped():
    """CS carried a 500 refund limit but call_payment_api was not whitelisted, so
    RB-002 contained every refund and RB-003's limit was dead config."""
    live = SecurityMonitor()
    ok = live.enforce_policy("customer_service_agent", "call_payment_api", amount=45.0)
    over = live.enforce_policy("customer_service_agent", "call_payment_api", amount=600.0)
    assert ok["status"] == "PASS"
    assert over["rule_id"] == "RB-003"


def test_rule_engine_does_not_depend_on_tool_mocks():
    import security_monitor
    with open(security_monitor.__file__, encoding="utf-8") as f:
        assert "mock_tools" not in f.read().split('"""', 2)[-1]


# --- corpus separation ------------------------------------------------------------------

def test_scripted_e2e_runs_are_never_persisted(monkeypatch):
    """Under the scripted planner an e2e 'attack' is a benign workload draw with an
    attack label. Persisting it would put label noise in a corpus."""
    from red_team.scenarios import SCENARIOS
    written = []
    monkeypatch.setattr(EventLogger, "log", lambda self, rec: written.append(rec))
    monkeypatch.setattr(graph, "PLANNER_MODE", "scripted")
    SCENARIOS[0].run_end_to_end(persist=True)
    assert written == []


def test_behavioural_traces_label_only_attack_calls():
    from red_team.behavioural import TRACES, run_trace
    trace = next(t for t in TRACES if t.scenario_id == "B-101")
    recs = run_trace(trace, seed=3)
    attack = [r for r in recs if r.is_attack]
    cover = [r for r in recs if not r.is_attack]
    assert attack and cover
    assert all(r.attack_id == "B-101" for r in attack)
    assert all(r.attack_id is None for r in cover)
    assert all(r.enforcement_mode == "observe" for r in recs)


def test_delegation_pivot_trace_reaches_the_target_role():
    from red_team.behavioural import TRACES, run_trace
    trace = next(t for t in TRACES if t.scenario_id == "B-105")
    recs = run_trace(trace, seed=1)
    attack = [r for r in recs if r.is_attack]
    assert attack and all(r.agent_role == "finance_agent" for r in attack)
    assert all((r.delegation_depth or 0) >= 2 for r in attack)
