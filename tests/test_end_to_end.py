"""End-to-end scenario path (tracker p5-3).

These run under the scripted planner so they are free and deterministic. That
means they verify the *plumbing* — that a task reaches a planner, that a plan
reaches the gate, that the gate emits exactly one record per call, that
components are restored afterwards. They deliberately do not assert detection
outcomes, because under the scripted planner the plan ignores the injected text
and any detection rate would be an artefact of the workload distribution.
"""
import pytest
from langchain_core.messages import AIMessage, HumanMessage

import graph
from event_logger import CapturingLogger
from logging_schema import ToolCallRecord
from red_team.scenarios import SCENARIOS


class _NullMonitor:
    policy = {"agents": {}, "global_rules": {"window_seconds": 60}}

    def enforce_policy(self, *a, **k):
        return {"status": "PASS", "reason": "disabled", "owasp_tag": None, "rule_id": None}


# --- _latest_task: the bug that made injection untestable --------------------

def test_latest_task_returns_the_human_turn_not_the_last_message():
    """Regression: agents used to plan against the orchestrator's own status line.

    `reversed(messages)` returns the newest message, which by the time an agent
    node runs is 'orchestrator: routing to finance_agent'. Injected text never
    reached a planner, so end-to-end injection could not fire while appearing to.
    """
    state = {"messages": [
        HumanMessage(content="ATTACKER TEXT"),
        AIMessage(content="orchestrator: routing to finance_agent"),
    ]}
    assert graph._latest_task(state) == "ATTACKER TEXT"


def test_latest_task_falls_back_when_there_is_no_human_turn():
    state = {"messages": [AIMessage(content="resumed session note")]}
    assert graph._latest_task(state) == "resumed session note"


# --- component swapping ------------------------------------------------------

def test_use_components_restores_originals():
    original_monitor, original_logger = graph.monitor, graph.event_logger
    with graph.use_components(monitor_override=_NullMonitor(), logger_override=CapturingLogger()):
        assert graph.monitor is not original_monitor
    assert graph.monitor is original_monitor
    assert graph.event_logger is original_logger


def test_use_components_restores_on_exception():
    """A control run that raised must not leave enforcement disabled for the
    rest of the process."""
    original = graph.monitor
    with pytest.raises(RuntimeError):
        with graph.use_components(monitor_override=_NullMonitor()):
            raise RuntimeError("boom")
    assert graph.monitor is original


# --- run_session -------------------------------------------------------------

def test_run_session_emits_records_and_reaches_the_gate():
    records, state = graph.run_session(
        "Reconcile the pending invoices for this cycle.",
        session_id="test-e2e-1",
    )
    assert all(isinstance(r, ToolCallRecord) for r in records)
    assert state["context"]["session_id"] == "test-e2e-1"


def test_run_session_does_not_persist_by_default(tmp_path, monkeypatch):
    """persist=False must keep evaluation runs out of the shared corpus."""
    written = []
    monkeypatch.setattr(graph.EventLogger, "log", lambda self, rec: written.append(rec))
    graph.run_session("Open a billing ticket.", session_id="test-e2e-2", persist=False)
    assert written == []


def test_run_session_records_carry_the_session_id():
    records, _ = graph.run_session(
        "Query the tickets schema for open items.", session_id="test-e2e-3"
    )
    assert all(r.session_id == "test-e2e-3" for r in records)


# --- scenario integration ----------------------------------------------------

def test_every_scenario_declares_an_injected_task():
    missing = [s.attack_id for s in SCENARIOS if not s.supports_e2e()]
    assert not missing, f"scenarios without injected_task cannot run e2e: {missing}"


def test_run_end_to_end_rejects_a_scenario_with_no_task():
    class NoTask(type(SCENARIOS[0])):
        attack_id = "X-000"
        injected_task = None

    with pytest.raises(ValueError, match="cannot run end to end"):
        NoTask().run_end_to_end()


def test_end_to_end_result_is_tagged_as_e2e():
    result = SCENARIOS[0].run_end_to_end()
    assert result.mode == "e2e"
    assert result.tool_calls >= 0
    # reached_gate must agree with the call count, since it is what separates a
    # real miss from a run where nothing was ever attempted.
    assert result.reached_gate == (result.tool_calls > 0)


def test_direct_and_e2e_are_distinguishable():
    """The two modes must never be silently mixed in one table: they answer
    different questions and are not comparable."""
    from security_monitor import SecurityMonitor
    direct = SCENARIOS[0].run(SecurityMonitor())
    e2e = SCENARIOS[0].run_end_to_end()
    assert direct.mode == "direct" and e2e.mode == "e2e"


def test_vacuous_only_applies_to_e2e():
    from security_monitor import SecurityMonitor
    direct = SCENARIOS[0].run(SecurityMonitor())
    assert direct.vacuous is False


# --- self-delegation ---------------------------------------------------------

def test_llm_planner_refuses_self_delegation():
    """Observed for real: hr_agent delegated to hr_agent, burned its step budget,
    and the session produced zero tool calls — which scores as 'not detected'
    when the attack was in fact never attempted."""
    from agent_runtime import LLMPlanner

    class _Model:
        def invoke(self, _messages):
            return type("R", (), {"content": '{"action":"delegate","to":"hr_agent"}'})()

    plan = LLMPlanner(_Model()).plan(
        "hr_agent", "task", {"steps_remaining": 5, "delegation_depth": 0, "max_delegation_depth": 3}
    )
    assert plan.kind == "finish"
    assert "itself" in plan.rationale
