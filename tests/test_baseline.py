"""The control condition must stay a control.

The baseline's only job is to be unaffected by the thing it is a control for. If a
policy edit or a new rule could change the baseline column, the comparison stops
being a comparison.
"""
from red_team.baseline import NullMonitor, _detection_rate, _false_positive_rate
from red_team.scenarios import SCENARIOS


def test_null_monitor_passes_everything():
    null = NullMonitor()
    for scenario in SCENARIOS:
        action = scenario.build_action()
        check = null.enforce_policy(
            agent_role=action.agent_role, action_type=action.tool,
            resource=action.resource, amount=action.amount, args_text=action.args_text,
        )
        assert check["status"] == "PASS"
        assert check["rule_id"] is None


def test_null_monitor_is_not_a_security_monitor_subclass():
    """Composition, not inheritance, so a new rule cannot leak into the control."""
    from security_monitor import SecurityMonitor
    assert not issubclass(NullMonitor, SecurityMonitor)


def test_null_monitor_ignores_policy_changes(tmp_path, policy_path):
    """Same verdict whichever policy file exists — it never reads one."""
    null = NullMonitor()
    a = null.enforce_policy(agent_role="finance_agent", action_type="call_payment_api", amount=10**9)
    b = null.enforce_policy(agent_role="ghost_agent", action_type="execute_shell")
    assert a == b


def test_null_monitor_exposes_policy_for_the_sliding_window():
    """guarded_tool_call reads monitor.policy for window_seconds. Without this the
    gate would crash the moment the baseline is wired through the real graph."""
    assert NullMonitor().policy["global_rules"]["window_seconds"] == 60


def test_baseline_detects_nothing_across_the_suite():
    results = [s.run(NullMonitor()) for s in SCENARIOS]
    dr, caught, n_attacks = _detection_rate(results)
    fpr, flagged, n_benign = _false_positive_rate(results)
    assert n_attacks == sum(s.is_attack for s in SCENARIOS)
    assert caught == 0 and dr == 0.0
    assert flagged == 0 and fpr == 0.0


def test_metrics_helpers_partition_on_ground_truth():
    """_detection_rate must count attacks by is_attack, not by expect_detected."""
    class Row:
        def __init__(self, is_attack, expect_detected, detected):
            self.is_attack, self.expect_detected, self.detected = is_attack, expect_detected, detected

    rows = [
        Row(True, True, True),    # caught attack
        Row(True, False, False),  # known-gap attack: still an attack
        Row(False, False, False),  # benign
    ]
    dr, caught, n = _detection_rate(rows)
    assert (caught, n) == (1, 2), "the known gap must stay in the attack denominator"
    assert dr == 0.5
