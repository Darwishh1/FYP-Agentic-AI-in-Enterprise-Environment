"""
Base classes for red-team attack scenarios.

Every scenario subclasses BaseAttackScenario, declares its taxonomy metadata,
and builds one AgentAction (the malicious — or, for controls, benign — tool-call
attempt). The runner feeds that action through the detection engine and compares
the verdict to what the scenario expected, yielding Detection Rate / FPR / per-
OWASP coverage.

Design note: scenarios target the DETECTION ENGINE directly (deterministic, no
LLM cost), not the LLM orchestrator. The monitor is what the thesis measures; the
graph is just the environment those actions occur in. When Layers 1/2/4 exist,
the same AgentAction feeds the composite scorer instead of only the rule engine.

ATLAS is intentionally recorded at the TACTIC level only (e.g. "Privilege
Escalation"), per the knowledge base's warning not to guess AML.T technique IDs
from memory — attach a specific technique ID only after checking the live matrix.
"""
from dataclasses import dataclass


@dataclass
class AgentAction:
    """One tool-call attempt as the detection engine sees it."""
    agent_role: str
    tool: str
    resource: str | None = None
    amount: float | None = None
    args_text: str | None = None
    call_count: int | None = None
    hour: int | None = None


@dataclass
class AttackResult:
    """Outcome of running one scenario through the detection engine."""
    attack_id: str
    name: str
    expected_owasp: str | None
    expect_detected: bool
    detected: bool
    status: str
    rule_id: str | None
    actual_owasp: str | None
    detected_layer: str | None
    correct: bool          # detected == expect_detected
    owasp_correct: bool     # actual OWASP tag == expected (only meaningful if detected)


class BaseAttackScenario:
    """Subclass and set the metadata + build_action(). See scenarios.py."""
    attack_id: str = "BASE"
    name: str = "base scenario"
    owasp_tag: str | None = None        # expected OWASP ASI category
    atlas_tactic: str | None = None     # tactic-level only (see module docstring)
    severity: str = "MEDIUM"            # LOW | MEDIUM | HIGH | CRITICAL
    stealth_level: str = "LOW"          # LOW | MEDIUM | HIGH | VERY HIGH
    expected_detection_layer: str = "rule_based"
    target_agent: str | None = None
    expect_detected: bool = True        # True for attacks, False for benign controls

    def build_action(self) -> AgentAction:
        raise NotImplementedError("Each scenario must build its AgentAction.")

    def run(self, monitor) -> AttackResult:
        """Execute this scenario against the rule-based detection engine."""
        action = self.build_action()
        check = monitor.enforce_policy(
            agent_role=action.agent_role,
            action_type=action.tool,
            resource=action.resource,
            amount=action.amount,
            args_text=action.args_text,
            hour=action.hour,
            call_count=action.call_count,
        )

        detected = check["status"] != "PASS"       # any finding counts as a flag
        actual_owasp = check.get("owasp_tag")
        return AttackResult(
            attack_id=self.attack_id,
            name=self.name,
            expected_owasp=self.owasp_tag,
            expect_detected=self.expect_detected,
            detected=detected,
            status=check["status"],
            rule_id=check.get("rule_id"),
            actual_owasp=actual_owasp,
            detected_layer=self.expected_detection_layer if detected else None,
            correct=(detected == self.expect_detected),
            owasp_correct=(detected and actual_owasp == self.owasp_tag),
        )
