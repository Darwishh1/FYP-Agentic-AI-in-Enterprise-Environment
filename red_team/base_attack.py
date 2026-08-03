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
import time
from dataclasses import dataclass

from attack_context import attack_label, get_attack_label
from logging_schema import ToolCallRecord
from event_logger import EventLogger


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
    is_attack: bool         # ground truth: what the input IS
    expect_detected: bool   # expectation: what the monitor SHOULD say about it
    detected: bool
    status: str
    rule_id: str | None
    actual_owasp: str | None
    detected_layer: str | None
    correct: bool           # detected == expect_detected
    owasp_correct: bool     # actual OWASP tag == expected (only meaningful if detected)

    @property
    def known_gap(self) -> bool:
        """True when this scenario is an attack we already expect to slip through.

        These are the scenarios that keep the suite honest. They count as attacks in
        every metric, so a miss shows up as a miss, but they are not runner failures
        and should not be reported as ones.
        """
        return self.is_attack and not self.expect_detected


class BaseAttackScenario:
    """Subclass and set the metadata + build_action(). See scenarios.py.

    Two labels, deliberately separate — do not collapse them again:

      is_attack       Ground truth. Is this input actually malicious? This is the
                      label every metric partitions on, and the only one that
                      belongs in a ToolCallRecord.
      expect_detected Expectation. Should the monitor flag it *today*? This is an
                      assertion about current capability, and it is allowed to be
                      False for an attack you know you do not catch yet.

    They were previously one field, with is_attack derived from expect_detected. That
    made the ground truth a function of the prediction, so a missed attack could not
    be expressed at all: every metric derived from it was circular, and the suite
    could never contain the one case a ROC curve most needs, an attack that slips.
    """
    attack_id: str = "BASE"
    name: str = "base scenario"
    owasp_tag: str | None = None        # expected OWASP ASI category
    atlas_tactic: str | None = None     # tactic-level only (see module docstring)
    severity: str = "MEDIUM"            # LOW | MEDIUM | HIGH | CRITICAL
    stealth_level: str = "LOW"          # LOW | MEDIUM | HIGH | VERY HIGH
    expected_detection_layer: str = "rule_based"
    target_agent: str | None = None
    is_attack: bool = True              # True for attacks, False for benign controls
    expect_detected: bool = True        # defaults to "we think we catch it"

    def build_action(self) -> AgentAction:
        raise NotImplementedError("Each scenario must build its AgentAction.")

    def run(self, monitor, *, logger: EventLogger | None = None) -> AttackResult:
        """Execute this scenario against the rule-based detection engine.

        When *logger* is provided (the runner passes one), a labelled
        ToolCallRecord is emitted so the JSONL corpus contains ground-truth
        positives and negatives from the red-team suite.
        """
        action = self.build_action()

        # The label is set around the whole execution, not stamped on the record
        # afterwards. Today enforce_policy is called directly and nothing else reads
        # the contextvar, but when scenarios are routed through the real graph (p5-3)
        # guarded_tool_call picks the same label up with no further wiring.
        with attack_label(self.attack_id, is_attack=self.is_attack):
            t0 = time.perf_counter()
            check = monitor.enforce_policy(
                agent_role=action.agent_role,
                action_type=action.tool,
                resource=action.resource,
                amount=action.amount,
                args_text=action.args_text,
                hour=action.hour,
                call_count=action.call_count,
            )
            latency_ms = (time.perf_counter() - t0) * 1000
            labelled_is_attack, labelled_attack_id = get_attack_label()

        detected = check["status"] != "PASS"       # any finding counts as a flag
        actual_owasp = check.get("owasp_tag")

        # --- emit labelled JSONL record ---
        if logger is not None:
            args_dict = {
                "resource": action.resource,
                "amount": action.amount,
                "args_text": action.args_text,
            }
            rule_ids = [check["rule_id"]] if check.get("rule_id") else []
            owasp_tags = [check["owasp_tag"]] if check.get("owasp_tag") else []
            record = ToolCallRecord(
                session_id=f"redteam-{self.attack_id}",
                turn_index=1,
                timestamp=ToolCallRecord.utcnow_iso(),
                agent_role=action.agent_role,
                privilege_level="unknown",
                delegation_source=None,
                tool_name=action.tool,
                args_raw=args_dict,
                args_hash=ToolCallRecord.args_to_hash(args_dict),
                schema_accessed=action.resource,
                result_status="BLOCKED" if check["status"] == "CONTAIN" else "SUCCESS",
                rows_returned=None,
                bytes_returned=0,
                latency_ms=round(latency_ms, 3),
                policy_status=check["status"],
                rule_ids=rule_ids,
                owasp_tags=owasp_tags,
                is_attack=labelled_is_attack,
                attack_id=labelled_attack_id,
            )
            logger.log(record)

        return AttackResult(
            attack_id=self.attack_id,
            name=self.name,
            expected_owasp=self.owasp_tag,
            is_attack=self.is_attack,
            expect_detected=self.expect_detected,
            detected=detected,
            status=check["status"],
            rule_id=check.get("rule_id"),
            actual_owasp=actual_owasp,
            detected_layer=self.expected_detection_layer if detected else None,
            correct=(detected == self.expect_detected),
            owasp_correct=(detected and actual_owasp == self.owasp_tag),
        )
