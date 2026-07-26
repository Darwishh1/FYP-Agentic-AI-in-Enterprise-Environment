"""
Rule-based security layer (detection Layer 3).

enforce_policy() runs the request against the declarative policy.yaml and returns
the single most-severe finding, tagged with an OWASP ASI category and a rule id.

Status tiers (severity ascending):
  PASS    - compliant
  WARN    - logged, allowed to continue (e.g. after-hours high-priv op)
  ALERT   - notify/throttle, still allowed (e.g. rapid tool cycling)
  CONTAIN - block the action (schema breach, tool not whitelisted, payment breach,
            injected instructions, rogue identity)

Only CONTAIN blocks; the graph gates on it. WARN/ALERT are surfaced for scoring
and the audit trail. This is the rule input that later fuses with the statistical
(Isolation Forest), sequential (LSTM), and semantic (LLM) layers.
"""
import yaml

from mock_tools import contains_instruction_pattern

_SEVERITY = {"PASS": 0, "WARN": 1, "ALERT": 2, "CONTAIN": 3}


class SecurityMonitor:
    def __init__(self, policy_path: str = "policy.yaml"):
        with open(policy_path, "r", encoding="utf-8") as f:
            self.policy = yaml.safe_load(f)

    def enforce_policy(
        self,
        agent_role: str,
        action_type: str,
        resource: str | None = None,
        *,
        amount: float | None = None,
        args_text: str | None = None,
        hour: int | None = None,
        call_count: int | None = None,
        tool_call_rate: int | None = None,
    ) -> dict:
        """Evaluate one action against policy. Returns the most severe finding as
        {status, reason, owasp_tag, rule_id}. Extra kwargs enable extra rules but
        are all optional, so existing 3-arg callers keep working.

        tool_call_rate: windowed count of calls for (agent, tool) within the
        sliding window. When provided, RB-004 uses this instead of cumulative
        call_count."""
        agent_rules = self.policy.get("agents", {}).get(agent_role)

        # RB-000: rogue / unknown identity — always the top-priority block.
        if not agent_rules:
            return self._finding("CONTAIN", "Unknown rogue agent identity.", "ASI10", "RB-000")

        findings = []

        # RB-002: tool not in this agent's whitelist.
        if action_type not in agent_rules.get("allowed_tools", []):
            findings.append(self._finding(
                "CONTAIN", f"Tool '{action_type}' is not whitelisted for {agent_role}.",
                "ASI02", "RB-002",
            ))

        # RB-001: DB access outside the agent's schema whitelist.
        if action_type == "db_query" and resource is not None \
                and resource not in agent_rules.get("db_schemas", []):
            findings.append(self._finding(
                "CONTAIN", f"Unauthorized access to schema '{resource}' by {agent_role}.",
                "ASI03", "RB-001",
            ))

        # RB-003: payment above the role's limit.
        if action_type == "call_payment_api" and amount is not None:
            limit = agent_rules.get("payment_limit", 0)
            if amount > limit:
                findings.append(self._finding(
                    "CONTAIN", f"Payment {amount} exceeds {agent_role} limit of {limit}.",
                    "ASI02", "RB-003",
                ))

        # RB-005: tool arguments contain injected natural-language instructions.
        if args_text and contains_instruction_pattern(args_text):
            findings.append(self._finding(
                "CONTAIN", "Tool arguments contain instruction-like injection pattern.",
                "ASI01", "RB-005",
            ))

        # RB-004: rapid tool cycling within the sliding window.
        # Resolve cap: per-tool override > per-agent fallback > skip.
        _rate = tool_call_rate if tool_call_rate is not None else call_count
        if _rate is not None:
            per_tool = agent_rules.get("tool_rate_limits", {}).get(action_type)
            per_agent = agent_rules.get("max_calls_per_minute")
            cap = per_tool if per_tool is not None else per_agent
            window = self.policy.get("global_rules", {}).get("window_seconds", 60)
            if cap is not None and _rate > cap:
                findings.append(self._finding(
                    "ALERT",
                    f"Call rate {_rate} for tool '{action_type}' exceeds "
                    f"{agent_role} cap of {cap} per {window}s.",
                    "ASI02", "RB-004",
                ))

        # RB-006: high-privilege operation outside allowed hours.
        if hour is not None and agent_rules.get("privilege_level") == "HIGH":
            allowed = agent_rules.get("allowed_hours", [0, 24])
            if not (allowed[0] <= hour < allowed[1]):
                findings.append(self._finding(
                    "WARN", f"High-privilege op by {agent_role} at hour {hour} (outside {allowed}).",
                    "ASI03", "RB-006",
                ))

        if not findings:
            return self._finding("PASS", "Compliant operation context.", None, None)

        # Return the single most severe finding.
        return max(findings, key=lambda f: _SEVERITY[f["status"]])

    @staticmethod
    def _finding(status: str, reason: str, owasp_tag: str | None, rule_id: str | None) -> dict:
        return {"status": status, "reason": reason, "owasp_tag": owasp_tag, "rule_id": rule_id}
