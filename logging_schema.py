"""
Machine-readable tool-call record for the structured log pipeline.

Every tool call (passed or blocked) emits exactly one ToolCallRecord through
event_logger.EventLogger. These records are the training corpus for the
statistical (Layer 1) and temporal (Layer 2) detection layers.

Fields fall into four groups:
  - Session/turn identity (who, when)
  - Tool call detail      (what, with what args)
  - Execution outcome     (what happened)
  - Policy verdict        (what the rule engine said)
  - Ground-truth labels   (set only by red_team.runner)
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


@dataclass
class ToolCallRecord:
    # --- session / turn identity ---
    session_id: str
    turn_index: int
    timestamp: str                          # ISO 8601, UTC

    # --- agent identity ---
    agent_role: str
    privilege_level: str
    delegation_source: str | None           # which node routed here

    # --- tool call detail ---
    tool_name: str
    args_raw: dict                          # unredacted, for semantic layer
    args_hash: str                          # sha256 of canonical JSON

    # --- execution outcome ---
    schema_accessed: str | None
    result_status: str                      # SUCCESS / BLOCKED / ERROR
    rows_returned: int | None
    bytes_returned: int
    latency_ms: float

    # --- policy verdict ---
    policy_status: str                      # PASS / WARN / CONTAIN
    rule_ids: list[str] = field(default_factory=list)
    owasp_tags: list[str] = field(default_factory=list)

    # --- ground-truth labels (set by red-team runner only) ---
    is_attack: bool = False
    attack_id: str | None = None

    # -- helpers --

    def to_json(self) -> str:
        """Serialize to a single compact JSON string (one JSONL line)."""
        return json.dumps(asdict(self), default=str, ensure_ascii=False)

    @staticmethod
    def args_to_hash(args: dict) -> str:
        """Canonical SHA-256 hex digest for an args dict."""
        canonical = json.dumps(args, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def utcnow_iso() -> str:
        """Current UTC timestamp in ISO 8601."""
        return datetime.now(timezone.utc).isoformat()
