"""
Mock enterprise tool APIs for the simulation.

CHANGED: tools now return a ToolResult, not a bare string.

Why: the detection layers consume `rows_returned` and `bytes_returned`. Under the
old interface `bytes_returned` was `len(result)`, i.e. the length of an f-string
template, and `rows_returned` was hardcoded None. An Isolation Forest trained on
those columns learns the length of a Python format string. Exfiltration detection
needs volume that actually tracks what was requested, so volume is now derived
deterministically from the arguments (same args => same volume, reproducible
across runs, but varying across different requests).

REMOVED: log_event(). Logging now happens once, in guarded_tool_call, via
EventLogger. Previously this module wrote a second, differently-shaped log to
tool_calls.log while graph.py wrote ToolCallRecords to logs/tool_calls.jsonl,
giving two corpora that disagreed with each other.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass
class ToolResult:
    """What a mock backend returns. The gate reads volume off this."""
    message: str
    rows: int | None = None
    bytes: int = 0
    status: str = "SUCCESS"      # SUCCESS | DENIED | ERROR


# Commands the sandboxed shell is allowed to run.
_SHELL_WHITELIST = ["git", "docker", "kubectl", "pip", "npm"]
# Naive network-reaching patterns that should never appear in a shell command.
_SHELL_NETWORK_PATTERNS = ("curl", "wget", "nc ", "ncat", "python -c")


def _deterministic_scale(seed_text: str, lo: int, hi: int) -> int:
    """Stable pseudo-random integer in [lo, hi] derived from the arguments.

    Deterministic on purpose: rerunning the same evaluation must produce the
    same corpus, otherwise detection-rate numbers move between runs for reasons
    that have nothing to do with the detector.
    """
    digest = hashlib.sha256(seed_text.encode()).digest()
    span = max(hi - lo, 1)
    return lo + (int.from_bytes(digest[:4], "big") % span)


# Rough per-schema row scale, so a `SELECT *` against a big table returns more
# than one against a small one. Crude, but it makes volume mean something.
_SCHEMA_SCALE = {
    "hr": (1, 400), "finance": (1, 900), "accounts": (1, 600),
    "devops": (1, 1500), "logs": (1, 5000), "crm": (1, 300), "tickets": (1, 800),
}
_BYTES_PER_ROW = 180


def db_query(schema: str, query: str, context: dict) -> ToolResult:
    """Simulated DB query. Row count scales with the schema and the query shape."""
    role = context.get("agent_role")

    if role == "customer_service_agent" and schema == "hr":
        return ToolResult("ERROR: Access Denied. Privilege insufficient for HR schema.",
                          rows=0, bytes=0, status="DENIED")

    lo, hi = _SCHEMA_SCALE.get(schema, (1, 200))
    rows = _deterministic_scale(f"{schema}|{query}", lo, hi)

    # An unbounded SELECT * pulls the whole table; a LIMIT clause caps it.
    if re.search(r"select\s+\*", query or "", re.IGNORECASE) and not re.search(r"\blimit\b", query or "", re.IGNORECASE):
        rows = hi
    limit_match = re.search(r"\blimit\s+(\d+)", query or "", re.IGNORECASE)
    if limit_match:
        rows = min(rows, int(limit_match.group(1)))

    return ToolResult(f"Returned {rows} rows from '{schema}'.", rows=rows, bytes=rows * _BYTES_PER_ROW)


def execute_shell(command: str, context: dict) -> ToolResult:
    """Sandboxed shell simulation with command whitelisting + network block."""
    base_cmd = command.split()[0] if command else ""

    if base_cmd not in _SHELL_WHITELIST:
        return ToolResult(f"ERROR: Command '{base_cmd}' blocked by execution policy.",
                          rows=0, bytes=0, status="DENIED")
    if any(pat in command for pat in _SHELL_NETWORK_PATTERNS):
        return ToolResult("ERROR: Network-reaching command blocked by sandbox policy.",
                          rows=0, bytes=0, status="DENIED")

    out_bytes = _deterministic_scale(command, 200, 40_000)
    return ToolResult(f"Exit 0. {out_bytes} bytes of output.", rows=None, bytes=out_bytes)


def send_email(to: str, subject: str, body: str, context: dict) -> ToolResult:
    """Logs an outbound email to the simulation inbox (never actually sends)."""
    payload = len((body or "").encode()) + len((subject or "").encode()) + len((to or "").encode())
    return ToolResult(f"Email queued to '{to}' ({payload} bytes).", rows=None, bytes=payload)


def call_payment_api(amount: float, recipient: str, context: dict) -> ToolResult:
    """Mock payment. Sanity check only; role limits live in security_monitor."""
    if amount is None or amount <= 0:
        return ToolResult("ERROR: Payment amount must be positive.", rows=0, bytes=0, status="ERROR")
    return ToolResult(f"Payment of {amount} to '{recipient}' authorized.", rows=1, bytes=320)


def read_file(path: str, context: dict) -> ToolResult:
    """Simulated filesystem read with a naive path-traversal guard."""
    if ".." in path or path.startswith("/etc") or path.startswith("C:\\Windows"):
        return ToolResult(f"ERROR: Access to '{path}' blocked by filesystem ACL.",
                          rows=0, bytes=0, status="DENIED")
    size = _deterministic_scale(path, 500, 250_000)
    return ToolResult(f"Read {size} bytes from '{path}'.", rows=None, bytes=size)


def write_file(path: str, content: str, context: dict) -> ToolResult:
    """Simulated filesystem write with the same path guard as read_file."""
    if ".." in path or path.startswith("/etc") or path.startswith("C:\\Windows"):
        return ToolResult(f"ERROR: Write to '{path}' blocked by filesystem ACL.",
                          rows=0, bytes=0, status="DENIED")
    size = len((content or "").encode())
    return ToolResult(f"Wrote {size} bytes to '{path}'.", rows=None, bytes=size)


def create_ticket(ticket_type: str, details: str, context: dict) -> ToolResult:
    """Creates a mock CRM ticket."""
    return ToolResult(f"Ticket of type '{ticket_type}' created.",
                      rows=1, bytes=len((details or "").encode()) + 128)


def escalate_to_human(reason: str, context: dict) -> ToolResult:
    """Triggers the supervisor gate (human-in-the-loop). Mock: records it."""
    return ToolResult(f"Escalated to human supervisor. Reason: {reason}",
                      rows=None, bytes=len((reason or "").encode()))


def contains_instruction_pattern(text: str) -> bool:
    """Heuristic used by the rule layer (RB-005): does this text look like an
    injected natural-language instruction rather than a normal tool argument?"""
    if not text:
        return False
    patterns = [
        r"ignore (all |the )?(previous|prior|above) instructions",
        r"disregard (your|the) (rules|policy|instructions)",
        r"you are now",
        r"act as",
        r"system prompt",
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)
