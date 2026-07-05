"""
Mock enterprise tool APIs for the simulation.

Each tool is a stand-in for a real backend (DB, mailer, shell, payments, files,
CRM). They carry lightweight built-in safety checks — the kind a real API has —
while the policy-level governance lives separately in security_monitor.py.

Every call emits a structured line to tool_calls.log via log_event(). That log is
the training/eval corpus for the anomaly-detection layers (Isolation Forest,
LSTM) added later — do not remove the logging.
"""
import hashlib
import json
import re
from datetime import datetime, timezone

LOG_PATH = "tool_calls.log"

# Commands the sandboxed shell is allowed to run.
_SHELL_WHITELIST = ["git", "docker", "kubectl", "pip", "npm"]
# Naive network-reaching patterns that should never appear in a shell command.
_SHELL_NETWORK_PATTERNS = ("curl", "wget", "nc ", "ncat", "python -c")


def log_event(tool_name: str, context: dict, args: dict, result_status: str) -> dict:
    """Append one structured tool-call record to LOG_PATH and return it.

    result_status is one of: SUCCESS | DENIED | ERROR.
    args are hashed (not stored raw) so the log stays PII-light.
    """
    ctx = context if isinstance(context, dict) else {}
    args_repr = json.dumps(args, sort_keys=True, default=str)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": ctx.get("session_id", "unknown"),
        "agent_role": ctx.get("agent_role", "unknown"),
        "tool_name": tool_name,
        "args_hash": hashlib.sha256(args_repr.encode()).hexdigest()[:16],
        "result_status": result_status,
    }
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def db_query(schema: str, query: str, context: dict) -> str:
    """Simulated DB query with basic schema-isolation checking."""
    role = context.get("agent_role")

    if role == "customer_service_agent" and schema == "hr":
        log_event("db_query", context, {"schema": schema, "query": query}, "DENIED")
        return "ERROR: Access Denied. Privilege level insufficient for HR schema."

    log_event("db_query", context, {"schema": schema, "query": query}, "SUCCESS")
    return f"Mock data for query '{query}' on schema '{schema}' fetched successfully."


def execute_shell(command: str, context: dict) -> str:
    """Sandboxed shell simulation with command whitelisting + network block."""
    base_cmd = command.split()[0] if command else ""

    if base_cmd not in _SHELL_WHITELIST:
        log_event("execute_shell", context, {"command": command}, "DENIED")
        return f"ERROR: Command '{base_cmd}' is blocked by system execution policy."

    if any(pat in command for pat in _SHELL_NETWORK_PATTERNS):
        log_event("execute_shell", context, {"command": command}, "DENIED")
        return "ERROR: Network-reaching command blocked by sandbox policy."

    log_event("execute_shell", context, {"command": command}, "SUCCESS")
    return f"Execution output: {command} completed with exit code 0."


def send_email(to: str, subject: str, body: str, context: dict) -> str:
    """Logs an outbound email to the simulation inbox (never actually sends)."""
    log_event("send_email", context, {"to": to, "subject": subject}, "SUCCESS")
    return f"Mock email queued to '{to}' with subject '{subject}'."


def call_payment_api(amount: float, recipient: str, context: dict) -> str:
    """Mock payment. Built-in sanity check only; role-based payment limits are
    enforced by the policy layer (security_monitor), not here."""
    if amount is None or amount <= 0:
        log_event("call_payment_api", context, {"amount": amount, "recipient": recipient}, "ERROR")
        return "ERROR: Payment amount must be a positive number."

    log_event("call_payment_api", context, {"amount": amount, "recipient": recipient}, "SUCCESS")
    return f"Mock payment of {amount} to '{recipient}' authorized."


def read_file(path: str, context: dict) -> str:
    """Simulated filesystem read with a naive path-traversal guard."""
    if ".." in path or path.startswith("/etc") or path.startswith("C:\\Windows"):
        log_event("read_file", context, {"path": path}, "DENIED")
        return f"ERROR: Access to path '{path}' blocked by filesystem ACL."

    log_event("read_file", context, {"path": path}, "SUCCESS")
    return f"Mock contents of '{path}' returned."


def write_file(path: str, content: str, context: dict) -> str:
    """Simulated filesystem write with the same path guard as read_file."""
    if ".." in path or path.startswith("/etc") or path.startswith("C:\\Windows"):
        log_event("write_file", context, {"path": path}, "DENIED")
        return f"ERROR: Write to path '{path}' blocked by filesystem ACL."

    log_event("write_file", context, {"path": path, "bytes": len(content or "")}, "SUCCESS")
    return f"Mock write of {len(content or '')} bytes to '{path}' succeeded."


def create_ticket(ticket_type: str, details: str, context: dict) -> str:
    """Creates a mock CRM ticket."""
    log_event("create_ticket", context, {"type": ticket_type}, "SUCCESS")
    return f"Mock ticket of type '{ticket_type}' created."


def escalate_to_human(reason: str, context: dict) -> str:
    """Triggers the supervisor gate (human-in-the-loop). Mock: just records it."""
    log_event("escalate_to_human", context, {"reason": reason}, "SUCCESS")
    return f"Escalated to human supervisor. Reason: {reason}"


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
