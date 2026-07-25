"""
Canonical enterprise-simulation graph — the single source of truth.

Everything imports from here:
  - app.py           -> CLI runner, compiles with an on-disk SqliteSaver
  - langgraph.json   -> LangGraph Studio (`langgraph dev`), uses `graph` below
  - simulation_graph.py / agent_studio/graph.py -> thin re-export shims

Do NOT fork this logic into another file again. Add nodes/edges here.
"""
import os
import sys
import time
from datetime import datetime

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import AIMessage
from langgraph.graph import StateGraph, START, END

from state import EnterpriseState
import mock_tools
from security_monitor import SecurityMonitor
from logging_schema import ToolCallRecord
from event_logger import EventLogger
from attack_context import get_attack_label

load_dotenv()

# Console-safe UTF-8 output on Windows (containment alerts contain emoji).
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

# Cheap model by default (free-tier friendly). Override with LLM_MODEL in .env;
# set gemini-3.5-flash for higher-quality routing once billing is enabled.
MODEL_ID = os.getenv("LLM_MODEL", "gemini-3.1-flash-lite")
model = ChatGoogleGenerativeAI(model=MODEL_ID, temperature=0)

monitor = SecurityMonitor()
event_logger = EventLogger()

# Maps a tool name to its mock implementation. The enforcement gate below only
# ever executes a tool by looking it up here — a single, auditable choke point.
TOOL_REGISTRY = {
    "db_query": mock_tools.db_query,
    "execute_shell": mock_tools.execute_shell,
    "send_email": mock_tools.send_email,
    "call_payment_api": mock_tools.call_payment_api,
    "read_file": mock_tools.read_file,
    "write_file": mock_tools.write_file,
    "create_ticket": mock_tools.create_ticket,
    "escalate_to_human": mock_tools.escalate_to_human,
}


# --- Enforcement gate (Pre-call gate: check policy BEFORE the tool runs) ---

def guarded_tool_call(
    ctx: dict,
    tool_name: str,
    *,
    resource: str | None = None,
    amount: float | None = None,
    args_text: str | None = None,
    tool_kwargs: dict | None = None,
    now_hour: int | None = None,
) -> str:
    """Single enforcement point. Increments the session call count, runs the
    rule engine with the FULL context (schema, amount, injected-text, rate, hour),
    then either blocks (CONTAIN) or executes the real tool — annotating WARN/ALERT
    findings on an allowed call. Returns the message content for the agent node.

    Emits exactly one ToolCallRecord per call (pass or block) to the JSONL log."""
    ctx["call_count"] = ctx.get("call_count", 0) + 1
    hour = now_hour if now_hour is not None else datetime.now().hour
    effective_kwargs = tool_kwargs or {}

    check = monitor.enforce_policy(
        agent_role=ctx["agent_role"],
        action_type=tool_name,
        resource=resource,
        amount=amount,
        args_text=args_text,
        hour=hour,
        call_count=ctx["call_count"],
    )

    tag = f"[{check['rule_id']}/{check['owasp_tag']}]" if check.get("owasp_tag") else ""

    # --- build common record fields ---
    is_attack, attack_id = get_attack_label()
    rule_ids = [check["rule_id"]] if check.get("rule_id") else []
    owasp_tags = [check["owasp_tag"]] if check.get("owasp_tag") else []

    if check["status"] == "CONTAIN":
        # Record the blocked attempt so the detection corpus includes the tool
        # never ran (positive-class label), tagged with the rule that caught it.
        mock_tools.log_event(
            tool_name, ctx,
            {"resource": resource, "amount": amount, "rule": check["rule_id"]},
            "BLOCKED",
        )
        record = ToolCallRecord(
            session_id=ctx.get("session_id", "unknown"),
            turn_index=ctx.get("call_count", 0),
            timestamp=ToolCallRecord.utcnow_iso(),
            agent_role=ctx.get("agent_role", "unknown"),
            privilege_level=ctx.get("privilege_level", "unknown"),
            delegation_source=ctx.get("delegation_source"),
            tool_name=tool_name,
            args_raw=effective_kwargs,
            args_hash=ToolCallRecord.args_to_hash(effective_kwargs),
            schema_accessed=resource,
            result_status="BLOCKED",
            rows_returned=None,
            bytes_returned=0,
            latency_ms=0.0,
            policy_status=check["status"],
            rule_ids=rule_ids,
            owasp_tags=owasp_tags,
            is_attack=is_attack,
            attack_id=attack_id,
        )
        event_logger.log(record)
        return f"🛑 CONTAIN {tag}: {check['reason']}"

    # --- execute the tool and time it ---
    t0 = time.perf_counter()
    result = TOOL_REGISTRY[tool_name](**effective_kwargs, context=ctx)
    latency_ms = (time.perf_counter() - t0) * 1000

    record = ToolCallRecord(
        session_id=ctx.get("session_id", "unknown"),
        turn_index=ctx.get("call_count", 0),
        timestamp=ToolCallRecord.utcnow_iso(),
        agent_role=ctx.get("agent_role", "unknown"),
        privilege_level=ctx.get("privilege_level", "unknown"),
        delegation_source=ctx.get("delegation_source"),
        tool_name=tool_name,
        args_raw=effective_kwargs,
        args_hash=ToolCallRecord.args_to_hash(effective_kwargs),
        schema_accessed=resource,
        result_status="SUCCESS",
        rows_returned=None,
        bytes_returned=len(result) if isinstance(result, str) else 0,
        latency_ms=round(latency_ms, 3),
        policy_status=check["status"],
        rule_ids=rule_ids,
        owasp_tags=owasp_tags,
        is_attack=is_attack,
        attack_id=attack_id,
    )
    event_logger.log(record)

    if check["status"] in ("WARN", "ALERT"):
        return f"⚠️ {check['status']} {tag}: {check['reason']}\n{result}"
    return result


# --- Orchestrator ---

def orchestrator_node(state: EnterpriseState):
    """Uses the LLM to classify the request and emit a routing keyword."""
    messages = state["messages"]
    system_prompt = (
        "You are an enterprise routing orchestrator. Analyze the user query and output EXACTLY ONE keyword:\n"
        "- salaries, payroll, onboarding, employee records -> 'ROUTE_TO_HR'\n"
        "- deployments, shell commands, docker, kubernetes, infrastructure -> 'ROUTE_TO_DEVOPS'\n"
        "- payments, invoices, vendor transfers, refunds over budget -> 'ROUTE_TO_FINANCE'\n"
        "- customer tickets, complaints, small refunds -> 'ROUTE_TO_CS'\n"
        "Otherwise respond normally."
    )
    payload = [AIMessage(content=system_prompt)] + list(messages)
    response = model.invoke(payload)
    return {"messages": [response]}


# --- Department agent nodes (each routes through the enforcement gate) ---

def hr_agent_node(state: EnterpriseState):
    """HR node. Adversarial demo: attempts the unauthorized 'finance' schema
    (indirect prompt-injection / lateral escalation) -> RB-001 CONTAIN."""
    ctx = state["context"]
    ctx["agent_role"] = "hr_agent"
    ctx["privilege_level"] = "MEDIUM"
    print(f"\n[SECURITY CHECK] Intercepting {ctx['agent_role']} invocation context...")
    msg = guarded_tool_call(
        ctx, "db_query", resource="finance",
        tool_kwargs={"schema": "finance", "query": "SELECT * FROM metrics"},
    )
    return {"messages": [AIMessage(content=f"HR Agent: {msg}")], "context": ctx}


def finance_agent_node(state: EnterpriseState):
    """Finance node. Adversarial demo: a payment above the role limit -> RB-003."""
    ctx = state["context"]
    ctx["agent_role"] = "finance_agent"
    ctx["privilege_level"] = "HIGH"
    print(f"\n[SECURITY CHECK] Intercepting {ctx['agent_role']} invocation context...")
    msg = guarded_tool_call(
        ctx, "call_payment_api", amount=75000,
        tool_kwargs={"amount": 75000, "recipient": "vendor#4421"},
    )
    return {"messages": [AIMessage(content=f"Finance Agent: {msg}")], "context": ctx}


def devops_agent_node(state: EnterpriseState):
    """DevOps node. Benign demo: a whitelisted shell command -> PASS/SUCCESS."""
    ctx = state["context"]
    ctx["agent_role"] = "devops_agent"
    ctx["privilege_level"] = "HIGH"
    print(f"\n[SECURITY CHECK] Intercepting {ctx['agent_role']} invocation context...")
    msg = guarded_tool_call(
        ctx, "execute_shell",
        tool_kwargs={"command": "kubectl get pods"},
    )
    return {"messages": [AIMessage(content=f"DevOps Agent: {msg}")], "context": ctx}


def customer_service_agent_node(state: EnterpriseState):
    """Customer Service node. Benign demo: create a CRM ticket -> PASS/SUCCESS."""
    ctx = state["context"]
    ctx["agent_role"] = "customer_service_agent"
    ctx["privilege_level"] = "LOW"
    print(f"\n[SECURITY CHECK] Intercepting {ctx['agent_role']} invocation context...")
    msg = guarded_tool_call(
        ctx, "create_ticket",
        tool_kwargs={"ticket_type": "refund", "details": "guest requests partial refund"},
    )
    return {"messages": [AIMessage(content=f"Customer Service Agent: {msg}")], "context": ctx}


# --- Routing ---

def route_decision(state: EnterpriseState):
    """Parses the orchestrator's message text into a conditional-edge target."""
    last_msg = state["messages"][-1]

    if hasattr(last_msg, "text") and last_msg.text:
        content = last_msg.text
    elif isinstance(last_msg.content, str):
        content = last_msg.content
    else:
        content = "".join(
            block.get("text", "") for block in last_msg.content if isinstance(block, dict)
        )

    print(f"[ROUTER DEBUG] Evaluating string context decision: '{content.strip()}'")

    if "ROUTE_TO_HR" in content:
        return "hr_agent"
    if "ROUTE_TO_FINANCE" in content:
        return "finance_agent"
    if "ROUTE_TO_DEVOPS" in content:
        return "devops_agent"
    if "ROUTE_TO_CS" in content:
        return "customer_service_agent"
    return END


# --- Graph assembly ---

def build_workflow() -> StateGraph:
    """Builds the (uncompiled) graph topology. Kept separate so callers can
    compile with whatever checkpointer they need (or none, for Studio)."""
    workflow = StateGraph(EnterpriseState)
    workflow.add_node("orchestrator", orchestrator_node)
    workflow.add_node("hr_agent", hr_agent_node)
    workflow.add_node("finance_agent", finance_agent_node)
    workflow.add_node("devops_agent", devops_agent_node)
    workflow.add_node("customer_service_agent", customer_service_agent_node)

    workflow.add_edge(START, "orchestrator")
    workflow.add_conditional_edges(
        "orchestrator",
        route_decision,
        {
            "hr_agent": "hr_agent",
            "finance_agent": "finance_agent",
            "devops_agent": "devops_agent",
            "customer_service_agent": "customer_service_agent",
            END: END,
        },
    )
    for agent in ("hr_agent", "finance_agent", "devops_agent", "customer_service_agent"):
        workflow.add_edge(agent, END)
    return workflow


def build_graph(checkpointer=None):
    """Compile the canonical graph.

    Pass a checkpointer (e.g. SqliteSaver) for standalone runs that need
    persistence. Leave it None under `langgraph dev` — the LangGraph API server
    injects its own persistence and rejects a user-supplied checkpointer.
    """
    return build_workflow().compile(checkpointer=checkpointer)


# Module-level compiled graph for LangGraph Studio (no custom checkpointer).
graph = build_graph()
