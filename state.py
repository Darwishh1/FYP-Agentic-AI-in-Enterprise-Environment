"""
Graph state schema.

SessionContext gained delegation fields. Without them the graph cannot express
a chain of agents handing work to each other, which means `cross_agent_hops`
(an Isolation Forest feature) and "multi-hop lateral movement" (an LSTM target)
are not just unimplemented but unrepresentable.
"""
from typing import Annotated, Sequence, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class SessionContext(TypedDict, total=False):
    session_id: str
    agent_role: str          # 'hr_agent', 'finance_agent', ...
    privilege_level: str     # 'LOW' | 'MEDIUM' | 'HIGH'
    tool_whitelist: list[str]
    call_count: int

    # --- delegation tracking ---
    delegation_source: str | None   # which agent handed work to this one
    delegation_path: list[str]      # ordered roles visited this session
    delegation_depth: int           # len(path) - 1, cached for the rule engine
    steps_remaining: int            # budget, prevents runaway agent loops

    # --- simulated clock & sliding window (RB-004) ---
    sim_time_seconds: float                     # monotonic sim clock for the session
    tool_call_timestamps: dict[str, list[float]]  # key="role:tool", value=list of sim times


class EnterpriseState(TypedDict):
    # add_messages handles message IDs and dedup properly. The previous
    # `lambda x, y: x + y` concatenated blindly, which double-appends on any
    # node retry and is not serialisable by the checkpointer.
    messages: Annotated[Sequence[BaseMessage], add_messages]
    context: SessionContext


def new_context(session_id: str, root_role: str = "orchestrator", steps: int = 6) -> SessionContext:
    """Build a fresh session context. Use this instead of hand-rolling the dict."""
    return {
        "session_id": session_id,
        "agent_role": root_role,
        "privilege_level": "LOW",
        "tool_whitelist": [],
        "call_count": 0,
        "delegation_source": None,
        "delegation_path": [root_role],
        "delegation_depth": 0,
        "steps_remaining": steps,
        "sim_time_seconds": 0.0,
        "tool_call_timestamps": {},
    }
