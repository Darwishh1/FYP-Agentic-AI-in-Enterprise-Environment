from typing import Annotated, Sequence, TypedDict
from langchain_core.messages import BaseMessage

class SessionContext(TypedDict):
    session_id: str
    agent_role: str        # e.g., 'hr_agent', 'finance_agent'
    privilege_level: str   # 'LOW', 'MEDIUM', 'HIGH'
    tool_whitelist: list[str]
    call_count: int

class EnterpriseState(TypedDict):
    # Tracks the conversation history across the graph
    messages: Annotated[Sequence[BaseMessage], lambda x, y: x + y]
    # Tracks the security and operational metadata of the current session
    context: SessionContext