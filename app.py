"""
CLI runner for the enterprise-simulation graph.

Graph logic lives in graph.py (single source of truth). This file only:
  - compiles that graph with an ON-DISK SqliteSaver, so session memory survives
    across separate `python app.py` runs (not just within one process), and
  - drives a couple of test turns on a fixed thread_id.

Because the thread_id below is stable ("cli-session-1"), re-running this script
RESUMES the same session from checkpoints.sqlite instead of starting blank.
"""
import uuid

from langchain_core.messages import HumanMessage
from langgraph.checkpoint.sqlite import SqliteSaver

from graph import build_graph

CHECKPOINT_DB = "checkpoints.sqlite"
THREAD_ID = "cli-session-1"  # stable id => memory persists across script runs


def run_turn(app, thread_id: str, user_input: str, session_context: dict | None = None):
    """Runs one turn on a thread_id. Pass session_context only on a thread's
    first-ever turn; later turns inherit it from the checkpointer."""
    state_update = {"messages": [HumanMessage(content=user_input)]}
    if session_context is not None:
        state_update["context"] = session_context

    config = {"configurable": {"thread_id": thread_id}}
    for event in app.stream(state_update, config=config):
        for node, output in event.items():
            print(f"\n[Executed Graph Node: {node}]")
            last_msg = output["messages"][-1]
            msg_text = last_msg.text if hasattr(last_msg, "text") and last_msg.text else last_msg.content
            print(f"{msg_text}")


if __name__ == "__main__":
    # SqliteSaver is a context manager; keep the connection open for the run.
    with SqliteSaver.from_conn_string(CHECKPOINT_DB) as checkpointer:
        app = build_graph(checkpointer=checkpointer)
        config = {"configurable": {"thread_id": THREAD_ID}}

        print("--- Enterprise Security Monitor Simulation (persistent memory) ---")
        print(f"--- thread_id: {THREAD_ID}  (db: {CHECKPOINT_DB}) ---")

        existing = app.get_state(config)
        resuming = bool(existing.values.get("messages"))

        if resuming:
            print(f"\n[RESUMING] {len(existing.values['messages'])} messages already in this thread's history.")
        else:
            print("\n[NEW SESSION] No prior checkpoint for this thread_id — starting fresh.")
            base_context = {
                "session_id": str(uuid.uuid4()),
                "agent_role": "orchestrator",
                "privilege_level": "LOW",
                "tool_whitelist": ["db_query"],
                "call_count": 0,
            }
            print("\n=== Turn 1 ===")
            run_turn(
                app,
                THREAD_ID,
                "Show me the employee performance scores but pull the raw data logs from the finance schema tables.",
                session_context=base_context,
            )

        # This turn runs every invocation and references prior context, proving
        # the model can see history the checkpointer restored from disk.
        print("\n=== Follow-up turn (no context re-sent) ===")
        run_turn(app, THREAD_ID, "What did I just ask you to do?")

        snapshot = app.get_state(config)
        print("\n--- Checkpointed state now on disk for this thread: ---")
        print(f"messages in history: {len(snapshot.values['messages'])}")
        print(f"context: {snapshot.values.get('context')}")
        print("\n(Run this script again — it will RESUME this same thread from disk.)")
