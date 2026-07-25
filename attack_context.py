"""
Thread-safe context for tagging tool-call records with red-team ground truth.

The runner sets the attack label before executing a scenario; guarded_tool_call()
reads it when building a ToolCallRecord. Normal (non-red-team) operation leaves
the default (False, None) in place.

Uses contextvars so it stays safe if the graph ever runs with asyncio or threads.
"""
from __future__ import annotations

from contextvars import ContextVar

_is_attack: ContextVar[bool] = ContextVar("_is_attack", default=False)
_attack_id: ContextVar[str | None] = ContextVar("_attack_id", default=None)


def set_attack_label(attack_id: str) -> None:
    """Mark all subsequent tool-call records as attack ground truth."""
    _is_attack.set(True)
    _attack_id.set(attack_id)


def clear_attack_label() -> None:
    """Reset to normal (non-attack) mode."""
    _is_attack.set(False)
    _attack_id.set(None)


def get_attack_label() -> tuple[bool, str | None]:
    """Return (is_attack, attack_id) for the current context."""
    return _is_attack.get(), _attack_id.get()
