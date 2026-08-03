"""
Thread-safe context for tagging tool-call records with red-team ground truth.

The runner sets the attack label before executing a scenario; guarded_tool_call()
reads it when building a ToolCallRecord. Normal (non-red-team) operation leaves
the default (False, None) in place.

Uses contextvars so it stays safe if the graph ever runs with asyncio or threads.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

_is_attack: ContextVar[bool] = ContextVar("_is_attack", default=False)
_attack_id: ContextVar[str | None] = ContextVar("_attack_id", default=None)


def set_attack_label(attack_id: str, is_attack: bool = True) -> None:
    """Label subsequent tool-call records with red-team ground truth.

    *is_attack* is the ground truth about the input, not a prediction about the
    verdict. A benign control still carries its scenario id, so its records can be
    traced back, but must be labelled is_attack=False — it is a true negative, and
    counting it as a positive is what makes a false-positive rate meaningless.
    """
    _is_attack.set(is_attack)
    _attack_id.set(attack_id)


def clear_attack_label() -> None:
    """Reset to normal (non-attack) mode."""
    _is_attack.set(False)
    _attack_id.set(None)


@contextmanager
def attack_label(attack_id: str, is_attack: bool = True) -> Iterator[None]:
    """Scope the ground-truth label to a block, restoring whatever was set before.

    Prefer this over the bare setters. It resets via contextvar tokens rather than
    clearing to the default, so a scenario running inside another labelled scope
    cannot silently strip the outer label on the way out.
    """
    tok_flag = _is_attack.set(is_attack)
    tok_id = _attack_id.set(attack_id)
    try:
        yield
    finally:
        _is_attack.reset(tok_flag)
        _attack_id.reset(tok_id)


def get_attack_label() -> tuple[bool, str | None]:
    """Return (is_attack, attack_id) for the current context."""
    return _is_attack.get(), _attack_id.get()
