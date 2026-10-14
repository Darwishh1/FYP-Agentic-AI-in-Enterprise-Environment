"""Text heuristics used by the rule engine.

Moved out of mock_tools.py: the rule engine (security_monitor.py) imported its
injection heuristic from the tool mocks, so Layer 3 depended on the simulated
environment it is supposed to be judging. mock_tools re-exports the name for
backwards compatibility.
"""
from __future__ import annotations

import re

_INSTRUCTION_PATTERNS = [
    r"ignore (all |the )?(previous|prior|above) instructions",
    r"disregard (your|the) (rules|policy|instructions)",
    r"you are now",
    r"act as",
    r"system prompt",
]


def contains_instruction_pattern(text: str) -> bool:
    """Heuristic used by the rule layer (RB-005): does this text look like an
    injected natural-language instruction rather than a normal tool argument?"""
    if not text:
        return False
    return any(re.search(p, text, re.IGNORECASE) for p in _INSTRUCTION_PATTERNS)
