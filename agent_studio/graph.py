"""
DEPRECATED — compatibility shim only.

The canonical graph now lives in ../graph.py. This file previously held a stale,
simplified copy (no security monitor). Studio should use the ROOT langgraph.json,
which points at ./graph.py:graph. This shim re-exports the canonical graph so any
old reference here stays in sync instead of drifting.
"""
import os
import sys

# Make the project root importable so we can re-export the canonical graph.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from graph import build_graph, build_workflow, graph  # noqa: E402,F401
