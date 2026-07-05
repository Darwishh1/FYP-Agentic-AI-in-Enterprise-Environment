"""
DEPRECATED — kept only as a compatibility shim.

The real graph now lives in graph.py (single source of truth). This module used
to hold its own diverging copy; that copy has been removed to stop the three-way
drift. Import from graph.py instead.
"""
from graph import build_graph, build_workflow, graph  # noqa: F401

# Backwards-compatible alias: older code did `from simulation_graph import app`.
app = graph
