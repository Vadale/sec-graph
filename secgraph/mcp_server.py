"""Our own MCP server (stdio): list_paths, get_path_slice, find_unguarded_sinks,
explain_layer, get_function_taint. Reads graph.json + taint.json.

Run alongside ``graphify --mcp``. See ROADMAP.md Phase 6.
"""
from __future__ import annotations
