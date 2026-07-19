"""Taint engine: flow-sensitive intraprocedural taint (Phase 2) + summary-based
interprocedural taint (Phase 3).

Deterministic; confidence + provenance on every finding. No graphify. See ROADMAP.md.
"""
from __future__ import annotations

from pathlib import Path

from .engine import (
    TaintCtx,
    expr_taint,
    find_unguarded_sinks,
    run_function,
    run_function_inter,
    run_module,
)
from .interproc import run_project, run_project_full
from .model import EMPTY_SUMMARY, Finding, Origin, SinkPoint, Summary

__all__ = [
    "run_function",
    "run_function_inter",
    "run_module",
    "run_project",
    "run_project_full",
    "expr_taint",
    "find_unguarded_sinks",
    "scan_project",
    "TaintCtx",
    "Finding",
    "Origin",
    "SinkPoint",
    "Summary",
]


def scan_project(root: Path | str, rules=None, oracle: dict | None = None) -> list[Finding]:
    """Build the IR for every ``.py`` under ``root`` and run interprocedural taint.

    Loads the packaged rule packs by default. Cross-function flows (the tiny fixture's
    get_user -> run_query SQLi) are found here. ``oracle`` (graphify's resolved calls,
    built in the orchestration layer) is optional -- import/local resolution alone already
    binds the common cases.
    """
    from ..ir import build_project_ir
    from ..rules import default_rules_dir, load_rules

    if rules is None:
        rules = load_rules(default_rules_dir())
    return run_project(build_project_ir(root), rules, oracle=oracle)
