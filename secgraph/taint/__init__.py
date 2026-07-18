"""Taint engine: flow-sensitive intraprocedural taint (Phase 2); summary-based
interprocedural comes in Phase 3.

Deterministic; confidence + provenance on every finding. No graphify. See ROADMAP.md.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .engine import expr_taint, run_function, run_module
from .model import Finding, Origin

__all__ = [
    "run_function",
    "run_module",
    "expr_taint",
    "scan_project",
    "Finding",
    "Origin",
]


def scan_project(root: Path | str, rules=None) -> list[Finding]:
    """Build the IR for every ``.py`` under ``root`` and run intraprocedural taint.

    Loads the packaged rule packs by default. This is intraprocedural only (Phase 2):
    cross-function flows (the tiny fixture's get_user -> run_query) arrive in Phase 3.
    """
    from ..ir import build_project_ir
    from ..rules import default_rules_dir, load_rules

    if rules is None:
        rules = load_rules(default_rules_dir())

    findings: list[Finding] = []
    for module in build_project_ir(root):
        findings.extend(run_module(module, rules))
    return findings
