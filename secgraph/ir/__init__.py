"""Statement/variable-level IR: tree-sitter re-parse -> per-function CFG + def-use.

No graphify imports here (quarantine wall). Public API:

    build_module_ir(path[, source_file])   -> one analyzed ModuleIR (cfg + def-use)
    build_project_ir(root)                  -> [ModuleIR] for every .py under root
    join_functions / join_modules           -> attach graphify node ids (caller passes
                                               the nodes, fetched via the adapter)

See ROADMAP.md Phase 1.
"""
from __future__ import annotations

from pathlib import Path

from .cfg import analyze_function, analyze_module, build_cfg, compute_defuse
from .join import join_functions, join_modules
from .lower import lower_file, lower_source
from .model import (
    AccessPath,
    Assign,
    Attr,
    BinOp,
    Call,
    CFG,
    Def,
    DefUse,
    Expr,
    ExprStmt,
    For,
    FunctionIR,
    If,
    Index,
    Literal,
    ModuleIR,
    Name,
    Return,
    Span,
    Stmt,
    Unknown,
    Unsupported,
    Use,
    While,
    access_path,
    iter_uses,
)

__all__ = [
    "build_module_ir",
    "build_project_ir",
    "lower_file",
    "lower_source",
    "analyze_function",
    "analyze_module",
    "build_cfg",
    "compute_defuse",
    "join_functions",
    "join_modules",
    # model
    "AccessPath", "Assign", "Attr", "BinOp", "Call", "CFG", "Def", "DefUse", "Expr",
    "ExprStmt", "For", "FunctionIR", "If", "Index", "Literal", "ModuleIR", "Name",
    "Return", "Span", "Stmt", "Unknown", "Unsupported", "Use", "While",
    "access_path", "iter_uses",
]


def build_module_ir(path: Path | str, source_file: str | None = None) -> ModuleIR:
    """Lower one Python file and compute per-function CFG + def-use."""
    module = lower_file(path, source_file)
    analyze_module(module)
    return module


_SKIP_DIRS = {
    ".venv", "venv", "env", ".env", "site-packages", "__pycache__", "node_modules",
    ".git", "build", "dist", "graphify-out", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".eggs",
}


def build_project_ir(root: Path | str) -> list[ModuleIR]:
    """Build analyzed IR for every ``.py`` under ``root`` (skipping virtualenvs, caches,
    and hidden dirs), stamping ``source_file`` relative to ``root`` (POSIX separators) so
    it matches graphify's node keys for the join.

    Note: this walks the filesystem directly. When the CLI wires IR to graphify (Phase 4),
    the authoritative file set should come from the adapter's ``detect_files`` (graphify's
    own ignore rules), sharing one ``root`` so the join never desyncs.
    """
    root = Path(root)
    modules: list[ModuleIR] = []
    for py in sorted(root.rglob("*.py")):
        dirs = py.relative_to(root).parts[:-1]
        if any(d in _SKIP_DIRS or d.startswith(".") for d in dirs):
            continue
        modules.append(build_module_ir(py, py.relative_to(root).as_posix()))
    return modules
