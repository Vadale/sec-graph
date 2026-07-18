"""Resolve each call site to a project function, with a strict precedence:

    rule (source/sink/sanitizer/propagator)  >  import  >  same-module local  >
    oracle singleton (graphify's deduped calls edges, disambiguation only)  >  unresolved

Imports beat the oracle: the import map is exact program semantics; the oracle is deduped
and lossy (docs/pitfalls.md #2) so it may only shrink an ambiguous candidate set to a
singleton, never invent a bind. One binding max per site => the SCC call graph and the
analysis never drift. Pure IR + rules; no graphify import here (the oracle arrives as a
plain dict built in the orchestration layer).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..ir.cfg import analyze_function
from ..ir.model import Attr, Call, FunctionIR, ModuleIR, Name, iter_calls, stmt_exprs
from ..rules.match import (
    match_propagator,
    match_sanitizer,
    match_sink,
    match_source,
    resolve_fqn,
)
from ..rules.model import Rules

FnKey = tuple[str, int]                 # (source_file, function start_line) -- the join key
SiteKey = tuple[int, int, int, int]     # a Call's Span (start_line, start_col, end_line, end_col)

_BUILTINS = frozenset({
    "int", "float", "str", "bytes", "bool", "len", "print", "range", "list", "dict",
    "set", "tuple", "repr", "format", "open", "isinstance", "getattr", "setattr", "super",
    "enumerate", "zip", "map", "filter", "sorted", "min", "max", "sum", "abs", "type",
})


@dataclass(frozen=True, slots=True)
class Binding:
    target: FnKey
    provenance: str    # "import" | "local" | "oracle"
    name: str          # callee function name (for the trace)


@dataclass(slots=True)
class FnIndex:
    fn_of: dict[FnKey, FunctionIR] = field(default_factory=dict)
    module_of: dict[str, ModuleIR] = field(default_factory=dict)
    by_fqn: dict[str, FnKey] = field(default_factory=dict)
    by_name: dict[str, list[FnKey]] = field(default_factory=dict)
    project_tops: frozenset = frozenset()


def module_name(source_file: str) -> str:
    """``pkg/db.py`` -> ``pkg.db``; ``pkg/__init__.py`` -> ``pkg``."""
    parts = source_file[:-3].split("/") if source_file.endswith(".py") else source_file.split("/")
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def site_key(call: Call) -> SiteKey:
    s = call.span
    return (s.start_line, s.start_col, s.end_line, s.end_col)


def fn_key(fn: FunctionIR) -> FnKey:
    return (fn.source_file, fn.span.start_line)


def _local_names(fn: FunctionIR) -> set[str]:
    if fn.defuse is None:
        analyze_function(fn)
    return set(fn.params) | {d.var for d in fn.defuse.defs}


def _shadow_imap(module: ModuleIR, fn: FunctionIR) -> dict[str, str]:
    locals_ = _local_names(fn)
    return {k: v for k, v in module.imports.items() if k not in locals_}


def _is_nested(fn: FunctionIR, others: list[FunctionIR]) -> bool:
    for o in others:
        if o is fn or o.source_file != fn.source_file:
            continue
        if o.span.start_line < fn.span.start_line and fn.span.end_line <= o.span.end_line:
            return True
    return False


def build_index(modules: list[ModuleIR]) -> FnIndex:
    idx = FnIndex()
    tops: set[str] = set()
    for module in modules:
        idx.module_of[module.source_file] = module
        tops.add(module_name(module.source_file).split(".", 1)[0])
        for fn in module.functions:
            idx.fn_of[fn_key(fn)] = fn
    idx.project_tops = frozenset(tops)

    for module in modules:
        mod_fqn = module_name(module.source_file)
        for fn in module.functions:
            key = fn_key(fn)
            idx.by_name.setdefault(fn.name, []).append(key)
            # module-global callables only: exclude nested defs and class methods from by_fqn
            if not _is_nested(fn, module.functions) and fn.enclosing_class is None:
                idx.by_fqn.setdefault(f"{mod_fqn}.{fn.name}", key)
    for name in idx.by_name:
        idx.by_name[name].sort()
    return idx


def classify_site(
    call: Call,
    fn: FunctionIR,
    module: ModuleIR,
    index: FnIndex,
    oracle: dict[FnKey, frozenset],
    rules: Rules,
) -> tuple[str, Optional[Binding]]:
    imap = _shadow_imap(module, fn)
    if (match_sink(call, imap, rules) or match_sanitizer(call, imap, rules)
            or match_propagator(call, imap, rules) or match_source(call, imap, rules)):
        return "rule", None

    f = call.func
    if isinstance(f, Name):
        if f.ident in _local_names(fn):
            return "unresolved", None                            # shadowed / callable variable
        if f.ident in module.imports:                            # `from db import run_query`
            fqn = module.imports[f.ident]
            k = index.by_fqn.get(fqn)
            if k is not None:
                return "bound-import", Binding(k, "import", index.fn_of[k].name)
            top = fqn.split(".", 1)[0]
            return ("external" if top not in index.project_tops else "unresolved"), None
        k = index.by_fqn.get(f"{module_name(module.source_file)}.{f.ident}")
        if k is not None:                                        # same-module module-global call
            return "bound-local", Binding(k, "local", index.fn_of[k].name)
        if f.ident in _BUILTINS:
            return "builtin", None
        return "unresolved", None

    if isinstance(f, Attr):
        fqn = resolve_fqn(f, imap)                              # `import db; db.run_query(...)`
        if fqn is not None:
            k = index.by_fqn.get(fqn)
            if k is not None:
                return "bound-import", Binding(k, "import", index.fn_of[k].name)
            top = fqn.split(".", 1)[0]
            if top in index.project_tops:
                return "unresolved", None                        # project path, fn not indexed (method/nested)
            return "external", None                              # stdlib / third-party
        cands = sorted(k for k in index.by_name.get(f.attr, ()) if k in oracle.get(fn_key(fn), frozenset()))
        if len(cands) == 1:
            return "bound-oracle", Binding(cands[0], "oracle", index.fn_of[cands[0]].name)
        return "unresolved", None

    return "unresolved", None


def resolve_all_sites(
    modules: list[ModuleIR],
    index: FnIndex,
    oracle: dict[FnKey, frozenset],
    rules: Rules,
) -> tuple[dict[FnKey, dict[SiteKey, Binding]], list[dict]]:
    """Returns (per-function resolved bindings, per-site rows for the stats/kill-gate)."""
    sites: dict[FnKey, dict[SiteKey, Binding]] = {}
    rows: list[dict] = []
    for module in modules:
        for fn in module.functions:
            fk = fn_key(fn)
            fn_sites: dict[SiteKey, Binding] = {}
            for stmt in fn.cfg.stmt_of.values() if fn.cfg else []:
                for expr in stmt_exprs(stmt):
                    for call in iter_calls(expr):
                        category, binding = classify_site(call, fn, module, index, oracle, rules)
                        if binding is not None:
                            fn_sites[site_key(call)] = binding
                        rows.append({
                            "file": fn.source_file,
                            "line": call.span.start_line,
                            "col": call.span.start_col,
                            "category": category,
                            "target": binding.name if binding else "",
                        })
            if fn_sites:
                sites[fk] = fn_sites
    rows.sort(key=lambda r: (r["file"], r["line"], r["col"]))
    return sites, rows


def binding_rate(rows: list[dict]) -> dict:
    """The KILL-GATE metric. gate = bound / (bound + unresolved); rule/external/builtin are
    excluded from the denominator (already semantically handled or not binding targets)."""
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    bound = counts.get("bound-import", 0) + counts.get("bound-local", 0) + counts.get("bound-oracle", 0)
    unresolved = counts.get("unresolved", 0)
    total = len(rows)
    gate = bound / (bound + unresolved) if (bound + unresolved) else 1.0
    accounted = (total - unresolved) / total if total else 1.0
    return {"counts": counts, "total": total, "bound": bound, "unresolved": unresolved,
            "gate_rate": gate, "accounted_rate": accounted}
