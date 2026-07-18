"""Intraprocedural flow-sensitive taint over the IR. Deterministic; no graphify.

Forward may-analysis: each variable's taint state is a ``frozenset[Origin]``. Sources
introduce origins; assignments propagate or kill; sanitizer calls clear their result;
propagators pass taint from selected args; any other call over-approximates (result is
tainted if the receiver or any argument is). A sink call whose taint-carrying argument is
tainted yields a ``Finding``. The fixpoint is a standard worklist over the CFG, so a
value tainted on any path reaches the sink (flow-sensitive, sound-for-may).
"""
from __future__ import annotations

from typing import Optional

from ..ir.model import (
    ENTRY,
    EXIT,
    Assign,
    Attr,
    BinOp,
    Call,
    Expr,
    ExprStmt,
    For,
    If,
    Index,
    Literal,
    ModuleIR,
    Name,
    Return,
    Stmt,
    Unknown,
    Unsupported,
    Walrus,
    While,
    child_exprs,
    iter_calls,
)
from ..ir.cfg import analyze_function
from ..rules.match import match_propagator, match_sanitizer, match_sink, match_source
from ..rules.model import Rules
from .model import Finding, Origin

State = dict[str, frozenset]  # var name -> frozenset[Origin]

_CONF_ORDER = {"high": 3, "medium": 2, "low": 1}


def _min_conf(a: str, b: str) -> str:
    return a if _CONF_ORDER.get(a, 2) <= _CONF_ORDER.get(b, 2) else b


def _stmt_exprs(s: Stmt) -> list[Optional[Expr]]:
    if isinstance(s, (Assign, ExprStmt)):
        return [s.value]
    if isinstance(s, Return):
        return [s.value] if s.value is not None else []
    if isinstance(s, (If, While)):
        return [s.test]
    if isinstance(s, For):
        return [s.iter]
    if isinstance(s, Unknown):
        return list(s.children)
    if isinstance(s, Unsupported):
        return list(s.uses)
    return []


def _walrus_pairs(expr: Optional[Expr]) -> list[tuple[str, Expr]]:
    if expr is None:
        return []
    out = [(expr.target, expr.value)] if isinstance(expr, Walrus) else []
    for c in child_exprs(expr):
        out += _walrus_pairs(c)
    return out


def expr_taint(expr: Optional[Expr], state: State, imap: dict[str, str], rules: Rules) -> frozenset:
    """The set of Origins tainting the value of ``expr`` under ``state``."""
    if expr is None or isinstance(expr, Literal):
        return frozenset()

    src = match_source(expr, imap, rules)
    if src is not None:
        return frozenset({Origin(src.id, src.layers, expr.span, src.confidence)})

    if isinstance(expr, Call):
        if match_sanitizer(expr, imap, rules) is not None:
            return frozenset()  # sanitizer clears its result
        prop = match_propagator(expr, imap, rules)
        if prop is not None:
            args = (
                expr.args
                if "any" in prop.from_args
                else [expr.args[i] for i in prop.from_args if isinstance(i, int) and i < len(expr.args)]
            )
            out = frozenset()
            for a in args:
                out |= expr_taint(a, state, imap, rules)
            return out
        # unknown call: propagate taint of receiver + args (over-approximation)
        out = expr_taint(expr.func, state, imap, rules)
        for a in expr.args:
            out |= expr_taint(a, state, imap, rules)
        return out

    if isinstance(expr, Name):
        return state.get(expr.ident, frozenset())
    if isinstance(expr, Attr):
        return expr_taint(expr.value, state, imap, rules)
    if isinstance(expr, Index):
        return expr_taint(expr.value, state, imap, rules) | expr_taint(expr.index, state, imap, rules)
    if isinstance(expr, BinOp):
        return expr_taint(expr.left, state, imap, rules) | expr_taint(expr.right, state, imap, rules)
    if isinstance(expr, Walrus):
        return expr_taint(expr.value, state, imap, rules)
    if isinstance(expr, Unknown):
        out = frozenset()
        for c in expr.children:
            out |= expr_taint(c, state, imap, rules)
        return out
    return frozenset()


def _transfer(stmt: Stmt, state: State, imap: dict[str, str], rules: Rules) -> State:
    new: State = dict(state)

    def _bind(names, value: Optional[Expr]) -> None:
        t = expr_taint(value, state, imap, rules)
        for name in names:
            if t:
                new[name] = t
            else:
                new.pop(name, None)

    for e in _stmt_exprs(stmt):                       # walrus defs anywhere in the stmt
        for tgt, val in _walrus_pairs(e):
            _bind([tgt], val)

    if isinstance(stmt, Assign):
        _bind(stmt.targets, stmt.value)
    elif isinstance(stmt, For):
        _bind(stmt.targets, stmt.iter)                # loop var carries the iterable's taint
    return new


def _merge(states: list[State]) -> State:
    out: State = {}
    for s in states:
        for v, origins in s.items():
            out[v] = out.get(v, frozenset()) | origins
    return out


def run_function(fn, imap: dict[str, str], rules: Rules) -> list[Finding]:
    """Intraprocedural taint on one function. Parameters start untainted (Phase 3 will
    seed tainted parameters via interprocedural summaries)."""
    if fn.cfg is None:
        analyze_function(fn)
    cfg = fn.cfg

    # Don't remap import names shadowed by a parameter or a local assignment: a param
    # named `request` is NOT flask.request. Avoids false positives (reviewer WP2 #4).
    local_names = set(fn.params) | {d.var for d in fn.defuse.defs}
    imap = {k: v for k, v in imap.items() if k not in local_names}

    preds: dict[int, list[int]] = {n: [] for n in cfg.succ}
    for a, outs in cfg.succ.items():
        for b in outs:
            preds[b].append(a)

    IN: dict[int, State] = {n: {} for n in cfg.succ}
    OUT: dict[int, State] = {n: {} for n in cfg.succ}

    worklist = list(cfg.succ.keys())
    while worklist:
        n = worklist.pop()
        merged = _merge([OUT[p] for p in preds[n]])
        IN[n] = merged
        new_out = merged if n in (ENTRY, EXIT) else _transfer(cfg.stmt_of[n], merged, imap, rules)
        if new_out != OUT[n]:
            OUT[n] = new_out
            worklist.extend(cfg.succ[n])

    findings: dict[tuple, Finding] = {}
    for sid, stmt in cfg.stmt_of.items():
        state = IN[sid]
        for expr in _stmt_exprs(stmt):
            for call in iter_calls(expr):
                sink = match_sink(call, imap, rules)
                if sink is None:
                    continue
                for i in sink.taint_args:
                    if i >= len(call.args):
                        continue
                    for origin in expr_taint(call.args[i], state, imap, rules):
                        f = Finding(
                            function=fn.name,
                            source_file=fn.source_file,
                            source_id=origin.source_id,
                            source_line=origin.span.start_line,
                            sink_id=sink.id,
                            sink_line=call.span.start_line,
                            cwe=sink.cwe,
                            severity=sink.severity,
                            layers=tuple(sorted(set(origin.layers) | set(sink.layers))),
                            confidence=_min_conf(origin.confidence, sink.confidence),
                        )
                        findings[f.key] = f

    return sorted(findings.values(), key=lambda f: f.key)  # f.key is a total order (dedup key)


def run_module(module: ModuleIR, rules: Rules) -> list[Finding]:
    findings: list[Finding] = []
    for fn in module.functions:
        findings.extend(run_function(fn, module.imports, rules))
    return findings
