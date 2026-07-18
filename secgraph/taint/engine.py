"""Flow-sensitive taint over the IR: intraprocedural (Phase 2) plus, when a call context
is supplied, interprocedural via function summaries (Phase 3). Deterministic; no graphify.

Forward may-analysis over the CFG. Summaries are computed by SEEDING each parameter with a
synthetic param-origin and reusing this same fixpoint: every transfer is distributive over
origin-set union, so one run yields both the real findings (real-source origins at sinks)
and the conditional summary (param-origins at sinks/returns). ``expr_taint`` is PURE; all
finding/summary emission happens in the post-fixpoint scan, partitioned by
``Origin.param_index``.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from ..callgraph.resolve import site_key
from ..ir.cfg import analyze_function
from ..ir.model import (
    ENTRY,
    EXIT,
    Assign,
    Attr,
    BinOp,
    Call,
    For,
    Index,
    Literal,
    ModuleIR,
    Name,
    Return,
    Stmt,
    Unknown,
    Walrus,
    child_exprs,
    iter_calls,
    stmt_exprs,
)
from ..rules.match import match_propagator, match_sanitizer, match_sink, match_source
from ..rules.model import Rules
from .model import EMPTY_SUMMARY, Finding, Origin, SinkPoint, Summary

State = dict[str, frozenset]  # var name -> frozenset[Origin]

_CONF_ORDER = {"high": 3, "medium": 2, "low": 1}


def _min_conf(a: str, b: str) -> str:
    return a if _CONF_ORDER.get(a, 2) <= _CONF_ORDER.get(b, 2) else b


def _sink_param_key(item):
    """Total order for (param_index, SinkPoint) tuples (SinkPoint isn't orderable)."""
    i, sp = item
    return (i, sp.sink_id, sp.file, sp.function, sp.line, sp.via)


@dataclass(slots=True)
class TaintCtx:
    """What a taint run needs. With the defaults (no sites, no seeding) the run is byte-
    identical to Phase-2 intraprocedural taint."""

    imap: dict[str, str]
    rules: Rules
    summaries: dict = field(default_factory=dict)   # dict[FnKey, Summary] (read-only during a run)
    sites: dict = field(default_factory=dict)        # dict[SiteKey, Binding] for THIS function
    seed_params: bool = False


def _walrus_pairs(expr):
    if expr is None:
        return []
    out = [(expr.target, expr.value)] if isinstance(expr, Walrus) else []
    for c in child_exprs(expr):
        out += _walrus_pairs(c)
    return out


def expr_taint(expr, state: State, ctx: TaintCtx) -> frozenset:
    """The set of Origins tainting the value of ``expr`` under ``state``. Pure."""
    if expr is None or isinstance(expr, Literal):
        return frozenset()

    src = match_source(expr, ctx.imap, ctx.rules)
    if src is not None:
        return frozenset({Origin(src.id, src.layers, expr.span, src.confidence)})

    if isinstance(expr, Call):
        if match_sanitizer(expr, ctx.imap, ctx.rules) is not None:
            return frozenset()  # sanitizer clears its result
        prop = match_propagator(expr, ctx.imap, ctx.rules)
        if prop is not None:
            args = (
                expr.args
                if "any" in prop.from_args
                else [expr.args[i] for i in prop.from_args if isinstance(i, int) and i < len(expr.args)]
            )
            out = frozenset()
            for a in args:
                out |= expr_taint(a, state, ctx)
            return out
        binding = ctx.sites.get(site_key(expr))
        if binding is not None:                       # RESOLVED call -> use summary (even if bottom)
            summ = ctx.summaries.get(binding.target, EMPTY_SUMMARY)
            out = set(summ.return_origins)
            for i in sorted(summ.return_params):
                if i < len(expr.args):
                    out |= expr_taint(expr.args[i], state, ctx)
            return frozenset(out)
        # UNRESOLVED call -> over-approximate: tainted if receiver or any arg is
        out = expr_taint(expr.func, state, ctx)
        for a in expr.args:
            out |= expr_taint(a, state, ctx)
        return out

    if isinstance(expr, Name):
        return state.get(expr.ident, frozenset())
    if isinstance(expr, Attr):
        return expr_taint(expr.value, state, ctx)
    if isinstance(expr, Index):
        return expr_taint(expr.value, state, ctx) | expr_taint(expr.index, state, ctx)
    if isinstance(expr, BinOp):
        return expr_taint(expr.left, state, ctx) | expr_taint(expr.right, state, ctx)
    if isinstance(expr, Walrus):
        return expr_taint(expr.value, state, ctx)
    if isinstance(expr, Unknown):
        out = frozenset()
        for c in expr.children:
            out |= expr_taint(c, state, ctx)
        return out
    return frozenset()


def _transfer(stmt: Stmt, state: State, ctx: TaintCtx) -> State:
    new: State = dict(state)

    def _bind(names, value) -> None:
        t = expr_taint(value, state, ctx)
        for name in names:
            if t:
                new[name] = t
            else:
                new.pop(name, None)

    for e in stmt_exprs(stmt):
        for tgt, val in _walrus_pairs(e):
            _bind([tgt], val)
    if isinstance(stmt, Assign):
        _bind(stmt.targets, stmt.value)
    elif isinstance(stmt, For):
        _bind(stmt.targets, stmt.iter)
    return new


def _merge(states: list[State]) -> State:
    out: State = {}
    for s in states:
        for v, origins in s.items():
            out[v] = out.get(v, frozenset()) | origins
    return out


def _lift(sp: SinkPoint, callee: str, provenance: str) -> SinkPoint:
    via = sp.via if (callee in sp.via or len(sp.via) >= 8) else (callee, *sp.via)
    conf = _min_conf(sp.confidence, "medium") if provenance == "oracle" else sp.confidence
    return replace(sp, via=via, confidence=conf)


def _finding(fn, o: Origin, sp: SinkPoint) -> Finding:
    cross = sp.file != fn.source_file or bool(sp.via)
    parts = (fn.name, *sp.via, sp.function)
    trace = tuple(p for i, p in enumerate(parts) if i == 0 or p != parts[i - 1]) if cross else ()
    return Finding(
        function=fn.name,
        source_file=o.source_file or fn.source_file,
        source_id=o.source_id,
        source_line=o.span.start_line,
        sink_id=sp.sink_id,
        sink_line=sp.line,
        cwe=sp.cwe,
        severity=sp.severity,
        layers=tuple(sorted(set(o.layers) | set(sp.layers))),
        confidence=_min_conf(o.confidence, sp.confidence),
        sink_file=sp.file,
        sink_function=sp.function,
        trace=trace,
    )


def run_function_inter(fn, ctx: TaintCtx) -> tuple[list[Finding], Summary]:
    """One taint run: returns (findings, this function's summary). With ``ctx.seed_params``
    false and ``ctx.sites`` empty this reduces to intraprocedural taint."""
    if fn.cfg is None:
        analyze_function(fn)
    cfg = fn.cfg

    # Shadow-filter the import map for this function (a param/local named `request` is not
    # flask.request) -- same rule as call resolution, avoids false positives.
    local_names = set(fn.params) | {d.var for d in fn.defuse.defs}
    wctx = replace(ctx, imap={k: v for k, v in ctx.imap.items() if k not in local_names})

    seed: State = {}
    if ctx.seed_params:
        for i, p in enumerate(fn.params):
            seed[p] = frozenset({Origin(f"param:{i}", (), fn.span, "high",
                                        param_index=i, source_file=fn.source_file)})

    preds: dict[int, list[int]] = {n: [] for n in cfg.succ}
    for a, outs in cfg.succ.items():
        for b in outs:
            preds[b].append(a)

    IN: dict[int, State] = {n: {} for n in cfg.succ}
    OUT: dict[int, State] = {n: dict(seed) if n == ENTRY else {} for n in cfg.succ}

    worklist = list(cfg.succ.keys())
    while worklist:
        n = worklist.pop()
        merged = _merge([OUT[p] for p in preds[n]])
        IN[n] = merged
        if n == ENTRY:
            new_out = dict(seed)
        elif n == EXIT:
            new_out = merged
        else:
            new_out = _transfer(cfg.stmt_of[n], merged, wctx)
        if new_out != OUT[n]:
            OUT[n] = new_out
            worklist.extend(cfg.succ[n])

    findings: dict[tuple, Finding] = {}
    sink_params: set = set()
    return_params: set = set()
    return_origins: set = set()

    def _emit(o: Origin, sp: SinkPoint, pidx_target: set) -> None:
        if o.param_index is not None:
            pidx_target.add((o.param_index, sp))
        else:
            f = _finding(fn, o, sp)
            findings.setdefault(f.key, f)

    for sid, stmt in cfg.stmt_of.items():
        state = IN[sid]
        for expr in stmt_exprs(stmt):
            for call in iter_calls(expr):
                sink = match_sink(call, wctx.imap, wctx.rules)
                if sink is not None:                      # (A) a rule sink in THIS function
                    sp = SinkPoint(sink.id, sink.cwe, sink.severity, sink.layers,
                                   sink.confidence, fn.source_file, fn.name, call.span.start_line)
                    for i in sink.taint_args:
                        if i < len(call.args):
                            for o in expr_taint(call.args[i], state, wctx):
                                _emit(o, sp, sink_params)
                binding = wctx.sites.get(site_key(call))
                if binding is not None:                   # (B) a summarized callee's sinks
                    summ_sinks = sorted(
                        wctx.summaries.get(binding.target, EMPTY_SUMMARY).sink_params,
                        key=_sink_param_key,
                    )
                    for i, sp in summ_sinks:
                        if i < len(call.args):
                            sp2 = _lift(sp, binding.name, binding.provenance)
                            for o in expr_taint(call.args[i], state, wctx):
                                _emit(o, sp2, sink_params)
        if isinstance(stmt, Return) and stmt.value is not None:    # (C) return facts
            for o in expr_taint(stmt.value, IN[sid], wctx):
                if o.param_index is not None:
                    return_params.add(o.param_index)
                else:
                    return_origins.add(o if o.source_file else replace(o, source_file=fn.source_file))

    summary = Summary(frozenset(return_params), frozenset(return_origins), frozenset(sink_params))
    return sorted(findings.values(), key=lambda f: f.key), summary


def run_function(fn, imap: dict[str, str], rules: Rules) -> list[Finding]:
    """Intraprocedural taint (public, unchanged): no summaries, params untainted."""
    return run_function_inter(fn, TaintCtx(imap=imap, rules=rules))[0]


def run_module(module: ModuleIR, rules: Rules) -> list[Finding]:
    findings: list[Finding] = []
    for fn in module.functions:
        findings.extend(run_function(fn, module.imports, rules))
    return findings
