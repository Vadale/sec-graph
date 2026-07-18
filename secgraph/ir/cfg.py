"""Per-function control-flow graph and def-use chains over the IR.

Statement-level CFG (node ids are statement ``sid``s plus ENTRY/EXIT). ``break``/
``continue`` are wired to the enclosing loop's exit/header. Def-use is a classic forward
reaching-definitions fixpoint, so a use links to every definition that can reach it --
flow-sensitive, which is what the Phase-2 taint pass needs. Deterministic; no graphify.
"""
from __future__ import annotations

from typing import Optional

from .model import (
    ENTRY,
    EXIT,
    PARAM_SITE,
    Assign,
    Branch,
    CFG,
    Def,
    DefUse,
    ExprStmt,
    For,
    FunctionIR,
    If,
    ModuleIR,
    Return,
    Stmt,
    Unsupported,
    Use,
    While,
    iter_uses,
    iter_walrus_targets,
)

_BREAK = "break_statement"
_CONTINUE = "continue_statement"


def _sub_bodies(s: Stmt) -> list[list[Stmt]]:
    if isinstance(s, If):
        return [s.body, s.orelse]
    if isinstance(s, (While, For)):
        return [s.body]
    if isinstance(s, Branch):
        return list(s.arms)
    return []


def _stmt_exprs(s: Stmt) -> list:
    if isinstance(s, (Assign, ExprStmt)):
        return [s.value]
    if isinstance(s, Return):
        return [s.value] if s.value is not None else []
    if isinstance(s, (If, While)):
        return [s.test]
    if isinstance(s, For):
        return [s.iter]
    if isinstance(s, Unsupported):
        return list(s.uses)
    return []


def _def_vars(s: Stmt) -> list[str]:
    base: list[str] = []
    if isinstance(s, Assign):
        base = list(s.targets)
    elif isinstance(s, For):
        base = list(s.targets)
    for e in _stmt_exprs(s):        # walrus targets bound anywhere in the statement
        base += iter_walrus_targets(e)
    return base


def _stmt_uses(s: Stmt) -> list[tuple[str, object]]:
    out: list[tuple[str, object]] = []
    for e in _stmt_exprs(s):
        out += iter_uses(e)
    return out


# ---- CFG construction ------------------------------------------------------------

def build_cfg(fn: FunctionIR) -> CFG:
    succ: dict[int, list[int]] = {ENTRY: [], EXIT: []}
    stmt_of: dict[int, Stmt] = {}

    def register(stmts: list[Stmt]) -> None:
        for s in stmts:
            stmt_of[s.sid] = s
            succ.setdefault(s.sid, [])
            for body in _sub_bodies(s):
                register(body)

    register(fn.body)

    def link(a: int, b: int) -> None:
        if b not in succ[a]:
            succ[a].append(b)

    def is_kind(s: Stmt, kind: str) -> bool:
        return isinstance(s, Unsupported) and s.kind == kind

    def wire_seq(stmts: list[Stmt], after: int, loop: Optional[tuple[int, int]]) -> int:
        if not stmts:
            return after
        for i, s in enumerate(stmts):
            nxt = stmts[i + 1].sid if i + 1 < len(stmts) else after
            wire_stmt(s, nxt, loop)
        return stmts[0].sid

    def wire_stmt(s: Stmt, after: int, loop: Optional[tuple[int, int]]) -> None:
        if is_kind(s, _BREAK):
            link(s.sid, loop[1] if loop else after)   # loop exit
        elif is_kind(s, _CONTINUE):
            link(s.sid, loop[0] if loop else after)    # loop header
        elif isinstance(s, Return):
            link(s.sid, EXIT)
        elif isinstance(s, If):
            link(s.sid, wire_seq(s.body, after, loop))
            link(s.sid, wire_seq(s.orelse, after, loop))
        elif isinstance(s, Branch):
            if s.arms:
                for arm in s.arms:
                    link(s.sid, wire_seq(arm, after, loop))
            else:
                link(s.sid, after)
        elif isinstance(s, (While, For)):
            inner = (s.sid, after)                     # (header, exit)
            link(s.sid, wire_seq(s.body, s.sid, inner))
            link(s.sid, after)
        else:
            link(s.sid, after)

    link(ENTRY, wire_seq(fn.body, EXIT, None))
    return CFG(succ=succ, stmt_of=stmt_of, entry=ENTRY, exit=EXIT)


# ---- reaching definitions -> def-use ---------------------------------------------

def compute_defuse(fn: FunctionIR, cfg: CFG) -> DefUse:
    preds: dict[int, list[int]] = {n: [] for n in cfg.succ}
    for a, outs in cfg.succ.items():
        for b in outs:
            preds[b].append(a)

    gen: dict[int, set[tuple[str, int]]] = {n: set() for n in cfg.succ}
    killvars: dict[int, set[str]] = {n: set() for n in cfg.succ}
    gen[ENTRY] = {(p, PARAM_SITE) for p in fn.params}
    for sid, s in cfg.stmt_of.items():
        dv = _def_vars(s)
        gen[sid] = {(v, sid) for v in dv}
        killvars[sid] = set(dv)

    IN: dict[int, set[tuple[str, int]]] = {n: set() for n in cfg.succ}
    OUT: dict[int, set[tuple[str, int]]] = {n: set(gen[n]) for n in cfg.succ}

    worklist = list(cfg.succ.keys())
    while worklist:
        n = worklist.pop()
        new_in: set[tuple[str, int]] = set()
        for p in preds[n]:
            new_in |= OUT[p]
        IN[n] = new_in
        new_out = gen[n] | {(v, s) for (v, s) in new_in if v not in killvars[n]}
        if new_out != OUT[n]:
            OUT[n] = new_out
            worklist.extend(cfg.succ[n])

    defs = [Def(p, PARAM_SITE) for p in fn.params]
    for sid, s in cfg.stmt_of.items():
        for v in _def_vars(s):
            defs.append(Def(v, sid))

    uses: list[Use] = []
    for sid, s in cfg.stmt_of.items():
        for var, span in _stmt_uses(s):
            reaching = sorted({site for (v, site) in IN[sid] if v == var})
            uses.append(Use(var=var, at=sid, span=span, reaching=reaching))
    return DefUse(defs=defs, uses=uses)


def analyze_function(fn: FunctionIR) -> FunctionIR:
    fn.cfg = build_cfg(fn)
    fn.defuse = compute_defuse(fn, fn.cfg)
    return fn


def analyze_module(module: ModuleIR) -> ModuleIR:
    for fn in module.functions:
        analyze_function(fn)
    return module
