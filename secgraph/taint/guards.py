"""Auth-barrier detection for the unguarded-sink finding (WP-C2). Pure, graphify-free.

``guard_map(fn, imap, rules)`` returns, per statement ``sid``, the auth guards in scope there:
  * **B1** decorators on the function (``@login_required``) guard every statement;
  * **B2** a statement inside an ``if`` arm the auth condition dominates
    (``if user.is_admin: sink()``);
  * **B3** a statement after an auth gate whose *failure* arm terminates
    (``if not authed: abort(); sink()``).

Soundness first: a false "guarded" hides an unguarded sink (a security false negative), so we only
credit an auth term when the boolean structure PROVES it holds on the path. ``_true_guards`` /
``_false_guards`` compute the auth terms guaranteed true when a test is truthy / falsy, threading
polarity through ``and`` / ``or`` / ``not`` (De Morgan). A term merely mentioned under an ``or``, a
comparison, or as a call argument credits nothing (safe under-claim -> we over-report unguarded).
"""
from __future__ import annotations

from typing import Optional

from ..ir.model import (
    Attr,
    BinOp,
    Branch,
    Call,
    ExprStmt,
    For,
    If,
    Name,
    Return,
    Unknown,
    Unsupported,
    While,
)
from ..rules.match import resolve_fqn
from ..rules.model import Rules


def _callee_name(func) -> Optional[str]:
    if isinstance(func, Attr):
        return func.attr
    if isinstance(func, Name):
        return func.ident
    return None


def _auth_term(expr, rules: Rules) -> Optional[str]:
    """The auth term iff ``expr`` AS A WHOLE is an auth test -- an auth attribute read or a guard-
    callable call. A term nested inside a comparison or as a call argument returns None."""
    if isinstance(expr, Attr) and expr.attr in rules.barriers.test_attrs:
        return expr.attr
    if isinstance(expr, Call):
        name = _callee_name(expr.func)
        if name in rules.barriers.callables:
            return name
    return None


def _true_guards(expr, rules: Rules) -> frozenset:
    """Auth terms guaranteed true whenever ``expr`` is truthy."""
    term = _auth_term(expr, rules)
    if term is not None:
        return frozenset({term})
    if isinstance(expr, Unknown) and expr.kind == "not_operator" and expr.children:
        return _false_guards(expr.children[0], rules)
    if isinstance(expr, BinOp) and expr.op == "and":
        return _true_guards(expr.left, rules) | _true_guards(expr.right, rules)
    if isinstance(expr, BinOp) and expr.op == "or":
        return _true_guards(expr.left, rules) & _true_guards(expr.right, rules)
    return frozenset()


def _false_guards(expr, rules: Rules) -> frozenset:
    """Auth terms guaranteed true whenever ``expr`` is falsy (dual of ``_true_guards``)."""
    if isinstance(expr, Unknown) and expr.kind == "not_operator" and expr.children:
        return _true_guards(expr.children[0], rules)
    if isinstance(expr, BinOp) and expr.op == "and":     # ¬(A∧B) = ¬A ∨ ¬B -> guaranteed in both
        return _false_guards(expr.left, rules) & _false_guards(expr.right, rules)
    if isinstance(expr, BinOp) and expr.op == "or":      # ¬(A∨B) = ¬A ∧ ¬B -> union
        return _false_guards(expr.left, rules) | _false_guards(expr.right, rules)
    return frozenset()


def _terminates(stmts, imap: dict[str, str], rules: Rules) -> bool:
    """The block cannot fall through -- its last statement returns, raises, or aborts."""
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, Return):
        return True
    if isinstance(last, Unsupported) and last.kind == "raise_statement":
        return True
    if isinstance(last, ExprStmt) and isinstance(last.value, Call):
        func = last.value.func
        if _callee_name(func) in rules.barriers.aborts or resolve_fqn(func, imap) in rules.barriers.aborts:
            return True
    return False


def _walk(stmts, active: frozenset, out: dict[int, tuple[str, ...]],
          imap: dict[str, str], rules: Rules) -> None:
    running = set(active)
    for s in stmts:
        out[s.sid] = tuple(sorted(running))
        if isinstance(s, If):
            t_true = _true_guards(s.test, rules)
            t_false = _false_guards(s.test, rules)
            _walk(s.body, frozenset(running | t_true), out, imap, rules)     # B2: arm the test dominates
            _walk(s.orelse, frozenset(running | t_false), out, imap, rules)
            if _terminates(s.body, imap, rules):        # B3: failure arm dies -> survivors took the other
                running |= t_false
            if _terminates(s.orelse, imap, rules):
                running |= t_true
        elif isinstance(s, (While, For)):
            _walk(s.body, frozenset(running), out, imap, rules)
        elif isinstance(s, Branch):
            for arm in s.arms:
                _walk(arm, frozenset(running), out, imap, rules)


def guard_map(fn, imap: dict[str, str], rules: Rules) -> dict[int, tuple[str, ...]]:
    """``sid`` -> auth guards in scope at that statement (empty tuple where absent)."""
    base = frozenset(d for d in fn.decorators if d in rules.barriers.decorators)      # B1
    out: dict[int, tuple[str, ...]] = {}
    _walk(fn.body, base, out, imap, rules)
    return out
