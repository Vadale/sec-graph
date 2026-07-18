"""Match IR expressions against rules, resolving names via a module's import map.

Matching is by resolved FQN (``request`` -> ``flask.request``, ``os.system``) or by
call shape: a callee entry starting with ``.`` (e.g. ``.execute``) is a duck-typed
method-name match on any receiver -- which is how we catch ``cursor.execute(q)`` without
resolving the receiver's type (docs/pitfalls.md #3). No graphify here.
"""
from __future__ import annotations

from typing import Optional

from ..ir.model import Attr, Call, Index, Name
from .model import PropagatorRule, Rules, SanitizerRule, SinkRule, SourceRule


def resolve_fqn(expr, imap: dict[str, str]) -> Optional[str]:
    """Resolve a Name/Attr chain to a fully-qualified name using the import map."""
    if isinstance(expr, Name):
        return imap.get(expr.ident, expr.ident)
    if isinstance(expr, Attr):
        base = resolve_fqn(expr.value, imap)
        return f"{base}.{expr.attr}" if base else None
    return None


def _method_name(call: Call) -> Optional[str]:
    return call.func.attr if isinstance(call.func, Attr) else None


def _call_matches(call: Call, imap: dict[str, str], callee_list: tuple[str, ...]) -> bool:
    method = _method_name(call)
    fqn = resolve_fqn(call.func, imap)
    for entry in callee_list:
        if entry.startswith("."):
            if method is not None and method == entry[1:]:
                return True
        elif fqn is not None and fqn == entry:
            return True
    return False


def match_source(expr, imap: dict[str, str], rules: Rules) -> Optional[SourceRule]:
    if isinstance(expr, Index):                       # request.args["id"] -> match request.args
        return match_source(expr.value, imap, rules)
    if isinstance(expr, Attr):
        base_fqn = resolve_fqn(expr.value, imap)
        for r in rules.sources:
            if (r.kind in ("attribute-read", "subscript-read")
                    and r.base is not None and base_fqn == r.base
                    and expr.attr in r.attributes):
                return r
        return None
    if isinstance(expr, Call):
        fqn = resolve_fqn(expr.func, imap)
        for r in rules.sources:
            if r.kind == "call" and fqn is not None and fqn in r.callee:
                return r
        return None
    return None


def _first_call_match(call: Call, imap: dict[str, str], candidates):
    """First rule in ``candidates`` whose callee matches ``call`` (None if none match)."""
    for r in candidates:
        if r.kind == "call" and _call_matches(call, imap, r.callee):
            return r
    return None


def match_sink(call: Call, imap: dict[str, str], rules: Rules) -> Optional[SinkRule]:
    return _first_call_match(call, imap, rules.sinks)


def match_sanitizer(call: Call, imap: dict[str, str], rules: Rules) -> Optional[SanitizerRule]:
    return _first_call_match(call, imap, rules.sanitizers)


def match_propagator(call: Call, imap: dict[str, str], rules: Rules) -> Optional[PropagatorRule]:
    return _first_call_match(call, imap, rules.propagators)
