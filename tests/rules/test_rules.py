"""Rules loader + matcher tests (FQN resolution, method-name vs FQN sinks)."""
from __future__ import annotations

from secgraph.ir.model import Attr, Call, Index, Name, Span
from secgraph.rules import (
    default_rules_dir,
    load_rules,
    match_sanitizer,
    match_sink,
    match_source,
    resolve_fqn,
)

RULES = load_rules(default_rules_dir())
S = Span(1, 0, 1, 0)


def _n(x: str) -> Name:
    return Name(x, S)


def _a(v, attr: str) -> Attr:
    return Attr(v, attr, S)


def _c(func, args) -> Call:
    return Call(func, args, S)


def test_rules_load_expected_ids() -> None:
    assert {"flask-request-input", "env-secret"} <= {r.id for r in RULES.sources}
    assert {"py-sql-exec", "py-os-command"} <= {r.id for r in RULES.sinks}
    assert "int-coerce" in {r.id for r in RULES.sanitizers}


def test_resolve_fqn_via_import_map() -> None:
    imap = {"request": "flask.request", "os": "os"}
    assert resolve_fqn(_a(_n("request"), "args"), imap) == "flask.request.args"
    assert resolve_fqn(_a(_n("os"), "system"), imap) == "os.system"


def test_match_source_attribute_and_subscript() -> None:
    imap = {"request": "flask.request"}
    expr = Index(_a(_n("request"), "args"), _n("id"), S)  # request.args["id"]
    rule = match_source(expr, imap, RULES)
    assert rule is not None and rule.id == "flask-request-input"


def test_match_sink_method_name_duck_typed() -> None:
    # cur.execute(q): matched by ".execute" method name, no receiver resolution needed
    expr = _c(_a(_n("cur"), "execute"), [_n("q")])
    rule = match_sink(expr, {}, RULES)
    assert rule is not None and rule.id == "py-sql-exec" and rule.cwe == "CWE-89"


def test_match_sink_fqn() -> None:
    expr = _c(_a(_n("os"), "system"), [_n("c")])
    rule = match_sink(expr, {"os": "os"}, RULES)
    assert rule is not None and rule.id == "py-os-command" and rule.cwe == "CWE-78"


def test_match_sanitizer_bare_builtin() -> None:
    expr = _c(_n("int"), [_n("x")])
    rule = match_sanitizer(expr, {}, RULES)
    assert rule is not None and rule.id == "int-coerce"
