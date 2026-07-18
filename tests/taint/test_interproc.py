"""Interprocedural taint tests: cross-file findings, summary correctness (source-wrapper,
sanitizer-wrapper, param-kill), recursion termination, superset invariant, determinism,
and the call-site binding-rate (KILL-GATE) metric."""
from __future__ import annotations

from pathlib import Path

from secgraph.callgraph import binding_rate, build_index, resolve_all_sites
from secgraph.ir import analyze_module, build_project_ir, lower_source
from secgraph.rules import default_rules_dir, load_rules
from secgraph.taint import run_module, run_project

RULES = load_rules(default_rules_dir())
TINY = Path(__file__).resolve().parents[1] / "fixtures" / "tiny"
INTRA = Path(__file__).resolve().parents[1] / "fixtures" / "intra"


def _modules(files: dict[str, bytes]):
    return [analyze_module(lower_source(src, name)) for name, src in files.items()]


def _scan(files: dict[str, bytes]):
    return run_project(_modules(files), RULES)


def test_cross_file_sqli_found_with_trace() -> None:
    findings = run_project(build_project_ir(TINY), RULES)
    sqli = [f for f in findings if f.sink_id == "py-sql-exec"]
    assert len(sqli) == 1
    f = sqli[0]
    assert (f.source_id, f.source_file, f.source_line) == ("flask-request-input", "app.py", 17)
    assert (f.sink_file, f.sink_function, f.sink_line) == ("db.py", "run_query", 12)
    assert f.cwe == "CWE-89"
    assert "run_query" in f.trace and "get_user" in f.trace


def test_interproc_is_superset_of_intra() -> None:
    modules = build_project_ir(INTRA)
    intra = {f.key for m in modules for f in run_module(m, RULES)}
    inter = {f.key for f in run_project(modules, RULES)}
    assert intra <= inter


def test_source_wrapper_via_return_origins() -> None:
    fs = _scan({
        "a.py": b"from flask import request\ndef get_uid():\n    return request.args['id']\n",
        "b.py": b"from a import get_uid\ndef q(cur):\n    cur.execute(get_uid())\n",
    })
    assert any(f.sink_id == "py-sql-exec" and f.source_id == "flask-request-input" for f in fs)


def test_sanitizer_wrapper_cleans_across_call() -> None:
    fs = _scan({
        "a.py": b"def clean(x):\n    return int(x)\n",
        "b.py": (b"from flask import request\nfrom a import clean\n"
                 b"def q(cur):\n    uid = clean(request.args['id'])\n    cur.execute(uid)\n"),
    })
    assert fs == []   # the summarized sanitizer-wrapper removes the taint (precision win)


def test_param_reassigned_before_sink_no_finding() -> None:
    fs = _scan({
        "a.py": b"def f(x, cur):\n    x = ''\n    cur.execute(x)\n",
        "b.py": (b"from flask import request\nfrom a import f\n"
                 b"def q(cur):\n    f(request.args['id'], cur)\n"),
    })
    assert fs == []   # x is reassigned before the sink -> param never reaches it


def test_recursion_terminates() -> None:
    # self-recursive function must reach a summary fixpoint (no hang / no cap breach)
    fs = _scan({"a.py": b"def rec(n, cur):\n    if n:\n        rec(n, cur)\n    cur.execute(n)\n"})
    assert isinstance(fs, list)


def test_interproc_deterministic() -> None:
    a = [f.key for f in run_project(build_project_ir(TINY), RULES)]
    b = [f.key for f in run_project(build_project_ir(TINY), RULES)]
    assert a == b


def test_relative_import_cross_file_flow() -> None:
    # reviewer WP3 H1: `from .db import run_query` (relative) must resolve like `from db import`
    fs = _scan({
        "pkg/db.py": (b"import sqlite3\ndef run_query(uid):\n"
                      b"    conn = sqlite3.connect('x')\n    conn.execute('%s' % uid)\n"),
        "pkg/app.py": (b"from flask import request\nfrom .db import run_query\n"
                       b"def get_user():\n    return run_query(request.args['id'])\n"),
    })
    assert any(f.sink_id == "py-sql-exec" and f.sink_file == "pkg/db.py" for f in fs)


def test_method_name_collision_binds_to_function_not_method() -> None:
    # reviewer WP3 M1: a class method sharing a name must NOT hijack the module-function bind
    fs = _scan({
        "mod.py": (b"class C:\n    def clean(self, x):\n        return x\n"
                   b"def clean(x):\n    return x\n"),
        "app.py": (b"from flask import request\nfrom mod import clean\n"
                   b"def q(cur):\n    cur.execute(clean(request.args['id']))\n"),
    })
    assert any(f.sink_id == "py-sql-exec" for f in fs)


def test_constructor_does_not_clear_taint() -> None:
    # WP3-b soundness trap: User.__init__ returns None and stores the arg on self (no def),
    # so its summary return_params is empty. Trusting it would CLEAR taint; the engine must
    # over-approximate so `u = User(tainted)` keeps taint.
    fs = _scan({
        "models.py": b"class User:\n    def __init__(self, name):\n        self.name = name\n",
        "app.py": (b"from flask import request\nfrom models import User\n"
                   b"def q(cur):\n    u = User(request.args['id'])\n    cur.execute(u.name)\n"),
    })
    assert any(f.sink_id == "py-sql-exec" for f in fs)


def test_taint_through_project_method() -> None:
    # method summary: Svc.run's param q reaches a sink; the caller passes tainted at that arg
    # (receiver self -> param 0, so the arg maps to param 1).
    fs = _scan({
        "svc.py": b"class Svc:\n    def run(self, q, cur):\n        cur.execute(q)\n",
        "app.py": (b"from flask import request\nfrom svc import Svc\n"
                   b"def h(cur):\n    s = Svc()\n    s.run(request.args['id'], cur)\n"),
    })
    assert any(f.sink_id == "py-sql-exec" and f.sink_function == "run" for f in fs)


def test_keyword_argument_maps_to_correct_param() -> None:
    # run(a, q, cur): q reaches the sink; caller passes it BY KEYWORD out of order
    fs = _scan({
        "svc.py": b"def run(a, q, cur):\n    cur.execute(q)\n",
        "app.py": (b"from flask import request\nfrom svc import run\n"
                   b"def h(cur):\n    run(1, cur=cur, q=request.args['id'])\n"),
    })
    assert any(f.sink_id == "py-sql-exec" for f in fs)


def test_method_field_escape_does_not_clear_taint() -> None:
    # reviewer WP3-b #1: `wrap` stores its arg on self and returns it, so the method summary
    # under-approximates; the over_approx floor (method with self.x=) must keep the taint.
    fs = _scan({
        "m.py": b"class C:\n    def wrap(self, q):\n        self.q = q\n        return self.q\n",
        "app.py": (b"from flask import request\nfrom m import C\n"
                   b"def h(cur):\n    c = C()\n    cur.execute(c.wrap(request.args['id']))\n"),
    })
    assert any(f.sink_id == "py-sql-exec" for f in fs)


def test_staticmethod_does_not_drop_first_arg() -> None:
    # reviewer WP3-b #2: @staticmethod has no self, so the first arg maps to param 0
    fs = _scan({
        "m.py": b"class C:\n    @staticmethod\n    def run(x, cur):\n        cur.execute(x)\n",
        "app.py": (b"from flask import request\nfrom m import C\n"
                   b"def h(cur):\n    C.run(request.args['id'], cur)\n"),
    })
    assert any(f.sink_id == "py-sql-exec" for f in fs)


def test_same_module_class_method_resolves() -> None:
    # reviewer WP3-b #3: `v = C()` in the SAME module must type v as C (Tier-1), not external
    fs = _scan({
        "app.py": (b"from flask import request\n"
                   b"class C:\n    def run(self, q, cur):\n        cur.execute(q)\n\n"
                   b"def h(cur):\n    v = C()\n    v.run(request.args['id'], cur)\n"),
    })
    assert any(f.sink_id == "py-sql-exec" for f in fs)


def test_adr007_library_object_external_and_constructor_bound() -> None:
    from secgraph.callgraph.resolve import build_index, classify_site
    from secgraph.ir import analyze_module, lower_source
    from secgraph.ir.model import Attr, Name, iter_calls, stmt_exprs

    mods = [
        analyze_module(lower_source(
            b"from flask_sqlalchemy import SQLAlchemy\ndb = SQLAlchemy()\n", "app/__init__.py")),
        analyze_module(lower_source(
            b"from app import db\n\n"
            b"class User(db.Model):\n    def check(self, x):\n        return x\n\n"
            b"def q():\n    db.session.commit()\n    u = User()\n    u.rows()\n", "app/models.py")),
    ]
    index = build_index(mods)
    got: dict[str, str] = {}
    for m in mods:
        for fn in m.functions:
            for stmt in (fn.cfg.stmt_of.values() if fn.cfg else []):
                for e in stmt_exprs(stmt):
                    for call in iter_calls(e):
                        cat, _ = classify_site(call, fn, m, index, {}, RULES)
                        f = call.func
                        got[f.ident if isinstance(f, Name) else f.attr if isinstance(f, Attr) else "?"] = cat
    assert got.get("commit") == "external"   # db.session.commit -> library-object method (the 83% fix)
    assert got.get("User") == "bound"        # class constructor
    assert got.get("rows") == "external"     # method inherited from db.Model (library-backed base)


def test_binding_rate_on_tiny() -> None:
    modules = build_project_ir(TINY)
    index = build_index(modules)
    _sites, rows = resolve_all_sites(modules, index, {}, RULES)
    stats = binding_rate(rows)
    # run_query(uid)=bound-import; conn.execute=rule; sqlite3.connect=external; .fetchall=unknown
    assert stats["counts"].get("bound-import", 0) >= 1
    assert stats["unresolved_project"] == 0
    assert stats["PCR"] == 1.0
