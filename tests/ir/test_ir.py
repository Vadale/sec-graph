"""IR unit tests: lowering, spans/params, k=1 access paths, CFG (linear + branches +
loops), def-use reaching definitions, and determinism. No graphify here."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from secgraph import ir
from secgraph.ir.model import (
    ENTRY,
    EXIT,
    PARAM_SITE,
    Assign,
    Call,
    For,
    If,
    Name,
    Return,
    While,
    access_path,
)

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "tiny"


def _fn(module: ir.ModuleIR, name: str) -> ir.FunctionIR:
    return next(f for f in module.functions if f.name == name)


def test_functions_spans_and_params() -> None:
    app = ir.build_module_ir(FIX / "app.py", "app.py")
    db = ir.build_module_ir(FIX / "db.py", "db.py")
    get_user = _fn(app, "get_user")
    run_query = _fn(db, "run_query")
    # start_line must equal graphify's function source_location (the join depends on it)
    assert get_user.span.start_line == 16
    assert get_user.params == []
    assert run_query.span.start_line == 9
    assert run_query.params == ["uid"]


def test_access_path_is_k1_with_subscript() -> None:
    get_user = _fn(ir.build_module_ir(FIX / "app.py", "app.py"), "get_user")
    assign = next(s for s in get_user.body if isinstance(s, Assign) and s.targets == ["uid"])
    ap = access_path(assign.value)  # RHS is request.args["id"]
    assert ap is not None
    assert (ap.base, ap.field, ap.subscripted) == ("request", "args", True)
    assert str(ap) == "request.args[...]"


def test_cfg_linear() -> None:
    run_query = _fn(ir.build_module_ir(FIX / "db.py", "db.py"), "run_query")
    cfg = run_query.cfg
    assert (cfg.entry, cfg.exit) == (ENTRY, EXIT)
    assert cfg.succ[ENTRY] == [0]
    assert cfg.succ[0] == [1]
    assert cfg.succ[1] == [2]
    assert cfg.succ[2] == [EXIT]


def test_defuse_reaching_definitions() -> None:
    run_query = _fn(ir.build_module_ir(FIX / "db.py", "db.py"), "run_query")
    du = {(u.var, u.at): u.reaching for u in run_query.defuse.uses}
    assert du[("uid", 1)] == [PARAM_SITE]   # uid in the query string -> the parameter
    assert du[("conn", 2)] == [0]           # conn in the return -> conn = sqlite3.connect
    assert du[("query", 2)] == [1]          # query in the return -> query = ... % uid
    assert du[("sqlite3", 0)] == []         # a global/import -> no local def

    get_user = _fn(ir.build_module_ir(FIX / "app.py", "app.py"), "get_user")
    du2 = {(u.var, u.at): u.reaching for u in get_user.defuse.uses}
    assert du2[("uid", 1)] == [0]           # uid in run_query(uid) -> uid = request.args[...]


def test_cfg_if_merges_both_branch_defs() -> None:
    src = b"def f(x):\n    if x:\n        y = 1\n    else:\n        y = 2\n    return y\n"
    module = ir.analyze_module(ir.lower_source(src, "t.py"))
    f = _fn(module, "f")
    if_stmt = next(s for s in f.body if isinstance(s, If))
    assert len(f.cfg.succ[if_stmt.sid]) == 2  # then-entry and else-entry
    y_uses = [u for u in f.defuse.uses if u.var == "y"]
    assert len(y_uses) == 1
    assert len(y_uses[0].reaching) == 2       # y in `return y` reaches BOTH assignments


def test_cfg_while_has_backedge() -> None:
    src = b"def g(n):\n    i = 0\n    while i < n:\n        i = i + 1\n    return i\n"
    module = ir.analyze_module(ir.lower_source(src, "t.py"))
    g = _fn(module, "g")
    while_stmt = next(s for s in g.body if isinstance(s, While))
    body_head = while_stmt.body[0]
    assert while_stmt.sid in g.cfg.succ[body_head.sid]  # loop body flows back to the header


def _serialize(module: ir.ModuleIR) -> str:
    def enc(o: object):
        if dataclasses.is_dataclass(o) and not isinstance(o, type):
            return {f.name: enc(getattr(o, f.name)) for f in dataclasses.fields(o)}
        if isinstance(o, (list, tuple)):
            return [enc(x) for x in o]
        if isinstance(o, dict):
            return {str(k): enc(v) for k, v in sorted(o.items(), key=lambda kv: str(kv[0]))}
        return o
    return json.dumps(enc(module), sort_keys=True, default=str)


def test_ir_is_deterministic() -> None:
    a = ir.build_module_ir(FIX / "db.py", "db.py")
    b = ir.build_module_ir(FIX / "db.py", "db.py")
    assert _serialize(a) == _serialize(b)


def _assign_calling(fn: ir.FunctionIR, callee: str) -> int | None:
    for sid, s in fn.cfg.stmt_of.items():
        if (isinstance(s, Assign) and isinstance(s.value, Call)
                and isinstance(s.value.func, Name) and s.value.func.ident == callee):
            return sid
    return None


def test_chained_assignment_defines_all_targets() -> None:
    src = b"def f():\n    a = b = source()\n    return sink(b)\n"
    f = _fn(ir.analyze_module(ir.lower_source(src, "t.py")), "f")
    assign = next(s for s in f.body if isinstance(s, Assign))
    assert set(assign.targets) == {"a", "b"}
    b_use = next(u for u in f.defuse.uses if u.var == "b")
    assert b_use.reaching == [assign.sid]   # b in the return reaches the chained assignment


def test_for_tuple_target_defines_all_names() -> None:
    src = b"def f(d):\n    for k, v in d.items():\n        sink(v)\n"
    f = _fn(ir.analyze_module(ir.lower_source(src, "t.py")), "f")
    for_stmt = next(s for s in f.body if isinstance(s, For))
    assert set(for_stmt.targets) == {"k", "v"}
    v_use = next(u for u in f.defuse.uses if u.var == "v")
    assert for_stmt.sid in v_use.reaching   # v bound by the tuple loop target


def test_walrus_defines_target() -> None:
    src = b"def f():\n    if (n := source()):\n        return sink(n)\n    return 0\n"
    f = _fn(ir.analyze_module(ir.lower_source(src, "t.py")), "f")
    if_stmt = next(s for s in f.body if isinstance(s, If))
    n_use = next(u for u in f.defuse.uses if u.var == "n")
    assert if_stmt.sid in n_use.reaching   # n := source() defines n at the if statement


def test_break_flows_to_loop_exit_not_fallthrough() -> None:
    # reviewer WP1 finding #1: the break path's tainted def must survive to the use.
    src = (
        b"def f(items):\n"
        b"    t = clean()\n"
        b"    for it in items:\n"
        b"        if it:\n"
        b"            t = source()\n"
        b"            break\n"
        b"        t = safe()\n"
        b"    return t\n"
    )
    f = _fn(ir.analyze_module(ir.lower_source(src, "t.py")), "f")
    src_sid = _assign_calling(f, "source")
    assert src_sid is not None
    ret_sid = next(sid for sid, s in f.cfg.stmt_of.items() if isinstance(s, Return))
    t_reaching = next(u.reaching for u in f.defuse.uses if u.var == "t" and u.at == ret_sid)
    # the break skips `t = safe()`, so the tainted `t = source()` reaches `return t`
    assert src_sid in t_reaching
