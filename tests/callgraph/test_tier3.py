"""Tier-3 parameter-annotation typing (the fastapi UNK/TRR mover): a receiver known only through
its annotation (`def handler(svc: Service)`) binds the method, surfacing a cross-file flow that a
name-only resolver misses."""
from __future__ import annotations

from pathlib import Path

from secgraph.callgraph import build_index, resolve_all_sites
from secgraph.ir import build_project_ir
from secgraph.ir.lower import lower_source
from secgraph.rules import default_rules_dir, load_rules
from secgraph.taint import run_project

RULES = load_rules(default_rules_dir())
TIER3 = Path(__file__).resolve().parents[1] / "fixtures" / "tier3"


def test_param_annotations_are_captured() -> None:
    mod = lower_source(b"def f(u: User, s: auth.Svc, o: Optional[X], x=1):\n    pass\n", "m.py")
    # bare + dotted annotations captured; the generic Optional[X] is deferred (safe under-claim)
    assert mod.functions[0].param_types == {"u": "User", "s": "auth.Svc"}


def test_annotated_receiver_binds_the_method() -> None:
    mods = build_project_ir(TIER3)
    _sites, rows = resolve_all_sites(mods, build_index(mods), {}, RULES)
    site = next(r for r in rows if r["file"] == "app.py" and r["line"] == 8 and r["method"])
    assert site["category"] == "bound"        # svc: Service -> Service.query (was unknown-receiver)


def test_tier3_surfaces_a_flow_a_name_resolver_misses() -> None:
    mods = build_project_ir(TIER3)
    fs = run_project(mods, RULES)
    assert any(f.cwe == "CWE-89" and f.function == "handler" and f.sink_function == "query" for f in fs)
    # delta proof: clear the annotations (Tier-3 off) and the cross-file flow disappears
    off = build_project_ir(TIER3)
    for m in off:
        for fn in m.functions:
            fn.param_types = {}
    assert not run_project(off, RULES)
