"""WP-C2: auth-barrier detection + the unguarded-sink finding.

Covers decorator harvesting, the three barrier detectors (decorator / dominating gate / in-arm),
cross-hop guard accumulation, the two polarity-soundness cases (a non-terminating or inverted
`if` must NOT be claimed as a guard), and `find_unguarded_sinks`."""
from __future__ import annotations

from pathlib import Path

from secgraph.ir import build_project_ir
from secgraph.ir.lower import lower_source
from secgraph.rules import default_rules_dir, load_rules
from secgraph.taint import find_unguarded_sinks, run_project

RULES = load_rules(default_rules_dir())
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "auth"
SCC = Path(__file__).resolve().parents[1] / "fixtures" / "auth_scc"


def _by_fn():
    return {f.function: f for f in run_project(build_project_ir(FIX), RULES)}


def test_decorator_is_harvested_onto_functionir() -> None:
    mod = lower_source(b"@login_required\ndef v():\n    pass\n\ndef plain():\n    pass\n", "m.py")
    fns = {f.name: f for f in mod.functions}
    assert fns["v"].decorators == ("login_required",)
    assert fns["plain"].decorators == ()


def test_three_barrier_detectors() -> None:
    f = _by_fn()
    assert f["guarded_by_decorator"].guards == ("login_required",)   # B1
    assert f["guarded_by_gate"].guards == ("is_authenticated",)      # B3 dominating gate
    assert f["guarded_in_arm"].guards == ("is_admin",)               # B2 authorised arm
    for name in ("guarded_by_decorator", "guarded_by_gate", "guarded_in_arm"):
        assert not find_unguarded_sinks([f[name]])


def test_guard_accumulates_across_a_call_hop() -> None:
    f = _by_fn()["guarded_cross_hop"]
    assert f.sink_function == "_helper" and f.guards == ("login_required",)  # barrier lifted from caller


def test_unguarded_sink_is_flagged() -> None:
    f = _by_fn()["unguarded_sink"]
    assert f.guards == () and f.cwe == "CWE-89"


def test_polarity_soundness_non_terminating_and_inverted_ifs_do_not_guard() -> None:
    # a security tool must NOT claim "guarded" wrongly (that hides an unguarded sink)
    f = _by_fn()
    assert f["not_a_gate"].guards == ()      # `if authed: log()` has no terminating arm
    assert f["inverted_gate"].guards == ()   # `if authed: abort()` -> passing means UN-authorised


def test_compound_boolean_polarity() -> None:
    # reviewer FINDING 1: a term merely mentioned under `or`/`and-not` must not credit a guard
    f = _by_fn()
    assert f["or_bypass"].guards == ()        # `if authed or debug:` -> reachable anonymous when debug
    assert f["or_bypass_gate"].guards == ()   # `if authed or debug: ... else: return` -> no proof
    assert f["and_not_authed"].guards == ()   # `if flag and not authed:` -> runs only when NOT authed
    assert f["and_authed"].guards == ("is_admin",)  # `if admin and flag:` => admin (sound to credit)


def test_recursive_scc_does_not_hide_an_unguarded_path() -> None:
    # reviewer FINDING 2: the same source->sink reachable guarded AND unguarded in one SCC must be
    # reported unguarded (a keep-first merge across fixpoint iterations would freeze "guarded")
    findings = run_project(build_project_ir(SCC), RULES)
    f = next(x for x in findings if x.sink_function == "do_sink")
    assert f.guards == () and f in find_unguarded_sinks(findings)


def test_find_unguarded_sinks_returns_exactly_the_unguarded() -> None:
    unguarded = {f.function for f in find_unguarded_sinks(run_project(build_project_ir(FIX), RULES))}
    assert unguarded == {"unguarded_sink", "not_a_gate", "inverted_gate",
                         "or_bypass", "or_bypass_gate", "and_not_authed"}


def test_guards_are_deterministic() -> None:
    a = {f.function: f.guards for f in run_project(build_project_ir(FIX), RULES)}
    b = {f.function: f.guards for f in run_project(build_project_ir(FIX), RULES)}
    assert a == b
