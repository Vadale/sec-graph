"""Phase-10 tests: layer enrichment over ingested findings (ADR-014) — credentials/PII layers +
the auth/unguarded verdict + the honest guard tri-state (analyzed / unknown)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from secgraph.ingest.enrich import _STRLIT, _guard_verdict, _label_layers
from secgraph.ir.lower import lower_source
from secgraph.mcp_view import TaintView
from secgraph.project import analyze_ingest
from secgraph.rules import default_rules_dir, load_rules

RULES = load_rules(default_rules_dir())
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "ingest"
APP = FIX / "enrich-app"
SARIF = FIX / "enrich.sarif"


def _findings(out: Path) -> dict:
    return {f["rule_id"]: f for f in json.loads((out / "taint.json").read_text())["findings"]}


def _clean():
    shutil.rmtree(APP / "graphify-out", ignore_errors=True)


def test_enrich_adds_credentials_layer_lexically(tmp_path) -> None:
    try:
        out = tmp_path / "out"
        analyze_ingest(APP, out, [str(SARIF)], [])
        f = _findings(out)["sqli-with-password"]
        assert "credentials" in f["layers"]                                     # added by enrich
        assert any(p.startswith("enrich:lexical") for p in f["provenance"])     # honestly marked as lexical
    finally:
        _clean()


def test_enrich_computes_python_guard_verdict(tmp_path) -> None:
    try:
        out = tmp_path / "out"
        analyze_ingest(APP, out, [str(SARIF)], [])
        f = _findings(out)
        guarded = f["sqli-behind-login"]
        assert guarded["guard_status"] == "analyzed" and not guarded["unguarded"]
        assert "login_required" in guarded["guards"]                            # @login_required detected
        leak = f["sqli-with-password"]
        assert leak["guard_status"] == "analyzed" and leak["unguarded"]         # no barrier -> unguarded
    finally:
        _clean()


def test_non_python_sink_stays_guard_unknown(tmp_path) -> None:
    try:
        out = tmp_path / "out"
        analyze_ingest(APP, out, [str(SARIF)], [])
        f = _findings(out)["js-sqli"]
        assert f["guard_status"] == "unknown" and not f["unguarded"] and f["guards"] == []   # no false glow
    finally:
        _clean()


def test_find_unguarded_sinks_tri_state(tmp_path) -> None:
    try:
        out = tmp_path / "out"
        analyze_ingest(APP, out, [str(SARIF)], [])
        v = TaintView(out)
        default = v.find_unguarded_sinks()
        assert default["unknown_count"] == 1                                    # the js finding
        assert all(p["guard_status"] == "analyzed" for p in default["paths"])   # unknowns excluded by default
        assert len(v.find_unguarded_sinks(include_unknown=True)["paths"]) == len(default["paths"]) + 1
    finally:
        _clean()


def test_strlit_regex_is_linear_no_redos() -> None:
    # reviewer HIGH: a quote + long backslash run must not backtrack exponentially
    _STRLIT.sub(" ", '"' + "\\" * 80 + "x")          # linear regex -> returns instantly (would hang if ReDoS)
    assert _STRLIT.findall('x = "hunter2"') == [('"', "hunter2")]   # still matches normal strings


def test_oneline_guard_is_analyzed_guarded() -> None:
    # reviewer MEDIUM: `if <auth>: sink()` on one line must bind the sink to the INNER arm statement
    mod = lower_source(b"from x import current_user\ndef v(q):\n    if current_user.is_admin: run(q)\n", "v.py")
    fn_index = {"v.py": [(fn.span.start_line, fn.span.end_line, fn, mod) for fn in mod.functions]}
    f = {"source_file": "v.py", "sink_file": "v.py", "sink_line": 3, "hops": [],
         "guards": [], "unguarded": False, "guard_status": "unknown", "layers": []}
    _guard_verdict(f, fn_index, RULES)
    assert f["guard_status"] == "analyzed" and not f["unguarded"] and "is_admin" in f["guards"]


def test_lexical_ignores_comments_and_string_bodies(tmp_path) -> None:
    # reviewer LOW: identifiers inside a trailing comment or a string body must not add a layer
    (tmp_path / "a.py").write_text('db.run(x)  # never log the password\ny = "invalid email address"\n')
    f = {"source_file": "a.py", "source_line": 1, "sink_file": "a.py", "sink_line": 2, "hops": [],
         "layers": ["untrusted-input", "dangerous-sink"], "provenance": []}
    _label_layers(f, tmp_path, RULES)
    assert "credentials" not in f["layers"] and "pii" not in f["layers"]


def test_enrichment_is_deterministic(tmp_path) -> None:
    try:
        a = analyze_ingest(APP, tmp_path / "a", [str(SARIF)], [])["taint_json"].read_bytes()
        b = analyze_ingest(APP, tmp_path / "b", [str(SARIF)], [])["taint_json"].read_bytes()
        assert a == b
    finally:
        _clean()
