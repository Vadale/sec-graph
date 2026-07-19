"""Phase-9 tests: SARIF / semgrep ingestion → the normalized finding dict → the map + MCP pipeline
(ADR-014). Fixtures are hand-written (no semgrep/CodeQL dependency in CI), like the graphify contract."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from secgraph.ingest import ingest_findings
from secgraph.ingest.normalize import normalize_path, parse_cwe, severity_of
from secgraph.mcp_view import TaintView
from secgraph.project import analyze_ingest

FIX = Path(__file__).resolve().parents[1] / "fixtures"
TINY = FIX / "tiny"
SARIF = FIX / "ingest" / "tiny.sarif"
OTHER = FIX / "ingest" / "tiny-otherroot.sarif"
SEMGREP = FIX / "ingest" / "tiny.semgrep.json"


def _clean():
    shutil.rmtree(TINY / "graphify-out", ignore_errors=True)


# ---- unit: normalizer / maps -----------------------------------------------------

def test_normalize_path_forms() -> None:
    known = {"app.py", "db.py", "pkg/x.py"}
    assert normalize_path("db.py", None, {}, TINY, known)[0] == "db.py"                 # relative, present
    assert normalize_path("file:///nowhere/db.py", None, {}, TINY, known)[0] == "db.py"  # abs file:// -> suffix
    assert normalize_path("repo/backend/app.py", None, {}, TINY, known)[0] == "app.py"   # different cwd -> suffix
    assert normalize_path("%25enc/db.py", None, {}, TINY, known)[0] == "db.py"            # percent-decoded suffix
    assert normalize_path("file:///etc/passwd", None, {}, TINY, known)[0] is None         # escape -> unbound


def test_root_clamp_blocks_prefix_sibling_escape(tmp_path) -> None:
    # reviewer HIGH: a prefix-sibling `../proj-evil` must not slip past a string-prefix clamp
    root = tmp_path / "proj"
    (root / "sub").mkdir(parents=True)
    (root / "app.py").write_text("x = 1\n")
    (tmp_path / "proj-evil").mkdir()
    (tmp_path / "proj-evil" / "secret.txt").write_text("AWS_KEY=hunter2\n")
    known = {"app.py"}
    assert normalize_path("../proj-evil/secret.txt", None, {}, root, known)[0] is None   # escapes -> rejected
    assert normalize_path("../proj/app.py", None, {}, root, known)[0] == "app.py"         # back inside -> ok
    assert normalize_path("app.py", None, {}, root, known)[0] == "app.py"


def test_malformed_results_are_dropped_not_crashing(tmp_path) -> None:
    # reviewer MEDIUM: a wrong-typed field in one result must not abort the whole ingest
    findings, report = ingest_findings(TINY, [str(FIX / "ingest" / "malformed.sarif")], [], None)
    _clean()
    assert any(f["rule_id"] == "good" for f in findings)                     # the valid one survives
    assert sum(1 for d in report.dropped if d["reason"] == "parse-error") >= 2   # the two bad shapes dropped


def test_severity_and_cwe_maps() -> None:
    assert severity_of("error", "8.8") == "high" and severity_of("warning", "9.5") == "critical"
    assert severity_of("note") == "low" and severity_of(None) == "medium"
    assert parse_cwe(["external/cwe/cwe-089"]) == "CWE-89" and parse_cwe(["CWE-89: x"]) == "CWE-89"
    assert parse_cwe(["nope"]) is None


# ---- SARIF ingestion end-to-end --------------------------------------------------

def test_sarif_ingest_binds_and_writes_artifacts(tmp_path) -> None:
    try:
        r = analyze_ingest(TINY, tmp_path / "out", [str(SARIF)], [])
        d = json.loads(r["taint_json"].read_text())
        assert d["engine"]["mode"] == "ingest" and Path(d["root"]).is_absolute()
        assert r["report"].n_findings == 3 and r["binding"]["none"] == 0          # 3 bound
        assert len(r["report"].dropped) == 1                                       # /etc/passwd dropped (clamp)
        xf = next(f for f in d["findings"] if f["rule_id"] == "py/sql-injection")
        assert xf["source_node"] == "app_get_user" and xf["sink_node"] == "db_run_query"  # cross-file, codeFlow
        assert xf["cwe"] == "CWE-89" and xf["severity"] == "high" and len(xf["hops"]) == 2
        assert r["html"].exists()
    finally:
        _clean()


def test_suffix_rescue_binds_a_different_cwd_sarif(tmp_path) -> None:
    try:
        r = analyze_ingest(TINY, tmp_path / "out", [str(OTHER)], [])
        f = json.loads(r["taint_json"].read_text())["findings"][0]
        assert f["source_file"] == "app.py" and f["source_node"] == "app_get_user"   # repo/backend/app.py -> app.py
        assert f["sink_node"] == "db_run_query"
    finally:
        _clean()


def test_semgrep_ingest_uses_the_dataflow_trace(tmp_path) -> None:
    try:
        findings, report = ingest_findings(TINY, [], [str(SEMGREP)], None)
        f = findings[0]
        assert f["source_file"] == "app.py" and f["source_line"] == 17           # taint_source
        assert f["sink_file"] == "db.py" and f["sink_line"] == 12                 # taint_sink
        assert [(h["file"], h["line"]) for h in f["hops"]] == [("app.py", 17), ("db.py", 11), ("db.py", 12)]
        assert f["cwe"] == "CWE-89" and f["severity"] == "high"
    finally:
        _clean()


def test_ingest_is_deterministic(tmp_path) -> None:
    try:
        a = analyze_ingest(TINY, tmp_path / "a", [str(SARIF)], [])["taint_json"].read_bytes()
        b = analyze_ingest(TINY, tmp_path / "b", [str(SARIF)], [])["taint_json"].read_bytes()
        assert a == b
    finally:
        _clean()


def test_get_path_slice_emits_per_hop_windows(tmp_path) -> None:
    try:
        out = tmp_path / "out"
        analyze_ingest(TINY, out, [str(SARIF)], [])
        v = TaintView(out)
        pid = next(f["id"] for f in v.findings if f["rule_id"] == "py/sql-injection")
        windows = v.get_path_slice(pid)["windows"]
        assert [w["role"] for w in windows] == ["source", "sink"]                 # 2 hops -> source + sink
        assert all(w["stale"] is False for w in windows)                          # fresh tree -> not stale
    finally:
        _clean()
