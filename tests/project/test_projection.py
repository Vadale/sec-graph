"""Phase-4 projection tests: analyze produces graph.json (annotated) + taint.json + the
self-contained HTML map, joins findings to graphify nodes, and respects the sidecar discipline."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from secgraph.project import analyze_project
from secgraph.viz import render_html

FIX = Path(__file__).resolve().parents[1] / "fixtures"
TINY = FIX / "tiny"
METHODS = FIX / "methods"


def _clean(*fixtures: Path) -> None:
    for fx in (fixtures or (TINY,)):
        shutil.rmtree(fx / "graphify-out", ignore_errors=True)  # graphify AST cache under the fixture


def test_analyze_produces_three_artifacts(tmp_path: Path) -> None:
    try:
        r = analyze_project(TINY, tmp_path / "out")
        assert r["graph_json"].exists() and r["taint_json"].exists() and r["html"].exists()
        assert r["findings"] >= 1
    finally:
        _clean()


def test_taint_json_has_cross_file_finding_with_slices(tmp_path: Path) -> None:
    try:
        r = analyze_project(TINY, tmp_path / "out")
        data = json.loads(r["taint_json"].read_text())
        f = next(f for f in data["findings"] if f["cwe"] == "CWE-89")
        assert f["source_file"] == "app.py" and f["sink_file"] == "db.py"
        assert "request.args" in f["source_slice"] and "execute" in f["sink_slice"]
        assert f["trace"] == ["get_user", "run_query"]
    finally:
        _clean()


def test_graph_json_annotated_and_node_count_unchanged(tmp_path: Path) -> None:
    try:
        out = tmp_path / "out"
        r = analyze_project(TINY, out)
        annotated = json.loads(r["graph_json"].read_text())
        # sidecar discipline: projection annotates but never changes the node set
        assert len(annotated["nodes"]) == 6
        assert any("sec_layers" in n for n in annotated["nodes"])
        assert any(str(h.get("id", "")).startswith("sec-path-") for h in annotated.get("hyperedges", []))
    finally:
        _clean()


def test_html_is_self_contained(tmp_path: Path) -> None:
    try:
        html = analyze_project(TINY, tmp_path / "out")["html"].read_text()
        assert "http://" not in html and "https://" not in html   # no external resources
        assert 'id="layers"' in html and 'id="map"' in html       # layer rail + graph canvas
        assert "secgraph-graph" in html and "secgraph-findings" in html   # graph + findings embedded
        assert "db_run_query" in html and "app_get_user" in html   # the graph nodes are in the map payload
    finally:
        _clean()


def test_method_hosted_finding_annotates_the_method_node(tmp_path: Path) -> None:
    # Regression for the name-join bug: graphify labels methods ``.get()`` (leading dot), so a
    # join by function name annotated nothing for methods. The join must be structural.
    try:
        r = analyze_project(METHODS, tmp_path / "out")
        g = json.loads(r["graph_json"].read_text())
        method_node = next(n for n in g["nodes"] if n.get("label") == ".get()")
        assert method_node.get("sec_layers")                      # method node IS annotated
        edge = next(h for h in g["hyperedges"] if str(h.get("id", "")).startswith("sec-path-"))
        assert set(edge["nodes"]) == {"view_userview_get", "dao_run_query"}  # cross-file, method endpoint
    finally:
        _clean(METHODS)


def test_render_html_neutralizes_script_data_breakout() -> None:
    # A code slice containing ``<!--<script>`` must not survive literally in the payload, else the
    # HTML tokenizer swallows the following <script> block and the whole report renders blank.
    f = {
        "function": "q", "source_id": "s", "source_file": "a.py", "source_line": 1,
        "sink_id": "k", "sink_file": "a.py", "sink_line": 2, "sink_function": "q",
        "cwe": "CWE-89", "severity": "high", "layers": ["untrusted-input"], "confidence": "high",
        "trace": [], "source_slice": 'x = "<!--<script>alert(1)</script>-->"', "sink_slice": "",
    }
    html = render_html({"nodes": [], "links": [], "hyperedges": []}, [f], "root")
    assert "<!--<script>" not in html and "</script>alert" not in html   # neutralized
    assert "\\u003c" in html                                             # escaped instead
    assert "secgraph-findings" in html and "getContext" in html          # data + canvas JS intact
