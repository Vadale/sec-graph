"""Phase-6 MCP tests: the read-only TaintView tools (list_paths / get_path_slice /
find_unguarded_sinks / explain_layer / get_function_taint), the taint.json id+file_hashes
extension, and that the FastMCP server + triage prompts build over real artifacts."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from secgraph.mcp_server import build_server, render_path_prompt
from secgraph.mcp_view import TaintView
from secgraph.project import analyze_project

AUTH = Path(__file__).resolve().parents[1] / "fixtures" / "auth"
METHODS = Path(__file__).resolve().parents[1] / "fixtures" / "methods"


@pytest.fixture(scope="module")
def analyzed(tmp_path_factory):
    out = tmp_path_factory.mktemp("mcp")
    analyze_project(AUTH, out)
    yield out
    shutil.rmtree(AUTH / "graphify-out", ignore_errors=True)


@pytest.fixture(scope="module")
def view(analyzed):
    return TaintView(analyzed)


def test_taint_json_has_id_hashes_nodes_and_absolute_root(analyzed: Path) -> None:
    data = json.loads((analyzed / "taint.json").read_text())
    assert Path(data["root"]).is_absolute()          # serve reads slices regardless of its cwd
    findings = data["findings"]
    assert findings and all(f["id"].startswith("path-") for f in findings)
    f = findings[0]
    assert f["file_hashes"] and all(h.startswith("sha256:") for h in f["file_hashes"].values())
    assert "source_node" in f and "sink_node" in f    # sound node binding for get_function_taint


def test_get_function_taint_resolves_method_nodes(tmp_path: Path) -> None:
    # regression (reviewer HIGH): graphify labels a method `.get()`; get_function_taint must bind
    # via the stamped source_node/sink_node, not a dotted-name match (which returned empty)
    out = tmp_path / "m"
    analyze_project(METHODS, out)
    try:
        g = json.loads((out / "graph.json").read_text())
        node = next(n["id"] for n in g["nodes"] if n.get("label") == ".get()")
        assert TaintView(out).get_function_taint(node)["paths"]      # method-hosted path resolves
    finally:
        shutil.rmtree(METHODS / "graphify-out", ignore_errors=True)


def test_list_paths_filters_and_ranks_unguarded_first(view: TaintView) -> None:
    lp = view.list_paths(layer="untrusted-input")
    assert lp["total"] >= 1
    assert all("untrusted-input" in p["layers"] for p in lp["paths"])
    assert lp["paths"][0]["unguarded"] is True          # unguarded ranked ahead of guarded
    assert view.list_paths(layer="no-such-layer")["total"] == 0


def test_get_path_slice_is_minimal_and_hash_verified(view: TaintView) -> None:
    pid = view.find_unguarded_sinks()["paths"][0]["id"]
    s = view.get_path_slice(pid, context_lines=2)
    assert [w["role"] for w in s["windows"]] == ["source", "sink"]
    assert all(w["stale"] is False for w in s["windows"])           # fresh -> not stale
    total_lines = sum(len(w["code"]) for w in s["windows"])
    assert total_lines <= 2 * (2 * 2 + 1)                           # bounded by the context windows
    assert all(any(ln["mark"] for ln in w["code"]) for w in s["windows"])   # the sink/source line marked


def test_get_path_slice_flags_stale(analyzed: Path, tmp_path: Path) -> None:
    data = json.loads((analyzed / "taint.json").read_text())
    data["findings"][0]["file_hashes"] = {k: "sha256:deadbeef" for k in data["findings"][0]["file_hashes"]}
    (tmp_path / "taint.json").write_text(json.dumps(data))
    s = TaintView(tmp_path).get_path_slice(data["findings"][0]["id"])
    assert all(w["stale"] for w in s["windows"])                    # bogus hash -> stale


def test_find_unguarded_sinks(view: TaintView) -> None:
    us = view.find_unguarded_sinks()
    assert us["total"] >= 1 and all(p["unguarded"] for p in us["paths"])


def test_explain_layer_is_deterministic_provenance(view: TaintView) -> None:
    ds = view.explain_layer("dangerous-sink")
    assert any(s["id"] == "py-sql-exec" for s in ds["provenance"]["sinks"])
    assert "login_required" in view.explain_layer("auth")["provenance"]["decorators"]
    assert view.explain_layer("bogus")["error"] == "unknown layer"


def test_get_function_taint_includes_intra_paths(view: TaintView, analyzed: Path) -> None:
    # a guarded intra finding (source & sink in one function) has no hyperedge -> must still resolve
    g = json.loads((analyzed / "graph.json").read_text())
    node = next(n["id"] for n in g["nodes"] if n.get("label") == "unguarded_sink()")
    gt = view.get_function_taint(node)
    assert gt["paths"] and any(p["unguarded"] for p in gt["paths"])


def test_server_and_prompts_build(view: TaintView, analyzed: Path) -> None:
    assert build_server(analyzed) is not None                       # FastMCP wiring is valid
    pid = view.find_unguarded_sinks()["paths"][0]["id"]
    prompt = render_path_prompt(view, pid)
    assert "Triage this data-flow path" in prompt and "source -->" not in prompt
    assert "sink --" in prompt                                      # the slice is embedded
