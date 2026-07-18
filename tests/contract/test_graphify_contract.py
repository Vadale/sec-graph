"""Contract test: pins the graphify 0.9.6 schema sec-graph depends on.

Runs graphify (through the quarantine wall -- ``secgraph.graphify_adapter``, never
importing graphify directly) over ``tests/fixtures/tiny`` and asserts the exact shape
we build on. A graphify version bump MUST pass this before it lands. Every assertion
here corresponds to a fact in docs/pitfalls.md or a join/annotation the design relies on.
"""
from __future__ import annotations

import json
import re
import shutil
from importlib.metadata import version
from pathlib import Path

import pytest

from secgraph import graphify_adapter as gx

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "tiny"
LINE_RE = re.compile(r"^L\d+$")  # pitfall #1: source_location is start-line only
CONFIDENCE_ENUM = {"EXTRACTED", "INFERRED", "AMBIGUOUS"}  # pitfall #5


def _clean_fixture_cache() -> None:
    # extract(cache_root=FIXTURE) writes an AST cache into the fixture tree; keep the
    # suite reproducible-from-clean (finding #9).
    shutil.rmtree(FIXTURE / "graphify-out", ignore_errors=True)


@pytest.fixture(scope="module")
def extraction() -> gx.Extraction:
    detected = gx.detect_files(FIXTURE)
    code_files = gx.collect_code_files(detected)
    assert {p.name for p in code_files} == {"app.py", "db.py"}
    ext = gx.extract_entities(code_files, cache_root=FIXTURE)
    yield ext
    _clean_fixture_cache()


def test_graphifyy_is_pinned() -> None:
    assert version("graphifyy") == gx.GRAPHIFY_PIN


def test_extraction_top_level(extraction: gx.Extraction) -> None:
    assert {"nodes", "edges"} <= set(extraction)
    assert extraction["nodes"], "expected AST nodes"
    assert extraction["edges"], "expected AST edges"


def test_node_schema(extraction: gx.Extraction) -> None:
    required = {"id", "label", "file_type", "source_file", "source_location"}
    for node in extraction["nodes"]:
        assert required <= set(node), node
        assert LINE_RE.match(node["source_location"]), node["source_location"]
        assert not Path(node["source_file"]).is_absolute(), node["source_file"]


def test_source_file_is_relative_for_the_join(extraction: gx.Extraction) -> None:
    """ADR-002 joins IR functions to graphify nodes by (source_file, start_line); it
    only works while graphify relativizes source_file to cache_root. If graphify ever
    drifts back to absolute paths this fails loudly (the other tests would not)."""
    code_files = {n["source_file"] for n in extraction["nodes"] if n["file_type"] == "code"}
    assert code_files == {"app.py", "db.py"}, code_files


def test_edge_schema(extraction: gx.Extraction) -> None:
    required = {"source", "target", "relation", "confidence"}
    for edge in extraction["edges"]:
        assert required <= set(edge), edge
        assert edge["confidence"] in CONFIDENCE_ENUM, edge["confidence"]


def test_file_nodes_are_not_labelled_as_functions(extraction: gx.Extraction) -> None:
    """Negative guard for the `name()` function convention (finding #7): a drift where
    everything gains parens would otherwise pass test_calls_edge silently."""
    by_label = {n["label"]: n for n in extraction["nodes"]}
    assert "app.py" in by_label
    assert not by_label["app.py"]["label"].endswith("()")


def test_calls_edge_is_function_to_function(extraction: gx.Extraction) -> None:
    """pitfall #2: `calls` edges are function->function, one per (caller, callee),
    with the call-site line as an `L{n}` source_location -- and here they resolve
    across the file boundary (graphify's core value-add)."""
    nodes = {n["id"]: n for n in extraction["nodes"]}
    calls = [e for e in extraction["edges"] if e.get("relation") == "calls"]
    assert calls, "fixture must produce at least one project-internal `calls` edge"
    for edge in calls:
        assert edge["source"] in nodes and edge["target"] in nodes
        assert nodes[edge["source"]]["label"].endswith("()"), nodes[edge["source"]]
        assert nodes[edge["target"]]["label"].endswith("()"), nodes[edge["target"]]
        assert edge.get("source_file")
        assert LINE_RE.match(edge["source_location"]), edge["source_location"]
        assert edge["confidence"] == "EXTRACTED"

    # the fixture's known cross-file call: get_user (app.py) -> run_query (db.py)
    xfile = [
        e
        for e in calls
        if nodes[e["source"]]["label"] == "get_user()"
        and nodes[e["target"]]["label"] == "run_query()"
    ]
    assert xfile, "expected the cross-file get_user -> run_query call"
    e = xfile[0]
    assert nodes[e["source"]]["source_file"] == "app.py"
    assert nodes[e["target"]]["source_file"] == "db.py"


def test_extra_attrs_survive_build_to_json_roundtrip(
    extraction: gx.Extraction, tmp_path: Path
) -> None:
    """pitfall #5/#6: extra attrs survive build -> to_json, on BOTH nodes and links.
    Our projection annotates graph.json with `sec_*` fields (a link on `calls` edges,
    layers on nodes); this proves the carrier survives."""
    graph = gx.build_graph(extraction, root=FIXTURE, directed=True)

    probe_node = next(iter(graph.nodes))
    graph.nodes[probe_node]["sec_probe_node"] = "kept-node"
    u, v = next((u, v) for u, v, d in graph.edges(data=True) if d.get("relation") == "calls")
    graph.edges[u, v]["sec_probe_link"] = "kept-link"

    communities = gx.cluster_graph(graph)
    out = tmp_path / "graph.json"
    assert gx.write_graph_json(graph, communities, out)  # fresh path -> writes

    data = json.loads(out.read_text())
    assert {"nodes", "links"} <= set(data)
    node = next(n for n in data["nodes"] if n["id"] == probe_node)
    assert node.get("sec_probe_node") == "kept-node"
    link = next(l for l in data["links"] if l["source"] == u and l["target"] == v)
    assert link.get("sec_probe_link") == "kept-link"


def test_run_graphify_counts_match_the_written_artifact(tmp_path: Path) -> None:
    """finding #1/#2: the reported counts describe graph.json (post-build), not the
    pre-build extraction, and the whole run_graphify path is exercised."""
    try:
        result = gx.run_graphify(FIXTURE, out_dir=tmp_path / "out")
        assert result.graph_json.exists()
        data = json.loads(result.graph_json.read_text())
        assert result.n_nodes == len(data["nodes"])
        assert result.n_edges == len(data["links"])
        assert result.n_calls == sum(1 for l in data["links"] if l.get("relation") == "calls")
        assert result.n_calls >= 1
    finally:
        _clean_fixture_cache()  # run_graphify used cache_root=FIXTURE


def test_run_graphify_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        gx.run_graphify(tmp_path / "does-not-exist", out_dir=tmp_path / "out")


def test_run_graphify_rejects_codeless_dir(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError):
        gx.run_graphify(empty, out_dir=tmp_path / "out")
