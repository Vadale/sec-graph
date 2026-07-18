"""The quarantine wall: the ONLY module in sec-graph allowed to import graphify.

Every ``graphify.*`` import lives here (DECISIONS.md ADR-002, docs/pitfalls.md). A
later graphify upgrade -- or a divorce/Rust-kernel port -- touches only this file.
Pinned to ``graphifyy==GRAPHIFY_PIN``; a bump must pass ``tests/contract`` first.

Return-value boundary:
  * ``detect_files`` / ``extract_entities`` return plain dicts (graphify's schema).
  * ``build_graph`` / ``cluster_graph`` return a *live* NetworkX graph whose node/edge
    attributes are graphify-shaped (``_origin``, ``_src``/``_tgt``, ``file_type``, ...).
    Treat that as a soft boundary: a consumer that reads those graphify-specific attrs
    is a mild coupling to revisit before Phase 1 leans on it.

Verified graphify 0.9.6 schema (docs/pitfalls.md): nodes
``{id, label, file_type, source_file, source_location="L{n}", _origin}``; edges
``{source, target, relation, confidence in {EXTRACTED,INFERRED,AMBIGUOUS}, ...}``;
function nodes labelled ``name()``; function->function ``calls`` edges as the
interprocedural resolution oracle; ``graph.json`` stores edges under ``links``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import networkx as nx
from graphify.build import build_from_json as _build_from_json
from graphify.cluster import cluster as _cluster
from graphify.detect import detect as _detect
from graphify.export import to_json as _to_json
from graphify.extract import collect_files as _collect_files
from graphify.extract import extract as _extract

#: The exact graphify version this adapter is verified against.
GRAPHIFY_PIN = "0.9.6"

Extraction = dict[str, Any]

__all__ = [
    "GRAPHIFY_PIN",
    "Extraction",
    "GraphifyResult",
    "detect_files",
    "collect_code_files",
    "extract_entities",
    "build_graph",
    "cluster_graph",
    "write_graph_json",
    "run_graphify",
]


def detect_files(path: Path | str) -> dict[str, Any]:
    """Detect analyzable files under ``path`` (wraps ``graphify.detect.detect``)."""
    return _detect(Path(path))


def collect_code_files(detect_result: dict[str, Any]) -> list[Path]:
    """Flatten the ``code`` entries of a detect result into concrete file paths."""
    code = detect_result.get("files", {}).get("code", [])
    out: list[Path] = []
    for entry in code:
        p = Path(entry)
        out.extend(_collect_files(p) if p.is_dir() else [p])
    return out


def extract_entities(code_files: list[Path | str], cache_root: Path | str) -> Extraction:
    """Structural (AST) extraction of code files -> ``{nodes, edges, ...}``.

    Deterministic and LLM-free. ``cache_root`` anchors the relative ``source_file`` of
    every node (keep it at the analyzed root so the later ``(source_file, start_line)``
    join stays stable) and locates graphify's per-file content cache.
    """
    return _extract([Path(f) for f in code_files], cache_root=Path(cache_root), parallel=True)


def build_graph(extraction: Extraction, root: Path | str, directed: bool = True) -> nx.Graph:
    """Build graphify's NetworkX graph. Always ``directed=True`` in sec-graph.

    Note: ``build`` prunes edges whose endpoint node does not exist (e.g. imports of
    external/stdlib modules), so the built graph can have fewer edges than the raw
    extraction. Count from here (or from the written ``graph.json``), never from the
    extraction, when reporting to the user.
    """
    return _build_from_json(extraction, root=str(root), directed=directed)


def cluster_graph(graph: nx.Graph) -> dict[int, list[str]]:
    """Leiden community detection -> ``{community_id: [node_ids]}``.

    Returns ``{}`` only if clustering raises (defensive); an empty or edgeless graph
    normally yields one community per node.
    """
    try:
        return _cluster(graph)
    except Exception:  # pragma: no cover - defensive on degenerate graphs
        return {}


def write_graph_json(graph: nx.Graph, communities: dict[int, list[str]], out_path: Path | str) -> bool:
    """Write graphify's ``graph.json`` (nodes + ``links`` + hyperedges).

    Returns graphify's write flag: ``False`` means the shrink-guard (#479) refused to
    overwrite a *larger* existing graph. We keep ``force=False`` on purpose so a
    graphify-curated graph is never silently clobbered; ``run_graphify`` turns a
    ``False`` into a clear error instead of a silent stale artifact.
    """
    return _to_json(graph, communities, str(out_path))


@dataclass
class GraphifyResult:
    """Summary of one graphify pass. Counts describe the written ``graph.json``."""

    graph_json: Path
    n_nodes: int
    n_edges: int
    n_calls: int


def run_graphify(path: Path | str, out_dir: Path | str = "graphify-out") -> GraphifyResult:
    """Run graphify end-to-end over ``path`` and write ``out_dir/graph.json``.

    Raises ``FileNotFoundError`` if ``path`` does not exist, ``ValueError`` if it holds
    no analyzable code, and ``RuntimeError`` if graphify refuses to overwrite a larger
    existing ``graph.json`` (use a clean ``out_dir``). Counts are read back from the
    written artifact so they always match the file.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"path does not exist: {path}")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    detected = detect_files(path)
    code_files = collect_code_files(detected)
    if not code_files:
        raise ValueError(f"no analyzable code files under {path}")

    extraction = extract_entities(code_files, cache_root=path)
    graph = build_graph(extraction, root=path, directed=True)
    communities = cluster_graph(graph)

    graph_json = out_dir / "graph.json"
    wrote = write_graph_json(graph, communities, graph_json)
    if not wrote or not graph_json.exists():
        raise RuntimeError(
            f"graphify refused to write {graph_json}: an existing graph is larger "
            f"(shrink-guard). Use a clean out_dir or remove the file."
        )

    data = json.loads(graph_json.read_text(encoding="utf-8"))
    links = data.get("links", [])
    return GraphifyResult(
        graph_json=graph_json,
        n_nodes=len(data.get("nodes", [])),
        n_edges=len(links),
        n_calls=sum(1 for e in links if e.get("relation") == "calls"),
    )
