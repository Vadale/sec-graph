"""Projection: run graphify + the taint engine, emit the sidecar ``taint.json``, annotate
graphify's ``graph.json`` in place, and render the layered HTML map.

Sidecar discipline (docs/pitfalls.md): statement-level facts go ONLY to ``taint.json``;
``graph.json`` gets coarse annotations (``sec_layers`` on the source/sink function nodes and
one hyperedge per finding -- pitfall #7, rendered as a hull) by post-processing the dict
directly (never via ``to_json`` -- pitfall #10), and its node count is left unchanged.

Findings are mapped to graphify function nodes through the *same* structural join the rest of
the codebase uses (``ir.join`` by ``(source_file, def-line)`` -- ADR-002 / pitfall #9), never by
function name: graphify labels a method ``.get()`` while the IR names it ``get``, and two classes
in one file can both host a ``get``, so a name join silently mis-/under-annotates every method.
Each finding's source/sink statement line is resolved to its enclosing function by span
containment (tightest wins, so nested defs land on the inner node).
"""
from __future__ import annotations

import json
from pathlib import Path

from .ir.join import join_modules
from .ir.model import ModuleIR
from .taint.model import Finding


def _read_slice(root: Path, rel_file: str, line: int) -> str:
    try:
        lines = (root / rel_file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return lines[line - 1].strip() if 1 <= line <= len(lines) else ""


def _finding_dict(f: Finding, root: Path) -> dict:
    sink_file = f.sink_file or f.source_file
    return {
        "function": f.function,
        "source_id": f.source_id, "source_file": f.source_file, "source_line": f.source_line,
        "sink_id": f.sink_id, "sink_file": sink_file, "sink_line": f.sink_line,
        "sink_function": f.sink_function,
        "cwe": f.cwe, "severity": f.severity, "layers": list(f.layers), "confidence": f.confidence,
        "trace": list(f.trace),
        "source_slice": _read_slice(root, f.source_file, f.source_line),
        "sink_slice": _read_slice(root, sink_file, f.sink_line),
    }


def _enclosing_node(
    by_file: dict[str, list[tuple[int, int, str]]], file: str, line: int
) -> str | None:
    """The graphify node id of the tightest function whose span contains ``line`` in ``file``."""
    best_start = -1
    best_id: str | None = None
    for start, end, node_id in by_file.get(file, ()):
        if start <= line <= end and start > best_start:
            best_start, best_id = start, node_id
    return best_id


def _annotate_graph_json(
    graph_json: Path, findings: list[Finding], modules: list[ModuleIR]
) -> None:
    data = json.loads(graph_json.read_text(encoding="utf-8"))
    nodes = data.get("nodes", [])
    n_before = len(nodes)

    join_modules(modules, nodes)          # bind FunctionIR.graphify_node by (file, def-line)
    node_by_id = {n["id"]: n for n in nodes}
    by_file: dict[str, list[tuple[int, int, str]]] = {}
    for module in modules:
        for fn in module.functions:
            if fn.graphify_node is not None:
                by_file.setdefault(fn.source_file, []).append(
                    (fn.span.start_line, fn.span.end_line, fn.graphify_node))

    hyperedges = data.setdefault("hyperedges", [])
    for i, f in enumerate(findings):
        src = node_by_id.get(_enclosing_node(by_file, f.source_file, f.source_line))
        sink = node_by_id.get(_enclosing_node(by_file, f.sink_file or f.source_file, f.sink_line))
        for node in (src, sink):
            if node is not None:
                node["sec_layers"] = sorted(set(node.get("sec_layers", [])) | set(f.layers))
        if src is not None and sink is not None and src is not sink:
            hyperedges.append({
                "id": f"sec-path-{i}",
                "kind": "taint-path",       # namespaced; distinguishes our paths from graphify's
                "label": f"{f.source_id} -> {f.sink_id}" + (f" ({f.cwe})" if f.cwe else ""),
                "nodes": sorted({src["id"], sink["id"]}),
            })

    assert len(data.get("nodes", [])) == n_before, "projection changed graph.json node count"
    graph_json.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def analyze_project(path: Path | str, out_dir: Path | str = "graphify-out") -> dict:
    """Run graphify + interprocedural taint over ``path`` and write graph.json (annotated),
    taint.json, and secgraph.html into ``out_dir``."""
    from . import graphify_adapter
    from .ir import build_project_ir
    from .rules import default_rules_dir, load_rules
    from .taint import run_project
    from .viz import render_html

    path = Path(path)
    out_dir = Path(out_dir)
    rules = load_rules(default_rules_dir())

    modules = build_project_ir(path)
    findings = run_project(modules, rules)
    result = graphify_adapter.run_graphify(path, out_dir)     # writes out_dir/graph.json
    _annotate_graph_json(result.graph_json, findings, modules)

    finding_dicts = [_finding_dict(f, path) for f in findings]
    taint_json = out_dir / "taint.json"
    taint_json.write_text(
        json.dumps({"version": 1, "root": str(path), "findings": finding_dicts},
                   indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    html_path = out_dir / "secgraph.html"
    html_path.write_text(render_html(finding_dicts, str(path)), encoding="utf-8")

    return {
        "findings": len(findings),
        "graph_json": result.graph_json,
        "taint_json": taint_json,
        "html": html_path,
    }
