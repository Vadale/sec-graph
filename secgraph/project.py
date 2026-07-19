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

import hashlib
import json
import re
from pathlib import Path

from .ir.join import join_modules
from .ir.model import ModuleIR
from .taint.model import Finding

_LINE = re.compile(r"^L(\d+)$")


def _read_slice(root: Path, rel_file: str, line: int) -> str:
    try:
        lines = (root / rel_file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return lines[line - 1].strip() if 1 <= line <= len(lines) else ""


def _file_hash(root: Path, rel_file: str) -> str:
    """sha256 of a file's bytes, stored so the MCP ``get_path_slice`` can flag a slice as stale
    when the file drifted since analysis (ROADMAP §8.2)."""
    try:
        return "sha256:" + hashlib.sha256((root / rel_file).read_bytes()).hexdigest()
    except OSError:
        return ""


def _finding_dict(f: Finding, root: Path) -> dict:
    sink_file = f.sink_file or f.source_file
    return {
        "function": f.function,
        "source_id": f.source_id, "source_file": f.source_file, "source_line": f.source_line,
        "sink_id": f.sink_id, "sink_file": sink_file, "sink_line": f.sink_line,
        "sink_function": f.sink_function,
        "cwe": f.cwe, "severity": f.severity, "layers": list(f.layers), "confidence": f.confidence,
        "trace": list(f.trace),
        "guards": list(f.guards), "unguarded": not f.guards,   # unguarded = no auth barrier on the path
        "source_slice": _read_slice(root, f.source_file, f.source_line),
        "sink_slice": _read_slice(root, sink_file, f.sink_line),
        "file_hashes": {rel: _file_hash(root, rel) for rel in dict.fromkeys([f.source_file, sink_file])},
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


def _bind_node(file: str, line: int, by_file, code_nodes, file_nodes) -> tuple[str | None, str]:
    """Bind a finding's (file, line) to a graph node, structurally only (ADR-008/014):
    span (Python IR) -> nearest preceding def-line (any language graphify parsed; pitfall #1 gives
    no end lines) -> the file node -> none."""
    got = _enclosing_node(by_file, file, line)
    if got is not None:
        return got, "span"
    best_line, best_id = -1, None
    for def_line, node_id in code_nodes.get(file, ()):
        if def_line <= line and def_line > best_line:
            best_line, best_id = def_line, node_id
    if best_id is not None:
        return best_id, "nearest-def"
    if file in file_nodes:
        return file_nodes[file], "file"
    return None, "none"


def _annotate_graph_json(
    graph_json: Path, findings: list[dict], modules: list[ModuleIR]
) -> dict[str, int]:
    """Bind each finding DICT to graph nodes (stamping ``source_node``/``sink_node`` + a
    ``binding:*`` provenance tag in place), annotate ``sec_layers`` + one hyperedge per bound
    finding, and leave the node count unchanged. Returns the binding-method counts (report)."""
    data = json.loads(graph_json.read_text(encoding="utf-8"))
    nodes = data.get("nodes", [])
    n_before = len(nodes)

    join_modules(modules, nodes)          # bind FunctionIR.graphify_node by (file, def-line)
    node_by_id = {n["id"]: n for n in nodes}
    by_file: dict[str, list[tuple[int, int, str]]] = {}     # (Python IR spans) for the tightest join
    for module in modules:
        for fn in module.functions:
            if fn.graphify_node is not None:
                by_file.setdefault(fn.source_file, []).append(
                    (fn.span.start_line, fn.span.end_line, fn.graphify_node))
    code_nodes: dict[str, list[tuple[int, str]]] = {}       # graphify function nodes (nearest-def)
    file_nodes: dict[str, str] = {}                         # graphify file nodes (file fallback)
    for n in nodes:
        if n.get("file_type") != "code":
            continue
        label, sf = str(n.get("label", "")), n.get("source_file")
        m = _LINE.match(str(n.get("source_location", "")))
        if sf is None:
            continue
        if label.endswith("()") and m:
            code_nodes.setdefault(sf, []).append((int(m.group(1)), n["id"]))
        elif label == sf.rsplit("/", 1)[-1]:                 # the file's own node (label == basename)
            file_nodes.setdefault(sf, n["id"])

    hyperedges = data.setdefault("hyperedges", [])
    counts = {"span": 0, "nearest-def": 0, "file": 0, "none": 0}
    for i, f in enumerate(findings):
        sink_file = f.get("sink_file") or f["source_file"]
        src_id, _ = _bind_node(f["source_file"], f["source_line"], by_file, code_nodes, file_nodes)
        sink_id, sink_m = _bind_node(sink_file, f["sink_line"], by_file, code_nodes, file_nodes)
        f["source_node"], f["sink_node"] = src_id, sink_id
        counts[sink_m] += 1
        f.setdefault("provenance", []).append(f"binding:{sink_m}")
        for nid in {src_id, sink_id}:
            node = node_by_id.get(nid)
            if node is not None:
                node["sec_layers"] = sorted(set(node.get("sec_layers", [])) | set(f.get("layers", [])))
        if src_id and sink_id and src_id != sink_id:
            hyperedges.append({
                "id": f"sec-path-{i}", "kind": "taint-path",
                "label": f"{f['source_id']} -> {f['sink_id']}" + (f" ({f['cwe']})" if f.get("cwe") else ""),
                "nodes": sorted({src_id, sink_id}),
            })

    assert len(data.get("nodes", [])) == n_before, "projection changed graph.json node count"
    graph_json.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return counts


def emit_artifacts(path: Path | str, out_dir: Path | str, finding_dicts: list[dict],
                   modules: list[ModuleIR], engine: dict) -> dict:
    """The shared projection tail (both the built-in engine and SARIF ingestion target it): run
    graphify, assign ids, bind + annotate graph.json, write taint.json + the HTML map."""
    from . import graphify_adapter
    from .viz import render_html

    path, out_dir = Path(path), Path(out_dir)
    result = graphify_adapter.run_graphify(path, out_dir)     # writes out_dir/graph.json
    for i, f in enumerate(finding_dicts):                     # callers pass findings pre-sorted
        f["id"] = f"path-{i:04d}"
    counts = _annotate_graph_json(result.graph_json, finding_dicts, modules)

    taint_json = out_dir / "taint.json"
    taint_json.write_text(
        # absolute root so `secgraph serve` reads slices regardless of its cwd (gitignored artifact)
        json.dumps({"version": 1, "root": str(path.resolve()), "engine": engine,
                    "findings": finding_dicts}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    graph_data = json.loads(result.graph_json.read_text(encoding="utf-8"))
    (out_dir / "secgraph.html").write_text(render_html(graph_data, finding_dicts, str(path)), encoding="utf-8")
    return {
        "findings": len(finding_dicts),
        "unguarded": sum(1 for f in finding_dicts if f.get("unguarded")),
        "binding": counts,
        "graph_json": result.graph_json, "taint_json": taint_json, "html": out_dir / "secgraph.html",
    }


def analyze_project(path: Path | str, out_dir: Path | str = "graphify-out") -> dict:
    """Built-in fallback: run graphify + the interprocedural taint engine (ADR-014 -- used when no
    external SARIF is supplied), and emit the 3 artifacts."""
    from .ir import build_project_ir
    from .rules import default_rules_dir, load_rules
    from .taint import run_project

    path = Path(path)
    modules = build_project_ir(path)
    findings = run_project(modules, load_rules(default_rules_dir()))
    finding_dicts = [_finding_dict(f, path) for f in findings]
    return emit_artifacts(path, out_dir, finding_dicts, modules, {"mode": "builtin"})


def analyze_ingest(path: Path | str, out_dir: Path | str, sarif_paths, semgrep_paths) -> dict:
    """Pivot path (ADR-014): ingest external SAST findings (SARIF / semgrep JSON) and render them
    through the same projection + map + MCP pipeline. graphify + the IR still run (map substrate +
    span binding + Phase-10 enrichment); the taint engine does not."""
    from .ingest import ingest_findings
    from .ingest.enrich import enrich_findings
    from .ir import build_project_ir
    from .rules import default_rules_dir, load_rules

    path = Path(path)
    rules = load_rules(default_rules_dir())
    modules = build_project_ir(path)
    findings, report = ingest_findings(path, sarif_paths, semgrep_paths, rules)
    enrich_findings(findings, path, modules, rules)          # credentials/PII layers + auth verdict
    r = emit_artifacts(path, out_dir, findings, modules, {"mode": "ingest", "inputs": report.inputs})
    r["report"] = report
    return r
