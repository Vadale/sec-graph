"""Pure, deterministic read-only view over the analysis artifacts (``taint.json`` + ``graph.json``)
that backs the MCP tools (ROADMAP §13). No graphify, no LLM, no MCP-SDK import here -- so the tool
logic is unit-testable on its own; ``secgraph.mcp_server`` is only a thin FastMCP wrapper over this.

Principle: **coarse discovery -> precise slicing**. ``list_paths`` returns ranked summaries; the
agent then pulls exactly one path's minimal, hash-verified code windows with ``get_path_slice`` --
never the whole repo.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

_CONF = {"high": 3, "medium": 2, "low": 1}
_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _rank(f: dict) -> tuple:
    """Ranking key: unguarded first, then severity, then confidence, then id (stable)."""
    return (0 if f.get("unguarded") else 1,
            -_SEV.get(f.get("severity", ""), 0), -_CONF.get(f.get("confidence", ""), 0), f.get("id", ""))


class TaintView:
    def __init__(self, out_dir: Path | str) -> None:
        out = Path(out_dir)
        taint = json.loads((out / "taint.json").read_text(encoding="utf-8"))
        self.root = Path(taint.get("root", "."))
        self.findings: list[dict] = taint.get("findings", [])
        self.by_id = {f["id"]: f for f in self.findings if "id" in f}   # tolerate a pre-Phase-6 artifact
        gj = out / "graph.json"
        self.graph = json.loads(gj.read_text(encoding="utf-8")) if gj.exists() else {"nodes": [], "hyperedges": []}

    # ---- tools (ROADMAP §13) -----------------------------------------------------

    def list_paths(self, layer: str | None = None, min_confidence: str | None = None,
                   file: str | None = None, limit: int = 50, offset: int = 0) -> dict:
        rows = self._filter(self.findings, layer, min_confidence, file)
        ranked = sorted(rows, key=_rank)
        page = ranked[offset:offset + max(0, limit)]
        return {"total": len(ranked), "offset": offset, "limit": limit,
                "paths": [self._summary(f) for f in page]}

    def find_unguarded_sinks(self, layer: str | None = None) -> dict:
        rows = [f for f in self.findings if f.get("unguarded")]
        rows = self._filter(rows, layer, None, None)
        return {"total": len(rows), "paths": [self._summary(f) for f in sorted(rows, key=_rank)]}

    def get_path_slice(self, path_id: str, context_lines: int = 3) -> dict:
        f = self.by_id.get(path_id)
        if f is None:
            return {"error": f"unknown path_id {path_id!r}"}
        hashes = f.get("file_hashes", {})
        hops = f.get("hops")
        if hops:                                        # ingested paths carry per-hop locations
            windows, seen = [], set()
            for i, h in enumerate(hops):
                if (h["file"], h["line"]) in seen:
                    continue
                seen.add((h["file"], h["line"]))
                role = "source" if i == 0 else "sink" if i == len(hops) - 1 else "hop"
                windows.append(self._window(role, h["file"], h["line"], context_lines, hashes.get(h["file"])))
        else:
            sink_file = f.get("sink_file") or f["source_file"]
            windows = [
                self._window("source", f["source_file"], f["source_line"], context_lines, hashes.get(f["source_file"])),
                self._window("sink", sink_file, f["sink_line"], context_lines, hashes.get(sink_file)),
            ]
        return {"id": path_id, "cwe": f.get("cwe"), "layers": f.get("layers", []),
                "confidence": f.get("confidence"), "unguarded": f.get("unguarded"),
                "guards": f.get("guards", []), "trace": f.get("trace", []), "windows": windows}

    def explain_layer(self, layer: str) -> dict:
        """Deterministic provenance for a layer, read from the rule packs (no guessing)."""
        from .rules import default_rules_dir, load_rules
        rules = load_rules(default_rules_dir())
        if layer == "untrusted-input":
            prov = {"sources": [r.id for r in rules.sources if layer in r.layers]}
        elif layer == "dangerous-sink":
            prov = {"sinks": [{"id": r.id, "cwe": r.cwe} for r in rules.sinks if layer in r.layers]}
        elif layer in rules.labels:
            lr = rules.labels[layer]
            prov = {"identifiers": list(lr.identifiers), "confidence": lr.confidence,
                    "secret_patterns": [p.id for p in (rules.secrets.patterns if rules.secrets else ())
                                        if layer in p.layers]}
        elif layer == "auth":
            b = rules.barriers
            prov = {"decorators": list(b.decorators), "callables": list(b.callables),
                    "test_attrs": list(b.test_attrs), "aborts": list(b.aborts)}
        else:
            return {"layer": layer, "error": "unknown layer", "known": self._layers()}
        nodes = [n["id"] for n in self.graph.get("nodes", []) if layer in n.get("sec_layers", [])]
        return {"layer": layer, "provenance": prov, "tagged_nodes": nodes,
                "path_count": sum(1 for f in self.findings if layer in f.get("layers", []))}

    def get_function_taint(self, node_id: str) -> dict:
        """Taint summary for one graphify entity node: its layers + the paths whose source or sink
        node IS this node. Uses the sound ``source_node``/``sink_node`` binding stamped by the
        projection (the (file, def-line) span join), so methods (`.get()`) and same-name functions
        resolve correctly -- a name match on the dotted label would not."""
        node = next((n for n in self.graph.get("nodes", []) if n.get("id") == node_id), None)
        if node is None:
            return {"error": f"unknown node_id {node_id!r}"}
        hits = [f for f in self.findings if node_id in (f.get("source_node"), f.get("sink_node"))]
        paths = [self._summary(f) for f in sorted(hits, key=_rank)]
        return {"node_id": node_id, "label": node.get("label"),
                "sec_layers": node.get("sec_layers", []), "paths": paths}

    # ---- helpers -----------------------------------------------------------------

    def _layers(self) -> list[str]:
        return sorted({layer for f in self.findings for layer in f.get("layers", [])})

    def _filter(self, rows, layer, min_confidence, file):
        if layer:
            rows = [f for f in rows if layer in f.get("layers", [])]
        if file:
            rows = [f for f in rows if file in (f.get("source_file"), f.get("sink_file"))]
        if min_confidence:
            floor = _CONF.get(min_confidence, 0)
            rows = [f for f in rows if _CONF.get(f.get("confidence", ""), 0) >= floor]
        return rows

    def _summary(self, f: dict) -> dict:
        return {
            "id": f["id"], "cwe": f.get("cwe"), "severity": f.get("severity"),
            "source": f"{f['source_id']} @ {f['source_file']}:{f['source_line']}",
            "sink": f"{f['sink_id']} @ {f.get('sink_file') or f['source_file']}:{f['sink_line']}",
            "layers": f.get("layers", []), "confidence": f.get("confidence"),
            "unguarded": f.get("unguarded"), "guards": f.get("guards", []), "hops": f.get("trace", []),
        }

    def _window(self, role: str, rel: str, line: int, ctx: int, expected_hash: str | None) -> dict:
        path = self.root / rel
        try:
            raw = path.read_bytes()
        except OSError:
            return {"role": role, "file": rel, "line": line, "stale": True, "error": "unreadable"}
        cur = "sha256:" + hashlib.sha256(raw).hexdigest()
        lines = raw.decode("utf-8", "replace").splitlines()
        lo, hi = max(1, line - ctx), min(len(lines), line + ctx)
        code = [{"n": n, "text": lines[n - 1], "mark": n == line} for n in range(lo, hi + 1)]
        return {"role": role, "file": rel, "line": line,
                "stale": bool(expected_hash) and cur != expected_hash, "code": code}
