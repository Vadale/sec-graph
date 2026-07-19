"""Semgrep native JSON (`semgrep scan --json --dataflow-traces`) -> raw findings (ADR-014,
Phase 9). Its `extra.dataflow_trace` is the richest trace source. Graphify-free. Defensive: the
`taint_source`/`taint_sink` serialization (``["CliLoc",[loc,content]]`` / ``CliCall`` nesting) has
changed across semgrep versions -- we dig for the leaf location and pin the shape in fixtures."""
from __future__ import annotations

from pathlib import Path

from .normalize import confidence_of, normalize_path, parse_cwe, to_int

_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _find_loc(node):
    """(path, line, content) from semgrep's tagged/bare location shapes, or None."""
    if isinstance(node, dict):
        if "path" in node and "start" in node:
            return node["path"], to_int((node.get("start") or {}).get("line"), 1), None
        if "location" in node:
            got = _find_loc(node["location"])
            return (got[0], got[1], node.get("content")) if got else None
    if isinstance(node, list):
        tag = node[0] if node and isinstance(node[0], str) else None
        if tag in ("CliLoc",) and len(node) > 1 and isinstance(node[1], list) and node[1]:
            got = _find_loc(node[1][0])
            content = node[1][1] if len(node[1]) > 1 else None
            return (got[0], got[1], content) if got else None
        for c in node:                                    # CliCall / other nesting -> first leaf loc
            got = _find_loc(c)
            if got:
                return got
    return None


def _hop(pathinfo, root: Path, known: set[str]) -> dict | None:
    if pathinfo is None:
        return None
    rel, _ = normalize_path(pathinfo[0], None, {}, root, known)
    return None if rel is None else {"file": rel, "line": pathinfo[1], "expr": pathinfo[2] or ""}


def _sg_result(res: dict, root: Path, known: set[str]) -> dict | None:
    sink = _hop((res.get("path"), to_int((res.get("start") or {}).get("line"), 1), None), root, known)
    if sink is None:
        return None
    extra = res.get("extra", {}) or {}
    meta = extra.get("metadata", {}) or {}
    trace_obj = extra.get("dataflow_trace") or {}
    src = _hop(_find_loc(trace_obj.get("taint_source")), root, known)
    inter = [_hop(_find_loc(v), root, known) for v in (trace_obj.get("intermediate_vars") or [])]
    hops = [h for h in [src, *inter, sink] if h is not None] if src is not None else [sink]
    source = hops[0]
    check = res.get("check_id", "semgrep")
    sink_id = check.rsplit(".", 1)[-1]
    return {
        "rule_id": check, "sink_id": sink_id,
        "source_id": "semgrep:source" if src is not None else sink_id,
        "source_file": source["file"], "source_line": source["line"],
        "sink_file": sink["file"], "sink_line": sink["line"], "sink_snippet": extra.get("lines"),
        "hops": [{"file": h["file"], "line": h["line"], "expr": h["expr"]} for h in hops],
        "trace": list(dict.fromkeys(f"{h['file']}:{h['line']}" for h in hops)),
        "cwe": parse_cwe(meta.get("cwe"), check),
        "severity": _SEV.get(extra.get("severity"), "medium"),
        "confidence": confidence_of(None, meta.get("confidence")),
        "message": extra.get("message", ""),
        "provenance": ["ingest:semgrep", "tool:Semgrep"],
    }


def parse_semgrep(data: dict, root: Path, known: set[str]) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    dropped: list[dict] = []
    for res in data.get("results", []) or []:
        uri = res.get("path", "?") if isinstance(res, dict) else "?"
        try:                                          # a malformed result must not abort the ingest
            f = _sg_result(res, root, known)
        except (KeyError, AttributeError, TypeError, IndexError):
            dropped.append({"uri": uri, "reason": "parse-error", "tool": "Semgrep"})
            continue
        (findings if f is not None else dropped).append(
            f if f is not None else {"uri": uri, "reason": "sink-unbound", "tool": "Semgrep"})
    return findings, dropped
