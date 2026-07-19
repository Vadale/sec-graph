"""Deterministic orderings for the prioritization metric (PROTOCOL §4). The claim is O3 vs O2 —
never O3 vs O1 (beating unsorted SARIF is trivial).

- O2 = severity-sorted raw SARIF: (security-severity desc, level rank, file, line). The real baseline an
  engineer gets with one `jq`.
- O3 = sec-graph's list_paths order, computed with the SAME `_rank` the MCP server uses (guard tier,
  severity, confidence, id) — imported from secgraph.mcp_view so O3 is exactly the product ordering.

Both return a list of finding join-keys (rule_id, sink_file, sink_line)."""
from __future__ import annotations

from secgraph.mcp_view import _rank

_LEVEL = {"error": 0, "warning": 1, "note": 2, "none": 3}


def _f(x, default=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def order_O2(results: list[dict], rules: dict) -> list[tuple]:
    def key(r):
        rid = r.get("ruleId", "")
        secsev = _f((rules.get(rid, {}).get("properties") or {}).get("security-severity"))
        pl = r["locations"][0]["physicalLocation"]
        f, l = pl["artifactLocation"]["uri"], pl["region"]["startLine"]
        return (-secsev, _LEVEL.get(r.get("level", "warning"), 1), f, l)
    out = []
    for r in sorted(results, key=key):
        pl = r["locations"][0]["physicalLocation"]
        out.append((r.get("ruleId"), pl["artifactLocation"]["uri"], pl["region"]["startLine"]))
    return out


def taint_join_key(f: dict) -> tuple:
    return (f.get("rule_id"), f.get("sink_file") or f.get("source_file"), f.get("sink_line"))


def order_O3(taint_findings: list[dict]) -> list[tuple]:
    return [taint_join_key(f) for f in sorted(taint_findings, key=_rank)]
