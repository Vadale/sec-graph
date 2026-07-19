"""SARIF 2.1.0 -> raw findings (ADR-014, Phase 9). Graphify-free. Defensive: every relevant
producer (CodeQL, ``semgrep --sarif``, Bandit, Snyk) emits SARIF, and the shapes vary -- the
fixture contract tests pin what we accept, like ``tests/contract`` pins graphify."""
from __future__ import annotations

from pathlib import Path

from .normalize import confidence_of, normalize_path, parse_cwe, severity_of, to_int


def _rule_index(driver: dict) -> dict:
    rules = driver.get("rules", []) or []
    return {r.get("id"): r for r in rules if r.get("id")}


def _cwe_for(rule: dict, result: dict) -> str | None:
    taxa = [t.get("name") or t.get("id") for t in (result.get("taxa") or []) if isinstance(t, dict)]
    props = rule.get("properties", {}) if rule else {}
    return parse_cwe(taxa, props.get("tags"), props.get("cwe"), result.get("ruleId"))


def _artifact(phys: dict, bases: dict, root: Path, known: set[str]):
    al = phys.get("artifactLocation", {})
    rel, reason = normalize_path(al.get("uri", ""), al.get("uriBaseId"), bases, root, known)
    region = phys.get("region", {})
    return rel, to_int(region.get("startLine"), 1), (region.get("snippet") or {}).get("text"), reason


def _loc(location: dict, bases: dict, root: Path, known: set[str]) -> dict:
    rel, line, snippet, reason = _artifact(location.get("physicalLocation", {}), bases, root, known)
    ll = location.get("logicalLocations") or []
    fqn = (ll[0].get("fullyQualifiedName") or ll[0].get("name")) if ll else None
    return {"file": rel, "line": line, "snippet": snippet, "reason": reason, "fqn": fqn,
            "expr": (location.get("message") or {}).get("text") or ""}


def _result(res: dict, rules_by_id: dict, tool: str,
            bases: dict, root: Path, known: set[str]) -> dict | None:
    locs = res.get("locations") or []
    if not locs:
        return None
    sink = _loc(locs[0], bases, root, known)
    if sink["file"] is None:                                   # sink unbindable -> drop (report it)
        return None
    rule_id = res.get("ruleId") or ""
    rule = rules_by_id.get(rule_id, {})

    flow_locs = []
    cflows = res.get("codeFlows") or []
    if cflows:
        tflows = cflows[0].get("threadFlows") or []
        if tflows:
            flow_locs = [_loc(tl.get("location", {}), bases, root, known)
                         for tl in (tflows[0].get("locations") or [])]
            flow_locs = [f for f in flow_locs if f["file"] is not None]
    if flow_locs:
        source, hops = flow_locs[0], flow_locs            # ordered source -> ... -> sink
        if (hops[-1]["file"], hops[-1]["line"]) != (sink["file"], sink["line"]):
            hops = [*hops, sink]                          # the flow must end at the authoritative sink
    else:
        source, hops = sink, [sink]                       # no flow -> source := sink (self-loop)

    trace = tuple(dict.fromkeys(h["fqn"] or f"{h['file']}:{h['line']}" for h in hops))
    sink_id = (rule_id.rsplit(".", 1)[-1].rsplit("/", 1)[-1]) or "finding"
    props = rule.get("properties", {})
    prov = ["ingest:sarif", f"tool:{tool}"]
    if len(cflows) > 1:
        prov.append(f"ingest:+{len(cflows) - 1}-alt-flows")
    return {
        "rule_id": rule_id or sink_id, "sink_id": sink_id,
        "source_id": (tool.split(" ", 1)[0].lower() + ":source") if flow_locs else sink_id,
        "source_file": source["file"], "source_line": source["line"],
        "sink_file": sink["file"], "sink_line": sink["line"], "sink_snippet": sink["snippet"],
        "hops": [{"file": h["file"], "line": h["line"], "expr": h["expr"]} for h in hops],
        "trace": list(trace),
        "cwe": _cwe_for(rule, res),
        "severity": severity_of(res.get("level") or rule.get("defaultConfiguration", {}).get("level"),
                                props.get("security-severity")),
        "confidence": confidence_of(props.get("precision"), props.get("confidence")),
        "message": (res.get("message") or {}).get("text") or "",
        "function": source["fqn"] or "", "sink_function": sink["fqn"] or "",
        "provenance": prov,
    }


def parse_sarif(data: dict, root: Path, known: set[str]) -> tuple[list[dict], list[dict]]:
    """(raw findings, dropped {uri, reason}) from a SARIF 2.1.0 document (all runs)."""
    findings: list[dict] = []
    dropped: list[dict] = []
    for run in data.get("runs", []) or []:
        driver = run.get("tool", {}).get("driver", {})
        tool = " ".join(filter(None, [driver.get("name", "SARIF"),
                                      driver.get("semanticVersion") or driver.get("version")]))
        rules_by_id = _rule_index(driver)
        bases = run.get("originalUriBaseIds", {}) or {}
        for res in run.get("results", []) or []:
            try:                                          # a malformed result must not abort the ingest
                f = _result(res, rules_by_id, tool, bases, root, known)
            except (KeyError, AttributeError, TypeError, IndexError):
                dropped.append({"uri": "?", "reason": "parse-error", "tool": tool})
                continue
            if f is None:
                loc = ((res.get("locations") or [{}])[0] if isinstance(res.get("locations"), list) else {})
                al = loc.get("physicalLocation", {}).get("artifactLocation", {}) if isinstance(loc, dict) else {}
                dropped.append({"uri": al.get("uri", "?"), "reason": "sink-unbound", "tool": tool})
            else:
                findings.append(f)
    return findings, dropped
