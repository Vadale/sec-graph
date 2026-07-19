"""Ingest external SAST findings (SARIF / semgrep JSON) into the normalized finding-dict contract
(ADR-014, Phase 9). Graphify-free; the projection binds the dicts to graph nodes. Deterministic:
identical inputs -> identical (dedup'd, sorted) findings."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .normalize import build_finding
from .sarif import parse_sarif
from .semgrep import parse_semgrep

_SKIP = {".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache",
         ".pytest_cache", "dist", "build", "graphify-out", ".ruff_cache"}


@dataclass(slots=True)
class IngestReport:
    inputs: list[dict] = field(default_factory=list)     # {path, sha256, kind, tools, n}
    dropped: list[dict] = field(default_factory=list)    # {uri, reason, tool}
    n_findings: int = 0


def _known_files(root: Path) -> set[str]:
    out: set[str] = set()
    for p in root.rglob("*"):
        rel = p.relative_to(root)
        if p.is_file() and not (set(rel.parts) & _SKIP):
            out.add(rel.as_posix())
    return out


def _sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _dedup(findings: list[dict]) -> list[dict]:
    """First finding per (rule_id, source, sink) wins; a later tool's hit is noted in provenance."""
    seen: dict[tuple, dict] = {}
    for f in findings:
        key = (f["rule_id"], f["source_file"], f["source_line"], f["sink_file"], f["sink_line"])
        if key in seen:
            for p in f.get("provenance", []):
                if p.startswith("tool:") and p not in seen[key]["provenance"]:
                    seen[key]["provenance"].append(p)
        else:
            seen[key] = f
    return list(seen.values())


def ingest_findings(root: Path | str, sarif_paths, semgrep_paths, rules) -> tuple[list[dict], IngestReport]:
    root = Path(root)
    known = _known_files(root)
    report = IngestReport()
    raws: list[dict] = []
    for sp, kind, parse in ([(p, "sarif", parse_sarif) for p in (sarif_paths or [])]
                            + [(p, "semgrep", parse_semgrep) for p in (semgrep_paths or [])]):
        data = json.loads(Path(sp).read_text(encoding="utf-8"))
        fs, dropped = parse(data, root, known)
        raws.extend(fs)
        report.dropped.extend(dropped)
        tools = sorted({p[len("tool:"):] for f in fs for p in f["provenance"] if p.startswith("tool:")})
        report.inputs.append({"path": str(sp), "sha256": _sha(Path(sp)), "kind": kind,
                              "tools": tools, "n": len(fs)})

    built: list[dict] = []
    for r in raws:
        try:                                          # a malformed raw finding must not abort the ingest
            built.append(build_finding(r, root))
        except (KeyError, TypeError, ValueError):
            report.dropped.append({"uri": r.get("sink_file", "?"), "reason": "build-error", "tool": "?"})
    findings = _dedup(built)
    findings.sort(key=lambda f: (f["sink_file"], f["sink_line"], f["source_file"],
                                 f["source_line"], f["rule_id"]))
    report.n_findings = len(findings)
    return findings, report
