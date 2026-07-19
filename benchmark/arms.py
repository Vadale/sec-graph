"""The three evidence renderers (PROTOCOL §3). Each turns ONE finding into the evidence block a
triage LLM sees. Everything else (model, prompt skeleton, decoding) is held constant in triage.py.

- Arm A (control, steelman): the rendered SARIF fields + the FULL numbered text of every file in the
  finding's data-flow. A's evidence is a strict superset of the raw material behind B — a B win cannot
  be "A lacked information."
- Arm B (treatment): exactly the real sec-graph MCP payload (list_paths summary + get_path_slice
  windows + enrichment layers/guard verdict).
- Arm C (ablation): B's slices with the enrichment stripped (isolates minimal-slices vs enrichment).
"""
from __future__ import annotations

from pathlib import Path

# ---- SARIF helpers ---------------------------------------------------------------------------

def rule_index(run: dict) -> dict:
    return {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}


def primary_loc(result: dict) -> tuple[str, int]:
    pl = result["locations"][0]["physicalLocation"]
    return pl["artifactLocation"]["uri"], pl["region"]["startLine"]


def flow_steps(result: dict) -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    for cf in result.get("codeFlows", []) or []:
        for tf in cf.get("threadFlows", []):
            for loc in tf.get("locations", []):
                pl = loc["location"]["physicalLocation"]
                msg = (loc["location"].get("message") or {}).get("text", "")
                out.append((pl["artifactLocation"]["uri"], pl["region"]["startLine"], msg))
        break   # first code flow only (as get_path_slice does)
    return out


def flow_files(result: dict) -> list[str]:
    """Every distinct file the finding touches (sink + all flow steps), in first-seen order."""
    seen: list[str] = []
    for f, _ in [primary_loc(result)]:
        if f not in seen:
            seen.append(f)
    for f, _l, _m in flow_steps(result):
        if f not in seen:
            seen.append(f)
    return seen


def sarif_key(result: dict, ordinal: int) -> tuple:
    f, l = primary_loc(result)
    return (result.get("ruleId"), f, l, ordinal)


def join_key(result: dict) -> tuple:
    """The structural join between SARIF, truth.json and sec-graph: (rule_id, sink_file, sink_line)."""
    f, l = primary_loc(result)
    return (result.get("ruleId"), f, l)


# ---- rendering -------------------------------------------------------------------------------

def _numbered(path: Path) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "  <file unreadable>"
    return "\n".join(f"{n:5}  {t}" for n, t in enumerate(lines, 1))


def _windows_text(windows: list[dict]) -> str:
    out: list[str] = []
    for w in windows:
        stale = "  [STALE]" if w.get("stale") else ""
        out.append(f"# {w['role']} -- {w['file']}:{w['line']}{stale}")
        for ln in w.get("code", []):
            out.append(f"{'>' if ln['mark'] else ' '} {ln['n']:>5}  {ln['text']}")
    return "\n".join(out)


def render_A(result: dict, rules: dict, root: Path) -> str:
    rid = result.get("ruleId", "?")
    rule = rules.get(rid, {})
    props = rule.get("properties", {})
    sd = (rule.get("shortDescription") or {}).get("text", "")
    fd = (rule.get("fullDescription") or {}).get("text", "")
    f, l = primary_loc(result)
    out = [f"A static analyzer flagged this finding.",
           f"Rule: {rid}" + (f" — {sd}" if sd else ""),
           f"Description: {fd}" if fd and fd != sd else "",
           f"Severity: {props.get('problem.severity', '?')} (security-severity {props.get('security-severity', '?')})",
           f"Message: {result['message']['text']}",
           f"Primary location: {f}:{l}"]
    steps = flow_steps(result)
    if steps:
        out.append("Data-flow steps (source -> sink):")
        out += [f"  {sf}:{sl} — {sm}" for sf, sl, sm in steps]
    for ff in flow_files(result):
        out.append(f"\n===== {ff} (full source, numbered) =====")
        out.append(_numbered(root / ff))
    return "\n".join(x for x in out if x != "")


def render_B(payload: dict) -> str:
    s = payload["summary"]
    out = [f"sec-graph flagged a data-flow path ({s.get('id')}).",
           f"CWE: {s.get('cwe')}   severity: {s.get('severity')}   confidence: {s.get('confidence')}",
           f"Enrichment layers: {', '.join(s.get('layers') or []) or '(none)'}",
           f"Auth barrier: unguarded={s.get('unguarded')}  guard_status={s.get('guard_status')}  "
           f"guards={', '.join(s.get('guards') or []) or '(none)'}",
           f"Source: {s.get('source')}",
           f"Sink:   {s.get('sink')}",
           "Minimal hash-verified code windows (source -> sink):",
           _windows_text(payload.get("windows", []))]
    return "\n".join(out)


def render_C(payload: dict) -> str:
    """Ablation: same minimal slices, enrichment stripped (no layers/guard verdict)."""
    s = payload["summary"]
    out = [f"sec-graph flagged a data-flow path ({s.get('id')}).",
           f"CWE: {s.get('cwe')}   severity: {s.get('severity')}",
           f"Source: {s.get('source')}",
           f"Sink:   {s.get('sink')}",
           "Minimal hash-verified code windows (source -> sink):",
           _windows_text(payload.get("windows", []))]
    return "\n".join(out)
