"""Layer enrichment over ingested findings (ADR-014, Phase 10) -- the differentiator over raw SAST
output. Graphify-free. Two enrichments, both HONESTLY labelled:

* **sensitive-data layers** -- lexical: identifiers/literals on the finding's source/sink/hop lines
  (the tool already proved data flows through them) via ``ident_label``/``classify_secret``. This is
  identifier-on-a-verified-flow, *not* taint-on-the-value (weaker than ADR-009 origins) -> add-only,
  ``enrich:lexical@…`` provenance.
* **auth / unguarded** -- for a Python sink, the real ADR-010 ``guard_map`` over the enclosing
  function (``guard_status:"analyzed"``); everything else stays ``guard_status:"unknown"`` and the
  consumers claim NEITHER verdict (no glow, no green ring) -- ADR-010's asymmetry without a false glow.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..callgraph.resolve import _shadow_imap
from ..ir.model import Branch, For, If, ModuleIR, While
from ..project import _read_slice
from ..rules.labels import classify_secret, ident_label
from ..taint.guards import guard_map

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# non-ambiguous: a backslash is consumed ONLY by `\\.` (the "other" branch excludes it), so there is
# no exponential partition of a backslash run -> linear, no ReDoS. `(?!\1)` still allows the other quote.
_STRLIT = re.compile(r"""(['"])((?:\\.|(?!\1)[^\\])*)\1""")


def _flow_points(f: dict) -> list[tuple[str, str, int]]:
    pts = [("source", f["source_file"], f["source_line"]),
           ("sink", f.get("sink_file") or f["source_file"], f["sink_line"])]
    pts += [("hop", h["file"], h["line"]) for h in f.get("hops", [])]
    return pts


def _label_layers(f: dict, root: Path, rules) -> None:
    added: set[str] = set()
    prov: set[str] = set()
    for role, file, line in _flow_points(f):
        text = _read_slice(root, file, line)
        if not text:
            continue
        code = _STRLIT.sub(" ", text).split("#", 1)[0]   # drop string bodies + trailing comment first,
        for name in _IDENT.findall(code):                # so `# ...password` / "...email..." don't false-label
            layers, _ = ident_label(name, rules)
            if layers:
                added |= set(layers)
                prov.add(f"enrich:lexical@{role}")
        for m in _STRLIT.finditer(text):                 # secrets, though, come FROM the string literals
            lyrs, sid, _ = classify_secret(m.group(2), rules)
            if lyrs:
                added |= set(lyrs)
                prov.add(f"enrich:{sid}")
    if added - set(f["layers"]):
        f["layers"] = sorted(set(f["layers"]) | added)      # add-only (never remove an engine layer)
    f["provenance"].extend(sorted(prov))


def _substmts(s):
    if isinstance(s, If):
        yield s.body
        yield s.orelse
    elif isinstance(s, (While, For)):
        yield s.body
    elif isinstance(s, Branch):
        yield from s.arms


def _sid_at_line(body, line: int) -> int | None:
    """The sid of the tightest statement whose span contains ``line`` -- the sink statement, so its
    guards match the engine's ``guards.get(sid)``. On a same-line compound (`if auth: sink()`) the
    inner arm statement (deeper, visited later) must win, else we'd read the outer `if`'s guards."""
    best_key, best_sid = None, None
    stack = [body]
    while stack:
        for s in stack.pop():
            sp = getattr(s, "span", None)
            if sp is not None and sp.start_line <= line <= sp.end_line:
                key = (sp.start_line, -sp.end_line)          # innermost: largest start, smallest span
                if best_key is None or key >= best_key:       # >= so the deeper same-line statement wins
                    best_key, best_sid = key, s.sid
            for sub in _substmts(s):
                stack.append(sub)
    return best_sid


def _guard_verdict(f: dict, fn_index: dict, rules) -> None:
    sink_file = f.get("sink_file") or f["source_file"]
    if not sink_file.endswith(".py"):
        return                                               # non-Python -> guard_status stays "unknown"
    best = None
    for start, end, fn, module in fn_index.get(sink_file, ()):
        if start <= f["sink_line"] <= end and (best is None or start > best[0]):
            best = (start, fn, module)
    if best is None:
        return                                               # module-level / no enclosing fn -> unknown
    _, fn, module = best
    imap = _shadow_imap(module, fn)          # drop imports the fn shadows -- the engine's own filter (false-guarded fix)
    gm = guard_map(fn, imap, rules)
    base = tuple(d for d in fn.decorators if d in rules.barriers.decorators)
    guards = gm.get(_sid_at_line(fn.body, f["sink_line"]), base)
    f["guards"] = list(guards)
    f["unguarded"] = not guards
    f["guard_status"] = "analyzed"


def enrich_findings(findings: list[dict], root: Path | str, modules: list[ModuleIR], rules) -> None:
    """Enrich ingested findings in place: sensitive-data layers + the Python auth/unguarded verdict."""
    root = Path(root)
    fn_index: dict[str, list] = {}
    for m in modules:
        for fn in m.functions:
            fn_index.setdefault(fn.source_file, []).append((fn.span.start_line, fn.span.end_line, fn, m))
    for f in findings:
        _label_layers(f, root, rules)
        _guard_verdict(f, fn_index, rules)
