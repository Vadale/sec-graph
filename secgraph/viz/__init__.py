"""Render the analysis as a single self-contained interactive graph map (``secgraph.html``).

An Obsidian/graphify-style force-directed node-link map (ADR-012): the base graph is grayscale
geometry, colour is spent only on security semantics, and a glow marks only UNGUARDED sink paths --
so the critical routes (credentials/PII reaching a dangerous sink with no auth barrier) are the
unmistakable hero. The layout, rendering and interactions are hand-written vanilla JS on a Canvas
(no CDN / no library -- strict CSP), seeded for a deterministic layout. Untrusted text (labels, code
slices) is inserted via ``textContent`` / ``fillText`` only, and the embedded JSON escapes ``<`` so
it cannot break out of its ``<script type="application/json">`` island.

The heavy CSS/JS live beside this module as ``map.css`` / ``map.js`` (real files, not Python
strings) and are inlined at render time.
"""
from __future__ import annotations

import json
from pathlib import Path

_HERE = Path(__file__).parent
_NODE_KEYS = ("id", "label", "file_type", "source_file", "source_location", "community", "sec_layers")
_LINK_KEYS = ("source", "target", "relation")


def _prune(graph: dict) -> dict:
    """Keep only what the map draws (a real repo's graph.json is large; the HTML must stay small).
    Routes come from the findings' ``source_node``/``sink_node``, so hyperedges are not embedded."""
    nodes = [{k: n.get(k) for k in _NODE_KEYS if k in n} for n in graph.get("nodes", [])]
    links = [{k: e.get(k) for k in _LINK_KEYS if k in e} for e in graph.get("links", [])]
    return {"nodes": nodes, "links": links}


def _embed(obj) -> str:
    # '<' only occurs inside JSON string values -> < keeps valid JSON and can't leave script-data
    return json.dumps(obj, ensure_ascii=False).replace("<", "\\u003c")


def _esc(s: str) -> str:
    """Escape the one dynamic value (the analyzed path) interpolated into HTML outside a JSON island."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_html(graph: dict, findings: list[dict], root: str) -> str:
    css = (_HERE / "map.css").read_text(encoding="utf-8")
    js = (_HERE / "map.js").read_text(encoding="utf-8")
    n_find = len(findings)
    n_unguarded = sum(1 for f in findings if f.get("unguarded"))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sec-graph &mdash; map</title><style>{css}</style></head>
<body>
<header>
  <div class="brand"><b>sec-graph</b> <span class="sub">{n_find} path{'' if n_find == 1 else 's'} &middot; \
{n_unguarded} unguarded &middot; <code>{_esc(root)}</code></span></div>
  <input id="search" type="search" placeholder="Search functions / files&hellip;  ( / )" autocomplete="off">
  <button class="btn" id="fit" title="Zoom to fit (F)">Fit</button>
  <button class="btn" id="theme" title="Toggle theme">&#9680;</button>
</header>
<div class="wrap">
  <aside class="rail">
    <button class="preset" id="preset-critical" title="credentials/PII reaching a dangerous sink, unguarded">
      &#9888; Critical paths</button>
    <label class="sw"><input type="checkbox" id="only-unguarded"> Unguarded only</label>
    <label class="sw"><input type="checkbox" id="full-graph"> Show full graph</label>
    <h2>Layers</h2><div id="layers"></div>
    <div class="legend" id="legend"></div>
  </aside>
  <main>
    <canvas id="map"></canvas>
    <div class="tip" id="tip" hidden></div>
    <div class="hint" id="hint">drag to pan &middot; scroll to zoom &middot; click a path</div>
  </main>
  <aside class="side"><div id="panel"></div></aside>
</div>
<script id="secgraph-graph" type="application/json">{_embed(_prune(graph))}</script>
<script id="secgraph-findings" type="application/json">{_embed(findings)}</script>
<script>{js}</script>
</body></html>"""
