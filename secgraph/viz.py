"""Render the taint findings as a single self-contained HTML map (``secgraph.html``).

Layered "Google-Maps" toggles (one checkbox per security layer) filter which source->sink
paths are shown; each finding renders as a railway from its source to its sink with the code
slices. No external resources (CSP-safe / air-gapped). Code slices are inserted via
``textContent`` in JS (never innerHTML), so untrusted source text cannot inject markup.
"""
from __future__ import annotations

import json

_CSS = """
:root { color-scheme: light dark; --bg:#fbfbfd; --fg:#1d1d1f; --card:#fff; --line:#e3e3e8;
  --muted:#6e6e73; --accent:#0066cc; --chip:#eef1f6; --code:#f5f5f7; }
@media (prefers-color-scheme: dark){ :root{ --bg:#0e0e12; --fg:#e8e8ec; --card:#17171d;
  --line:#2a2a33; --muted:#9a9aa4; --accent:#4c9dff; --chip:#22222b; --code:#101015; } }
:root[data-theme=light]{ --bg:#fbfbfd; --fg:#1d1d1f; --card:#fff; --line:#e3e3e8; --muted:#6e6e73; --accent:#0066cc; --chip:#eef1f6; --code:#f5f5f7; }
:root[data-theme=dark]{ --bg:#0e0e12; --fg:#e8e8ec; --card:#17171d; --line:#2a2a33; --muted:#9a9aa4; --accent:#4c9dff; --chip:#22222b; --code:#101015; }
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{padding:20px 24px;border-bottom:1px solid var(--line)}
h1{margin:0;font-size:19px} .sub{color:var(--muted);font-size:13px;margin-top:4px}
.wrap{display:flex;gap:0;align-items:flex-start}
aside{width:240px;flex:none;padding:20px 18px;border-right:1px solid var(--line);
  position:sticky;top:0;height:100vh;overflow:auto}
aside h2{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}
.layer{display:flex;align-items:center;gap:9px;padding:6px 4px;cursor:pointer;border-radius:7px}
.layer:hover{background:var(--chip)} .layer input{accent-color:var(--accent)}
.dot{width:9px;height:9px;border-radius:50%;flex:none}
main{flex:1;padding:20px 24px;min-width:0}
.empty{color:var(--muted);padding:40px 0;text-align:center}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:14px}
.card .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sev{font-size:11px;font-weight:700;letter-spacing:.04em;padding:3px 8px;border-radius:6px;color:#fff}
.sev.critical{background:#c1121f} .sev.high{background:#d1495b} .sev.medium{background:#c98a1e} .sev.low{background:#5a7d9a}
.sev.unguarded{background:#9d174d} .chip.guard{background:#123f2a;color:#8fe3b0;border-color:#1c5c3e}
.cwe{font-weight:600} .conf{color:var(--muted);font-size:12px;margin-left:auto}
.rail{display:flex;align-items:center;gap:10px;margin:14px 0 6px;flex-wrap:wrap}
.node{background:var(--chip);border:1px solid var(--line);border-radius:8px;padding:8px 11px;min-width:0}
.node .role{font-size:10px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted)}
.node .loc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;margin-top:2px}
.arrow{color:var(--accent);font-size:20px;flex:none}
.trace{color:var(--muted);font-size:12px;font-family:ui-monospace,monospace;margin-top:4px}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:9px 12px;margin:4px 0 0;
  overflow-x:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
.chips{margin-top:10px;display:flex;gap:6px;flex-wrap:wrap}
.chip{font-size:11px;background:var(--chip);border:1px solid var(--line);border-radius:20px;padding:2px 10px;color:var(--muted)}
.themebtn{margin-left:auto;background:var(--chip);border:1px solid var(--line);color:var(--fg);
  border-radius:8px;padding:6px 12px;cursor:pointer;font-size:13px}
.hdr{display:flex;align-items:center;gap:12px}
"""

_LAYER_COLORS = {
    "untrusted-input": "#4c9dff", "dangerous-sink": "#d1495b", "credentials": "#c98a1e",
    "pii": "#8e7cc3", "auth": "#2a9d8f",
}

_JS = r"""
const DATA = JSON.parse(document.getElementById('secgraph-data').textContent);
const layers = [...new Set(DATA.flatMap(f => f.layers))].sort();
const state = new Set(layers);
const side = document.getElementById('layers');
const COLORS = %COLORS%;
for (const L of layers) {
  const row = document.createElement('label'); row.className = 'layer';
  const cb = document.createElement('input'); cb.type='checkbox'; cb.checked=true;
  cb.onchange = () => { cb.checked ? state.add(L) : state.delete(L); render(); };
  const dot = document.createElement('span'); dot.className='dot'; dot.style.background = COLORS[L] || '#888';
  const t = document.createElement('span'); t.textContent = L;
  row.append(cb, dot, t); side.append(row);
}
function node(role, file, line, fn) {
  const d = document.createElement('div'); d.className='node';
  const r = document.createElement('div'); r.className='role'; r.textContent = role;
  const l = document.createElement('div'); l.className='loc';
  l.textContent = file + ':' + line + (fn ? '  ' + fn + '()' : '');
  d.append(r, l); return d;
}
function render() {
  const main = document.getElementById('findings'); main.textContent = '';
  const shown = DATA.filter(f => f.layers.some(l => state.has(l)));
  document.getElementById('count').textContent =
    shown.length + ' of ' + DATA.length + ' finding' + (DATA.length===1?'':'s');
  if (!shown.length) { const e=document.createElement('div'); e.className='empty';
    e.textContent = DATA.length ? 'No findings match the selected layers.' : 'No findings.'; main.append(e); return; }
  for (const f of shown) {
    const c = document.createElement('div'); c.className='card';
    const top = document.createElement('div'); top.className='top';
    const sev = document.createElement('span'); sev.className='sev '+f.severity; sev.textContent=f.severity;
    const cwe = document.createElement('span'); cwe.className='cwe'; cwe.textContent=(f.cwe?f.cwe+' ':'')+f.source_id+' → '+f.sink_id;
    const conf = document.createElement('span'); conf.className='conf'; conf.textContent='confidence: '+f.confidence;
    top.append(sev, cwe);
    if (f.unguarded) { const u=document.createElement('span'); u.className='sev unguarded'; u.textContent='UNGUARDED'; top.append(u); }
    top.append(conf); c.append(top);
    const rail = document.createElement('div'); rail.className='rail';
    const a = document.createElement('span'); a.className='arrow'; a.textContent='→';
    rail.append(node('source', f.source_file, f.source_line, f.function), a,
                node('sink', f.sink_file, f.sink_line, f.sink_function));
    c.append(rail);
    if (f.trace && f.trace.length){ const tr=document.createElement('div'); tr.className='trace';
      tr.textContent='trace: '+f.trace.join(' → '); c.append(tr); }
    for (const s of [f.source_slice, f.sink_slice]) { if (s){ const p=document.createElement('pre'); p.textContent=s; c.append(p);} }
    const chips=document.createElement('div'); chips.className='chips';
    for (const L of f.layers){ const ch=document.createElement('span'); ch.className='chip'; ch.textContent=L; chips.append(ch);}
    if (f.guards && f.guards.length){ const g=document.createElement('span'); g.className='chip guard'; g.textContent='guarded by: '+f.guards.join(', '); chips.append(g);}
    c.append(chips);
    main.append(c);
  }
}
document.getElementById('theme').onclick = () => {
  const r=document.documentElement, cur=r.getAttribute('data-theme');
  const next = cur==='dark' ? 'light' : cur==='light' ? 'dark' :
    (matchMedia('(prefers-color-scheme: dark)').matches ? 'light' : 'dark');
  r.setAttribute('data-theme', next);
};
render();
"""


def render_html(findings: list[dict], root: str) -> str:
    # Escape every '<' as < inside the JSON payload. '<' only occurs in string values
    # (JSON structural tokens never use it), so this stays valid JSON that parses back to '<'
    # -- and with no literal '<' the HTML tokenizer can never leave script-data state, so a
    # code slice containing </script>, <!--<script>, etc. can neither break out nor silently
    # swallow the following <script> block (robust, not merely XSS-safe).
    data = json.dumps(findings, ensure_ascii=False).replace("<", "\\u003c")
    js = _JS.replace("%COLORS%", json.dumps(_LAYER_COLORS))
    n = len(findings)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sec-graph - taint map</title><style>{_CSS}</style></head>
<body>
<header><div class="hdr">
  <div><h1>sec-graph &mdash; taint map</h1>
  <div class="sub">{n} finding{'' if n == 1 else 's'} in <code>{root}</code> &mdash; toggle layers to isolate paths</div></div>
  <button class="themebtn" id="theme">&#9680; theme</button>
</div></header>
<div class="wrap">
  <aside><h2>Layers</h2><div id="layers"></div></aside>
  <main><div class="sub" id="count" style="margin-bottom:14px"></div><div id="findings"></div></main>
</div>
<script id="secgraph-data" type="application/json">{data}</script>
<script>{js}</script>
</body></html>"""
