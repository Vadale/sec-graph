# HANDOFF — state for the next session

## Where we are
Bootstrap + phases 0–8 (MVP) + Tier-3 typing + **Phases 9 + 10 (SARIF ingestion + layer enrichment
— the PIVOT) complete. 121 tests green**, quarantine wall intact. **The pivot is delivered**:
`secgraph analyze <path> --sarif F` ingests external SAST findings (CodeQL/Semgrep/Bandit/…), binds
them to the graph, **enriches** them with our credentials/PII + auth/unguarded layers (the
differentiator — a screenshot shows a Semgrep SQLi gaining a `credentials` glow it never emitted),
and renders the interactive map + MCP triage; the built-in taint engine is the no-SARIF fallback.
Dev env `.venv` (`uv pip install -e ".[dev]"`), `graphifyy==0.9.6`.

`secgraph analyze <path>` now produces the **three artifacts + the demo**:
`graph.json` (graphify's entity graph, coarsely annotated) · `taint.json` (fine, statement-level
findings with code slices + trace) · `secgraph.html` (self-contained layered map, `secgraph view`).

- **WP0**: graphify behind the quarantine wall; `secgraph analyze` → `graph.json`.
- **WP1**: the Python **IR** (tree-sitter → CFG + reaching-defs def-use + (file,line) join).
- **WP2**: rules engine + **intraprocedural** flow-sensitive taint (`secgraph scan`).
- **WP3 / WP3-b**: **interprocedural** summary-based taint; resolved method/constructor binds
  carry taint. `secgraph scan tests/fixtures/tiny` finds the cross-file SQLi (CWE-89) with a trace.
- **KILL-GATE (ADR-007):** PCR = **100% / 99.4% / 94.7%** on microblog / fastapi-realworld /
  flask-realworld (gate ≥85%). **Build-on-graphify thesis validated.**
- **WP-A**: `rules/python/sqlalchemy.yml` (ORM query-builder propagators, `text()`, raw-SQL sink);
  propagators carry the receiver's taint; **TRR** metric in `secgraph callgraph-stats`.
- **WP-B (Phase 4, projection half)**: `secgraph/project.py` + `secgraph/viz.py`. graph.json gets
  `sec_layers` on source/sink function nodes + one `sec-path-N` hyperedge per finding (node count
  unchanged — sidecar discipline). Findings map to nodes **structurally** (span-containment →
  `(file,def-line)` join; never by name — ADR-008). HTML is self-contained + script-data-safe.
- **WP-C1 (layer-tagger, credentials/PII half)**: `secgraph/rules/labels.py` + `rules/labels.yml` +
  `rules/secrets.yml`. Sensitive-data layers ride the **value** — the engine mints a fresh
  label-`Origin` (mint-don't-mutate, ADR-009) at 4 sites (subscript key, credential-named
  target/param, secret literal/module-constant). Word-based identifier match + secret classifier
  (named regexes → gated entropy). Flagship works: `credentials + dangerous-sink` findings. Also
  fixed the **f-string taint FN** (`execute(f"…{q}")` now CWE-89). Layers are already rendered as
  toggles by the WP-B viz.
- **WP-C2 (layer-tagger, auth/unguarded half)**: `secgraph/taint/guards.py` + `rules/labels.yml`
  barriers. `guard_map` detects auth barriers structurally (B1 decorators, B2 authorised arm, B3
  terminating gate), unified by a **polarity-sound** `_true_guards`/`_false_guards` (never falsely
  "guarded" — ADR-010). `SinkPoint.guards`/`Finding.guards` accumulate down the call path (`_lift`
  union) and merge by **intersection** on key collision (intra-run + across fixpoint iterations).
  `find_unguarded_sinks` + viz UNGUARDED badge + CLI unguarded count. **Phase 4 is now complete.**
- **Phase 6 (MCP triage server)**: `secgraph/mcp_view.py` (pure `TaintView`) + `secgraph/mcp_server.py`
  (thin FastMCP wrapper, lazy SDK import) + `secgraph serve`. Read-only view over the artifacts —
  never runs the engine/graphify/LLM. Tools: `list_paths`/`get_path_slice`(hash-verified minimal
  windows)/`find_unguarded_sinks`/`explain_layer`/`get_function_taint` + §15 defensive prompts.
  `taint.json` gained `id`/`file_hashes`/`source_node`/`sink_node`/absolute `root` (ADR-011).
- **Phase 5 (interactive graph map)**: `secgraph/viz/` package (`__init__.py` + `map.css` + `map.js`).
  A hand-rolled, self-contained, deterministic force-directed node-link map on Canvas (ADR-012,
  supersedes §12's vis-network fork). Security-neighborhood default, chroma=security / glow=unguarded,
  "Critical" preset (§11 killer query), focus/dim a path, detail card + Copy-MCP. `render_html` now
  takes `(graph, findings, root)`.

See `diary/2026-07-19-13-viz.md` (Phase 5), `-12-mcp.md`, `-11-wpc2.md`, `-10-wpc1.md`, `-06-killgate.md`.

## Decisions locked
`DECISIONS.md` ADR-000..014 (011 = MCP thin-wrapper-over-pure-view; 012 = hand-rolled Canvas graph
viz; 013 = packaging bundles the data; **014 = PIVOT — map + local-LLM-triage layer over ANY SAST via
SARIF ingestion; the taint engine is demoted to the built-in Python fallback**).

## Now on the OSS-release track (ADR-015, ROADMAP Phases 11–13). Pivot (9–10) DELIVERED + road-validated.
The product loop works end-to-end: ingest SARIF → bind → enrich → map + MCP triage. **Road-validated**
(2026-07-19): real Semgrep + **CodeQL** on PyGoat (40 findings, 33 with codeFlows, 40/40 bound, cross-file
23-hop path-injection); a **local Gemma 3n E4B triaged the 40 CodeQL findings via the real MCP server** at
82–88% class-agreement, ~3.5s + ~575 tok each. Screenshots + harness in scratchpad.

### Phase 11 — DONE (2026-07-19)
LICENSE → MIT (was Apache-2.0; ADR-015); pyproject `classifiers`; `secgraph --version`; CI `package` job
(wheel → clean-venv install → analyze-on-bundled-rules smoke → determinism) + Python 3.13. **Verified by
hand:** the wheel is genuinely pip-installable and analyzes from a clean env. 121 tests green.

### Next: Phase 12 — Benchmark (ADR-015)
The **non-circular control-vs-treatment** study: A (LLM on raw SAST output) vs B (LLM via sec-graph MCP)
on the SAME findings, scored against a **hand-labelled** `truth.json` (not the engine's CWE). Model
`gemma4:e4b-it-qat` only (Haiku if needed). **Consult a Fable 5 max agent on the design before locking.**
Seed from the Part-2 harness (`scratchpad/{mcp_pull,gemma_triage,score}.py`). Then Phase 13 (docs, doc-writer).

### Deferred (documented, not blockers)
- **FastAPI `Depends()` barriers** — IR captures param names/types but **not param default expressions**,
  so `x = Depends(get_current_user)` isn't seen; auth verdict under-claims on FastAPI DI (safe: never a
  false `guarded`, ADR-010). A self-contained later unit (needs a tree-sitter extraction extension).
- Raw-text multi-language secret scan reusing `classify_secret`; `[project.urls]` in pyproject (add when
  the GitHub repo exists).

### Icebox (engine is the fallback — maintenance only)
H2 field-sensitivity, Tier-3 generics, kwargs mapping. Nearest-def binding can mis-bind within a file
(coarse fallback, same-file only — reviewer LOW, acceptable).

### Icebox (engine is fallback now)
H2 field-sensitivity, Tier-3 generics, kwargs mapping — only if a fallback bug demands it. CI wheel
publish + a pinned benchmark harness. **Verify before README claims:** the licence/scope notes in ADR-014.

### C. Resolver/summary precision (lower priority)
- **Tier-3 annotation typing** (`def f(u: User)`) — the fastapi UNK/TRR mover (deferred; Fable
  predicted this is the tier that moves annotation-saturated DI code).
- **H2 (field-sensitivity):** a RESOLVED callee that launders taint through `self.x=x` / `d[k]=x`
  / a global has empty `return_params`, so callers can under-report. Fix: field-sensitive
  summaries (the `AccessPath` k=1 model already exists) or opaque-escape over-approximation.
- **kwargs/`*args`/defaults** arg→param mapping (currently positional-prefix only).

## Deferred items still open
- **Layer-scoped sanitizers** (`applies_to_layers` ignored; latent FN once PII/credential sinks
  land). **`fqn_hint`** unused (`.execute` DB-vs-ORM disambiguation).
- **`secrets.yml: test_path_globs`** is parsed into `SecretConfig` but not yet consumed — the
  intended test-path confidence downgrade (detect-don't-hide) is a small follow-up (thread
  `fn.source_file` into `classify_secret`). **Cross-module imported-constant** secrets
  (`from settings import SECRET_KEY`) are missed (degrades safely).
- **Auth barriers (WP-C2) deferred**: FastAPI `Depends(get_current_user)` barriers + entrypoint→
  source barrier reachability (a helper reached only from a `@login_required` route reads as
  unguarded — honest under-claim, Phase 7); a shadowed local `abort` could spoof termination; the
  merged-variant determinism nit (guards stay deterministic; a colliding non-guard field could differ).
- **`binding_rate`** excludes module-level call sites (documented under-count).
- **Phase 8:** package `rules/` as importlib data for a wheel.

## Watch out
- Keep every `graphify.*` import inside `graphify_adapter.py`. `secgraph/{ir,rules,taint,callgraph}`
  and `project.py`/`viz.py` are graphify-free; the interproc oracle arrives as a plain dict.
- **Projection joins are structural only** (ADR-008) — never reintroduce a function-name join;
  graphify labels methods `.get()` and same-name methods collide.
- **Sensitive-data layers mint, never mutate** (ADR-009) — a label/secret `Origin` is always
  constructed fresh with a `source_id` that encodes its layers; mutating `Origin.layers` in flight
  breaks summary monotonicity and the analyze-twice-byte-identical determinism gate.
- **Never credit an unproven guard** (ADR-010) — a false "guarded" hides an unguarded sink (a
  security FN). `guards.py`'s polarity analysis is load-bearing; do not reduce it to a first-match
  or substring scan. Guard merges are always by intersection (unguarded if any path is).
- On a build-specific technical doubt, consult a Fable 5 max agent before committing.
