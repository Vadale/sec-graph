# HANDOFF — state for the next session

## Where we are
Bootstrap + **WP0–WP3-b + WP-A + WP-B complete. 65 tests green**, quarantine wall intact, all
reviewed by the `reviewer` agent and simplify-passed. Dev env `.venv`
(`uv pip install -e ".[dev]"`), `graphifyy==0.9.6`.

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

See `diary/2026-07-19-09-wpb.md` (WP-B), `-08-wpa.md` (WP-A), `-06-killgate.md`, `-05-wp3.md`.

## Decisions locked
`DECISIONS.md` ADR-000..008 (008 = structural-only projection joins + script-data-safe viz).

## Next session — pick one
### A. Layer-tagger (the rest of ROADMAP Phase 4) — highest value for the map
`rules/labels.yml` + `rules/secrets.yml` **detection** (not yet wired): identifier dicts, Shannon
entropy, Luhn/format regexes, decorator/guard **barrier detection**, and `find_unguarded_sinks`
(auth-guard dominance). Today's layers are only `untrusted-input` / `dangerous-sink` from the
source/sink rules; this adds the **credentials / PII / tokens / auth** layers that make the
Google-Maps toggles meaningful. The viz already renders whatever layers exist — this feeds it.

### B. MCP server (Phase 6)
`secgraph serve` (currently `NotImplementedError`): expose isolated `taint.json` paths to an LLM
harness for triage, run alongside `graphify --mcp`. The taint.json schema (finding + slices +
trace) is the payload; keep the analysis core LLM-free (ADR-000).

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
- **`binding_rate`** excludes module-level call sites (documented under-count).
- **Phase 8:** package `rules/` as importlib data for a wheel.

## Watch out
- Keep every `graphify.*` import inside `graphify_adapter.py`. `secgraph/{ir,rules,taint,callgraph}`
  and `project.py`/`viz.py` are graphify-free; the interproc oracle arrives as a plain dict.
- **Projection joins are structural only** (ADR-008) — never reintroduce a function-name join;
  graphify labels methods `.get()` and same-name methods collide.
- On a build-specific technical doubt, consult a Fable 5 max agent before committing.
