# HANDOFF — state for the next session

## Where we are
Bootstrap + **WP0 + WP1 + WP2 + WP3 + WP3-b complete, incl. the KILL-GATE which PASSES. 56
tests green.** All reviewed by the `reviewer` agent, hardened, and simplify-passed. Dev env
`.venv` (`uv pip install -e ".[dev]"`), `graphifyy==0.9.6`.

**WP3-b**: resolved method/constructor call binds now carry taint (arg->param/receiver map,
`kw_names`, and an over-approx floor so a constructor / field-escaping method never CLEARS
taint). Benchmark bound counts rose (microblog 59->90); PCR 100%/93.8%/96%.

**KILL-GATE RESULT (ADR-007 metric):** PCR (project-call resolution) = **100% / 99.4% / 94.7%**
on microblog / fastapi-realworld / flask-realworld (gate >=85%); UNK 11-18% (<=40%). The raw
10-17% first measured was a classifier artifact. **Build-on-graphify thesis validated** — see
`diary/2026-07-18-06-killgate.md` and ADR-007.
- **WP0**: graphify behind the quarantine wall; `secgraph analyze` -> `graph.json`.
- **WP1**: the Python **IR** (tree-sitter -> CFG + reaching-defs def-use + (file,line) join).
- **WP2**: rules engine + **intraprocedural** flow-sensitive taint (`secgraph scan`).
- **WP3**: **interprocedural** summary-based taint. `secgraph scan tests/fixtures/tiny` now
  finds the cross-file SQLi (app.py `get_user` -> db.py `run_query`, CWE-89) with a trace.
  `secgraph callgraph-stats <path>` reports the binding-rate KILL-GATE metric.

See `diary/2026-07-18-05-wp3.md` and earlier `-04/-03/-02`.

## Decisions locked
`DECISIONS.md` ADR-000..007 (ADR-007 re-specifies the KILL-GATE metric).

## Next session — pick one
### A. Rules packs + TRR (biggest value-per-effort on ORM code)
`rules/python/sqlalchemy.yml` + `wtforms.yml`: propagators for `where/order_by/filter_by/
select_from/scalars/scalar/all/first/paginate`, WTForms `.data` as an attribute source,
`db.session.execute`+`text()` sink shape. On ORM code the blind mass is library query-builder
methods, so **library modeling (YAML), not more resolution, is what makes tainted paths
legible** (per ADR-007's kill-criterion). Then add TRR instrumentation (taint-relevant
resolution) to `callgraph-stats` and a pinned `tests/benchmarks/` harness.

### B. Phase 4 — projection + viz (the demo)
Annotate `graph.json` (coarse) + emit `taint.json` (fine) per the sidecar discipline; fork
graphify's HTML into `secgraph/viz.py` with the layer toggles + path sidebar. The site
taxonomy (external / project / unknown-receiver) is the edge-label vocabulary this renders.
Mind the WP0/WP1 Phase-4 follow-ups (graph.json filename collision; take the file set from the
adapter's `detect_files`).

### C. More resolver/summary precision (lower priority)
- **H2 (field-sensitivity, the important one):** a RESOLVED callee that launders taint
  through `d[k]=x` / `self.x=x` / a global has empty `return_params`, so callers miss the
  flow -> `run_project` can under-report vs the pure-intra over-approx (the `intra <= inter`
  superset holds only for the modeled fragment). Fix: field-sensitive summaries (the
  `AccessPath` model already represents k=1) or opaque-escape over-approximation.
- **Local-type / `self` / CHA resolver** for variable-receiver method calls graphify drops
  (raises the binding rate); wire graphify's `calls`/`inherits` edges as the oracle (built in
  the orchestration layer, passed to `run_project(oracle=...)` as a plain dict).
- **kwargs/`*args`/defaults** arg->param mapping (currently positional-prefix only).

### C. Phase 4 — projection + viz (annotate graph.json + taint.json, layer toggles).

## Deferred items still open
- **Layer-scoped sanitizers** (`applies_to_layers` ignored; latent FN once PII/credential
  sinks land). **`fqn_hint`** unused (`.execute` DB-vs-ORM disambiguation).
- **`binding_rate`** excludes module-level call sites (documented under-count).
- **Phase 4:** `graph.json` collides with graphify's artifact; take the file set from the
  adapter's `detect_files`. **Phase 8:** package `rules/` as importlib data for a wheel.

## Watch out
- Keep every `graphify.*` import inside `graphify_adapter.py`. `secgraph/{ir,rules,taint,callgraph}`
  are graphify-free; the interproc oracle arrives as a plain dict.
- On a build-specific technical doubt, consult a Fable 5 max agent before committing.
