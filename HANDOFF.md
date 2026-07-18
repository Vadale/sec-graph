# HANDOFF — state for the next session

## Where we are
Bootstrap + **WP0 + WP1 + WP2 + WP3-core complete. 49 tests green.** All reviewed by the
`reviewer` agent, hardened, and simplify-passed. Dev env `.venv`
(`uv pip install -e ".[dev]"`), `graphifyy==0.9.6`.
- **WP0**: graphify behind the quarantine wall; `secgraph analyze` -> `graph.json`.
- **WP1**: the Python **IR** (tree-sitter -> CFG + reaching-defs def-use + (file,line) join).
- **WP2**: rules engine + **intraprocedural** flow-sensitive taint (`secgraph scan`).
- **WP3**: **interprocedural** summary-based taint. `secgraph scan tests/fixtures/tiny` now
  finds the cross-file SQLi (app.py `get_user` -> db.py `run_query`, CWE-89) with a trace.
  `secgraph callgraph-stats <path>` reports the binding-rate KILL-GATE metric.

See `diary/2026-07-18-05-wp3.md` and earlier `-04/-03/-02`.

## Decisions locked
`DECISIONS.md` ADR-000..006. No new ADR yet.

## Next session — pick one
### A. Finish the WP3 KILL-GATE (needs a quick decision from Alessandro)
The metric TOOL ships. The remaining step is the **benchmark RUN**: measure `callgraph-stats`
binding rate on **3 real Flask/FastAPI repos**; need **>=60-70%** (else reassess the
build-on-graphify thesis). This needs external repos — decide whether to clone public ones
(e.g. PyGoat + 2 small Flask/FastAPI apps) or use repos Alessandro provides. **This is the
open decision.**

### B. WP3-b — close the deferred resolver/precision gaps (the rest of ROADMAP Phase 3)
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
