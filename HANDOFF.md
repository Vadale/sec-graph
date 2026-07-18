# HANDOFF — state for the next session

## Where we are
Bootstrap + **WP0 + WP1 + WP2 complete. 39 tests green.** All reviewed by the `reviewer`
agent, hardened, and simplify-passed. Dev env `.venv` (`uv pip install -e ".[dev]"`),
`graphifyy==0.9.6`.
- **WP0**: graphify behind the quarantine wall; `secgraph analyze` -> `graph.json`; schema
  pinned by a contract test.
- **WP1**: the Python **IR** (tree-sitter -> per-function CFG + reaching-defs def-use +
  the `(source_file, start_line)` join to graphify nodes).
- **WP2**: **rules engine + intraprocedural flow-sensitive taint**. `secgraph scan <path>`
  finds intra source->sink flows (SQLi/cmdi) with confidence + provenance. with/try/match
  are lowered as `Branch` CFG alternatives.

See `diary/2026-07-18-04-wp2.md` (WP2), `-03-wp1.md`, `-02-wp0.md`.

## Decisions locked
`DECISIONS.md` ADR-000..006. No new ADR in WP0/WP1/WP2.

## Next session: WP3 = ROADMAP Phase 3 (the core value + the KILL-GATE)
**Interprocedural summaries** — conditional "returns tainted iff argN tainted" summaries,
propagated over graphify's `calls` skeleton (via the adapter), + a local fallback resolver
for variable-receiver calls graphify drops, + CHA fan-out over `inherits`. This is where
the tiny fixture's cross-file `get_user -> run_query` SQLi (currently found by neither
`analyze` nor `scan`) becomes findable. Open with **`new-wp`**.

**KILL-GATE (go/no-go):** measure call-site binding rate on 3 real Flask/FastAPI repos —
need **>=60-70%** (graphify + local fallback combined). Below that, reassess the
build-on-graphify thesis before investing further. Consult a Fable 5 max agent if the
interprocedural design is uncertain.

## Deferred items to fold into WP3/WP4 (from the WP2 review)
- **Field sensitivity** (was WP1 blocker #6): the taint engine is variable-keyed; flows
  through `self.x` / `d[k]` are missed. The `AccessPath` model supports k=1 — propagate it.
- **Layer-scoped sanitizers**: `expr_taint` clears ALL layers on a sanitizer match; thread
  the sink layer so `int()` (scoped to `dangerous-sink`) doesn't clear a PII flow. Latent
  today; real once PII/credential sinks land (Phase 4).
- **`fqn_hint`** on sinks is loaded but unused — wire it to disambiguate `.execute`
  (DB cursor vs safe ORM) and cut duck-typed FPs.

## Watch out
- Keep every `graphify.*` import inside `graphify_adapter.py` (quarantine wall).
  `secgraph/{ir,rules,taint}` are graphify-free; `join` takes graphify node dicts as data.
- On a build-specific technical doubt, consult a Fable 5 max agent before committing.

## Open follow-ups (not blockers)
- **Phase 4 (projection):** `graph.json` filename collides with graphify's artifact
  (`out_dir=graphify-out`); decide a sec-graph-owned filename or `backup_if_protected`. Take
  the authoritative file set from the adapter's `detect_files` (not `build_project_ir`'s
  rglob) so the join never desyncs. `out_dir` vs `cache_root` two-dirs asymmetry.
- **Phase 8 (release):** `rules/` is loaded via the source tree (`default_rules_dir()`);
  package it as importlib data for a wheel.
