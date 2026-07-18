# HANDOFF — state for the next session

## Where we are
Bootstrap + **WP0 (ROADMAP Phase 0) complete**. graphify is wired behind the
quarantine wall, `secgraph analyze` produces a real `graph.json`, and the graphify
0.9.6 schema is pinned by a contract test (11 tests, all green). Reviewed by the
`reviewer` agent and hardened; simplify-pass ran clean. Dev env is `.venv`
(`uv pip install -e ".[dev]"`), `graphifyy==0.9.6`.

See `diary/2026-07-18-02-wp0.md` for the full WP0 record and evidence.

## Decisions locked
`DECISIONS.md` ADR-000..006: Python on graphify; depend-as-library + quarantine wall +
sidecar discipline + (file,line) join; taint precision; agent team; Apache-2.0/public;
pillars (Accuracy · Maintainability · Bug-finding · Simplicity). No new ADR in WP0.

## Next session: WP1 = ROADMAP Phase 1
**Python IR:** tree-sitter re-parse → per-function CFG + def-use (k=1 access paths) +
the `(source_file, start_line)` join from each IR function to its graphify node. Open
with the **`new-wp`** skill. Suggested executable acceptance:
- `pytest` stays green; new IR snapshot tests pass on `tests/fixtures/tiny`.
- 100% of fixture functions (`get_user`, `run_query`) join to a graphify node id.
- No `graphify.*` import outside `graphify_adapter.py`.

## Watch out
- Read `docs/pitfalls.md` before touching `graphify_adapter.py` / the projection.
- Keep every `graphify.*` import inside `graphify_adapter.py` (quarantine wall).
- Binding-rate **KILL-GATE** is at Phase 3 (≥60–70%); don't over-invest before it.
- On a build-specific technical doubt, consult a Fable 5 max agent before committing.

## Open follow-ups from WP0 (not blockers)
- `graph.json` filename collides with graphify's own artifact (`out_dir=graphify-out`).
  We avoid clobbering a *larger* curated graph but not an equal one, and don't call
  `backup_if_protected`. Decide at **Phase 4** (projection): sec-graph-owned filename
  or explicit backup.
- `out_dir` (CWD) vs `cache_root` (`<path>`) write two different `graphify-out` dirs.
- `build_graph`/`cluster_graph` return a live NetworkX graph with graphify-shaped
  attrs — a soft boundary to watch when Phase 1 consumes it.
