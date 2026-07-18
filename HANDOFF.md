# HANDOFF — state for the next session

## Where we are
Bootstrap complete (Fase C of the startup method). The full skeleton exists: method
docs (`CLAUDE.md`, `PLAN.md`, `ROADMAP.md`, `DECISIONS.md`), 5 agents, 3 skills, the
`secgraph/` package skeleton, `rules/` and `tests/` scaffolding, `pyproject.toml`,
`LICENSE` (Apache-2.0) + `NOTICE`, git initialized with the first commit.
**No functional code yet** — modules are stubs.

## Decisions locked
See `DECISIONS.md` (ADR-000..006): Python on graphify; depend-as-library + quarantine
wall + sidecar discipline + (file,line) join; taint precision; agent team;
Apache-2.0/public; pillars (Accuracy · Maintainability · Bug-finding · Simplicity).

## Next session: WP0 = ROADMAP Phase 0
Scaffold + graphify adapter + contract test. Open it with the **`new-wp`** skill.
Make the acceptance criteria executable, e.g.:
- `pip install -e .` succeeds.
- `secgraph analyze tests/fixtures/tiny` produces a valid graphify `graph.json`.
- `pytest tests/contract` passes (asserts the graphify schema we depend on).

## Watch out
- Read `docs/pitfalls.md` before touching `graphify_adapter.py` or `project.py`.
- Keep every `graphify.*` import inside `graphify_adapter.py` (quarantine wall).
- The binding-rate **KILL-GATE** is at Phase 3 (≥60–70%); don't over-invest before it.
- On a build-specific technical doubt, consult a Fable 5 max agent before committing.
