# HANDOFF — state for the next session

## Where we are
Bootstrap + **WP0 + WP1 complete**. WP0: graphify wired behind the quarantine wall,
`secgraph analyze` -> `graph.json`, schema pinned by a contract test. WP1: the Python
**IR** (tree-sitter re-parse -> per-function CFG + reaching-defs def-use + the
`(source_file, start_line)` join to graphify nodes). **23 tests green.** Both WPs
reviewed by the `reviewer` agent, hardened, and simplify-passed. Dev env `.venv`
(`uv pip install -e ".[dev]"`), `graphifyy==0.9.6`.

See `diary/2026-07-18-03-wp1.md` (WP1) and `-02-wp0.md` (WP0) for full records.

## Decisions locked
`DECISIONS.md` ADR-000..006. No new ADR in WP0/WP1.

## Next session: WP2 = ROADMAP Phase 2
**Rules engine + intraprocedural flow-sensitive taint** over the WP1 IR: load the YAML
source/sink/sanitizer packs (`rules/python/*.yml`), run a per-function flow-sensitive
taint pass on the CFG/def-use, report intra-function source->sink paths with
confidence + provenance. Open with **`new-wp`**.

**FIRST thing in WP2** — close Phase-2 blocker #2 below: without it, `with conn.cursor()
as c: c.execute(q)` (the canonical SQLi shape) is invisible.

## Phase-2 blockers carried from the WP1 review (MUST close in WP2)
- **#2 (HIGH):** `with` / `try` / `match` bodies are not lowered — in-block **defs and
  returns are dropped**. Fix: lower those bodies as statement lists (model the `with X as
  v` header as an alias def), so DB-cursor / try-wrapped flows are seen. Start here.
- **#6:** attribute/subscript assignment targets (`self.x = t`, `d[k] = t`) yield no def.
  Needs the k=1 field-sensitive def keyed on `AccessPath` (the model already carries it) —
  this is the field-sensitive taint model, natural to build with the taint pass.

## Watch out
- Read `docs/pitfalls.md` before touching `graphify_adapter.py` / the projection.
- Keep every `graphify.*` import inside `graphify_adapter.py` (quarantine wall). `secgraph/ir/`
  is graphify-free; `join` takes graphify node dicts as data.
- Binding-rate **KILL-GATE** is at Phase 3 (≥60–70%); don't over-invest before it.
- On a build-specific technical doubt, consult a Fable 5 max agent before committing.

## Open follow-ups (not blockers)
- WP0: `graph.json` filename collides with graphify's artifact (`out_dir=graphify-out`);
  we avoid clobbering a *larger* curated graph but not an equal one, and don't call
  `backup_if_protected`. Decide at **Phase 4** (projection). Plus the `out_dir` vs
  `cache_root` two-dirs asymmetry.
- WP1: `build_project_ir` walks the filesystem directly; when the CLI wires IR to graphify
  (Phase 4), take the authoritative file set from the adapter's `detect_files` so the join
  never desyncs. `build_graph`/`cluster_graph` hand back graphify-shaped NetworkX attrs — a
  soft boundary to watch.
