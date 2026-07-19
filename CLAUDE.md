# sec-graph — CLAUDE.md

## Mission
sec-graph is a local, **defensive** security tool: the **interactive security map +
local, LLM-free MCP triage layer over ANY SAST** (pivot, ADR-014). It ingests findings via
**SARIF** (CodeQL, Semgrep, Bandit, …) or semgrep JSON, binds them to a graphify entity
graph (Google-Maps-style toggleable layers, glow = UNGUARDED), enriches them with the
**credentials/PII + auth/unguarded** layers no engine emits, and hands isolated,
hash-verified path slices to the user's own LLM over MCP. A **built-in deterministic Python
taint engine** remains as the fallback when no external report is supplied (kept, maintained,
not the product). Built **on top of `graphify`** (MIT). The analysis core stays
**deterministic — no LLM on the critical path**.

## The 6 non-negotiable rules
1. **Language** — Italian with Alessandro; everything in the project (code, comments,
   docs, commit messages) in **English**.
2. **Self-containment** — everything the project needs lives in this folder. Tool
   memory is cache, never the source of truth: if it matters, it is a file here.
3. **Stack** — recent but **stable**. Python (built on graphify). Different tech only
   on explicit request, recorded in an ADR.
4. **Ask, don't assume** — ask what wasn't said; don't re-ask what was.
5. **No files before an explicit OK** on a proposal.
6. **Honest claims** — never declare done/tested/verified what isn't; acceptance
   criteria are **executed, not narrated**.

## Where things live
- `ROADMAP.md` — the full plan: phases 0–8 = work packages, each with a ready Build
  Prompt + executable acceptance criteria.
- `PLAN.md` — objective, designated reader, success criterion, non-goals.
- `DECISIONS.md` — the ADR log (append-only; supersede, never relitigate).
- `HANDOFF.md` — current state for the next session.
- `docs/architecture.md` — architecture orientation (pipeline, the two laws).
- `docs/pitfalls.md` — **verified graphify 0.9.6 constraints. Read before touching
  the adapter, projection, or viz.**
- `docs/background-brainstorm.md` — original idea exploration (background only).
- `secgraph/` — the package: `graphify_adapter`, `ir/`, `taint/`, `rules/`,
  `project`, `viz`, `mcp_server`, `cli`.
- `rules/` — YAML source/sink/sanitizer + labels + secrets packs (data).
- `tests/` — `contract/`, `fixtures/`, `corpus/`, `benchmarks/`.
- `.claude/agents/` — agent mandates. `.claude/skills/` — `new-wp`, `session-close`,
  `simplify-pass`. `diary/` — one entry per session.

## How we work
- **One work package (WP) at a time.** A WP = a ROADMAP phase. Open it with the
  `new-wp` skill; close the session with `session-close`.
- **Acceptance criteria are executable and verbatim** — commands with expected
  output, not adjectives. If a criterion isn't run, the WP isn't done.
- **Skills have gates. Do not skip the gates.** `simplify-pass` runs at end of phase
  and above ~500 lines; `session-close` updates HANDOFF/diary/DECISIONS and commits.
- **The two architectural laws** (see `docs/pitfalls.md`): the **quarantine wall**
  (all `graphify.*` imports only in `secgraph/graphify_adapter.py`) and the
  **sidecar discipline** (statement-level facts live in `taint.json`, never inside
  graphify's pipeline).
- **Priority pillars:** Accuracy · Maintainability · Bug-finding · Simplicity. When
  trading off, these win.
- **On a build-specific technical doubt, consult a Fable 5 max agent** before
  committing the plan (Alessandro's standing instruction).

## Agents
`reviewer` (read-only) · `simplifier` · `tester` (adversarial) · `security-auditor`
(read-only) · `doc-writer`. `architect`/`coder` are the main session, not separate
agents.

## Useful commands (once deps are installed)
```
uv pip install -e .            # or: pip install -e .
secgraph analyze <path>        # → graph.json + taint.json + secgraph.html
secgraph view                  # open the interactive layered map
secgraph serve                 # MCP server (run alongside `graphify --mcp`)
pytest                         # tests   ·   pytest tests/contract  → graphify contract
```
