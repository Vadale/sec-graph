# Decisions (ADR log)

Append-only. Decisions are **not relitigated** — supersede an ADR by writing a new
one. Format: ID · date · status · decision · why · alternatives rejected.

## ADR-000 — Build in Python on top of graphify (not Rust from scratch)
- 2026-07-18 · Accepted
- **Decision:** Implement sec-graph as a Python package built on graphify (MIT),
  reusing its tree-sitter parsing, cross-file call resolution, HTML, JSON and MCP
  scaffolding. Add the taint / data-flow engine graphify lacks.
- **Why:** graphify donates ~3–4 weeks of undifferentiated plumbing (especially
  cross-file call resolution across ~40 languages) and lets us focus on the novel
  part. "Runs on any PC" is met via `uv`/`pip`.
- **Rejected:** Rust-from-scratch (portable single binary, best taint performance,
  but re-implements parsing/viz/MCP and delays the demo ~4 weeks — kept as a later
  kernel-only optimization); wrapping Joern (JVM dependency).

## ADR-001 — Integration = depend-as-library, pinned; fork only the viz
- 2026-07-18 · Accepted
- **Decision:** `secgraph` depends on `graphifyy==0.9.6` (pinned). Do not fork
  graphify; the only forked surface is its ~600-line HTML viz template (Phase 5),
  attributed under MIT.
- **Why:** graphify is a fast-moving single-maintainer 0.9.x codebase whose node-ID
  scheme already changed within 0.9.x. A fork = a rebase treadmill over 44K lines
  for the ~10 functions we use.
- **Rejected:** full fork (churn); plugin via `resolver_registry` (extension surface
  too narrow for taint).

## ADR-002 — Quarantine wall + sidecar discipline + (file,line) join
- 2026-07-18 · Accepted
- **Decision:** (a) all `graphify.*` imports live only in
  `secgraph/graphify_adapter.py`; (b) statement-level facts live in a separate
  `taint.json`, `graph.json` gets only coarse annotations + hyperedges; (c) join IR
  functions to graphify nodes by `(source_file, start_line)`, never by recomputing
  node IDs.
- **Why:** keeps a later divorce / Rust-kernel port cheap; prevents graphify's entity
  pipeline from silently mangling fine-grained nodes; survives graphify's ID
  migrations. See `docs/pitfalls.md`.
- **Rejected:** importing graphify throughout (coupling); injecting statement nodes
  into graphify's graph (mangled by ghost-merge/Leiden/5k cap); recomputing IDs
  (breaks on version bumps).

## ADR-003 — Taint precision for the MVP
- 2026-07-18 · Accepted
- **Decision:** flow-sensitive intraprocedural + function-summary-based
  interprocedural (conditional summaries), context-insensitive, k=1 field access
  paths, deterministic, every path carries confidence + provenance; truncated paths
  marked `resolution-lost`.
- **Why:** the pragmatic sweet spot for a triage tool without a type system; higher
  precision is a later dial.
- **Rejected:** full IFDS/IDE (heavy, no mature Python lib); reusing Pysa (not
  embeddable — used out-of-band as a recall oracle instead).

## ADR-004 — Agent team
- 2026-07-18 · Accepted
- **Decision:** `reviewer` (read-only), `simplifier`, `tester` (adversarial),
  `security-auditor` (read-only), `doc-writer`. `architect`/`coder` are the main
  session, not separate agents.
- **Why:** few sharp mandates; a correctness-critical security tool needs independent
  review + adversarial testing + supply-chain audit; `doc-writer` serves OSS/GitHub
  adoption. `reviewer` and `security-auditor` have **no write tools** (structural
  constraint).
- **Rejected:** the fuller roster (session-writer folded into the `session-close`
  skill; ui/accessibility/tone deferred — minimal public prose for now).

## ADR-005 — License Apache-2.0, public repo
- 2026-07-18 · Accepted
- **Decision:** sec-graph's code under Apache-2.0; public GitHub repo. `NOTICE`
  attributes graphify (MIT) for the viz fork. **Never published:** the startup-method
  file, method material, or public 0-day dumps of third-party code.
- **Why:** permissive + patent grant, MIT-compatible for bundling graphify's viz;
  broad adoption.
- **Rejected:** GPLv3 (copyleft, complicates bundling); private (slows community
  value).

## ADR-006 — Priority pillars
- 2026-07-18 · Accepted
- **Decision:** Accuracy · Maintainability · Bug-finding · Simplicity (four,
  deliberately chosen — the method suggests three; these four are mutually
  reinforcing for this project).
- **Why:** an inaccurate analyzer has no value; contributors + pluggable languages
  need maintainability; it is a bug-finder and its own engine must be correct;
  simplicity keeps the quarantine/sidecar clean.
- **Rejected:** security/optimization/functionality as top pillars (secondary for
  now; optimization is revisited at the "regret-Rust" line in `ROADMAP.md` §17).
