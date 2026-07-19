# Contributing to sec-graph

Thanks for your interest. sec-graph is a **defensive** security tool; contributions that add
exploitation capability, detection‑evasion, or offensive tooling are out of scope and will be declined.

## Setup

```bash
uv pip install -e ".[dev]"      # or: pip install -e ".[dev]"
pytest                          # all tests must pass (121 today)
```

## The two architectural laws (please don't break them)

1. **Quarantine wall** — every `import graphify` / `graphify.*` usage lives **only** in
   `secgraph/graphify_adapter.py`. The rest of the package (`ir/`, `rules/`, `taint/`, `callgraph/`,
   `project.py`, `viz/`, `ingest/`) is graphify‑free; the interprocedural oracle arrives as a plain dict.
2. **Sidecar discipline** — statement‑level facts live in `taint.json`, never inside graphify's pipeline.
   `graph.json` gets only coarse annotations, by post‑processing the dict.

Both are enforced by convention + tests; see `docs/pitfalls.md` (read it before touching the adapter,
projection, or viz) and `docs/architecture.md`.

## How we work

- **Determinism is non‑negotiable.** `secgraph analyze` twice must be **byte‑identical**
  (`taint.json`). No wall‑clock, no set iteration order, no unsorted dict dumps in outputs.
- **Structural joins only** (ADR‑008) — findings bind to graph nodes by `(file, def‑line)` span, never by
  function name. Never reintroduce a name join.
- **Never credit an unproven guard** (ADR‑010) — a false "guarded" hides an unguarded sink. The guard
  analysis is polarity‑sound and load‑bearing; keep it that way.
- **Acceptance criteria are executable**, not adjectives — a change lands with a command + expected output
  (and a test where it makes sense).
- **Design decisions go in `DECISIONS.md`** as an append‑only ADR (supersede, never relitigate).

## Tests

- Unit + contract tests under `tests/`. New engine/enrichment behavior needs a fixture + a regression
  test (adversarial tests welcome — see `tests/` and the `tester` mandate).
- The **graphify contract test** (`pytest tests/contract`) pins the `graphify==0.9.6` behavior we rely
  on; if it fails, the dependency drifted — don't paper over it.

## Pull requests

Small, focused PRs. Explain *why*, link the ADR if you added one, and show the acceptance command
output. CI runs the test matrix (3 OS × Python 3.11–3.13) + a wheel‑install smoke test.

## Reporting a vulnerability

Please report security issues in sec-graph itself privately (see `SECURITY.md`) rather than in a public
issue, and give us a reasonable window to fix before disclosure.
