# HANDOFF — state for the next session

## Where we are
Bootstrap + **WP0–WP3-b + WP-A + WP-B + WP-C1 complete. 83 tests green**, quarantine wall intact,
all reviewed by the `reviewer` agent and simplify-passed. Dev env `.venv`
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
- **WP-C1 (layer-tagger, credentials/PII half)**: `secgraph/rules/labels.py` + `rules/labels.yml` +
  `rules/secrets.yml`. Sensitive-data layers ride the **value** — the engine mints a fresh
  label-`Origin` (mint-don't-mutate, ADR-009) at 4 sites (subscript key, credential-named
  target/param, secret literal/module-constant). Word-based identifier match + secret classifier
  (named regexes → gated entropy). Flagship works: `credentials + dangerous-sink` findings. Also
  fixed the **f-string taint FN** (`execute(f"…{q}")` now CWE-89). Layers are already rendered as
  toggles by the WP-B viz.

See `diary/2026-07-19-10-wpc1.md` (WP-C1), `-09-wpb.md`, `-08-wpa.md`, `-06-killgate.md`, `-05-wp3.md`.

## Decisions locked
`DECISIONS.md` ADR-000..009 (008 = structural projection joins + script-data-safe viz; 009 =
sensitive-data layers via Origin mint, word-based matching, f-string fix).

## Next session — pick one
### A. WP-C2 — auth/permissions layer + unguarded sinks (finishes the layer-tagger)
The other half of ROADMAP Phase 4: `FunctionIR.decorators` (harvest in `lower.py`), auth-barrier
detection (decorator dict `@login_required`/`Depends`, in-arm `if user.is_admin:`, dominating gate
`if not authed: abort()` via new `dominators()` in `ir/cfg.py`), `SinkPoint.guards`/`Finding.guards`
threaded through summaries (intersection-merge on key collision), and `find_unguarded_sinks` (a
dangerous sink with no barrier on the path) surfaced in the CLI + viz unguarded badge. Adds the
`auth` layer + the flagship *unguarded sink* finding. Deferred bits: FastAPI `Depends` barriers,
entrypoint-scope guard reachability (Phase 7).

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
- **`secrets.yml: test_path_globs`** is parsed into `SecretConfig` but not yet consumed — the
  intended test-path confidence downgrade (detect-don't-hide) is a small follow-up (thread
  `fn.source_file` into `classify_secret`). **Cross-module imported-constant** secrets
  (`from settings import SECRET_KEY`) are missed (degrades safely).
- **`binding_rate`** excludes module-level call sites (documented under-count).
- **Phase 8:** package `rules/` as importlib data for a wheel.

## Watch out
- Keep every `graphify.*` import inside `graphify_adapter.py`. `secgraph/{ir,rules,taint,callgraph}`
  and `project.py`/`viz.py` are graphify-free; the interproc oracle arrives as a plain dict.
- **Projection joins are structural only** (ADR-008) — never reintroduce a function-name join;
  graphify labels methods `.get()` and same-name methods collide.
- **Sensitive-data layers mint, never mutate** (ADR-009) — a label/secret `Origin` is always
  constructed fresh with a `source_id` that encodes its layers; mutating `Origin.layers` in flight
  breaks summary monotonicity and the analyze-twice-byte-identical determinism gate.
- On a build-specific technical doubt, consult a Fable 5 max agent before committing.
