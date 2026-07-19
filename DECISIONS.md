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

## ADR-007 — Re-specify the Phase-3 KILL-GATE (supersedes the single-rate gate)
- 2026-07-18 · Accepted (design consulted with a Fable 5 max agent)
- **Context:** the original gate ("call-site binding rate >=60-70%") was measured at
  10-17% on 3 real Flask/FastAPI repos (microblog/fastapi-realworld/flask-realworld). A
  verified breakdown showed the failure is **classifier failure, not resolution failure**:
  ~83% of "unresolved" are library method calls (`db.session.scalar`, `query.where`) whose
  receiver traces through a project package, so they were mis-labelled "unresolved" instead
  of "external"; ~17% are project **class constructors** we don't index. Project-internal
  *function* calls resolve fine. Also, the gate was run *before* the local fallback resolver
  that ROADMAP §14 named as part of the gated configuration.
- **Decision:** replace the single rate with **three numbers over a strict site partition**
  (`rule | builtin | bound | external | unknown-receiver | unresolved-project`), where
  `external` requires **positive evidence** (a resolved chain leaving the project, or a
  receiver whose value-origin is an external constructor/import) and absence of evidence
  goes to `unknown-receiver`, never `external` (anti-gaming):
  - **PCR** (project-call resolution) = `bound / (bound + unresolved-project)` — gate **>=85%**.
  - **UNK** (unknown-receiver / method-call sites) — reported, bounded **<=40%**, not hard-gated.
  - **TRR** (taint-relevant resolution) over call sites whose receiver/arg is tainted at the
    fixpoint = fraction `rule|builtin|bound|external` — gate **>=70%**. This is the number
    that validates the thesis (on the paths that matter, do we know what the call is).
  - `bound-oracle` (graphify name-singleton) is **excluded from the PCR numerator**.
- **Re-specified kill-criterion:** the build-on-graphify thesis is refuted only if, AFTER
  correct classification + the Tier-0..3 resolver, PCR < 70% (resolver can't bind project
  code) OR TRR < 50% with the blind mass being project (not library) calls. A blind mass of
  library methods is a **rules-pack** problem (YAML), not a resolution-architecture problem,
  and implies no graphify divorce.
- **Why:** resolution failures do not currently cost findings (the engine over-approximates
  unresolved calls and sinks are rule-matched *before* resolution), so the gate's real job
  is FP/triage quality and detecting resolver regressions — which the raw rate could not do.
  The site taxonomy is also the `provenance` vocabulary the viz (Phase 5) and triage prompts
  (§15) need.
- **graphify oracle:** NOT wired for resolution (it drops variable-receiver calls too, ~zero
  net gain); reserved as a **differential validator** (edges graphify's `calls` has that we
  mark unresolved-project = a resolver-bug list). Keeps ADR-000 honest: graphify's donation
  is the entity graph + artifact/viz/MCP substrate + validation skeleton, never per-site binding.
- **Rejected:** keeping the single all-sites rate (meaningless on ORM code, gameable);
  declaring the thesis dead on the mis-specified number.

## ADR-008 — Projection joins structurally; viz payload is script-data-safe
- 2026-07-19 · Accepted (Phase 4 / WP-B; reviewer-driven)
- **Context:** the first `_annotate_graph_json` mapped findings to graphify nodes by function
  **name** (`(source_file, function)`). graphify labels a method `.get()` (leading dot) while the
  IR names it `get`, and two classes in one file can both host a `get`, so the name join silently
  annotated **nothing for methods** and overwrote same-name nodes — the graphify/MCP-facing half
  of the projection (`sec_layers` + hyperedges) was empty for most real Python.
- **Decision:** projection annotation uses **structural joins only**, reusing ADR-002's
  `(source_file, def-line)` join (`ir.join.join_modules` binds `FunctionIR.graphify_node`); a
  finding's statement line is mapped to its enclosing function by **tightest span containment**
  (`_enclosing_node`). **Function-name joins are banned** for node mapping. graphify's node **ids**
  are still never recomputed (ADR-002 / pitfall #9) — only its `(file, def-line)` key is matched.
- **Decision (viz):** `render_html` embeds findings as JSON with every `<` escaped to `<`.
  `<` occurs only inside JSON string values, so this stays valid JSON that parses back to `<`,
  and with no literal `<` the HTML tokenizer cannot leave script-data state — a code slice
  containing `</script>` / `<!--<script>` can neither break out (XSS) nor silently swallow the
  following `<script>` block (blank-report self-DoS). Insertion into the DOM stays `textContent`.
- **Why:** methods/ORM models/views are where sensitive flows live; a name join made the layered
  map lie by omission. Span-containment is collision-proof and needs no new `Finding` fields.
- **Rejected:** threading graphify node ids onto `Finding` at taint time (the cross-file sink
  node isn't available there); qualifying names with the class (still collides on overloads and
  couples to graphify's `.method()` labelling); the narrower `</` → `<\/` viz guard (secure but
  not robust — leaves `<!--<script>` able to blank the report).

## ADR-009 — Sensitive-data layers attach to the value (Origin mint), not the IR node
- 2026-07-19 · Accepted (WP-C1; design consulted with a Fable 5 max agent, reviewer-hardened)
- **Context:** ROADMAP §11 wants credentials/PII/auth layers and the flagship query
  `credentials ∈ path.layers AND dangerous-sink ∈ path.layers`. §11's literal wording ("every IR
  node carries a layers bitmask, union along the path") invites threading labels through the whole
  IR/engine. But layers are facts about *values*, and the engine already carries value-facts as
  `Origin` sets on the taint state (`Finding.layers = origin.layers ∪ sink.layers`).
- **Decision (attachment):** sensitive-data evidence **mints a fresh label-`Origin`** unioned into
  the value's origin set — it **never mutates** an existing `Origin.layers`. Four localized mint
  sites in `engine.py`: (1) a source subscript key (`request.form['password']`); (2) a
  credential/PII-named assignment/for/walrus target; (3) a credential/PII-named parameter
  (unconditional — a real source even intraprocedurally); (4) a secret string literal or module
  constant. Label flow across functions is then free via summaries (`return_origins`/`sink_params`
  already carry Origins). Field-sensitivity-proof: a later k=1 pass changes the `State` key type,
  not the Origin payload.
- **The invariant (why mint, not mutate):** a mutated origin would (i) break summary monotonicity
  (`_summary_leq`) as layer-set elements change across the fixpoint, and (ii) break byte-determinism
  — `Finding.key` excludes `layers`, so layer-variant origins of one source id would collide under
  `findings.setdefault` over a hash-ordered frozenset. Guaranteed by construction instead: each
  minted `source_id` **encodes** its layers, and `layers`/`confidence` are pure functions of the
  matched set ⇒ colliding keys ⇒ byte-identical Findings. Verified: `analyze` twice is byte-identical.
- **Decision (matching):** identifiers match **word-based** (tokenise snake/camel, whole token-run
  + regular plural), never substring — so `tokenizer`/`next_token` never light up credentials; bare
  ambiguous tokens (`token`/`key`/`salt`) are excluded from the dicts. Secret literals: named
  formats first (AWS/JWT/PEM/GitHub/Slack/url-creds/Luhn-card), then a generic entropy fallback that
  is charset-, length- and hash-length-gated (rejects pure-decimal ids and md5/sha digests);
  deny-values match the *matched span* for named patterns (a real key in a string containing
  "example" is not suppressed) and the whole literal for the entropy fallback.
- **Decision (f-string):** a string with interpolations lowers to `Unknown("fstring", [interps])`
  (a correctness fix, not a layer feature): `execute(f"… {q}")` — the modern SQLi idiom — was
  previously an opaque `Literal` and a hard false negative.
- **Kept as tuples, not a bitmask:** `layers` stays `tuple[str,...]` (§11 said integer bitmask); the
  bitmask fights JSON/provenance readability at MVP scale.
- **Scope / deferred:** WP-C1 ships the sensitive-data (credentials/PII) layers on flows. The
  **auth/permissions layer + unguarded-sink** derived finding (decorator/gate/dominator barriers,
  `find_unguarded_sinks`) is **WP-C2** (next). Also deferred: cross-module imported-constant secrets;
  raw-text multi-language secret scan reusing `classify_secret` (Phase 8); layer-scoped sanitizers;
  `self.password = x` label loss (field-sensitivity H2); nested f-string format-spec interpolation.
- **Rejected:** IR-node bitmask (invasive, re-plumbed by field-sensitivity); post-hoc lexical
  finding enrichment (presence-in-function ≠ on the tainted value → the flagship degrades to grep);
  mutating origins in flight (breaks the two guarantees above).

## ADR-010 — Auth barriers + the unguarded-sink finding (structural, polarity-sound)
- 2026-07-19 · Accepted (WP-C2; design consulted with a Fable 5 max agent, reviewer-hardened)
- **Context:** ROADMAP §11's flagship derived finding is the **unguarded sink** — a dangerous sink
  with no auth barrier dominating it on the path. The governing constraint is asymmetric: a false
  "guarded" **hides** an unguarded sink (a security false negative), while a false "unguarded" only
  over-reports. So detection must **never credit a guard it cannot prove**.
- **Decision (detection is structural on the IR, not CFG dominators):** `guard_map(fn, imap, rules)`
  returns, per statement sid, the auth guards in scope, from three detectors: **B1** function
  decorators (`@login_required`); **B2** a statement in an `if` arm the auth condition dominates;
  **B3** a statement after an auth gate whose *failure* arm terminates (`if not authed: abort()`).
  B2/B3 are unified by a **polarity analysis**: `_true_guards`/`_false_guards` compute the auth
  terms guaranteed true when a test is truthy/falsy, threading `and`/`or`/`not` by De Morgan. An
  auth term under an `or`, inside a comparison, or as a call argument credits nothing (safe
  under-claim). The `if` model already carries `body`/`orelse`, so no separate dominator pass is
  needed.
- **Decision (guards ride the value's sink, accumulate, and merge by intersection):**
  `SinkPoint.guards` → `Finding.guards`; `_lift` **unions** the call-site guards when a callee's
  sink is lifted across a hop (barriers accumulate down the path); on a `Finding.key` collision
  (two path variants) guards **intersect** — guarded only if *every* observed path is (the sound
  direction). The intersection runs both intra-run (`engine._emit`) and **across fixpoint
  iterations** (`interproc`, not `setdefault`). `unguarded` is **derived** (`guards == ()`), never
  stored; `find_unguarded_sinks` is a filter. `guard_map` is purely structural, so guards can't
  change across the fixpoint and summary monotonicity holds; `_sink_param_key` includes guards for a
  total order.
- **Honesty:** the claim is "no auth barrier detected **on the analyzed path**." A barrier on an
  un-analyzed entrypoint above the source is not seen (safe under-claim). Reviewer found and we
  fixed two ship-blocking FNs before commit: a compound-boolean bypass (`if authed or debug:` →
  falsely guarded) and an SCC keep-first merge that froze an early "guarded" verdict over a later
  unguarded path.
- **Scope / deferred:** FastAPI `Depends(get_current_user)` barriers and entrypoint→source
  barrier reachability (Phase 7); a shadowed local `abort` spoofing termination; the merged-variant
  determinism nit (guards stay deterministic; a colliding non-guard field could differ — cosmetic).
- **Rejected:** first-match/substring auth detection (the compound-boolean FN); CFG statement
  dominators (the structural IR walk is simpler and sufficient); storing `unguarded` (derive it, so
  it can't drift from `guards`).

## ADR-011 — MCP server is a thin wrapper over a pure read-only view
- 2026-07-19 · Accepted (WP Phase 6; reviewer-hardened)
- **Context:** ROADMAP §13/§15 — expose the deterministic analysis (`taint.json` + `graph.json`)
  to an external LLM harness over MCP for token-frugal triage ("coarse discovery → precise
  slicing"). The mission requires the analysis core to stay LLM-free (ADR-000).
- **Decision (architecture):** the tool logic lives in a pure, graphify-free, SDK-free
  `secgraph/mcp_view.py` (`TaintView`) — unit-testable on its own; `secgraph/mcp_server.py` is only
  a thin `FastMCP` wrapper (the `mcp` SDK import is **lazy**, inside `build_server`, so `scan`/
  `analyze`/`--help` never pay it). The server is **read-only**: it never runs the taint engine,
  graphify, or an LLM — the analysis is already done. `secgraph serve <out_dir>` runs it over stdio.
- **Decision (taint.json carries what the tools need):** each finding gains `id` (`path-NNNN`),
  `file_hashes` (sha256 per involved file, so `get_path_slice` flags a **stale** window when the
  file drifted since analysis — §8.2), `source_node`/`sink_node` (the graphify node ids from the
  projection's (file, def-line) span join), and the artifact's `root` is stored **absolute** (so
  `serve` reads slices regardless of its cwd; taint.json is a gitignored local artifact, so a
  machine path is fine).
- **Decision (`get_function_taint` binds by node id, not name):** it matches findings by the stamped
  `source_node`/`sink_node`, not by the node's label — graphify labels a method `.get()` while the
  finding names it `get`, so a name match returned empty for every method/constructor (reviewer HIGH
  FN). This reuses ADR-008's structural join and also fixes same-name collisions.
- **Decision (`get_path_slice` = source+sink windows for the MVP):** the trace carries function
  names, not per-hop line numbers, so the minimal payload is the hash-verified source + sink code
  windows (the token-efficiency win — a few lines, not whole files). Per-hop intermediate windows
  are deferred (need hop locations stored on the finding).
- **Composition:** entity-level questions ("what calls X", shortest path) stay with
  `graphify --mcp`; data-flow paths are ours. Documented as **run both** (README). Defensive triage
  prompts (§15, CONFIRMED-vs-PLAUSIBLE discipline) shipped as MCP prompts.
- **Rejected:** putting tool logic directly in the FastMCP handlers (untestable without the SDK,
  couples logic to transport); a name match for `get_function_taint` (the method FN); a
  cwd-relative `root` (breaks slicing when the harness launches `serve` from elsewhere).

## ADR-012 — Hand-rolled Canvas graph viz (not a vis-network fork)
- 2026-07-19 · Accepted (Phase 5; UI/UX consulted with a Fable 5 max agent) · **supersedes ROADMAP §12**
- **Context:** ROADMAP §12 / pitfall #11 planned to *fork graphify's ~600-line vis-network HTML
  template*. But the self-contained rule (strict CSP: no CDN, no external anything) means
  vis-network would have to be **vendored inline (~700KB)** — a library dependency in the one file
  that must have none. The user's Phase-5 brief also asked for an Obsidian/graphify-style **graph**,
  not the current card list.
- **Decision:** replace the card viz with a hand-rolled interactive node-link **map**, everything
  (force layout + Canvas rendering + interactions) written in vanilla JS with **no library**, in a
  `secgraph/viz/` package (`__init__.py` Python wrapper + `map.css` + `map.js` inlined at render).
  Design (ADR consult): a **security-neighborhood default** (open on finding nodes + files + 1-hop,
  full graph opt-in — never render the whole repo → no hairball); **Canvas 2D** (SVG folds at the
  thousands-of-elements envelope; the Barnes-Hut quadtree doubles as the hit-test index); a **chroma
  monopoly** — grayscale base, colour only for security (credentials/pii/untrusted source fills,
  red sinks), **glow only for UNGUARDED**; a **"Critical" preset** = the §11 killer query
  (credentials/pii ∩ unguarded) as one click; deterministic **seeded** layout (mulberry32⊕FNV, no
  `Math.random`) so the emitted HTML stays byte-reproducible. The detail card reuses the old card +
  a **"Copy MCP command"** button (`get_path_slice(id)`) — closing the map→LLM loop.
- **Consequences:** no vis-network fork ⇒ **no NOTICE attribution** for it (graphify the library is
  still attributed). `render_html(findings, root)` → `render_html(graph, findings, root)`.
- **Deferred (Fable's post-cut-line):** file-collapse aggregation above ~1500 nodes, per-hop
  intermediate route slices (needs hop `(file,line)`), 1-hop expansion on context nodes, PNG export.
- **Rejected:** inlining vis-network/D3/cytoscape (violates self-containment); SVG (DOM-node blowup
  at scale); rendering the full codebase by default (the hairball trap — the map would bury the
  findings that are the entire point).

## ADR-013 — Packaging: bundle the data, keep the dev layout (Phase 8)
- 2026-07-19 · Accepted (Phase 8)
- **Context:** the analysis needs two kinds of data at runtime — the YAML **rule packs** (repo-root
  `rules/`, referenced by CLAUDE.md/docs/tests) and the **viz assets** (`secgraph/viz/map.css`,
  `map.js`). A `pip install`-able wheel must ship both, but moving `rules/` would churn the
  documented layout.
- **Decision:** hatchling **force-includes** the repo-root `rules/` into the wheel at
  `secgraph/_rule_packs`; the viz assets ship as package `artifacts` (they already live under the
  package). `default_rules_dir()` **dual-resolves**: the repo-root `rules/` in an editable dev
  checkout (`parents[2]/"rules"` exists), else the packaged copy via
  `importlib.resources.files("secgraph")/"_rule_packs"`. `viz/__init__.py` reads its assets
  `__file__`-relative, which works in both. Version bumped `0.0.0 → 0.1.0` (alpha).
- **Verified:** `uv build --wheel` produces `secgraph-0.1.0-py3-none-any.whl` containing all 4 rule
  packs + both viz assets; a fresh-venv install + `secgraph analyze` **run from outside the repo**
  emits the 3 artifacts, resolving the **packaged** `_rule_packs` (not the dev tree).
- **Rejected:** moving `rules/` under the package (churns the documented "where things live" +
  every reference); a zip-safe install (the loader globs `*.yml`, which needs a real filesystem
  path — fine, pip installs unzipped).
