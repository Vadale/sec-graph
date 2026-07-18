# sec-graph — Build Roadmap

> A local-first security tool that turns any codebase into an interactive
> **data-flow map**: it shows *where sensitive data (credentials, PII, tokens)
> and permission checks travel*, with toggleable "Google-Maps" layers so you can
> isolate only the paths that matter and hand them to an LLM for triage.
>
> **Strategy (decided 2026-07-18):** build **on top of `graphify`** (MIT, Python,
> tree-sitter) as a depended-on library — reuse its 40-language parsing,
> cross-file call resolution, graph artifact, HTML and MCP scaffolding — and add
> the one thing it does not have and that *is* our product: a deterministic
> **taint / data-flow engine + security layers**. This supersedes the earlier
> from-scratch-Rust plan; a Rust kernel port stays open as a later optimization
> (see §17), which the "quarantine" architecture below keeps cheap.

**Status:** planning complete, no code yet.
This document is the single source of truth for the build. Each phase ends with a
ready-to-paste **Build Prompt**.

---

## Table of contents

1. [Vision & scope](#1-vision--scope)
2. [Non-negotiable principles](#2-non-negotiable-principles)
3. [Why build on graphify (and the discipline it demands)](#3-why-build-on-graphify)
4. [Architecture overview](#4-architecture-overview)
5. [Technology stack](#5-technology-stack)
6. [Key design constraints (verified from graphify source)](#6-key-design-constraints)
7. [Repository layout](#7-repository-layout)
8. [Data model: annotated graph.json + taint.json sidecar](#8-data-model)
9. [The graphify integration contract](#9-the-graphify-integration-contract)
10. [The rules system (sources / sinks / sanitizers)](#10-the-rules-system)
11. [The layers model](#11-the-layers-model)
12. [Visualization](#12-visualization)
13. [MCP interface](#13-mcp-interface)
14. [Phased build plan (with Build Prompts)](#14-phased-build-plan)
15. [Runtime triage prompts (the "sniper prompts")](#15-runtime-triage-prompts)
16. [Testing & validation strategy](#16-testing--validation-strategy)
17. [Risks, scope cuts, and the "regret-Rust" line](#17-risks-scope-cuts)
18. [MVP definition of done](#18-mvp-definition-of-done)
19. [Post-MVP roadmap](#19-post-mvp-roadmap)
20. [Open-source & responsible-use notes](#20-open-source--responsible-use-notes)

---

## 1. Vision & scope

Security bugs rarely live at the obvious point (the login form). They live on
**paths**: an untrusted input in file A flows through helper B and lands in a
dangerous sink in file C, sometimes *before* the auth barrier. Humans and LLMs
both drown in the surrounding noise.

sec-graph builds a **taint / data-flow graph** of a codebase and renders it as an
interactive map. The user toggles layers — *"show only the railways carrying
passwords into dangerous sinks"* — like switching Google Maps from roads to
railways. Once a suspicious path is isolated, the user triages it with an LLM
**they already have**, driven through an MCP server that hands the model only the
minimal code slice for that path (a "sniper prompt"), not the whole repo.

We do not build the parsing/graph/viz/MCP plumbing from scratch: **graphify
already provides it, MIT-licensed, across ~40 languages.** graphify gives the
*map of entities*; sec-graph adds the *taint overlay* that graphify explicitly
does not do.

**In scope for the MVP**
- A `secgraph` Python package that orchestrates graphify and adds taint.
- Deterministic taint engine for **Python (Flask/FastAPI)** first.
- Five toggleable layers: Untrusted-Input, Dangerous-Sinks, Credentials/Secrets,
  PII, Auth/Permissions.
- Our own MCP server exposing discovery + precise slicing tools.
- Cheap, honestly-labeled partial value on graphify's other ~38 languages
  (secrets-in-code, sensitivity-proximity, attack-surface) — no dataflow required.

**Explicitly out of scope for the MVP** (see [§19](#19-post-mvp-roadmap))
- Active/dynamic exploitation of any kind — this is a **defensive, static** tool.
- Real cross-tier (frontend→backend) taint.
- A baked-in LLM. The engine never requires one.
- Full JS/TS taint (Python first; JS/TS is the immediate next language).
- A Rust rewrite (kept as a later kernel-only optimization).

---

## 2. Non-negotiable principles

1. **Deterministic core, no LLM required.** Parsing, resolution, taint, and layer
   tagging are 100% static analysis + dictionaries + entropy. Same input ⇒ same
   output. An LLM is *never* on the critical path.
2. **LLM-agnostic, externalized via MCP.** Reasoning/triage is done by the user's
   own agent harness (Claude Code, Codex, …) through our MCP server. sec-graph
   ships zero API keys and calls no model itself.
3. **Depend on graphify; never fork it (except one file).** `secgraph` depends on
   a pinned `graphifyy`. The only forked surface is graphify's ~600-line HTML viz
   template (MIT, attributed). See [§3](#3-why-build-on-graphify).
4. **The quarantine wall.** All `graphify.*` imports live in exactly one module
   (`graphify_adapter.py`). The taint core shares zero code with graphify and only
   consumes its resolved call skeleton and emits annotations back. This keeps a
   later divorce or Rust-kernel port cheap.
5. **The sidecar discipline (architectural law).** Statement/variable-level facts
   live in a separate `taint.json`. They must **never** enter graphify's pipeline,
   which would silently mangle them (entity ghost-merge, ID remap, `file_type`
   coercion, Leiden clustering, the 5,000-node viz cap). `graph.json` receives
   only coarse annotations + hyperedges.
6. **Honesty over soundness.** Without types we hit unresolved calls and dropped
   edges. Every path carries **confidence + provenance**; a truncated path is
   marked `resolution-lost`, never silently dropped or silently trusted.
7. **Ruthless scope discipline.** Nail SQLi + command-injection +
   sensitive-data-to-log/response end-to-end on Python before breadth.
8. **English everywhere in the product** (code, comments, docs, UI). Only the
   conversation with the maintainer is in Italian.

---

## 3. Why build on graphify

**The decision.** graphify (`github.com/safishamsi/graphify`, MIT, Python 100%,
tree-sitter, Leiden) gives us — for free and across ~40 languages — the layer that
would otherwise be weeks of work: multi-language parsing, an entity graph
(functions/classes/files), **cross-file `calls`/`imports`/`inherits` resolution**,
community detection, an interactive HTML, a `graph.json` artifact, and an MCP
server. It has **no data-flow or taint** — which is exactly and only what we add.

**What it buys** (≈3–4 weeks off the from-scratch plan): the entire "Phase 2:
symbol resolution & call graph" is **deleted** (biggest single saving); scaffolding
(Phase 0) shrinks to days; viz and MCP roughly halve.

**What it does NOT buy:** the taint engine itself (IR → CFG → def-use → intra +
interprocedural summaries). That work was never going to be donated by anyone, in
any language. graphify's graph is **entity-level** (function nodes); taint needs
**statement/variable-level** def-use — a different granularity we build ourselves.

**The discipline it demands** (why this is safe):
- **Depend-as-library, pinned** (`graphifyy==0.9.6`). graphify is a fast-moving
  single-maintainer 0.9.x codebase; its node-ID scheme already changed *within*
  0.9.x (issue #1504). A fork would put us on a rebase treadmill over 44K lines
  (extract.py alone is 16.6K) for the ~10 functions we use.
- **Quarantine wall** (`graphify_adapter.py` is the only import site) + a **CI
  contract test** that runs `extract()` on a fixture and asserts the schema we
  depend on. A graphify bump becomes a deliberate, tested event, not ambient
  breakage.
- **Structural join, not ID recomputation.** Both sides derive function boundaries
  from the same tree-sitter `function_definition`, so we join IR functions to
  graphify nodes by **`(relative source_file, start_line)`** — which survives
  graphify's ID migrations.

---

## 4. Architecture overview

```
 graphify.extract()  ─────────────►  entity graph: functions/classes/files,
   (tree-sitter, 40 langs, MIT)       resolved calls/imports/inherits  ──┐
        │                                                                 │ (call skeleton, §9)
        ▼                                                                 ▼
 secgraph.ir:  re-parse each file  ─►  per-function CFG + def-use IR  ─►  secgraph.taint:
   (tree-sitter, our own)              (k=1 access paths, spans)          intra (flow-sensitive)
        │                                                                 + interproc (summaries)
        │                                                                        │
        ▼                                                                        ▼
 secgraph.project:  join by (file,line)  ─────────────────────►  ┌── taint.json  (statement-level
                                                                  │     paths, slices, provenance) ── MCP
                                                                  └── graph.json (entity-level
                                                                        annotations + hyperedges) ─── viz
```

`secgraph` package (the quarantine architecture):

```
secgraph/
  graphify_adapter.py   # THE ONLY import site for graphify.* — the quarantine wall
  ir/                   # tree-sitter → per-function CFG + def-use IR (no graphify)
  taint/                # intra + summaries + interprocedural (no graphify)
  rules/                # YAML sources/sinks/sanitizers/frameworks + labels
  project.py            # projection: taint results → graph.json annotations + taint.json
  viz.py                # forked-from-graphify HTML template + layer panel (MIT, attributed)
  mcp_server.py         # OUR MCP server; reads graph.json + taint.json
  cli.py                # `secgraph analyze | serve | view`
```

**Two artifacts, two consumers.** `graph.json` (annotated, still a valid graphify
artifact) drives the map; `taint.json` (the sidecar) holds every statement-level
fact and drives MCP slicing. This split is the sidecar discipline of §2.

---

## 5. Technology stack

| Concern | Choice | Why |
|---|---|---|
| Language | **Python** | Build on graphify; ship as a `uv`/`pip` tool (runs on any PC). |
| Upstream engine | **`graphifyy==0.9.6`** (pinned, MIT) | Parsing, call resolution, entity graph, HTML/MCP scaffold. |
| Parsing (our IR) | `tree_sitter` + grammar wheels **already pinned by graphifyy** (`tree-sitter>=0.23,<0.26`, `tree-sitter-python`) | Same grammars graphify uses; no new native deps. |
| IR / graphs | own module: `__slots__` dataclasses, integer node IDs, flat arenas; `networkx` only at the entity layer (transitive dep), **never in the taint hot loop** | Fast, serializable, mypyc/Rust-portable later. |
| Taint labels | integer **bitmasks** (one bit per layer) | Set ops are single `|`/`&`. |
| Rules | `pyyaml` | Declarative sources/sinks/sanitizers/frameworks; hashed into provenance. |
| Secrets | stdlib `re` + Shannon entropy (`math`); `pyahocorasick` only if profiling demands | Deterministic credential/secret literal detection. |
| Parallelism | `concurrent.futures.ProcessPoolExecutor` (mirror graphify's own pattern) | Parse/lower/intra-summaries are embarrassingly parallel. |
| Caching | per-file IR + per-function summaries keyed `sha256(file)+rules_hash`, under `graphify-out/secgraph-cache/` | Warm incremental runs in seconds. |
| MCP | the `mcp` SDK (same one graphify's `[mcp]` extra uses) | Our own stdio server. |
| Viz | forked graphify **vis-network** HTML template | Layer toggles, hyperedge path hulls; keep their physics/search/XSS-escaping. |
| CLI | `typer` or `click` | `secgraph analyze | serve | view`. |
| Tests | `pytest`, snapshot fixtures, a contract test, PyT-derived corpus, Pysa recall oracle | See [§16](#16-testing--validation-strategy). |

**Recall oracle (CI only, out-of-band):** Meta's **Pysa/Pyre** run on benchmark
repos to measure our recall gap — never a runtime dependency. **Rule/test seed:**
the archived **PyT / python-taint** (source/sink lists + vulnerable-Flask corpus).

**Deliberately NOT used:** a graphify fork (except the viz file), stdlib-`ast`-based
engines (`Scalpel`, `LibCST` — Python-only, off the tree-sitter path), any cloud
call from the engine, embedding/vector stores.

---

## 6. Key design constraints

These are **verified from the installed graphify 0.9.6 source** and are
load-bearing — the design depends on them.

1. **`source_location` is start-line only** (`"L{line}"`) — no end line, no column,
   anywhere. → Function spans come from *our* re-parse.
2. **`calls` edges are function→function but deduplicated to one edge per
   (caller, callee)**; only the first call site's line survives. → We enumerate
   every call site in our own IR; graphify's edge is a *resolution oracle*, not a
   call-site list.
3. **Member calls on variable receivers are dropped.** Only `ClassName.method()`,
   `self.field.method()`, and import-evidenced bare names resolve cross-file;
   ambiguous names are *silently omitted*. → We add a local type-tracking fallback
   resolver (constructor types, `self.`, one round of param-type propagation).
4. **`indirect_call` INFERRED edges** exist for callbacks (`Thread(target=fn)`,
   `executor.submit(fn)`). → Free candidate edges for higher-order taint.
5. **Edge `relation` is free-form** (so `taint_flow` is a legal relation), but
   `confidence` is a hard enum `{EXTRACTED, INFERRED, AMBIGUOUS}`, and a numeric
   `confidence_score` field is already first-class. **Extra node/edge attrs survive
   the full round-trip.** → We annotate freely, but map our numeric confidence into
   `confidence_score` and pick the enum for `confidence`.
6. **graphify's MCP loads graph.json as a DiGraph, not MultiDiGraph** → two links
   between the same ordered pair **collapse (last-wins)**. → **Never emit a
   `taint_flow` link where a `calls` link already exists; annotate the `calls`
   link instead.** This makes the collapse a non-issue by construction.
7. **Hyperedges are first-class** and rendered by the HTML as labeled shaded hulls.
   → A taint path is naturally a hyperedge; **baseline path visualization is free.**
8. **`extract()` already does ProcessPoolExecutor + per-file content-hash cache**,
   and there is a formal extension point `resolver_registry.register(...)`. → Mirror
   its parallel/cache patterns; keep the registry in mind for a future
   better-Python-member-call resolver that improves *both* graphs.
9. **Node IDs are not a stability contract** (scheme migrated at #1504). → Join by
   `(source_file, start_line)`, never by recomputing IDs.
10. **`to_json` has a shrink-guard (#479); HTML caps at 5,000 nodes; graph.json
    load caps at 512 MiB.** → We **post-process the graph.json dict directly**
    (load, annotate, dump) rather than routing through `to_json`, sidestepping the
    shrink-guard and their dedup passes entirely.
11. **HTML is inline Python template strings with a field whitelist and no hook.**
    → We fork that ~600-line surface into `secgraph/viz.py` (the only fork).
12. **The MCP server has no tool-registration API** (private helpers). → We run our
    own server; document "run both" (`graphify --mcp` + `secgraph mcp`) since MCP
    hosts compose servers.

---

## 7. Repository layout

```
sec-graph/
  pyproject.toml                # deps: graphifyy==0.9.6, tree-sitter (matched range),
                                #       pyyaml, mcp, typer, pytest; extras: [dev] pyre-check
  LICENSE                       # Apache-2.0 (secgraph's own code)
  NOTICE                        # MIT attribution for graphify's forked viz template
  README.md                     # wow-first: GIF, one-command demo
  roadmap.md                    # this file
  secgraph/                     # the package (see §4)
  rules/
    python/{flask.yml,fastapi.yml,stdlib.yml}
    labels.yml
    secrets.yml                 # cross-language secret regexes + entropy thresholds
  tests/
    contract/                   # graphify schema contract tests (CI gate on version bump)
    fixtures/                   # tiny + cross-file Python fixtures (annotated # ruleid:/# ok:)
    corpus/                     # PyT-derived vulnerable snippets
    benchmarks/                 # PyGoat + 3 real Flask/FastAPI repos (binding-rate gate, Pysa oracle)
```

---

## 8. Data model

Two files. **`graph.json`** stays a valid graphify artifact; **`taint.json`** is
our sidecar and the source of truth for everything statement-level.

### 8.1 `graph.json` annotations (coarse, entity-level — drives viz + graphify MCP)

- **Node annotations** (extra attrs, survive round-trip):
  `sec_layers: ["untrusted-input","auth"]`, `sec_findings: {paths_through, unguarded_sinks}`,
  `sec_max_severity: 0.72`.
- **Edge annotations on existing `calls` edges** where taint rides a call:
  `confidence_score`, `sec_paths: ["path-0007"]` (do **not** add a parallel
  `taint_flow` link here — constraint §6.6).
- **New `taint_flow` links only where no structural edge exists** (globals, files,
  queues, env). `relation:"taint_flow"`, `confidence` enum + `confidence_score`.
- **One hyperedge per top-N finding**: `{id, label:"q → cursor.execute (SQLi?)",
  nodes:[fn ids on the path]}` — rendered as a hull for free.

Emit by post-processing the dict directly (load → annotate → dump), never via
`to_json` (constraint §6.10).

### 8.2 `taint.json` sidecar (fine-grained — drives our MCP)

```jsonc
{
  "version": 1,
  "rules_hash": "sha256:…",                     // provenance: which rule pack produced this
  "functions": {
    "fn:app/routes.py:41": { "graphify_node": "app_routes_get_user",
      "file": "app/routes.py", "span": [41, 78], "name": "get_user" }   // graphify_node via (file,line) join; null if unmatched
  },
  "paths": [
    { "id": "path-0007",
      "source": { "kind":"http-param", "layer":"untrusted-input",
                  "site": {"file":"app/routes.py","line":44,"col":12}, "expr":"request.args['q']" },
      "sink":   { "kind":"sql-exec", "layer":"dangerous-sink",
                  "site": {"file":"app/db.py","line":91}, "expr":"cursor.execute(query)" },
      "labels": ["untrusted-input"],
      "confidence": 0.72,
      "provenance": ["calls:EXTRACTED","summary:helpers.sanitize?absent","receiver:CHA"],
      "guards": [],                              // auth checks dominating the sink (empty = unguarded)
      "hops": [
        { "fn":"fn:app/routes.py:41", "graphify_node":"app_routes_get_user",
          "steps":[ {"line":44,"action":"source","var":"q"},
                    {"line":52,"action":"call-arg","callee":"fn:app/db.py:80","arg":0,"access_path":"q"} ] },
        { "fn":"fn:app/db.py:80", "graphify_node":"app_db_run_query",
          "steps":[ {"line":85,"action":"assign","var":"query"},
                    {"line":91,"action":"sink","var":"query"} ] }
      ],
      "file_hashes": {"app/routes.py":"sha256:…","app/db.py":"sha256:…"}   // staleness check for slices
    }
  ],
  "node_annotations": { "app_routes_get_user": {"layers":["untrusted-input","auth"], "path_ids":["path-0007"]} }
}
```

`get_path_slice` reads code windows from disk at call time and verifies
`file_hashes`, flagging stale slices instead of serving drifted line numbers.

---

## 9. The graphify integration contract

**Seams to hook** (all public API or stable artifact — nothing underscore-private):

| Seam | Use |
|---|---|
| `graphify.detect.detect`, `graphify.extract.collect_files` | file discovery + ignore rules |
| `graphify.extract.extract(paths, cache_root=…, parallel=True)` | entity nodes/edges + resolved `calls`/`imports`/`inherits`/`indirect_call`; **its output schema is the contract** |
| `graphify.build.build_from_json(extraction, directed=True, root=…)` | NetworkX DiGraph — **always `directed=True`** |
| `graphify.cluster.cluster`, `graphify.analyze.god_nodes` | community base layer; god-node context for triage |
| `graph.json` + `hyperedges` | the projection target (§8.1) |
| `resolver_registry.register` | *(future)* feed our receiver-type inference back as a resolution pass |

**Do NOT import** `serve.py`/`extract.py` internals (underscore-private, churning).
Reimplement the ~80 lines we need. Never mutate `graphify-out/` conventions — write
`graph.json` (annotated), `taint.json`, `secgraph.html` into the same dir so
graphify's own MCP/HTML keep working.

**Call skeleton = resolution oracle, not a call-site list.** Take from graphify:
function-level `calls` with direction/`source_file`/confidence (kills from-scratch
symbol resolution); `inherits` → **CHA fan-out** for dynamic dispatch (tag
`provenance:"CHA"`, discount confidence); `indirect_call` → higher-order candidates;
`imports` → module reachability for the cheap layers.

**What our IR must supply** (graphify cannot): every **call-site** with argument
expressions; **variable-receiver method calls** (`db.execute()` where
`db=Database()`) via local type tracking (`provenance:"local-type"`);
**arg→param binding**, kwargs, defaults, `*args`; Python **re-exports / `import *` /
`__init__` facades** via our import map; **decorator-mediated dispatch** (Flask
`@app.route`, FastAPI `Depends`) via framework rules.

**Degradation rule:** every unresolved/ambiguous case ends the path early with a
`resolution-lost` provenance marker — **never a wrong edge.** Acceptable for a
triage tool; fatal only above the binding-rate gate (§14 Phase 3, §17).

---

## 10. The rules system

Declarative YAML, **one file per framework**, matched against our IR by resolved
FQN + call shape (not regex over text). Matcher kinds: `attribute-read`,
`subscript-read`, `call`, `parameter`, `assignment`. Each rule carries `layers`,
`cwe`, `severity`, `confidence`. Seed sources/sinks/sanitizers from PyT's trigger
lists; ship a test corpus per pack (`# ruleid:` / `# ok:`).

```yaml
# rules/python/flask.yml
language: python
framework: flask
imports:
  - { module: flask, names: [request, session, make_response] }
sources:
  - id: flask-request-input
    kind: attribute-read
    base: flask.request
    attributes: [args, form, values, json, data, cookies, headers, files]
    layers: [untrusted-input]
  - id: env-secret
    kind: call
    callee: [os.getenv, os.environ.get]
    layers: [untrusted-input, credentials]
    confidence: medium
sinks:
  - id: py-sql-exec
    kind: call
    callee: [".execute", ".executemany", ".executescript"]   # method-name (duck-typed)
    fqn_hint: [sqlite3, psycopg2, sqlalchemy]
    taint_args: [0]
    layers: [dangerous-sink]
    cwe: CWE-89
    severity: high
  - id: py-os-command
    kind: call
    callee: [os.system, os.popen, subprocess.call, subprocess.run, subprocess.Popen]
    taint_args: [0]
    layers: [dangerous-sink]
    cwe: CWE-78
    severity: critical
sanitizers:
  - { id: shlex-quote, kind: call, callee: [shlex.quote], clears: return }
  - { id: int-coerce, kind: call, callee: [int, float], clears: return, applies_to_layers: [dangerous-sink] }
propagators:
  - { id: str-format, kind: call, callee: [".format", "json.dumps"], from_args: [any], to: return }
```

---

## 11. The layers model

Every IR node carries a `layers` bitmask + per-label `confidence`/`provenance`. A
path's layers = union of its nodes'. The killer query *"passwords into dangerous
sinks"* = `credentials ∈ path.layers AND dangerous-sink ∈ path.layers`.

| Layer | Deterministic signals | Confidence |
|---|---|---|
| **Untrusted-Input** | taint sources | High |
| **Dangerous-Sinks** | taint sinks | High |
| **Credentials/Secrets** | secret rules (env, keyring, `.pem`/`.key`); identifier dict `password|passwd|pwd|secret|token|api[_-]?key|priv.*key|credential|bearer|jwt|salt`; literal detection (Shannon entropy + format regex: AWS `AKIA…`, JWT `eyJ…`, PEM) | High |
| **PII** | identifier dict `email|ssn|dob|phone|address|first_?name|credit_?card|iban|passport|tax_id` + value regex (email, SSN, card w/ **Luhn**, IBAN) | Medium |
| **Auth/Permissions** | decorator/middleware dict (`@login_required`, `@permission_required`, FastAPI `Depends(get_current_user)`); fn-name dict (`authorize|is_admin|has_role|verify_token`); guard patterns (`if not current_user.is_admin: abort(403)`) | High for barriers |

Flagship derived finding: **unguarded sink** — a dangerous sink reachable with no
auth barrier dominating it on the path (`guards == []`). Pure graph reachability.

**Cheap partial value on graphify's other ~38 languages (no dataflow, honestly
labeled):**
1. **Secrets-in-code** (all langs incl. config): regex + entropy over raw text,
   pinned to file:line, projected onto graphify *file* nodes. `provenance:"lexical"`.
2. **Sensitivity proximity**: tag entity nodes whose identifiers match
   sensitive/sink lexicons, then BFS over graphify's `calls` edges — "≤2 hops from
   credential-handling code." Rendered as a low-confidence `INFERRED` layer,
   explicitly labeled *reachability heuristic, not dataflow*.
3. **Attack surface**: entry-point detection from decorators/annotations
   (Spring `@RequestMapping`, Rails routes, Go handlers) via per-framework rules.

Each is a YAML pack, not engine code. They make sec-graph useful on a Go/Java repo
day one — as a map, not a prover.

---

## 12. Visualization

Fork graphify's ~600-line vis-network template into `secgraph/viz.py` (MIT,
attributed in NOTICE) — the **only** fork — and emit `secgraph.html` *alongside*
graphify's `graph.html`. Keep their physics, search, info panel, and XSS escaping
(`esc()`/`sanitize_label`).

Additions:
- Carry `sec_layers`/`sec_paths` into the vis node/edge payloads (their `to_html`
  whitelists fields — the reason a fork is required).
- **A "Layers" checkbox panel** cloned from their community-legend pattern: the
  five layers; toggle = dim/hide nodes and edges lacking the tag.
- **A path sidebar** (Google-Maps mode): click a finding ⇒ highlight its hyperedge
  hull + edges, dim the rest; side panel shows the code slice + provenance + a
  "copy MCP command for this path" button.

Baseline path hulls come free from graphify's hyperedge rendering (constraint §6.7).
Keep the default view under graphify's 5,000-node cap — the layers *are* the
performance strategy (never render everything).

---

## 13. MCP interface

**Run our own server** (`secgraph mcp`, direct dep on the `mcp` SDK) — graphify's
has no tool-registration API (constraint §6.12). It reads `graph.json` +
`taint.json`. Principle: **coarse discovery → precise slicing**, so the agent never
loads the whole graph.

| Tool | Input | Output |
|---|---|---|
| `list_paths` | `layer?, min_confidence?, file?, limit, offset` | ranked path summaries `{id, source, sink, layers, confidence, hops}` |
| `get_path_slice` ★ | `path_id, context_lines=3` | per-hop code windows read from disk, **hash-verified** against `file_hashes`, with per-step annotations — the sniper-prompt payload |
| `find_unguarded_sinks` | `layer?` | paths where `guards == []` |
| `explain_layer` | `layer` | deterministic dict/rule provenance for the layer |
| `get_function_taint` | `node_id` | summary view for one graphify entity node |

★ `get_path_slice` is the core token-efficiency win — the whole point of the project.

**Entity-level questions** ("what calls X?", "shortest path", "god nodes") stay
with graphify's own server. Document **run both** (`graphify --mcp` + `secgraph
mcp`); MCP hosts compose servers natively. (Optional later: reimplement
`get_node`/`get_neighbors`/`shortest_path` over our loader for one-server UX — ~80
lines, not an MVP blocker.)

---

## 14. Phased build plan

8 weeks, focused solo dev. graphify deletes the old Phase 2 and shrinks 0/6/7; the
IR/rules/taint phases are unchanged in scope — that work is irreducible. Prefix
every session with the meta-prompt.

> **Meta-prompt (start of every phase):**
> "Read `roadmap.md` in full, then implement **Phase N** as specified in §14.
> Follow the non-negotiable principles (§2) — especially the quarantine wall and
> the sidecar discipline — and the verified graphify constraints (§6). Keep the
> engine deterministic and LLM-free, add pytest tests, and run the test suite +
> the graphify contract test before finishing. Do not exceed the phase scope; list
> anything you deferred."

---

### Phase 0 — Scaffold + graphify adapter + contract test  *(Week 1, part)*

**Goal:** `secgraph analyze <path>` runs graphify and round-trips its artifact.
**Deliverables:** package skeleton (§7); `graphify_adapter.py` wrapping
`detect`/`extract`/`build_from_json` with `graphifyy==0.9.6` pinned; a **CI
contract test** asserting the schema we depend on (node/edge required fields,
function-level `calls` attribution, `L{line}` format); Apache-2.0 + NOTICE.
**Acceptance:** on a fixture repo, we obtain graphify's entity graph + a valid
`graph.json`, and the contract test passes on all 3 OSes.

> **Build Prompt — Phase 0:** "Create the `secgraph` package (§7) and
> `graphify_adapter.py` as the sole import site for `graphify.*`, pinning
> `graphifyy==0.9.6`. Wrap `detect`, `collect_files`, `extract(parallel=True)`, and
> `build_from_json(directed=True)`. Add a pytest **contract test** in
> `tests/contract/` that runs `extract()` on `tests/fixtures/tiny` and asserts:
> node/edge required fields, that `calls` edges are function→function with a
> `source_file` and an `L{line}` `source_location`, and that extra attrs survive a
> build→to_json round-trip. Wire `secgraph analyze <path>` (typer) to produce
> graphify's `graph.json`. Add Apache-2.0 LICENSE + a NOTICE crediting graphify
> (MIT). CI matrix ubuntu/macos/windows."

---

### Phase 1 — Python IR: re-parse → CFG + def-use + the (file,line) join  *(Week 1)*

**Goal:** our own statement-level IR, joined to graphify's entity nodes.
**Deliverables:** `secgraph/ir/` — tree-sitter re-parse (grammars from graphify's
pinned deps), per-function CFG, def-use chains, k=1 access paths, `__slots__` nodes
+ integer IDs; the **`(source_file, start_line)` join** mapping each IR function to
its graphify node id (fallback: log unmatched-function diagnostic).
**Acceptance:** on a fixture, 100% of functions join to a graphify entity node;
CFG/def-use snapshot tests pass.

> **Build Prompt — Phase 1:** "Implement `secgraph/ir/`: re-parse Python files with
> `tree_sitter` (use the grammar versions graphify already pins), build a
> per-function CFG and def-use chains with k=1 access paths (interned `(base,field)`
> pairs), nodes as `__slots__` dataclasses with integer ids and spans. Implement the
> `(relative source_file, start_line)` structural join from each IR function to its
> graphify node id (do NOT recompute graphify's node-id recipe); log any unmatched
> function. Add snapshot tests over `tests/fixtures`. No taint yet, no graphify
> imports outside the adapter."

---

### Phase 2 — Rules engine + intraprocedural taint  *(Week 2)*

**Goal:** find a source→sink flow *within a function*, respecting sanitizers.
**Deliverables:** `secgraph/rules/` YAML loader (§10) + `rules/python/{flask,stdlib}.yml`
seeded from PyT; `secgraph/taint/` flow-sensitive forward worklist over the CFG;
bitmask labels; sanitizers clear taint.
**Acceptance:** intra findings reproduce on PyT's vulnerable Flask snippets; a
sanitizer on the path suppresses the finding.

> **Build Prompt — Phase 2:** "Implement the YAML rules loader (§10) and
> `rules/python/flask.yml` + `stdlib.yml`, seeding source/sink/sanitizer lists from
> the archived PyT project. Implement `secgraph/taint/` intraprocedural
> flow-sensitive taint: a worklist over each function's CFG, integer-bitmask labels,
> k=1 access paths, sanitizers clearing taint. Report intra-function source→sink
> paths with confidence + provenance. Add fixtures + the PyT-derived corpus proving
> flow-sensitivity."

---

### Phase 3 — Interprocedural summaries + the KILL-GATE  *(Week 3)*

**Goal:** the core value — cross-function/cross-file paths — on graphify's skeleton.
**Deliverables:** function summaries (conditional: "return tainted iff argN
tainted"); interprocedural propagation driven by **graphify's `calls` skeleton**
(§9) with SCC condensation for recursion; the **local fallback resolver**
(constructor types, `self.`, one param-type round) for variable-receiver calls
graphify drops; **CHA fan-out** over `inherits`; `resolution-lost` markers.
**⚠ KILL-GATE (must pass to proceed):** measure the **call-site binding rate** on 3
real Flask/FastAPI repos — need **≥60–70%** of call sites bound (graphify + local
fallback combined). Below that, the whole build-on-graphify thesis is at risk —
stop and reassess (see §17).
**Acceptance:** a `request.arg → service → cursor.execute` path is found end-to-end
across 3 files; binding-rate gate met.

> **Build Prompt — Phase 3:** "Extend `secgraph/taint/` to interprocedural analysis
> via conditional function summaries, propagated over graphify's resolved `calls`
> edges (loaded through the adapter) with SCC condensation for recursion. Add a
> local fallback resolver for variable-receiver method calls graphify drops
> (constructor types `v=ClassName()`, `self.method`, one round of param-type
> propagation), tagged `provenance:'local-type'`, and CHA fan-out over `inherits`
> edges. Mark truncated paths `resolution-lost`. **Then implement the binding-rate
> measurement** in `tests/benchmarks/` over 3 real Flask/FastAPI repos and report
> the percentage — this is a go/no-go gate at 60–70%."

---

### Phase 4 — Layers + projection to graph.json + taint.json  *(Week 4)*

**Goal:** tag the 5 layers and emit both artifacts.
**Deliverables:** `secgraph/rules/labels.yml` + `secrets.yml`; layer tagging
(dicts, entropy, Luhn, barrier detection); `find_unguarded_sinks`; `secgraph/project.py`
producing `taint.json` (§8.2) and annotating `graph.json` (§8.1) by **post-processing
the dict** (never `to_json`), obeying the DiGraph-collapse rule (§6.6) and the
sidecar discipline.
**Acceptance:** end-to-end path on a deliberately-vulnerable app (e.g. PyGoat) with
correct layers; a **projection test asserts graph.json node count is unchanged by
projection** (granularity-leakage guard).

> **Build Prompt — Phase 4:** "Implement `secgraph/rules/labels.yml` + `secrets.yml`
> and the layer tagger (§11: identifier dicts, Shannon entropy, format regexes incl.
> Luhn, decorator/guard barrier detection), plus `find_unguarded_sinks` (auth-guard
> dominance). Implement `secgraph/project.py`: write `taint.json` (§8.2) and annotate
> `graph.json` (§8.1) by loading→annotating→dumping the dict directly — never via
> `to_json`. Enforce: no `taint_flow` link where a `calls` link exists (annotate the
> calls edge); map numeric confidence to `confidence_score`; one hyperedge per top-N
> finding. Add a test asserting projection does not change graph.json node count."

---

### Phase 5 — Visualization fork  *(Week 5)*

**Goal:** the "Google Maps" map.
**Deliverables:** `secgraph/viz.py` (forked graphify vis-network template);
`sec_layers`/`sec_paths` in payloads; Layers checkbox panel; path sidebar with
highlight + code slice + "copy MCP command"; `secgraph view` emits/open `secgraph.html`.
**Acceptance:** toggle Untrusted-Input + Dangerous-Sinks + Credentials → only those
paths remain; click a path → slice + hull highlight; fully offline (no network in
devtools).

> **Build Prompt — Phase 5:** "Fork graphify's ~600-line vis-network HTML template
> into `secgraph/viz.py` (keep physics/search/XSS-escaping; attribute in NOTICE).
> Add `sec_layers`/`sec_paths` to node/edge payloads, a five-layer checkbox panel
> (toggle = dim/hide untagged elements) cloned from graphify's community legend, and
> a path sidebar (click → highlight the finding's hyperedge hull, dim the rest, show
> code slice + provenance + copy-MCP-command). Emit `secgraph.html` alongside
> graph.html; wire `secgraph view`. Verify zero network requests."

---

### Phase 6 — Our MCP server  *(Week 6)*

**Goal:** external LLM harness triages precisely.
**Deliverables:** `secgraph/mcp_server.py` (mcp SDK, stdio) exposing the §13 tools;
`get_path_slice` reads disk windows hash-verified against `file_hashes`; ship the
canned triage prompts (§15); `secgraph serve`.
**Acceptance:** from Claude Code, `list_paths` → `get_path_slice(p1)` returns the
minimal hash-verified slice; token count a fraction of dumping the involved files;
"run both servers" documented.

> **Build Prompt — Phase 6:** "Implement `secgraph/mcp_server.py` with the `mcp` SDK
> (stdio), reading `graph.json` + `taint.json`, exposing `list_paths`,
> `get_path_slice` (disk windows verified against `file_hashes`, flag stale),
> `find_unguarded_sinks`, `explain_layer`, `get_function_taint`. Register the §15
> triage prompts. Wire `secgraph serve`. Add an integration test asserting
> `get_path_slice` returns only the deduplicated on-path lines. Document running it
> alongside `graphify --mcp` in the README."

---

### Phase 7 — Framework depth + performance  *(Week 7)*

**Goal:** real Flask/FastAPI surface + fast warm runs.
**Deliverables:** entrypoint recognizers (Flask `@app.route`/blueprints, FastAPI
`@app.get/post` + `Depends` incl. auth deps as barriers); `rules/python/fastapi.yml`;
incremental cache (per-file IR + per-function summaries keyed `sha256+rules_hash`);
`ProcessPoolExecutor` parallelism; **Pysa recall oracle** in CI.
**Acceptance:** warm run < 10 s on a 50K-LOC repo; recall gap vs Pysa reported.

> **Build Prompt — Phase 7:** "Add Flask (route decorators, blueprints,
> `register_blueprint`) and FastAPI (`@app.get/post`, typed params as sources,
> `Depends(...)` resolution with auth deps as barriers) entrypoint recognizers +
> `rules/python/fastapi.yml`. Add per-file IR + per-function summary caching keyed by
> `sha256(file)+rules_hash` under `graphify-out/secgraph-cache/`, and
> ProcessPoolExecutor parallelism for parse/lower/intra. Add a CI job running Meta's
> Pysa on the benchmark repos and reporting the recall gap vs sec-graph. Target warm
> run < 10 s on 50K LOC."

---

### Phase 8 — Cheap multi-language layers, hardening, release  *(Week 8)*

**Goal:** breadth + launch.
**Deliverables:** the 3 dataflow-free layers on graphify's other languages (§11:
secrets-in-code, sensitivity proximity, attack surface); docs; version-pin policy;
README **GIF** (map → toggle → found SQLi → click slice → MCP triage); release via
`uv`/PyPI.
**Acceptance:** the [MVP definition of done](#18-mvp-definition-of-done) is met;
sec-graph shows *something* useful on a Go/Java repo.

> **Build Prompt — Phase 8:** "Implement the three no-dataflow layers over
> graphify's entity graph (§11): a cross-language secrets-in-code scanner
> (`rules/secrets.yml`, regex+entropy, projected onto file nodes), a
> sensitivity-proximity BFS over `calls` edges (INFERRED, labeled 'reachability, not
> dataflow'), and an attack-surface entry-point pack. Write the wow-first README with
> a GIF, a version-pin/upgrade policy for graphifyy, and `uv`/PyPI packaging. Ensure
> the tool produces a useful map on a non-Python (e.g. Go) repo."

---

## 15. Runtime triage prompts

Shipped as MCP prompts; the "sniper prompts." The model receives only a slice +
deterministic provenance, never the whole repo. **Defensive framing is mandatory.**

### 15.1 System prompt (triage session)

```
You are a defensive application-security assistant helping a developer audit and
FIX their own code, over a static data-flow tool (sec-graph) via MCP.

Rules of engagement:
- Purpose is defensive: find, explain, and remediate. Never produce a weaponized
  exploit or instructions to attack systems the user doesn't own.
- Ground every claim in the provided slice and provenance. If evidence is
  insufficient, say so and request a specific tool call (get_function_taint,
  get_path_slice) instead of guessing.
- Prefer get_path_slice over reading whole files. Stay token-frugal.
- Distinguish CONFIRMED (visible in the slice) from PLAUSIBLE (depends on unseen
  code). Respect confidence/provenance; a `resolution-lost` marker means the path
  truncated at an unresolved call — flag the assumption, don't fill the gap.
```

### 15.2 Per-path triage prompt (parameterized by `path_id`)

```
Triage this data-flow path for exploitability.

Layers: {{layers}}   Confidence: {{confidence}}   Unguarded: {{guards == []}}
Provenance: {{provenance}}

Path slice (source → sink, minimal lines):
{{get_path_slice(path_id)}}

Answer concisely:
1. Is the source genuinely attacker-controlled here? Why.
2. Does anything on the path actually sanitize the value for this sink? If a helper
   is opaque (resolution-lost / summary-absent), say what you'd need to confirm.
3. Verdict: CONFIRMED / PLAUSIBLE / FALSE-POSITIVE + one-line justification.
4. Severity (reasoned), factoring whether an auth barrier is crossed.
5. Minimal idiomatic fix at the right hop. Prefer the structural fix (e.g.
   parameterized query) over masking the symptom.
```

### 15.3 Layer-explanation prompt (parameterized by `layer`)

```
Explain, for a developer, what the "{{layer}}" layer shows in this project and why
these nodes were tagged, using only {{explain_layer(layer)}} (deterministic
provenance). List the top 3 riskiest nodes and what to check for each. Do not
invent nodes absent from the provenance.
```

---

## 16. Testing & validation strategy

- **graphify contract test** (CI gate): `extract()` on a fixture, assert the schema
  we depend on. A graphify version bump must pass this before it lands.
- **Unit + snapshot tests** for IR lowering and the discovered path set on fixtures
  (pin taint output).
- **Rule corpus**: PyT-derived vulnerable snippets annotated `# ruleid:` / `# ok:`;
  CI fails on regression.
- **Binding-rate gate** (Phase 3): call-site resolution ≥60–70% on 3 real repos —
  go/no-go for the whole strategy.
- **Granularity-leakage guard**: projection must not change graph.json node count.
- **Ground truth**: PyGoat for MVP; NodeGoat/Juice Shop when JS lands. Track
  precision/recall.
- **Pysa recall oracle** (Phase 7): out-of-band, measures our miss rate; never a
  runtime dep.
- **Determinism**: analyze twice → byte-identical `taint.json`.
- **Offline**: `secgraph.html` makes zero network requests.
- **Token-savings benchmark**: `get_path_slice` vs dumping involved files — publish
  the number.

---

## 17. Risks, scope cuts

**Top 3 risks specific to layering statement-taint on an entity-graph tool:**
1. **Upstream drift on an uncontracted schema** (graph.json shape + node IDs are
   conventions; IDs migrated at #1504). *Mitigate:* exact pin, single-file adapter,
   CI contract test, `(file,line)` join instead of ID recomputation.
2. **Granularity leakage** — statement nodes entering graphify's pipeline get
   mangled (ghost-merge, ID remap, `file_type` coercion, Leiden, 5K cap).
   *Mitigate:* the sidecar discipline is law; test that projection leaves node count
   unchanged.
3. **Resolution ceiling silently truncating paths** — graphify's precision-first
   edge dropping = a vuln path that ends mid-flight, invisibly. *Mitigate:* the
   Phase-3 binding-rate gate; `resolution-lost` markers surfaced in UI; the local
   fallback resolver; and, if the rate stays low, promoting our resolver into
   graphify's `resolver_registry` seam so both graphs improve.

**When you'd regret not doing pure Rust (the abort line):** if the real target
becomes **large monorepos (500K–1M+ LOC) with tight-loop / CI-gating usage**
expecting near-instant re-analysis. Pure-Python fixpoint + JSON artifacts hit a
wall there (graphify's own 512 MiB graph.json load cap is the omen) that caching and
multiprocessing delay but don't remove. For the stated MVP — local, on-demand triage
of small-to-medium Python/JS services with an LLM in the loop — Python-on-graphify
reaches a demoable product ~4 weeks sooner, and the quarantine + serialized-array IR
keep a **Rust-kernel port** (mypyc first, then a maturin extension for the fixpoint
only) open as an optimization, not a rewrite.

**Cut list (in order) if the 8 weeks slip:** drop the cheap 38-language layers
(Phase 8) → Python-only is a legit demo; drop FastAPI, keep Flask; drop incremental
caching (re-analyze each run); narrow to SQLi + command-injection + secret-to-log
end-to-end. Never cut: the binding-rate gate, the sidecar discipline, or
confidence/provenance.

---

## 18. MVP definition of done

`secgraph analyze ./pygoat` runs graphify + our taint pass and writes an annotated
`graph.json`, a `taint.json`, and `secgraph.html`. Opening the HTML and toggling
**Untrusted-Input + Dangerous-Sinks + Credentials** highlights a real path from a
Flask `request.args` into a raw SQL `execute` (a genuine PyGoat SQLi); clicking it
shows the code slice and the hyperedge hull. Then `secgraph serve` exposes MCP;
Claude Code calls `list_paths` → `get_path_slice` and triages that exact path with a
tiny token footprint. The map visibly *cleans up* when noise layers are off. It runs
from a `uv`/`pip` install on Windows, macOS, and Linux. Binding-rate gate met;
determinism, offline, and node-count-unchanged tests green.

---

## 19. Post-MVP roadmap

- **JavaScript/TypeScript** taint (Express, Next.js): reuse the IR driver + a
  per-language `LanguageConfig` (imitating graphify's own pattern); CJS+ESM,
  re-exports/barrels, destructuring (`const {body} = req`).
- **Cross-tier "network-hop" edge**: match frontend `fetch/axios` literal URL+method
  to backend routes; dashed low-confidence edge stitching frontend→backend. No real
  request-body taint.
- **More frameworks:** Django (urls/CBVs; `.raw()`/`.extra()`/raw cursor as SQLi
  sinks), then breadth.
- **Performance kernel:** mypyc-compile the taint module (~2–4×), then a maturin
  Rust extension for the fixpoint only — architecture untouched (the escape hatch of
  §17).
- **Better call resolution upstream:** register our receiver-type resolver via
  graphify's `resolver_registry` so both graphs improve.
- **Expand cheap layers** across more languages; SCA overlay (dependency packages as
  nodes; sensitive data into a known-vulnerable library function).

---

## 20. Open-source & responsible-use notes

- **Licensing:** sec-graph's own code under **Apache-2.0** (permissive + patent
  grant; MIT-compatible so we can depend on graphify and include its
  attributed viz fork). Ship a **NOTICE** crediting graphify (MIT) for the forked
  HTML template. If you prefer copyleft, GPLv3 is possible but complicates bundling —
  decide before the first public commit.
- **Defensive by design:** static triage only; no exploitation code ships. The
  triage prompts (§15) enforce a defensive framing.
- **Responsible defaults & docs:** default to auditing *your own* code; document a
  coordinated-disclosure stance; do not encourage mass-scanning third-party repos
  with public 0-day dumps. The heavy analysis capability already exists in public
  engines — sec-graph's contribution is clarity (the map) and token-efficient
  triage, overwhelmingly a defender's advantage.

---

*End of roadmap. Start with the Phase 0 Build Prompt. Whenever a build-specific
technical doubt arises, consult a Fable 5 max agent (per the maintainer's standing
instruction) before committing the plan.*
