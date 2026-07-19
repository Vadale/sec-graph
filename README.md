# sec-graph

**Local, defensive security tool that maps where your sensitive data goes.**

sec-graph builds a taint / data-flow map of a codebase — showing where credentials,
PII, tokens and permission checks travel — and lets you toggle *"Google-Maps"* layers
to isolate only the paths that matter. Isolated paths can then be triaged by an LLM
you already have (Claude Code, etc.) through a built-in MCP server that hands the
model only the minimal code slice for a path, not the whole repo.

It is built on top of [graphify](https://github.com/safishamsi/graphify) (MIT) and
adds the taint / data-flow engine graphify does not provide. The analysis core is
**deterministic** — no LLM is required to build the map.

## Status

**Alpha — the core pipeline works end-to-end.** The deterministic engine is built and
tested (101 tests): tree-sitter → an intermediate representation → flow-sensitive
intra- **and** interprocedural taint (cross-file SQLi/command-injection with a trace),
projected onto graphify's graph plus a self-contained layered HTML map, and an MCP
triage server. Layers today: **untrusted-input, dangerous-sink, credentials, PII**, and
the derived **unguarded-sink** finding (a dangerous sink with no auth barrier on the
path). Analysis is byte-reproducible.

Still ahead (see `ROADMAP.md`): visualization polish (Phase 5), resolver precision on
annotation-heavy code (Tier-3 typing), and packaging as a wheel (Phase 8). Not yet a
`pip install`-able release.

## Usage

```
secgraph analyze <path>   # build the map: graph.json + taint.json + secgraph.html
secgraph view             # open the interactive layered map in a browser
secgraph scan <path>      # print source→sink findings to the terminal
secgraph serve            # MCP triage server (run alongside `graphify --mcp`)
```

## Triage over MCP

`secgraph serve` exposes the *data-flow paths* to an LLM harness (Claude Code, etc.)
over MCP, handing the model only the **minimal, hash-verified code slice** for a path —
never the whole repo. Run it **alongside graphify's own server**, which answers the
entity-level questions (what calls X, shortest path); MCP hosts compose the two natively.

```
secgraph analyze <path>            # produce the artifacts first
secgraph serve --out-dir <dir>     # our data-flow tools + triage prompts (stdio)
graphify --mcp                     # graphify's entity graph tools (separate process)
```

Tools: `list_paths` (ranked, filter by layer/confidence/file) → `get_path_slice`
(the token-frugal payload) · `find_unguarded_sinks` · `explain_layer` ·
`get_function_taint`. Canned defensive triage prompts ship with the server.

## License

Apache-2.0 (see `LICENSE`). Built on graphify (MIT); attribution in `NOTICE`.

## Responsible use

Defensive and static only — sec-graph does not exploit anything. Intended for
auditing code you own or are authorized to review. Please practice coordinated
disclosure; do not use it to mass-scan third-party code and publish 0-days.
