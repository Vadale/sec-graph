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

**Pre-alpha — planning complete, implementation not started.** See `ROADMAP.md` for
the 8-week MVP plan and `PLAN.md` for scope. There is no working functionality yet;
this README describes the intended tool honestly, not a shipped one.

## Planned usage

```
secgraph analyze <path>   # build the map: graph.json + taint.json + secgraph.html
secgraph view             # open the interactive layered map
secgraph serve            # MCP server for LLM triage (run alongside `graphify --mcp`)
```

## License

Apache-2.0 (see `LICENSE`). Built on graphify (MIT); attribution in `NOTICE`.

## Responsible use

Defensive and static only — sec-graph does not exploit anything. Intended for
auditing code you own or are authorized to review. Please practice coordinated
disclosure; do not use it to mass-scan third-party code and publish 0-days.
