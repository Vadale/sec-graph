# Architecture

Full detail on the data model and integration points follows below (§4 architecture, §8 data model, §9 integration
contract). This is the orientation.

## The idea in one line
graphify gives the map of *entities* (functions/files, cross-file calls). sec-graph
adds the *taint overlay* (where values flow, source → sink) that graphify lacks.

## Pipeline
```
graphify.extract()  →  entity graph + resolved cross-file call skeleton
secgraph.ir         →  re-parse with tree-sitter → per-function CFG + def-use IR
secgraph.taint      →  flow-sensitive intra + summary-based interprocedural taint
secgraph.project    →  join by (file,line) → taint.json (fine) + annotated graph.json (coarse)
                       → secgraph.html (viz)   ·   secgraph mcp (triage)
```

## The two architectural laws (see docs/pitfalls.md)
1. **Quarantine wall** — every `graphify.*` import lives only in
   `secgraph/graphify_adapter.py`. The taint core shares no code with graphify.
2. **Sidecar discipline** — statement/variable-level facts live in `taint.json` and
   must never enter graphify's pipeline (it would mangle them via entity ghost-merge,
   ID remap, Leiden clustering, the 5,000-node viz cap). `graph.json` gets only coarse
   annotations + hyperedges.

## Two artifacts, two consumers
- `graph.json` (annotated, still a valid graphify artifact) → the interactive map.
- `taint.json` (the sidecar, every statement-level fact) → MCP slicing/triage.

## Package
`secgraph/{graphify_adapter, ir/, taint/, rules/, project, viz, mcp_server, cli}`
