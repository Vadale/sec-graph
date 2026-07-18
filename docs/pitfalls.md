# Pitfalls — verified graphify 0.9.6 constraints

Load-bearing facts verified by reading graphify 0.9.6's source. The design depends on
them. Full context: `ROADMAP.md` §6. **Read this before touching the adapter,
projection, or viz.**

1. **`source_location` is start-line only** (`"L{line}"`) — no end line, no column.
   → function spans come from *our* re-parse.
2. **`calls` edges are function→function but deduplicated** to one per (caller,
   callee); only the first call-site line survives. → enumerate call sites in our IR;
   graphify's edge is a *resolution oracle*, not a call-site list.
3. **Member calls on variable receivers are dropped**; ambiguous names silently
   omitted. → we add a local type-tracking fallback resolver.
4. **`indirect_call` INFERRED edges** exist for callbacks (`Thread(target=fn)`, …).
   → free higher-order taint candidates.
5. **`relation` is free-form** (so `taint_flow` is legal); `confidence` is a hard
   enum `{EXTRACTED, INFERRED, AMBIGUOUS}`; `confidence_score` is first-class; extra
   node/edge attrs survive the round-trip.
6. **MCP loads graph.json as a DiGraph (not multigraph)** → parallel links between the
   same ordered pair collapse (last-wins). → **NEVER emit a `taint_flow` link where a
   `calls` link exists; annotate the `calls` link instead.**
7. **Hyperedges are first-class** and rendered as labeled hulls. → a taint path = a
   hyperedge = free path visualization.
8. **`extract()` already does ProcessPool + per-file content-hash cache**;
   `resolver_registry.register(...)` is a formal extension point.
9. **Node IDs are not stable** (scheme migrated at #1504). → join by
   `(source_file, start_line)`, never by recomputing IDs.
10. **`to_json` has a shrink-guard; HTML caps at 5,000 nodes; graph.json load caps at
    512 MiB.** → annotate `graph.json` by post-processing the dict directly, not via
    `to_json`.
11. **HTML is inline template strings, field-whitelisted, no hook.** → fork the
    ~600-line viz into `secgraph/viz.py` (the only fork).
12. **The MCP server has no tool-registration API.** → run our own server; document
    "run both" (`graphify --mcp` + `secgraph mcp`).

**Pin:** `graphifyy==0.9.6`. A version bump must pass `pytest tests/contract` before
it lands.
