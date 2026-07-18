# PLAN

## Objective (one sentence)
Give developers and security analysts a local, deterministic map of where sensitive
data and permission checks flow through a codebase, and let them triage isolated
paths with their own LLM via MCP.

## Designated reader / user
Security analysts and developers auditing their **own** code — plus the open-source
community. They value a clean, honest map over a noisy alert list.

## Success criterion (executed, not narrated)
The MVP Definition of Done in `ROADMAP.md` §18: `secgraph analyze ./pygoat` yields a
map where toggling **Untrusted-Input + Dangerous-Sinks + Credentials** highlights a
real Flask `request.args` → SQL `execute` path; clicking shows the code slice;
`secgraph serve` lets Claude Code triage that exact path via MCP with a tiny token
footprint. Determinism, offline, and the binding-rate gate are all green.

## Non-goals (MVP)
- No active/dynamic exploitation — **static, defensive only**.
- No baked-in LLM (externalized via MCP).
- No real cross-tier (frontend→backend) taint.
- No Rust rewrite (kept as a later kernel-only optimization — see `ROADMAP.md` §17).
- Not JS/TS at MVP (Python first; JS/TS is the immediate next language).
