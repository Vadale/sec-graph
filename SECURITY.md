# Security Policy

## Scope

sec-graph is a local, read‑only, defensive analysis tool: it ingests SARIF findings, reads source, and
serves code slices to an MCP client. It runs no untrusted code and makes no outbound network calls.
The relevant threat is a **hostile input report** — a crafted SARIF/Semgrep file — trying to steer
sec-graph into reading files outside the analyzed tree. Ingested paths are normalized and **clamped
inside the analyzed root**; the MCP slice reads are root‑bounded. Reports of a bypass are welcome.

## Reporting a vulnerability

Please report security issues **privately** — use GitHub's *"Report a vulnerability"* (Security →
Advisories) on this repository, or email the maintainer — rather than opening a public issue. Include a
minimal reproduction. We aim to acknowledge within a few days and to fix before public disclosure;
we'll credit you unless you prefer otherwise.

## Not a vulnerability

Findings *about the code sec-graph analyzes* (i.e. the vulnerabilities it maps) are the tool working as
intended — not a vulnerability in sec-graph. The deliberately‑vulnerable apps referenced by the
benchmark are third‑party and are cloned at pinned commits for measurement only.
