---
name: new-wp
description: Open a new work package (a ROADMAP phase) for sec-graph. Reads HANDOFF and the relevant ADRs, then writes executable acceptance criteria BEFORE any code. Use at the start of a build session.
---

# new-wp — open a work package

**Gates (do not skip, in order):**

1. Read `HANDOFF.md` (current state) and the relevant ADRs in `DECISIONS.md`.
2. Read the target phase in `ROADMAP.md` — its Build Prompt and its acceptance
   criteria.
3. If the WP touches the adapter, projection, or viz, re-read `docs/pitfalls.md`.
4. **Restate the acceptance criteria as executable commands** (with expected output)
   *before* writing any code. Adjectives are not criteria.
5. Confirm only one WP is in progress. If a build-specific technical doubt arises,
   consult a Fable 5 max agent before committing the plan.

Only after all five: start implementing. One WP at a time.
