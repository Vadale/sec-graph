---
name: simplify-pass
description: Run the simplifier over changed sec-graph code at invariant behavior. Mandatory at end of each phase and above ~500 lines. Quality only — no bug-hunting, no new features.
---

# simplify-pass

**Gates (do not skip, in order):**

1. **Trigger check:** end of a phase, or a module crossed ~500 lines. If neither, skip.
2. Dispatch the `simplifier` agent over the changed files with the six-mission mandate
   (duplication, speculative generality, indirection, superfluous deps, dead code,
   accidental complexity).
3. Require test output proving behavior is unchanged before and after.
4. Reject any change that alters observable behavior or adds features — that is not
   simplification.
