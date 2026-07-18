---
name: session-close
description: Close a sec-graph work session honestly. Runs the acceptance criteria for real, writes the diary entry, updates HANDOFF and CLAUDE.md, records any new ADRs, and commits. Use at the end of every session.
---

# session-close — end a session

**Gates (do not skip, in order):**

1. **Run** the WP's acceptance criteria for real and paste the actual output. Never
   claim done without running (honesty rule 6).
2. If code crossed a phase boundary or ~500 lines, run `simplify-pass` first.
3. Write a `diary/` entry: what was done, what works (with evidence), what is pending,
   decisions taken.
4. Update `HANDOFF.md` (state for the next session) and `CLAUDE.md` if commands or
   structure changed.
5. If decisions were made, append ADR(s) to `DECISIONS.md` (never relitigate;
   supersede).
6. Commit in English with a truthful message. Do not push unless asked.
