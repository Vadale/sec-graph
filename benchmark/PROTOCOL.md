# sec-graph benchmark — PROTOCOL (pre-registration)

This document is the **binding, pre-registered protocol** for the Phase-12 benchmark (ADR-015),
locked by a Fable 5 max design review (2026-07-19). It is committed **before** any A/B/C run; its git
commit date is the pre-registration timestamp. Any change after the first run on an *unseen* repo is a
new commit with a written justification, and affected results are re-run and reported as **amended**.

## 0. The claim (and its scope)

sec-graph does **not** find vulnerabilities — an external SAST (here CodeQL) does. The hypothesis:

> Given the **same** SAST findings, sec-graph's view (enrichment layers + minimal hash-verified
> source→sink slices + unguarded-first prioritization) makes **triage** by a small local LLM more
> accurate, cheaper (tokens/time), and better-prioritized than triaging the raw SAST output.

Every claim is scoped to: **this model** (`gemma4:e4b-it-qat`), **these repos**, **Python**, and
**triage of an existing SAST's findings** — never detection, humans, other models/languages, or
production codebases. LLM-only; no human arm (its relevance is argued qualitatively + future work).

**Sentences we refuse to write:** "sec-graph makes vulnerability triage X% more accurate" (unscoped);
"statistically significant" attached to anything but the single primary endpoint; any claim of
detection ability, human-analyst benefit, or cross-model / cross-language / production generalization.

## 1. Corpus

CodeQL 2.26.1, suite `codeql/python-queries:codeql-suites/python-security-extended.qls`. Survey of
deliberately-vulnerable Python web apps (all attempts reported, per `corpus/manifest.json`):

| repo | role | CodeQL findings | included |
|---|---|---|---|
| PyGoat | **development** (rules/dicts/prompt tuned on it) | 40 | ✅ |
| Vulpy (`bad/` + `good/`) | unseen | 17 | ✅ |
| Vulnerable-Flask-App | unseen | 9 | ✅ |
| django.nV | — | 0 | ❌ Django template/ORM vulns not modelled |
| dvpwa | — | 1 | ❌ below threshold |

**Selection criterion (pre-declared):** deliberately-vulnerable Python web app with CodeQL
security-extended findings spanning ≥3 vuln classes and containing real auth code; the two highest-yield
non-dev candidates are the unseen set. The domain yields small per-repo counts; this is a **documented
limitation**, not a defect. **Results are split dev vs unseen.** PyGoat is dev because the rule packs,
enrichment dictionaries, and the triage prompt skeleton were developed against it.

**Freeze:** sec-graph is frozen at the git tag `benchmark-freeze` before first contact with the unseen
repos. No rule/dictionary/enrichment/prompt edit after that tag. A tool bug found mid-benchmark is a
**result** (reported; the fix ships in a labelled v-next run, both published).

## 2. Ground truth — `corpus/<repo>/truth.json`

Keyed on **SARIF identity** (`rule_id`, `file`, `line`, `fingerprint`, `ordinal`) — never sec-graph path
ids (truth must be definable without ever running sec-graph). Per finding:

- `real`: `true|false` — is this a genuinely exploitable/valid issue?
- `vuln_class`: one of the 15-item output taxonomy (§3).
- `guard`: `guarded | unguarded | n/a` **with a mandatory `guard_evidence` code citation** (`file:line — why`).
- `severity`: `low|medium|high|critical` per the rubric below, with a one-line `severity_rationale`.

**Severity rubric:** `critical` = pre-auth RCE / deserialization / SQLi; `high` = injection or
sensitive-data exposure reachable past weak/no auth; `medium` = authenticated-only or constrained
primitive; `low` = hygiene (e.g. weak hash of non-secret, missing cookie flag with no session impact).

**Labelling procedure (anti-circularity is procedural):**
1. `skeleton.py` emits a truth **skeleton** from the SARIF (keys only, empty labels) — keys are never
   hand-copied.
2. Labeller inputs allowed: the SARIF + the app source tree + the app's own vulnerability docs.
   **Forbidden: `taint.json`, the map, MCP output, any sec-graph result.** Guard state is read from the
   route/view code, not from the tool.
3. Labels are **drafted by Claude** (blind to sec-graph outputs, with mandatory code citations) and
   **verified/adjudicated by the maintainer**; `BENCHMARK.md` states this. The benchmarked model (Gemma)
   and its harness never write truth.
4. Reliability: a ≥30% second blind pass (maintainer, ≥3 days later or independent); raw agreement
   reported; disagreements resolved in a written adjudication log with code citations.
5. `truth.json` + this PROTOCOL are committed **before** the first A/B/C run on that repo (git history is
   the ledger).

## 3. Arms (the triage step)

Held **constant** across arms: model `gemma4:e4b-it-qat`, `temperature 0`, fixed `seed`,
`num_predict 220`, identical `num_ctx`, identical system prompt (a neutral analyst prompt — *not*
`mcp_server.SYSTEM_PROMPT`, which references tools absent in a batch pipeline), identical output schema
and taxonomy, the **same finding set** (every SARIF result), one call per finding, no chat history.

**Output schema (forced JSON, both arms):**
`{"vuln_class": <taxonomy>, "verdict": "real|false-positive|unsure", "auth_guarded": "yes|no|unknown", "severity": "low|medium|high|critical", "reason": "<=18 words"}`

Taxonomy (15): `sql-injection, command-injection, path-traversal, deserialization, xss, ssrf,
open-redirect, cleartext-storage-or-logging, weak-hashing-or-crypto, log-injection, insecure-cookie,
xml-external-entity-or-bomb, code-injection, csrf, none`.

- **Arm A — control (steelman).** Evidence = rendered SARIF fields (ruleId, rule short/full description,
  severity + security-severity, message, primary `file:line`, the ordered `codeFlows` steps) **+ the full
  numbered text of every file appearing in the finding's flow.** A's evidence is a strict **superset** of
  the raw material behind everything B is told — so a B win cannot be "A lacked information."
- **Arm B — treatment (product-faithful).** Exactly the real MCP payload (`list_paths` summary +
  `get_path_slice` ±3-line windows + `layers`/`unguarded`/`guards`/`cwe`), assembled via the real MCP
  client (as `scratchpad/mcp_pull.py`). Nothing added beyond what the tools return.
- **Arm C — ablation.** Arm B's slices with the enrichment stripped (`layers`, `guards`, `unguarded`,
  `guard_status` removed; keep cwe/severity/windows). Isolates minimal-slices vs enrichment.

**Context window:** raised to **16384 for both arms** (feasibility-checked on the Ollama host first).
Pre-declared fallback if the host cannot: `num_ctx=8192` with Arm A capped at "enclosing function(s) of
every flow point ± 40 lines," **cap events counted and reported**. Never allow silent truncation: assert
estimated prompt tokens < 0.9·`num_ctx` before each call and verify `prompt_eval_count` after.

**Blind-class condition (secondary):** strip ruleId/description/message from A and `cwe` from B; score
class-naming from evidence alone against truth. Boxed as secondary (extends Part 2 non-circularly).

**Intent-to-treat:** every SARIF result is in every arm's denominator. An ingest/bind/parse/ctx-cap
failure scores that arm **wrong** on accuracy metrics — never a silent drop. A coverage row
(ingested/bound/answered) is published so nothing exits the denominator silently.

## 4. Metrics

**Primary endpoint (declared in advance):** paired **real/FP accuracy** (`verdict` vs `truth.real`;
`unsure` counts wrong), tested with **exact McNemar** on discordant pairs, α=0.05. This is the only
significance test.

**Secondary (point estimate + bootstrap 95% CI, no p-values):** `guard_acc` (`auth_guarded` vs
`truth.guard`, n/a excluded, `unknown`=wrong); `class_acc` (exact taxonomy vs `truth.vuln_class`; one
pre-declared near-miss pair `insecure-cookie ≈ cookie-injection`) — **near-ceiling by construction** in
product-faithful mode (A holds the rule name, B the CWE), informative only in the blind-class condition;
`sev_exact` and `sev_within1` (±1 ordinal) + confusion matrix; efficiency (`prompt_tokens`, `gen_tokens`,
`wall_s` — median and total per arm per repo).

**Prioritization (deterministic; LLM cost enters only via composition):**
- **O2** = severity-sorted raw SARIF (key: `security-severity` desc, level rank, file, line) — the real
  baseline any engineer gets with one `jq`. **O3** = sec-graph `list_paths` `_rank` (guard tier, severity,
  confidence, id). (O1 = SARIF file order is descriptive only; the claim is **O3 vs O2**, never O3 vs O1.)
- Targets from truth: `T_crit` = {real ∧ critical}; `T_high` = {real ∧ (high|critical)}.
- `rank_first_crit(O)`, `precision@{5,10}(O, T_high)`, and `cost_to_first_confirmed_crit(arm,O)` (walk O,
  accumulate that arm's measured tokens/seconds until the first `T_crit` the arm called `real`). Primary
  comparison **B@O3 vs A@O2**, reported **decomposed** (ordering vs payload-size vs correctness) so it is
  not read as double-counting.

**Tool self-audit (no LLM — sec-graph vs truth):** guard-verdict accuracy on `analyzed` findings
(precision of "unguarded" and of "guarded" separately — ADR-010's asymmetry), `unknown` count, binding
coverage by provenance (`span|nearest-def|file|none`). Publishing our own tool's error rate next to the
arm results is a core credibility commitment.

## 5. Statistics (N ≈ 66, small)

Unit = finding, paired within model. **One** primary endpoint (§4). Everything else: bootstrap percentile
95% CIs (resample findings, 10k draws) — that is the multiplicity control. Findings within a repo are not
independent: report **per-repo tables** + a pooled estimate with the explicit caveat "pooled test assumes
finding-level independence" + a repo-level sign line ("Δ positive in k/3 repos"). Single-digit cells
(e.g. Vulnerable-Flask-App, FP counts) reported as **counts, not percentages**, flagged underpowered.
Decode variance: temp 0 + fixed seed, then **run the full sweep twice** and report the identical-output
rate; if <98%, report both runs.

## 6. Threats to validity → mitigations (the skeptic's list)

1. *Arm A is a strawman* → whole-file superset control; O2 baseline; both prompts published verbatim.
2. *Truth graded toward the tool* → SARIF-identity keys; labelled blind to tool outputs; mandatory
   citations; committed before runs; adjudication log; tool self-audit published.
3. *Cherry-picked corpus* → pre-declared criteria + full survey (incl. django.nV=0, dvpwa=1); dev/unseen
   split.
4. *Prompt tuned for B* → Arm A gets an equal dry-run tuning budget on PyGoat only, then the skeleton is
   frozen (git-dated) before unseen contact.
5. *Context window strangled A* → same `num_ctx`; truncation asserted + counted; cap policy pre-declared.
6. *Selection bias via ingestion* → intent-to-treat; B's failures score wrong; coverage row.
7. *Grader fudge* → schema-constrained JSON both arms; mechanical **exact-taxonomy** scorer (the Part-2
   keyword-matching scorer must NOT survive); near-miss set fixed pre-run.
8. *Class accuracy circular/ceiling* → hand-labelled classes; product-faithful class metric flagged
   near-ceiling; the blind-class condition carries the evidence-quality claim.
9. *One model / one run / one seed* → duplicate sweep; any Haiku point uses the identical harness and is
   an explicit single anecdote; all claims model-scoped.
10. *B handed the answers (unguarded flag)* → superset argument (B's extras are deterministic derivations
    of code A sees in full) + self-audit shows the verdict's error rate, which B inherits in `guard_acc`.
11. *A win would be buried* → git pre-registration; all cells published, including where A beats B.

## 7. MUST-DO / MUST-NOT

**MUST-DO:** (1) Arm A = SARIF fields + full numbered text of all flow files; identical `num_ctx`,
skeleton, decoding across arms. (2) Prioritization claim = **O3 vs O2** (severity-sorted), never O1.
(3) `truth.json` keyed on SARIF identity, labelled blind, citation-backed, committed before any run.
(4) Freeze `benchmark-freeze` before unseen contact; PyGoat = dev; split dev/unseen. (5) One primary
endpoint (paired real/FP, exact McNemar) pre-declared; else CIs only; intent-to-treat denominators;
publish the tool's own guard-verdict error rate. (6) Run Arm C + the duplicate sweep; report
truncation/cap + coverage rows; publish prompts + scorer verbatim. (7) Include the FP-rich element
(Vulpy `good/` under the same suite).

**MUST-NOT:** (1) No keyword matching in the scorer; no post-hoc near-miss additions; no label edits
after runs without a public amended-results commit. (2) No naive-N-line-window "raw baseline" (that's an
ablation, not the control). (3) No rule/dict/prompt edits after unseen contact; no silent repo/finding
drops. (4) No "statistically significant" outside the one primary endpoint; no unscoped "X% better", no
detection/human/cross-model/cross-language/production claims. (5) No engine-CWE in scoring; no sec-graph
ids as truth keys; no LLM-authored truth labels without stated human verification.
