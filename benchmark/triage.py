"""The triage step, held IDENTICAL across arms (PROTOCOL §3): same model, decoding, system prompt,
output schema and taxonomy — only the evidence block (from arms.py) differs. One call per finding.
Seeded from scratchpad/gemma_triage.py. Local model via Ollama; reasoning disabled (think:false) so
the JSON answer lands in message.content."""
from __future__ import annotations

import json
import os
import time
import urllib.request

HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
MODEL = "gemma4:e4b-it-qat"

TAXONOMY = ("sql-injection, command-injection, code-injection, path-traversal, deserialization, xss, "
            "ssrf, open-redirect, cleartext-storage-or-logging, weak-hashing-or-crypto, log-injection, "
            "insecure-cookie, cookie-injection, xml-external-entity-or-bomb, csrf, missing-cert-validation, "
            "debug-mode, info-exposure, none")

SYSTEM = ("You are a defensive application-security analyst triaging ONE static-analysis finding for a "
          "developer auditing their own code. Decide from the evidence alone whether it is a genuinely "
          "exploitable issue, its class, whether an auth barrier protects it, and its severity. Be precise "
          "and token-frugal.")

INSTRUCT = (
    "\n\nRespond with ONLY a JSON object, no prose:\n"
    '{{"vuln_class": "<one of: {taxo}>",\n'
    ' "verdict": "real|false-positive|unsure",\n'
    ' "auth_guarded": "yes|no|unknown",\n'
    ' "severity": "low|medium|high|critical",\n'
    ' "reason": "<=18 words, cite the sink"}}'
).format(taxo=TAXONOMY)


def triage(evidence: str, num_ctx: int, seed: int = 7, num_predict: int = 220) -> tuple[dict, dict]:
    """Run one triage call. Returns (verdict_dict, meta). meta carries tokens, wall time, and flags for
    truncation / context-cap so intent-to-treat can score failures rather than drop them."""
    prompt = evidence + INSTRUCT
    body = json.dumps({
        "model": MODEL, "stream": False, "format": "json", "think": False,
        "options": {"temperature": 0, "seed": seed, "num_ctx": num_ctx, "num_predict": num_predict},
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
    }).encode()
    t0 = time.time()
    req = urllib.request.Request(HOST + "/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        d = json.load(urllib.request.urlopen(req, timeout=600))
    except Exception as e:                                   # network/host failure -> scored wrong, not dropped
        return {"vuln_class": None, "verdict": None, "error": str(e)[:200]}, {"wall_s": round(time.time() - t0, 1)}
    wall = round(time.time() - t0, 1)
    content = d.get("message", {}).get("content", "") or ""
    ptok = d.get("prompt_eval_count")
    meta = {"wall_s": wall, "prompt_tokens": ptok, "gen_tokens": d.get("eval_count"),
            "done_reason": d.get("done_reason"),
            "ctx_capped": bool(ptok) and ptok >= 0.98 * num_ctx,   # prompt filled the window
            "truncated": d.get("done_reason") == "length"}
    try:
        verdict = json.loads(content)
    except Exception:
        verdict = {"vuln_class": None, "verdict": None, "parse_error": content[:200]}
    return verdict, meta
