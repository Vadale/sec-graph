"""Sweep orchestrator (PROTOCOL §3-4). Generates the LLM verdicts for arms A/B/C over the corpus and
dumps them to results/verdicts.json — deliberately WITHOUT scoring, so the expensive sweep (~2-4 h) is
decoupled from the (instant) scoring and can be re-scored after any truth-label amendment.

Arm B/C payloads come from `secgraph.mcp_view.TaintView` — exactly what the MCP server wraps
(ADR-011, thin-wrapper-over-pure-view), so they are byte-identical to the served MCP payload without
async/subprocess fragility. Score with report.py.

Usage: python benchmark/run.py [--runs 2] [--num-ctx 16384] [--limit N] [--repos pygoat,vulpy,...]
Source roots for Arm A come from benchmark/corpus/sources.json (repo -> abs path; fetch.py populates it).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

import arms
import rank
import triage
from secgraph.mcp_view import TaintView

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
BENCH_OUT_ENV = "SECGRAPH_BENCH_OUT"


def _load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def _est_tokens(s: str) -> int:
    return len(s) // 4


def build_B_payloads(bench_out: Path):
    """id/join-key -> {summary, windows} from the TaintView the MCP server wraps, plus O3 order + self-audit."""
    view = TaintView(bench_out)
    taint = _load(bench_out / "taint.json")
    findings = taint.get("findings", [])
    by_key = {}
    for f in findings:
        key = rank.taint_join_key(f)
        payload = {"summary": view._summary(f), "windows": view.get_path_slice(f["id"]).get("windows", [])}
        by_key[key] = payload
    o3 = rank.order_O3(findings)
    audit = [{"key": rank.taint_join_key(f), "guard_status": f.get("guard_status"),
              "unguarded": f.get("unguarded"), "binding": [p for p in f.get("provenance", []) if p.startswith("binding:")]}
             for f in findings]
    return by_key, o3, audit


def sweep(repos, runs, num_ctx, limit, seed):
    sources = _load(CORPUS / "sources.json")
    bench_out_base = Path(subprocess.os.environ.get(BENCH_OUT_ENV, "/tmp/secgraph-bench-out"))
    out = {"model": triage.MODEL, "num_ctx": num_ctx, "runs": runs, "seed": seed,
           "ollama_host": triage.HOST, "repos": {}}
    for repo in repos:
        root = Path(sources[repo])
        sarif = _load(CORPUS / repo / "codeql.sarif")
        run = sarif["runs"][0]
        rules = arms.rule_index(run)
        results = run["results"][:limit] if limit else run["results"]
        B_by_key, o3, audit = build_B_payloads(bench_out_base / repo)
        o2 = rank.order_O2(run["results"], rules)
        rep = {"o2": [list(k) for k in o2], "o3": [list(k) for k in o3], "self_audit": audit,
               "sarif_sha256": "sha256:" + hashlib.sha256((CORPUS / repo / "codeql.sarif").read_bytes()).hexdigest(),
               "findings": []}
        for i, res in enumerate(results):
            key = arms.join_key(res)
            evA = arms.render_A(res, rules, root)
            payload = B_by_key.get(key)
            rec = {"ordinal": i, "key": list(key), "arm_present": {"B": payload is not None},
                   "evidence_tokens": {"A": _est_tokens(evA)}, "arms": {}}
            variants = {"A": evA}
            if payload is not None:
                variants["B"] = arms.render_B(payload)
                variants["C"] = arms.render_C(payload)
                rec["evidence_tokens"]["B"] = _est_tokens(variants["B"])
                rec["evidence_tokens"]["C"] = _est_tokens(variants["C"])
            for arm, ev in variants.items():
                rec["arms"][arm] = []
                for r in range(runs):
                    verdict, meta = triage.triage(ev, num_ctx=num_ctx, seed=seed + r)
                    rec["arms"][arm].append({"verdict": verdict, "meta": meta})
                    print(f"  {repo}[{i}] {arm} run{r}: {verdict.get('verdict')}/{verdict.get('vuln_class')} "
                          f"{meta.get('wall_s')}s tok={meta.get('prompt_tokens')}", flush=True)
            # arms absent for B/C (intent-to-treat: report.py scores these wrong, never drops them)
            for arm in ("B", "C"):
                if arm not in rec["arms"]:
                    rec["arms"][arm] = [{"verdict": {"verdict": None, "unavailable": True}, "meta": {}} for _ in range(runs)]
            rep["findings"].append(rec)
        out["repos"][repo] = rep
        (ROOT / "results").mkdir(exist_ok=True)
        (ROOT / "results" / "verdicts.json").write_text(json.dumps(out, indent=1))   # incremental dump
        print(f"== {repo} done ({len(rep['findings'])} findings) ==", flush=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=2)
    ap.add_argument("--num-ctx", type=int, default=16384)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--repos", default="pygoat,vulpy,vulnerable-flask-app")
    a = ap.parse_args()
    t0 = time.time()
    sweep(a.repos.split(","), a.runs, a.num_ctx, a.limit or 0, a.seed)
    print(f"SWEEP DONE in {round(time.time()-t0)}s -> benchmark/results/verdicts.json", flush=True)


if __name__ == "__main__":
    main()
