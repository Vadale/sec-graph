"""Reproducibility: clone the corpus repos at their pinned commits, write corpus/sources.json (source
roots for Arm A), and run `secgraph analyze --sarif` into the bench-out dir (Arm B/C data). The CodeQL
SARIFs are already committed as the fixed finding sets, so CodeQL itself is NOT re-run here.

    python benchmark/fetch.py            # then: python benchmark/run.py ; python benchmark/report.py

Bench-out defaults to /tmp/secgraph-bench-out (override with $SECGRAPH_BENCH_OUT)."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
BENCH_OUT = Path(os.environ.get("SECGRAPH_BENCH_OUT", "/tmp/secgraph-bench-out"))


def sh(*cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def main():
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    included = [s for s in manifest["survey"] if s.get("included")]
    sources = {}
    for s in included:
        repo = s["repo"]
        src = CORPUS / repo / "src"
        if not src.exists():
            print(f"clone {repo} @ {s.get('commit','?')}")
            sh("git", "clone", "--quiet", s["url"], str(src))
            if s.get("commit"):
                sh("git", "-C", str(src), "checkout", "--quiet", s["commit"])
        sources[repo] = str(src.resolve())
        out = BENCH_OUT / repo
        print(f"analyze {repo} -> {out}")
        sh(os.environ.get("SECGRAPH", "secgraph"), "analyze", str(src.resolve()),
           "--sarif", str(CORPUS / repo / "codeql.sarif"), "--out-dir", str(out),
           stdout=subprocess.DEVNULL)
    (CORPUS / "sources.json").write_text(json.dumps(sources, indent=2))
    print(f"wrote {CORPUS/'sources.json'} ({len(sources)} repos). Now run: python benchmark/run.py")


if __name__ == "__main__":
    main()
