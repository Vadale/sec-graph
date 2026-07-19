"""Emit a truth-label SKELETON from a CodeQL SARIF: keys only (SARIF identity), empty labels.
The labeller fills these into truth.json; keys are never hand-copied (anti-typo, anti-circular).
Usage: python benchmark/skeleton.py benchmark/corpus/<repo>/codeql.sarif <repo> <commit>
"""
import hashlib
import json
import sys
from pathlib import Path


def _loc(r):
    try:
        pl = r["locations"][0]["physicalLocation"]
        return pl["artifactLocation"]["uri"], pl["region"]["startLine"]
    except (KeyError, IndexError):
        return None, None


def main(sarif_path: str, repo: str, commit: str) -> None:
    p = Path(sarif_path)
    d = json.loads(p.read_text())
    sha = "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
    findings = []
    for run in d.get("runs", []):
        for i, r in enumerate(run.get("results", [])):
            f, line = _loc(r)
            fp = (r.get("partialFingerprints") or {}).get("primaryLocationLineHash", "")
            findings.append({
                "key": {"rule_id": r.get("ruleId"), "file": f, "line": line,
                        "fingerprint": fp, "ordinal": i},
                # labels — filled by the (blind) labeller, verified by the maintainer:
                "real": None,                # true | false
                "vuln_class": None,          # one of the 15-item taxonomy (see PROTOCOL §3)
                "guard": None,               # guarded | unguarded | n/a
                "guard_evidence": "",        # MANDATORY code citation "file:line — why"
                "severity": None,            # low | medium | high | critical
                "severity_rationale": "",
                "notes": "",
            })
    out = {"repo": repo, "commit": commit, "sarif_sha256": sha,
           "labeller": "claude-drafted-blind; maintainer-verified", "process": "PROTOCOL.md#2",
           "findings": findings}
    dest = p.with_name("truth.skeleton.json")
    dest.write_text(json.dumps(out, indent=2))
    print(f"{repo}: {len(findings)} findings -> {dest}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3])
