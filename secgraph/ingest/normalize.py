"""Path/URI normalization + severity/CWE/confidence maps + the shared finding-dict builder for
ingested SAST results (ADR-014, Phase 9). Graphify-free -- reads JSON structures + disk only.

The URI normalizer is the join's lifeline: SARIF paths arrive relative, absolute ``file://``,
``uriBaseId``-anchored, percent-encoded, or relative to a *different* cwd than the analyzed root.
Every resolved path is **clamped inside the root** -- a hostile SARIF must not steer a slice read at
``../../etc/passwd`` (``_read_slice``/``get_path_slice`` do a bare ``root / rel`` read).
"""
from __future__ import annotations

import posixpath
import re
from pathlib import Path
from urllib.parse import unquote

from ..project import _file_hash, _read_slice

_SARIF_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
_PRECISION = {"very-high": "high", "high": "high", "medium": "medium", "low": "low"}
_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_CWE_RE = re.compile(r"(?i)cwe[-_/ ]?0*(\d+)")

# CWE family -> the extra DATA layer (every finding also gets untrusted-input by default, so the
# viz layer toggles can never orphan it -- map.js filters on DATA_LAYERS only).
_CWE_LAYER = {
    "798": "credentials", "259": "credentials", "321": "credentials",
    "312": "credentials", "522": "credentials", "256": "credentials",
    "359": "pii", "200": "pii",
}


def to_int(x, default: int = 1) -> int:
    """Coerce a line number to int (a hostile SARIF may carry ``"NaN"``); default on failure."""
    try:
        return int(x)
    except (TypeError, ValueError):
        return default


def parse_cwe(*candidates) -> str | None:
    """First ``CWE-<n>`` found across the candidates (SARIF taxa, tags, semgrep metadata)."""
    for c in candidates:
        for item in (c if isinstance(c, (list, tuple)) else [c]):
            if item is None:
                continue
            m = _CWE_RE.search(str(item))
            if m:
                return f"CWE-{int(m.group(1))}"
    return None


def cwe_layers(cwe: str | None) -> tuple[str, ...]:
    if not cwe:
        return ()
    m = _CWE_RE.search(cwe)
    layer = _CWE_LAYER.get(m.group(1)) if m else None
    return (layer,) if layer else ()


def severity_of(level: str | None, security_severity=None) -> str:
    base = _SARIF_SEV.get((level or "warning").lower(), "medium")
    try:
        s = float(security_severity)
        css = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
        return max(base, css, key=lambda x: _SEV_RANK[x])
    except (TypeError, ValueError):
        return base


def confidence_of(precision: str | None, fallback: str | None = None) -> str:
    return _PRECISION.get((precision or "").lower()) or _PRECISION.get((fallback or "").lower()) or "medium"


def _strip_scheme(uri: str) -> str:
    u = unquote(uri)
    if u.startswith("file://"):
        u = u[len("file://"):]
        if u.startswith("/") and re.match(r"/[A-Za-z]:", u):   # file:///C:/... -> C:/...
            u = u[1:]
    return u.replace("\\", "/")


def _resolve_base(uri_base_id: str | None, bases: dict) -> str:
    """Follow the ``originalUriBaseIds`` chain to a concrete prefix (bases may nest)."""
    parts: list[str] = []
    cur, seen = uri_base_id, set()
    while cur and cur in bases and cur not in seen:
        seen.add(cur)
        b = bases[cur]
        parts.append(_strip_scheme(b.get("uri", "")))
        cur = b.get("uriBaseId")
    return posixpath.join(*reversed(parts)) if parts else ""


def normalize_path(uri: str, uri_base_id, bases: dict, root: Path, known: set[str]) -> tuple[str | None, str]:
    """(rel_posix, reason) for a SARIF/semgrep artifact URI relative to ``root``, or (None, reason)."""
    if not uri:
        return None, "no-uri"
    u = _strip_scheme(uri)
    base = _resolve_base(uri_base_id, bases)
    if base and not posixpath.isabs(u):
        u = posixpath.join(base, u)
    u = posixpath.normpath(u)

    cand: str | None = None
    if posixpath.isabs(u) or re.match(r"[A-Za-z]:/", u):        # absolute (incl. Windows drive)
        try:
            rel = Path(u).resolve().relative_to(root.resolve())
            cand = rel.as_posix()
        except (ValueError, OSError):
            cand = None
    elif (root / u).exists():                                  # relative & present
        cand = u

    if cand is None:                                           # suffix-rescue against known files
        cand = _suffix_rescue(u, known)
    if cand is None:
        return None, "unmatched"
    try:                              # root clamp: a real path boundary (not a string prefix, so a
        resolved = (root / cand).resolve()                     # prefix-sibling `../proj-evil` can't slip
        cand = resolved.relative_to(root.resolve()).as_posix()  # through), re-derived so no `..` survives
    except (ValueError, OSError):
        return None, "escapes-root"
    return cand, "ok"


def _suffix_rescue(u: str, known: set[str]) -> str | None:
    """Unique whole-segment trailing-suffix match (handles a SARIF made from a different cwd)."""
    segs = [s for s in u.split("/") if s and s != "."]
    for i in range(len(segs)):
        suffix = "/".join(segs[i:])
        hits = [k for k in known if k == suffix or k.endswith("/" + suffix)]
        if len(hits) == 1:
            return hits[0]
    return None


def build_finding(raw: dict, root: Path) -> dict:
    """Turn a parser's raw finding into the normalized finding dict (§8.2 + additive fields).
    ``raw`` carries: rule_id, sink_id, source_id, source/sink file+line, hops[], cwe, severity,
    confidence, message, tool, provenance[]; paths already normalized by the caller."""
    src_file, sink_file = raw["source_file"], raw["sink_file"]
    cwe = raw.get("cwe")
    layers = tuple(sorted({"untrusted-input", "dangerous-sink", *cwe_layers(cwe)}))
    files = list(dict.fromkeys([src_file, sink_file, *(h["file"] for h in raw.get("hops", []))]))
    provenance = list(raw.get("provenance", []))
    # line-drift: the tool's matched snippet must agree with the disk line, else flag + cap confidence
    conf = raw.get("confidence", "medium")
    snippet = raw.get("sink_snippet")
    disk = _read_slice(root, sink_file, raw["sink_line"])
    if snippet and disk and snippet.split("\n", 1)[0].strip() not in disk and disk not in snippet:
        provenance.append("ingest:line-drift")
        conf = "low"
    return {
        "function": raw.get("function", ""),
        "source_id": raw.get("source_id") or raw["sink_id"],
        "source_file": src_file, "source_line": raw["source_line"],
        "sink_id": raw["sink_id"], "sink_file": sink_file, "sink_line": raw["sink_line"],
        "sink_function": raw.get("sink_function", ""),
        "rule_id": raw["rule_id"], "cwe": cwe, "severity": raw.get("severity", "medium"),
        "layers": list(layers), "confidence": conf, "message": (raw.get("message") or "")[:500],
        "trace": list(raw.get("trace", [])), "hops": list(raw.get("hops", [])),
        "guards": [], "unguarded": False, "guard_status": "unknown",   # Phase 10 fills these
        "provenance": provenance,
        "source_slice": _read_slice(root, src_file, raw["source_line"]),
        "sink_slice": disk,
        "file_hashes": {f: _file_hash(root, f) for f in files},
    }
