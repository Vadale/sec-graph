"""Load the declarative YAML rule packs into a ``Rules`` aggregate.

Lightweight validation (pyyaml only): required keys are checked; unknown keys are
ignored so packs can carry ``metadata``. See ROADMAP.md Section 10.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import yaml

from .model import PropagatorRule, Rules, SanitizerRule, SinkRule, SourceRule


def _tup(x: Any) -> tuple:
    if x is None:
        return ()
    if isinstance(x, (list, tuple)):
        return tuple(x)
    return (x,)


def _req(d: dict, key: str, ctx: str) -> Any:
    if key not in d or d[key] is None:
        raise ValueError(f"{ctx}: rule missing required key '{key}'")
    return d[key]


def _source(d: dict, ctx: str) -> SourceRule:
    return SourceRule(
        id=_req(d, "id", ctx),
        kind=_req(d, "kind", ctx),
        layers=_tup(_req(d, "layers", ctx)),
        base=d.get("base"),
        attributes=_tup(d.get("attributes")),
        callee=_tup(d.get("callee")),
        confidence=d.get("confidence", "high"),
        cwe=d.get("cwe"),
    )


def _sink(d: dict, ctx: str) -> SinkRule:
    return SinkRule(
        id=_req(d, "id", ctx),
        kind=_req(d, "kind", ctx),
        callee=_tup(_req(d, "callee", ctx)),
        taint_args=tuple(int(i) for i in _tup(d.get("taint_args", [0]))),
        layers=_tup(_req(d, "layers", ctx)),
        fqn_hint=_tup(d.get("fqn_hint")),
        cwe=d.get("cwe"),
        severity=d.get("severity", "medium"),
        confidence=d.get("confidence", "high"),
    )


def _sanitizer(d: dict, ctx: str) -> SanitizerRule:
    return SanitizerRule(
        id=_req(d, "id", ctx),
        kind=_req(d, "kind", ctx),
        callee=_tup(_req(d, "callee", ctx)),
        clears=d.get("clears", "return"),
        applies_to_layers=_tup(d.get("applies_to_layers")),
    )


def _propagator(d: dict, ctx: str) -> PropagatorRule:
    return PropagatorRule(
        id=_req(d, "id", ctx),
        kind=_req(d, "kind", ctx),
        callee=_tup(_req(d, "callee", ctx)),
        from_args=_tup(d.get("from_args", ["any"])) or ("any",),
        to=d.get("to", "return"),
    )


def load_rule_file(path: Path | str) -> Rules:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    ctx = path.name
    rules = Rules()
    rules.sources = [_source(d, ctx) for d in (data.get("sources") or [])]
    rules.sinks = [_sink(d, ctx) for d in (data.get("sinks") or [])]
    rules.sanitizers = [_sanitizer(d, ctx) for d in (data.get("sanitizers") or [])]
    rules.propagators = [_propagator(d, ctx) for d in (data.get("propagators") or [])]
    return rules


def _expand(source: Path | str) -> list[Path]:
    p = Path(source)
    if p.is_dir():
        return sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")])
    return [p]


def load_rules(source: Path | str | Iterable[Path | str]) -> Rules:
    """Load rules from a file, a directory (all ``*.yml`` under it), or a list of those."""
    paths: list[Path] = []
    if isinstance(source, (list, tuple)):
        for s in source:
            paths.extend(_expand(s))
    else:
        paths.extend(_expand(source))

    rules = Rules()
    for p in sorted(set(paths)):
        rules.extend(load_rule_file(p))
    return rules


def default_rules_dir() -> Path:
    """The repo-root ``rules/`` directory (packaged rule data lives there in dev).

    NOTE: for a wheel release (Phase 8) this must become importlib package data; today it
    resolves relative to the source tree, which is correct for the editable dev install.
    """
    return Path(__file__).resolve().parents[2] / "rules"
