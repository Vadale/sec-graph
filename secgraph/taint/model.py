"""Taint origins, function summaries, and findings for the taint pass."""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional

from ..ir.model import Span


@dataclass(frozen=True, slots=True)
class Origin:
    """A source that tainted a value. ``param_index`` marks a *synthetic* param seed used
    to compute summaries (real sources have ``None``); ``source_file`` is where the source
    was minted (needed once a source surfaces in another function's file)."""

    source_id: str
    layers: tuple[str, ...]
    span: Span
    confidence: str = "high"
    param_index: Optional[int] = None
    source_file: Optional[str] = None


@dataclass(frozen=True, slots=True)
class SinkPoint:
    """A sink reachable inside a function (possibly transitively via ``via``)."""

    sink_id: str
    cwe: Optional[str]
    severity: str
    layers: tuple[str, ...]
    confidence: str
    file: str
    function: str
    line: int
    via: tuple[str, ...] = ()
    guards: tuple[str, ...] = ()   # auth barriers dominating this sink on the path (empty = unguarded)


@dataclass(frozen=True, slots=True)
class Summary:
    """Conditional interprocedural summary of one function.

    ``return_params``: taint(param i) at entry => the return is tainted.
    ``return_origins``: real source origins that reach the return unconditionally.
    ``sink_params``: taint(param i) at entry => it reaches this SinkPoint.
    """

    return_params: frozenset          # frozenset[int]
    return_origins: frozenset         # frozenset[Origin]
    sink_params: frozenset            # frozenset[tuple[int, SinkPoint]]


EMPTY_SUMMARY = Summary(frozenset(), frozenset(), frozenset())


@dataclass(frozen=True, slots=True)
class Finding:
    """A source->sink flow (intra or cross-function). Confidence + provenance ride along."""

    function: str
    source_file: str
    source_id: str
    source_line: int
    sink_id: str
    sink_line: int
    cwe: Optional[str]
    severity: str
    layers: tuple[str, ...]
    confidence: str
    sink_file: str = ""
    sink_function: str = ""
    trace: tuple[str, ...] = ()
    guards: tuple[str, ...] = ()   # auth barriers on the path; empty => an UNGUARDED sink

    @property
    def key(self) -> tuple:
        # guards are deliberately excluded: two path variants with the same source->sink but
        # different guards share a key and merge by guard INTERSECTION (guarded only if every
        # observed path is guarded -- the sound direction for the unguarded claim).
        return (
            self.source_file, self.function, self.source_id, self.source_line,
            self.sink_id, self.sink_line, self.sink_file,
        )


def merge_finding(findings: dict, f: Finding) -> None:
    """Insert ``f`` under ``f.key`` into ``findings``; if a variant with the same key is already
    present, keep the guard INTERSECTION (see ``Finding.key``: a sink counts as guarded only if
    EVERY observed path guards it -- the sound direction for the unguarded claim; a keep-first
    merge would freeze an early guarded verdict over a later unguarded one). Shared by the intra
    scan (``engine``) and the interprocedural fixpoint driver (``interproc``)."""
    old = findings.get(f.key)
    if old is None:
        findings[f.key] = f
    elif old.guards != f.guards:
        findings[f.key] = replace(old, guards=tuple(sorted(set(old.guards) & set(f.guards))))
