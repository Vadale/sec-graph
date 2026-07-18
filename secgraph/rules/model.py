"""Typed model for the declarative YAML rule packs in the top-level ``rules/`` dir.

See ROADMAP.md Section 10. Rules are matched against the IR by resolved FQN + call shape
(``secgraph.rules.match``), not by regex over source text.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True, slots=True)
class SourceRule:
    id: str
    kind: str                              # attribute-read | subscript-read | call | parameter
    layers: tuple[str, ...]
    base: Optional[str] = None             # FQN of the base object (attribute-read)
    attributes: tuple[str, ...] = ()
    callee: tuple[str, ...] = ()           # for kind == call (e.g. os.getenv)
    confidence: str = "high"
    cwe: Optional[str] = None


@dataclass(frozen=True, slots=True)
class SinkRule:
    id: str
    kind: str                              # call
    callee: tuple[str, ...]                # ".execute" (method name) or "os.system" (FQN)
    taint_args: tuple[int, ...]
    layers: tuple[str, ...]
    fqn_hint: tuple[str, ...] = ()
    cwe: Optional[str] = None
    severity: str = "medium"
    confidence: str = "high"


@dataclass(frozen=True, slots=True)
class SanitizerRule:
    id: str
    kind: str                              # call
    callee: tuple[str, ...]
    clears: str = "return"
    applies_to_layers: tuple[str, ...] = ()  # empty = clears every layer


@dataclass(frozen=True, slots=True)
class PropagatorRule:
    id: str
    kind: str                              # call
    callee: tuple[str, ...]
    from_args: tuple[Any, ...] = ("any",)  # "any" or explicit arg indices
    to: str = "return"


@dataclass(slots=True)
class Rules:
    """Aggregated rules from one or more packs."""

    sources: list[SourceRule] = field(default_factory=list)
    sinks: list[SinkRule] = field(default_factory=list)
    sanitizers: list[SanitizerRule] = field(default_factory=list)
    propagators: list[PropagatorRule] = field(default_factory=list)

    def extend(self, other: "Rules") -> "Rules":
        self.sources.extend(other.sources)
        self.sinks.extend(other.sinks)
        self.sanitizers.extend(other.sanitizers)
        self.propagators.extend(other.propagators)
        return self
