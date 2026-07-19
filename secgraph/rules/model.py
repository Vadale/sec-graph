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


@dataclass(frozen=True, slots=True)
class LabelRule:
    """Identifier dictionary for one sensitive-data layer (credentials/pii). ``identifiers`` are
    matched word-based (token-run, not substring) so ``tokenizer`` never lights up ``token``."""

    layer: str
    identifiers: tuple[str, ...]
    confidence: str = "medium"


@dataclass(frozen=True, slots=True)
class SecretPattern:
    id: str
    regex: str                             # matched against a string literal's content
    layers: tuple[str, ...]
    confidence: str = "high"
    validator: Optional[str] = None        # e.g. "luhn" for credit cards


@dataclass(frozen=True, slots=True)
class SecretConfig:
    """Secret-literal detection: named formats first, entropy fallback charset-gated."""

    patterns: tuple[SecretPattern, ...] = ()
    deny_values: tuple[str, ...] = ()      # placeholder regexes (changeme, <...>, ${...})
    test_path_globs: tuple[str, ...] = ()  # confidence -> low under these (detect, never hide)
    min_length: int = 16
    max_length: int = 512
    base64_threshold: float = 4.5
    hex_threshold: float = 3.0
    confidence: str = "medium"             # entropy-fallback confidence


@dataclass(frozen=True, slots=True)
class BarrierRule:
    """Auth-barrier vocabulary for unguarded-sink detection: guard decorators, guard callables,
    auth-test attributes (``current_user.is_admin``), and terminating aborts (``abort(403)``)."""

    decorators: tuple[str, ...] = ()
    callables: tuple[str, ...] = ()
    test_attrs: tuple[str, ...] = ()
    aborts: tuple[str, ...] = ()


@dataclass(slots=True)
class Rules:
    """Aggregated rules from one or more packs."""

    sources: list[SourceRule] = field(default_factory=list)
    sinks: list[SinkRule] = field(default_factory=list)
    sanitizers: list[SanitizerRule] = field(default_factory=list)
    propagators: list[PropagatorRule] = field(default_factory=list)
    labels: dict[str, LabelRule] = field(default_factory=dict)   # layer -> identifier dict
    secrets: Optional[SecretConfig] = None
    barriers: BarrierRule = field(default_factory=BarrierRule)

    def extend(self, other: "Rules") -> "Rules":
        self.sources.extend(other.sources)
        self.sinks.extend(other.sinks)
        self.sanitizers.extend(other.sanitizers)
        self.propagators.extend(other.propagators)
        self.labels.update(other.labels)
        if other.secrets is not None:
            self.secrets = other.secrets
        u = lambda a, b: tuple(dict.fromkeys(a + b))   # union, order-preserving  # noqa: E731
        self.barriers = BarrierRule(
            u(self.barriers.decorators, other.barriers.decorators),
            u(self.barriers.callables, other.barriers.callables),
            u(self.barriers.test_attrs, other.barriers.test_attrs),
            u(self.barriers.aborts, other.barriers.aborts),
        )
        return self
