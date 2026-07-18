"""Taint origins and findings produced by the intraprocedural taint pass."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..ir.model import Span


@dataclass(frozen=True, slots=True)
class Origin:
    """A source that tainted a value: which rule fired, its layers, where, how sure."""

    source_id: str
    layers: tuple[str, ...]
    span: Span
    confidence: str = "high"


@dataclass(frozen=True, slots=True)
class Finding:
    """A source->sink flow found within one function (confidence + provenance ride along)."""

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

    @property
    def key(self) -> tuple:
        return (
            self.source_file, self.function, self.source_id, self.source_line,
            self.sink_id, self.sink_line,
        )
