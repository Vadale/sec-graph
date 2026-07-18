"""Declarative source/sink/sanitizer rules for the taint engine.

Load a pack directory into a ``Rules`` aggregate and match IR expressions against it.
See ROADMAP.md Section 10. No graphify here.
"""
from __future__ import annotations

from .loader import default_rules_dir, load_rule_file, load_rules
from .match import (
    match_propagator,
    match_sanitizer,
    match_sink,
    match_source,
    resolve_fqn,
)
from .model import (
    PropagatorRule,
    Rules,
    SanitizerRule,
    SinkRule,
    SourceRule,
)

__all__ = [
    "load_rules",
    "load_rule_file",
    "default_rules_dir",
    "resolve_fqn",
    "match_source",
    "match_sink",
    "match_sanitizer",
    "match_propagator",
    "Rules",
    "SourceRule",
    "SinkRule",
    "SanitizerRule",
    "PropagatorRule",
]
