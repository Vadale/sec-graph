"""Call-site resolution: bind each Call to a project function (for interprocedural taint)
and measure the binding rate (the Phase-3 KILL-GATE). Pure IR + rules; no graphify.
"""
from __future__ import annotations

from .resolve import (
    Binding,
    FnIndex,
    FnKey,
    binding_rate,
    build_index,
    resolve_all_sites,
    site_key,
    trr,
)

__all__ = [
    "Binding",
    "FnIndex",
    "FnKey",
    "build_index",
    "resolve_all_sites",
    "binding_rate",
    "trr",
    "site_key",
]
