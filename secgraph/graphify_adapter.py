"""The quarantine wall: the ONLY module allowed to import graphify.

Every ``graphify.*`` import in sec-graph lives here (see docs/pitfalls.md and
DECISIONS.md ADR-002). The taint core depends on this adapter's plain-data return
types, never on graphify internals. Pinned to graphifyy==0.9.6.

WP0 / Phase 0: wrap graphify.detect / extract / build_from_json here and add the
contract test in tests/contract. See ROADMAP.md Section 9.
"""
from __future__ import annotations
