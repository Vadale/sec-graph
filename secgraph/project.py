"""Projection: join taint results to graphify nodes by (source_file, start_line),
emit taint.json (fine-grained) + annotate graph.json (coarse). See ROADMAP.md 8.

Sidecar discipline: statement-level facts go ONLY to taint.json, never into
graphify's pipeline. Annotate graph.json by post-processing the dict, not via to_json.
"""
from __future__ import annotations
