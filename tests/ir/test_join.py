"""Join test: every IR function maps to its graphify node by (source_file, start_line).

Uses the quarantine-wall adapter to fetch graphify's nodes (the IR itself never imports
graphify) and passes them to the pure join.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from secgraph import graphify_adapter as gx
from secgraph import ir

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "tiny"


def test_all_fixture_functions_join_to_graphify() -> None:
    try:
        modules = ir.build_project_ir(FIX)
        detected = gx.detect_files(FIX)
        extraction = gx.extract_entities(gx.collect_code_files(detected), cache_root=FIX)
        matched, unmatched = ir.join_modules(modules, extraction["nodes"])

        assert (matched, unmatched) == (2, 0)  # 100% of fixture functions joined
        resolved = {
            (m.source_file, fn.name): fn.graphify_node
            for m in modules
            for fn in m.functions
        }
        assert resolved[("app.py", "get_user")] == "app_get_user"
        assert resolved[("db.py", "run_query")] == "db_run_query"
    finally:
        shutil.rmtree(FIX / "graphify-out", ignore_errors=True)  # graphify AST cache
