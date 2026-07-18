"""Join IR functions to graphify entity nodes by ``(source_file, start_line)``.

ADR-002 / docs/pitfalls.md #9: never recompute graphify's node ids (they migrate across
versions) -- match on the structural key both sides derive from the *same* tree-sitter
``function_definition``. graphify function nodes are ``file_type == "code"``, labelled
``name()``, with ``source_location == "L{n}"``.

Pure: takes graphify's node dicts (fetched by a caller through the quarantine-wall
adapter) and mutates ``FunctionIR.graphify_node``. No graphify import here.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from .model import FunctionIR, ModuleIR

_LINE = re.compile(r"^L(\d+)$")


def _function_index(graphify_nodes: Iterable[dict[str, Any]]) -> dict[tuple[str, int], str]:
    index: dict[tuple[str, int], str] = {}
    for node in graphify_nodes:
        if node.get("file_type") != "code":
            continue
        label = str(node.get("label", ""))
        if not label.endswith("()"):
            continue
        m = _LINE.match(str(node.get("source_location", "")))
        if m is None:
            continue
        key = (node.get("source_file"), int(m.group(1)))
        index.setdefault(key, node["id"])  # (file, line) is unique per function
    return index


def join_functions(
    functions: Iterable[FunctionIR], graphify_nodes: Iterable[dict[str, Any]]
) -> tuple[int, int]:
    """Fill ``graphify_node`` on each function. Returns ``(matched, unmatched)``."""
    index = _function_index(graphify_nodes)
    matched = unmatched = 0
    for fn in functions:
        node_id = index.get((fn.source_file, fn.span.start_line))
        fn.graphify_node = node_id
        if node_id is None:
            unmatched += 1
        else:
            matched += 1
    return matched, unmatched


def join_modules(
    modules: Iterable[ModuleIR], graphify_nodes: Iterable[dict[str, Any]]
) -> tuple[int, int]:
    nodes = list(graphify_nodes)
    matched = unmatched = 0
    for module in modules:
        m, u = join_functions(module.functions, nodes)
        matched += m
        unmatched += u
    return matched, unmatched
