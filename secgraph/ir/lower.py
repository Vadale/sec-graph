"""Lower a Python tree-sitter CST into sec-graph's IR (``secgraph.ir.model``).

Deterministic and graphify-free. We re-parse the source ourselves (the grammar wheels
come from graphify's pinned deps) because graphify's graph is entity-level and carries
only start lines; the taint engine needs statement/variable granularity and full spans.

Scope (ROADMAP Phase 1): functions (incl. decorated and methods), assignments (single,
chained ``a = b = x``, augmented), calls, attribute/subscript access, walrus ``:=``,
returns, and if/while/for control flow -- with correct break/continue edges.

Known Phase-1 limitations (tracked as Phase-2 blockers in HANDOFF, must close before/with
the taint pass):
  * ``with`` / ``try`` / ``match`` bodies are NOT lowered yet: the whole statement becomes
    an ``Unsupported`` node that surfaces header reads only -- **in-block defs and returns
    are dropped** (a false-negative source). Very common in the SQLi target scenario
    (``with conn.cursor() as c: c.execute(q)``), so this is the first Phase-2 fix.
  * Attribute/subscript assignment targets (``self.x = t``, ``d[k] = t``) yield no def --
    the field-sensitive (k=1) def belongs to the Phase-2 taint model (the AccessPath model
    already supports it).
Extend here, never in the engine.
"""
from __future__ import annotations

import itertools
from pathlib import Path
from typing import Iterator, Optional

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from .model import (
    Assign,
    Attr,
    BinOp,
    Call,
    Expr,
    ExprStmt,
    For,
    FunctionIR,
    If,
    Index,
    Literal,
    ModuleIR,
    Name,
    Return,
    Span,
    Stmt,
    Unknown,
    Unsupported,
    Walrus,
    While,
)

_PY_LANGUAGE = Language(tspython.language())

_LITERAL_TYPES = {
    "string", "concatenated_string", "integer", "float", "true", "false", "none",
    "ellipsis", "complex",
}
_BINARY_TYPES = {"binary_operator", "boolean_operator", "comparison_operator"}
_SCOPE_STMT_TYPES = {"function_definition", "decorated_definition", "class_definition"}
_TRIVIAL_STMT_TYPES = {
    "pass_statement", "break_statement", "continue_statement", "import_statement",
    "import_from_statement", "global_statement", "nonlocal_statement", "future_import_statement",
}
# children that hold deferred statement bodies (with/try/match); not lowered in Phase 1
_BLOCK_CONTAINER_TYPES = {
    "block", "elif_clause", "else_clause", "except_clause", "except_group_clause",
    "finally_clause", "case_clause",
}


def _parser() -> Parser:
    try:
        return Parser(_PY_LANGUAGE)
    except TypeError:  # older binding: assign after construction
        p = Parser()
        p.language = _PY_LANGUAGE
        return p


def _text(node) -> str:
    return node.text.decode("utf8", "replace")


def _named_stmts(block) -> list:
    return [c for c in block.named_children if c.type != "comment"]


# ---- expressions -----------------------------------------------------------------

def _lower_expr(node) -> Expr:
    t = node.type
    span = Span.of(node)
    if t == "identifier":
        return Name(_text(node), span)
    if t in _LITERAL_TYPES:
        return Literal(span)
    if t == "parenthesized_expression":
        inner = node.named_children
        return _lower_expr(inner[0]) if inner else Unknown(t, [], span)
    if t == "named_expression":  # walrus: target := value
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        return Walrus(
            _text(name) if name is not None else "",
            _lower_expr(value) if value is not None else Unknown("walrus", [], span),
            span,
        )
    if t == "attribute":
        obj = node.child_by_field_name("object")
        attr = node.child_by_field_name("attribute")
        return Attr(_lower_expr(obj), _text(attr) if attr is not None else "", span)
    if t == "subscript":
        value = node.child_by_field_name("value")
        idx = node.child_by_field_name("subscript")
        return Index(_lower_expr(value), _lower_expr(idx) if idx is not None else None, span)
    if t == "call":
        func = node.child_by_field_name("function")
        arglist = node.child_by_field_name("arguments")
        return Call(_lower_expr(func), _lower_args(arglist), span)
    if t in _BINARY_TYPES:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        op = node.child_by_field_name("operator")
        if left is not None and right is not None:
            return BinOp(_lower_expr(left), _lower_expr(right), _text(op) if op is not None else "", span)
        # comparison_operator has no left/right fields: keep operands as children so
        # their variable reads are still collected.
        return Unknown(t, [_lower_expr(c) for c in node.named_children], span)
    # everything else: keep children so nested names/calls/walrus are not lost
    return Unknown(t, [_lower_expr(c) for c in node.named_children], span)


def _lower_args(arglist) -> list[Expr]:
    if arglist is None:
        return []
    out: list[Expr] = []
    for c in arglist.named_children:
        if c.type == "comment":
            continue
        if c.type == "keyword_argument":
            v = c.child_by_field_name("value")
            out.append(_lower_expr(v) if v is not None else Unknown(c.type, [], Span.of(c)))
        elif c.type in ("list_splat", "dictionary_splat"):
            inner = c.named_children
            out.append(_lower_expr(inner[0]) if inner else Unknown(c.type, [], Span.of(c)))
        else:
            out.append(_lower_expr(c))
    return out


# ---- statements (each lowers to zero or more IR statements) -----------------------

def _identifier_targets(node) -> list[str]:
    if node is None:
        return []
    if node.type == "identifier":
        return [_text(node)]
    if node.type in ("pattern_list", "tuple_pattern", "tuple", "list_pattern", "list"):
        out: list[str] = []
        for c in node.named_children:
            out += _identifier_targets(c)
        return out
    return []  # attribute/subscript targets: no clean variable def in Phase 1


def _lower_block(block, sid: Iterator[int]) -> list[Stmt]:
    out: list[Stmt] = []
    for c in _named_stmts(block):
        out.extend(_lower_stmt(c, sid))
    return out


def _lower_alternative(node, sid: Iterator[int]) -> list[Stmt]:
    """Lower an if's `alternative` (elif_clause chain or else_clause) into an orelse body."""
    if node is None:
        return []
    if node.type == "else_clause":
        body = node.child_by_field_name("body")
        return _lower_block(body, sid) if body is not None else []
    if node.type == "elif_clause":
        cond = node.child_by_field_name("condition")
        cons = node.child_by_field_name("consequence")
        alt = node.child_by_field_name("alternative")
        return [
            If(
                next(sid),
                _lower_expr(cond) if cond is not None else Unknown("cond", [], Span.of(node)),
                _lower_block(cons, sid) if cons is not None else [],
                _lower_alternative(alt, sid),
                Span.of(node),
            )
        ]
    return []


def _lower_stmt(node, sid: Iterator[int]) -> list[Stmt]:
    t = node.type
    span = Span.of(node)

    if t == "expression_statement":
        inner = [c for c in node.named_children if c.type != "comment"]
        if not inner:
            return []
        child = inner[0]
        if child.type == "assignment":
            # unwrap chained assignment a = b = expr -> targets [a, b], value expr
            targets: list[str] = []
            cur = child
            while cur is not None and cur.type == "assignment":
                targets += _identifier_targets(cur.child_by_field_name("left"))
                cur = cur.child_by_field_name("right")
            value = _lower_expr(cur) if cur is not None else Unknown("empty", [], span)
            return [Assign(next(sid), targets, value, span)]
        if child.type == "augmented_assignment":
            left = child.child_by_field_name("left")
            right = child.child_by_field_name("right")
            children = [_lower_expr(left)] if left is not None else []
            if right is not None:
                children.append(_lower_expr(right))
            return [Assign(next(sid), _identifier_targets(left), Unknown("augmented", children, span), span)]
        return [ExprStmt(next(sid), _lower_expr(child), span)]

    if t == "return_statement":
        vals = [c for c in node.named_children if c.type != "comment"]
        return [Return(next(sid), _lower_expr(vals[0]) if vals else None, span)]

    if t == "if_statement":
        cond = node.child_by_field_name("condition")
        cons = node.child_by_field_name("consequence")
        alt = node.child_by_field_name("alternative")
        return [
            If(
                next(sid),
                _lower_expr(cond) if cond is not None else Unknown("cond", [], span),
                _lower_block(cons, sid) if cons is not None else [],
                _lower_alternative(alt, sid),
                span,
            )
        ]

    if t == "while_statement":
        cond = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        return [
            While(
                next(sid),
                _lower_expr(cond) if cond is not None else Unknown("cond", [], span),
                _lower_block(body, sid) if body is not None else [],
                span,
            )
        ]

    if t == "for_statement":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        body = node.child_by_field_name("body")
        return [
            For(
                next(sid),
                _identifier_targets(left),
                _lower_expr(right) if right is not None else Unknown("iter", [], span),
                _lower_block(body, sid) if body is not None else [],
                span,
            )
        ]

    if t in _SCOPE_STMT_TYPES:
        # a nested def/class is its own scope; collected separately as its own FunctionIR
        return [Unsupported(next(sid), t, [], span)]

    if t in _TRIVIAL_STMT_TYPES:
        return [Unsupported(next(sid), t, [], span)]

    # with/try/match/raise/assert/delete/...: keep, surface reads from non-block children
    # only (do NOT lower a block as an expression). In-block defs/returns are deferred
    # to Phase 2 -- see the module docstring.
    uses = [_lower_expr(c) for c in node.named_children if c.type not in _BLOCK_CONTAINER_TYPES]
    return [Unsupported(next(sid), t, uses, span)]


# ---- functions and modules -------------------------------------------------------

def _param_names(parameters) -> list[str]:
    if parameters is None:
        return []
    out: list[str] = []
    for c in parameters.named_children:
        if c.type == "identifier":
            out.append(_text(c))
            continue
        name = c.child_by_field_name("name")
        if name is not None and name.type == "identifier":
            out.append(_text(name))
            continue
        ident = next((d for d in c.named_children if d.type == "identifier"), None)
        if ident is not None:
            out.append(_text(ident))
    return out


def _iter_function_defs(node) -> Iterator:
    if node.type == "function_definition":
        yield node
    for c in node.children:
        yield from _iter_function_defs(c)


def _lower_function(fn, source_file: str) -> FunctionIR:
    name_node = fn.child_by_field_name("name")
    params = _param_names(fn.child_by_field_name("parameters"))
    body_node = fn.child_by_field_name("body")
    sid = itertools.count()
    body = _lower_block(body_node, sid) if body_node is not None else []
    return FunctionIR(
        name=_text(name_node) if name_node is not None else "<anonymous>",
        params=params,
        body=body,
        span=Span.of(fn),
        source_file=source_file,
    )


def lower_source(src: bytes, source_file: str) -> ModuleIR:
    """Lower one Python source buffer into a ``ModuleIR`` (functions only, for now)."""
    tree = _parser().parse(src)
    functions = [_lower_function(fn, source_file) for fn in _iter_function_defs(tree.root_node)]
    return ModuleIR(source_file=source_file, functions=functions)


def lower_file(path: Path | str, source_file: Optional[str] = None) -> ModuleIR:
    """Lower a Python file. ``source_file`` is the relative name to stamp (for the join);
    defaults to the path's name."""
    path = Path(path)
    rel = source_file if source_file is not None else path.name
    return lower_source(path.read_bytes(), rel)
