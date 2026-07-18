"""Lower a Python tree-sitter CST into sec-graph's IR (``secgraph.ir.model``).

Deterministic and graphify-free. We re-parse the source ourselves (the grammar wheels
come from graphify's pinned deps) because graphify's graph is entity-level and carries
only start lines; the taint engine needs statement/variable granularity and full spans.

Scope: functions (incl. decorated and methods), assignments (single, chained ``a = b = x``,
augmented), calls, attribute/subscript access, walrus ``:=``, returns, if/while/for control
flow (with correct break/continue edges), and with/try/match -- their bodies are lowered
(``with X as v`` becomes an alias def ``v = X``).

Over-approximations & known gaps:
  * try/except/else/finally and match are lowered as CFG alternatives that merge at a join
    (a ``Branch`` node): a variable reassigned in only one clause is unioned, not killed --
    sound for may-taint. Arms are treated as mutually-exclusive alternatives, so exception
    edges are approximate; match pattern captures are not yet bound as defs.
  * Attribute/subscript assignment targets (``self.x = t``, ``d[k] = t``) yield no def --
    Phase 2's taint engine is variable-keyed and does not yet propagate the k=1 AccessPath
    the model can represent, so flows through ``self.x`` are missed (a Phase-3 refinement).
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
    Branch,
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
        args, kw_names = _lower_args(node.child_by_field_name("arguments"))
        return Call(_lower_expr(func), args, span, kw_names)
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


def _lower_args(arglist) -> tuple[list[Expr], list[Optional[str]]]:
    """Return (arg exprs, parallel keyword names). A positional/splat arg has name None."""
    if arglist is None:
        return [], []
    args: list[Expr] = []
    names: list[Optional[str]] = []
    for c in arglist.named_children:
        if c.type == "comment":
            continue
        if c.type == "keyword_argument":
            name = c.child_by_field_name("name")
            v = c.child_by_field_name("value")
            args.append(_lower_expr(v) if v is not None else Unknown(c.type, [], Span.of(c)))
            names.append(_text(name) if name is not None else None)
        elif c.type in ("list_splat", "dictionary_splat"):
            inner = c.named_children
            args.append(_lower_expr(inner[0]) if inner else Unknown(c.type, [], Span.of(c)))
            names.append(None)
        else:
            args.append(_lower_expr(c))
            names.append(None)
    return args, names


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


def _lower_with_items(with_clause, sid: Iterator[int]) -> list[Stmt]:
    """`with X as v` -> `v = X` (alias def); `with X` -> an expr stmt using X."""
    out: list[Stmt] = []
    if with_clause is None:
        return out
    for item in with_clause.named_children:
        if item.type != "with_item":
            continue
        val = item.child_by_field_name("value")
        if val is None:
            kids = item.named_children
            val = kids[0] if kids else None
        if val is None:
            continue
        if val.type == "as_pattern":
            ctx = val.named_children[0] if val.named_children else None
            tgt = next((c for c in val.children if c.type == "as_pattern_target"), None)
            alias = None
            if tgt is not None:
                ai = next((d for d in tgt.named_children if d.type == "identifier"), None)
                alias = _text(ai) if ai is not None else None
            value_expr = _lower_expr(ctx) if ctx is not None else Unknown("with", [], Span.of(item))
            if alias:
                out.append(Assign(next(sid), [alias], value_expr, Span.of(item)))
            else:
                out.append(ExprStmt(next(sid), value_expr, Span.of(item)))
        else:
            out.append(ExprStmt(next(sid), _lower_expr(val), Span.of(item)))
    return out


def _clause_block(clause):
    return next((c for c in clause.children if c.type == "block"), None)


def _iter_case_clauses(match_node):
    for c in match_node.named_children:
        if c.type == "case_clause":
            yield c
        elif c.type == "block":  # match: block wrapping the case clauses
            for cc in c.named_children:
                if cc.type == "case_clause":
                    yield cc


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

    if t == "with_statement":
        clause = next((c for c in node.named_children if c.type == "with_clause"), None)
        out = _lower_with_items(clause, sid)
        body = node.child_by_field_name("body")
        if body is not None:
            out += _lower_block(body, sid)
        return out

    if t == "try_statement":
        # arms merge at a join (Branch), so a var reassigned in only one clause is unioned,
        # not sequentially killed. finally runs after the merge.
        bsid = next(sid)
        body = node.child_by_field_name("body")
        try_arm = _lower_block(body, sid) if body is not None else []
        handlers: list[list[Stmt]] = []
        final_body: list[Stmt] = []
        for clause in node.named_children:
            ct = clause.type
            if ct in ("except_clause", "except_group_clause"):
                blk = _clause_block(clause)
                handlers.append(_lower_block(blk, sid) if blk is not None else [])
            elif ct == "else_clause":
                blk = _clause_block(clause)
                try_arm += _lower_block(blk, sid) if blk is not None else []  # else runs on try success
            elif ct == "finally_clause":
                blk = _clause_block(clause)
                final_body = _lower_block(blk, sid) if blk is not None else []
        return [Branch(bsid, [try_arm, *handlers], span), *final_body]

    if t == "match_statement":
        out: list[Stmt] = []
        subject = node.child_by_field_name("subject")
        if subject is not None:
            out.append(ExprStmt(next(sid), _lower_expr(subject), span))
        bsid = next(sid)
        arms = [
            _lower_block(_clause_block(clause), sid) if _clause_block(clause) is not None else []
            for clause in _iter_case_clauses(node)
        ]
        out.append(Branch(bsid, arms, span))
        return out

    # raise/assert/delete/... : keep, surface reads from non-block children only (a block is
    # not an expression). These have no meaningful data-flow body to lower.
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


def _has_field_escape(fn_node) -> bool:
    """True if the function writes an attribute/subscript target (``self.x = ``, ``d[k] = ``) --
    an untracked channel, so an interprocedural summary through it must be over-approximated."""
    body = fn_node.child_by_field_name("body")
    if body is None:
        return False
    stack = list(body.children)
    while stack:
        n = stack.pop()
        if n.type in ("function_definition", "class_definition"):
            continue                        # a nested scope: its writes are its own
        if n.type in ("assignment", "augmented_assignment"):
            left = n.child_by_field_name("left")
            if left is not None and left.type in ("attribute", "subscript"):
                return True
        stack.extend(n.children)
    return False


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
        field_escape=_has_field_escape(fn),
    )


def _abs_module(module_node, source_file: str) -> str:
    """Resolve a ``from ... import`` module to an absolute dotted name, normalizing relative
    imports (``from .db import x`` in ``pkg/app.py`` -> ``pkg.db``) so the FQN index matches."""
    if module_node.type != "relative_import":
        return _text(module_node)
    text = _text(module_node)
    n_dots = len(text) - len(text.lstrip("."))
    rest = text[n_dots:]
    fqn = source_file[:-3] if source_file.endswith(".py") else source_file
    parts = [p for p in fqn.split("/") if p]
    if parts and parts[-1] == "__init__":
        parts.pop()                       # __init__ IS its package
    else:
        parts = parts[:-1]                # the package containing this module
    up = n_dots - 1
    base = parts[: len(parts) - up] if 0 <= up <= len(parts) else []
    base_fqn = ".".join(base)
    return f"{base_fqn}.{rest}" if rest else base_fqn


def _module_imports(root, source_file: str) -> dict[str, str]:
    """Top-level ``import`` / ``from ... import`` bindings: local name -> FQN.

    Lets the rule matcher resolve ``request`` -> ``flask.request``, ``os`` -> ``os`` etc.
    ``import a.b`` binds the top name ``a``; ``import x as y`` and ``from m import n as y``
    bind the alias.
    """
    imap: dict[str, str] = {}

    def visit(node) -> None:
        if node.type == "import_statement":
            for c in node.named_children:
                if c.type == "dotted_name":
                    top = _text(c).split(".", 1)[0]
                    imap[top] = top
                elif c.type == "aliased_import":
                    name = c.child_by_field_name("name")
                    alias = c.child_by_field_name("alias")
                    if name is not None and alias is not None:
                        imap[_text(alias)] = _text(name)
        elif node.type == "import_from_statement":
            kids = node.named_children
            if kids:
                module = _abs_module(kids[0], source_file) if kids[0].type in ("dotted_name", "relative_import") else ""
                for c in kids[1:]:
                    if c.type == "dotted_name":
                        local = _text(c).split(".", 1)[0]
                        imap[local] = f"{module}.{_text(c)}" if module else _text(c)
                    elif c.type == "aliased_import":
                        name = c.child_by_field_name("name")
                        alias = c.child_by_field_name("alias")
                        if name is not None and alias is not None:
                            imap[_text(alias)] = f"{module}.{_text(name)}" if module else _text(name)
        for c in node.children:
            visit(c)

    visit(root)
    return imap


def _resolve_callee_fqn(node, imap: dict[str, str]) -> Optional[str]:
    """Resolve a call's callee (identifier / attribute chain) to an FQN via the import map."""
    if node is None:
        return None
    if node.type == "identifier":
        n = _text(node)
        return imap.get(n, n)
    if node.type == "attribute":
        obj = node.child_by_field_name("object")
        attr = node.child_by_field_name("attribute")
        base = _resolve_callee_fqn(obj, imap)
        return f"{base}.{_text(attr)}" if base is not None and attr is not None else None
    return None


def _module_globals(root, imap: dict[str, str]) -> dict[str, Optional[str]]:
    """Module-level ``name = SomeCall(...)`` -> the callee's FQN (or None). Lets the resolver
    tell a project singleton (`store = Store()`) from a library object (`db = SQLAlchemy()`)."""
    globs: dict[str, Optional[str]] = {}
    for node in root.children:
        if node.type != "expression_statement":
            continue
        inner = [c for c in node.named_children if c.type != "comment"]
        if inner and inner[0].type == "assignment":
            a = inner[0]
            left = a.child_by_field_name("left")
            right = a.child_by_field_name("right")
            if left is not None and left.type == "identifier" and right is not None and right.type == "call":
                globs[_text(left)] = _resolve_callee_fqn(right.child_by_field_name("function"), imap)
    return globs


def _class_infos(root, imap: dict[str, str]) -> dict[str, list[str]]:
    """Class name -> resolved base-class FQNs (for constructor binding + method MRO)."""
    infos: dict[str, list[str]] = {}

    def visit(n) -> None:
        if n.type == "class_definition":
            name = n.child_by_field_name("name")
            supers = n.child_by_field_name("superclasses")
            bases: list[str] = []
            if supers is not None:
                for c in supers.named_children:
                    if c.type in ("identifier", "attribute"):
                        fqn = _resolve_callee_fqn(c, imap)
                        if fqn:
                            bases.append(fqn)
            if name is not None:
                infos.setdefault(_text(name), bases)
        for c in n.children:
            visit(c)

    visit(root)
    return infos


def _class_spans(root) -> list[tuple[str, Span]]:
    out: list[tuple[str, Span]] = []

    def visit(n) -> None:
        if n.type == "class_definition":
            name = n.child_by_field_name("name")
            out.append((_text(name) if name is not None else "<class>", Span.of(n)))
        for c in n.children:
            visit(c)

    visit(root)
    return out


def _enclosing_class(fn_span: Span, class_spans: list[tuple[str, Span]]) -> Optional[str]:
    best: Optional[tuple[str, int]] = None
    for name, cs in class_spans:
        if cs.start_line < fn_span.start_line and fn_span.end_line <= cs.end_line:
            if best is None or cs.start_line > best[1]:
                best = (name, cs.start_line)
    return best[0] if best is not None else None


def lower_source(src: bytes, source_file: str) -> ModuleIR:
    """Lower one Python source buffer into a ``ModuleIR`` (functions + import/global/class maps)."""
    tree = _parser().parse(src)
    root = tree.root_node
    imap = _module_imports(root, source_file)
    class_spans = _class_spans(root)
    functions = [_lower_function(fn, source_file) for fn in _iter_function_defs(root)]
    for fn in functions:
        fn.enclosing_class = _enclosing_class(fn.span, class_spans)
    return ModuleIR(
        source_file=source_file, functions=functions, imports=imap,
        globals=_module_globals(root, imap), classes=_class_infos(root, imap),
    )


def lower_file(path: Path | str, source_file: Optional[str] = None) -> ModuleIR:
    """Lower a Python file. ``source_file`` is the relative name to stamp (for the join);
    defaults to the path's name."""
    path = Path(path)
    rel = source_file if source_file is not None else path.name
    return lower_source(path.read_bytes(), rel)
