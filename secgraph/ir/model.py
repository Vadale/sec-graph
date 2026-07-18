"""Statement/variable-level IR for sec-graph.

Language-agnostic substrate the taint engine will run on. Built from tree-sitter CSTs
by ``secgraph.ir.lower`` (Python for now); no graphify here (quarantine wall). Nodes are
``slots=True`` dataclasses; statements carry an integer ``sid`` (unique within a
function) so the CFG and def-use chains can reference them cheaply and deterministically.

Design notes (docs/pitfalls.md, ROADMAP Phase 1):
  * ``FunctionIR.span.start_line`` equals graphify's function ``source_location`` line,
    which is what the ``(source_file, start_line)`` join in ``secgraph.ir.join`` relies on.
  * Access paths are k=1: a base variable plus at most one attribute, plus a flag for a
    trailing subscript (e.g. ``request.args[...]`` -> base=request, field=args, subscripted).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union


@dataclass(slots=True, frozen=True)
class Span:
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    @classmethod
    def of(cls, node) -> "Span":
        sr, sc = node.start_point
        er, ec = node.end_point
        return cls(sr + 1, sc, er + 1, ec)


@dataclass(slots=True, frozen=True)
class AccessPath:
    """k=1 access path: ``base``, an optional single ``field``, a trailing-subscript flag."""

    base: str
    field: Optional[str] = None
    subscripted: bool = False

    def __str__(self) -> str:
        s = self.base
        if self.field is not None:
            s += f".{self.field}"
        if self.subscripted:
            s += "[...]"
        return s


# ---- expressions -----------------------------------------------------------------

@dataclass(slots=True)
class Name:
    ident: str
    span: Span


@dataclass(slots=True)
class Literal:
    span: Span


@dataclass(slots=True)
class Attr:
    value: "Expr"
    attr: str
    span: Span


@dataclass(slots=True)
class Index:
    value: "Expr"
    index: Optional["Expr"]
    span: Span


@dataclass(slots=True)
class Call:
    func: "Expr"
    args: list["Expr"]
    span: Span
    kw_names: list[Optional[str]] = field(default_factory=list)  # parallel to args; None = positional


@dataclass(slots=True)
class BinOp:
    left: "Expr"
    right: "Expr"
    op: str
    span: Span


@dataclass(slots=True)
class Walrus:
    """Assignment expression ``target := value`` -- reads ``value``, defines ``target``."""

    target: str
    value: "Expr"
    span: Span


@dataclass(slots=True)
class Unknown:
    """An expression we do not model precisely; still holds children so name uses and
    nested calls are not lost (honesty over false precision)."""

    kind: str
    children: list["Expr"]
    span: Span


Expr = Union[Name, Literal, Attr, Index, Call, BinOp, Walrus, Unknown]


# ---- statements ------------------------------------------------------------------

@dataclass(slots=True)
class Assign:
    sid: int
    targets: list[str]          # simple identifier targets (single or chained a = b = ...)
    value: Expr
    span: Span


@dataclass(slots=True)
class ExprStmt:
    sid: int
    value: Expr
    span: Span


@dataclass(slots=True)
class Return:
    sid: int
    value: Optional[Expr]
    span: Span


@dataclass(slots=True)
class If:
    sid: int
    test: Expr
    body: list["Stmt"]
    orelse: list["Stmt"]
    span: Span


@dataclass(slots=True)
class While:
    sid: int
    test: Expr
    body: list["Stmt"]
    span: Span


@dataclass(slots=True)
class For:
    sid: int
    targets: list[str]          # loop variable(s); tuple targets bind them all
    iter: Expr
    body: list["Stmt"]
    span: Span


@dataclass(slots=True)
class Branch:
    """A multi-way branch: control takes exactly one arm, all merging after. Models
    ``try``/``except`` (arm 0 = try-body + else; then one arm per handler) and ``match``
    (one arm per case). Modeling clauses as *alternatives that merge* means a variable
    reassigned in only one clause is unioned at the join, never sequentially killed --
    sound for may-taint (unlike a flat statement list)."""

    sid: int
    arms: list[list["Stmt"]]
    span: Span


@dataclass(slots=True)
class Unsupported:
    """A statement kind with no precise IR node: nested def/class scopes,
    break/continue/pass/import/global, and raise/assert/delete/etc. Holds a best-effort
    list of used expressions (reads survive). ``break``/``continue`` still get the right
    loop edges in the CFG. (``with``/``try``/``match`` ARE lowered -- see ``lower.py``.)"""

    sid: int
    kind: str
    uses: list[Expr]
    span: Span


Stmt = Union[Assign, ExprStmt, Return, If, While, For, Branch, Unsupported]


# ---- control-flow graph + def-use ------------------------------------------------

ENTRY = -1
EXIT = -2
PARAM_SITE = -1  # a use that reaches a parameter is recorded with this def-site


@dataclass(slots=True)
class CFG:
    """Statement-level CFG. Node ids are statement ``sid``s plus ENTRY/EXIT sentinels."""

    succ: dict[int, list[int]]
    stmt_of: dict[int, Stmt]
    entry: int = ENTRY
    exit: int = EXIT


@dataclass(slots=True)
class Def:
    var: str
    site: int   # sid of the defining statement, or PARAM_SITE for a parameter


@dataclass(slots=True)
class Use:
    var: str
    at: int                 # sid of the statement containing the use
    span: Span
    reaching: list[int]     # def sites reaching this use ([] if none, PARAM_SITE for a param)


@dataclass(slots=True)
class DefUse:
    defs: list[Def]
    uses: list[Use]


# ---- functions and modules -------------------------------------------------------

@dataclass(slots=True)
class FunctionIR:
    name: str
    params: list[str]
    body: list[Stmt]
    span: Span
    source_file: str
    enclosing_class: Optional[str] = None  # set for methods (excluded from the module FQN index)
    field_escape: bool = False             # writes an arg to self.x / d[k] (an untracked channel)
    graphify_node: Optional[str] = None    # filled by secgraph.ir.join
    cfg: Optional[CFG] = None
    defuse: Optional[DefUse] = None


@dataclass(slots=True)
class ModuleIR:
    source_file: str
    functions: list[FunctionIR] = field(default_factory=list)
    imports: dict[str, str] = field(default_factory=dict)   # local name -> fully-qualified name
    globals: dict[str, Optional[str]] = field(default_factory=dict)  # module-level `x = Call()` -> callee FQN
    classes: dict[str, list[str]] = field(default_factory=dict)      # class name -> resolved base FQNs


# ---- helpers ---------------------------------------------------------------------

def _child_exprs(expr: Expr) -> list[Optional[Expr]]:
    """Sub-expressions of ``expr`` in source/child order -- the traversal shared by the
    walkers below, so the def-use ordering they produce stays identical.

    A ``Walrus`` yields only its ``value``: the ``target`` is a bound name (a def), not a
    child expression. An ``Index`` may yield a ``None`` index; callers recurse through it
    (``None`` contributes nothing).
    """
    if isinstance(expr, Attr):
        return [expr.value]
    if isinstance(expr, Index):
        return [expr.value, expr.index]
    if isinstance(expr, Call):
        return [expr.func, *expr.args]
    if isinstance(expr, BinOp):
        return [expr.left, expr.right]
    if isinstance(expr, Walrus):
        return [expr.value]
    if isinstance(expr, Unknown):
        return list(expr.children)
    return []  # Name, Literal: no sub-expressions


def iter_uses(expr: Optional[Expr]) -> list[tuple[str, Span]]:
    """Collect variable *reads* (name, span) in an expression, k=1-agnostic.

    For ``a.b`` the base ``a`` is the read (``b`` is a field, not a variable); for
    ``a[i]`` both ``a`` and names in ``i`` are reads; for a call, the callee's base and
    every argument's reads count.
    """
    if expr is None:
        return []
    out: list[tuple[str, Span]] = [(expr.ident, expr.span)] if isinstance(expr, Name) else []
    for c in _child_exprs(expr):
        out += iter_uses(c)
    return out


def iter_walrus_targets(expr: Optional[Expr]) -> list[str]:
    """Names bound by ``:=`` anywhere inside an expression (defs, not reads)."""
    if expr is None:
        return []
    out: list[str] = [expr.target] if isinstance(expr, Walrus) else []
    for c in _child_exprs(expr):
        out += iter_walrus_targets(c)
    return out


def child_exprs(expr: Expr) -> list[Optional[Expr]]:
    """Public view of an expression's sub-expressions (source/child order)."""
    return _child_exprs(expr)


def iter_calls(expr: Optional[Expr]) -> list["Call"]:
    """Every ``Call`` node inside an expression, in source order."""
    if expr is None:
        return []
    out: list[Call] = [expr] if isinstance(expr, Call) else []
    for c in _child_exprs(expr):
        out += iter_calls(c)
    return out


def stmt_exprs(s: "Stmt") -> list[Optional[Expr]]:
    """The top-level expression(s) of a statement (Branch/control sub-bodies excluded)."""
    if isinstance(s, (Assign, ExprStmt)):
        return [s.value]
    if isinstance(s, Return):
        return [s.value] if s.value is not None else []
    if isinstance(s, (If, While)):
        return [s.test]
    if isinstance(s, For):
        return [s.iter]
    if isinstance(s, Unsupported):
        return list(s.uses)
    return []


def access_path(expr: Optional[Expr]) -> Optional[AccessPath]:
    """k=1 access path of an lvalue/rvalue expression, or ``None`` if it has no stable base."""
    if expr is None:
        return None
    if isinstance(expr, Name):
        return AccessPath(base=expr.ident)
    if isinstance(expr, Attr):
        inner = access_path(expr.value)
        if inner is None:
            return None
        if inner.field is None and not inner.subscripted:
            return AccessPath(base=inner.base, field=expr.attr)
        # already at k=1 (a.b.c): keep base.b, drop deeper fields
        return AccessPath(base=inner.base, field=inner.field, subscripted=inner.subscripted)
    if isinstance(expr, Index):
        inner = access_path(expr.value)
        if inner is None:
            return None
        return AccessPath(base=inner.base, field=inner.field, subscripted=True)
    return None
