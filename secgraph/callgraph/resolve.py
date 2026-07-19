"""Resolve each call site and classify it, with a strict precedence:

    rule (source/sink/sanitizer/propagator)  >  import  >  same-module local  >
    class constructor / typed-receiver method  >  oracle singleton  >  unresolved

Every site gets exactly one category (ADR-007):
  rule | builtin | bound(-import/-local) | external | unknown-receiver | unresolved-project
``external`` requires POSITIVE evidence (a resolved chain leaving the project, or a receiver
whose value-origin is an external constructor/import); absence of evidence -> ``unknown-
receiver``, never ``external`` (anti-gaming). Pure IR + rules; no graphify import.

Only project *function* binds are returned as engine ``Binding``s (they feed the taint
summaries, unchanged from Phase 3). Constructor/method binds are counted for the metric but
their taint propagation is a follow-up (the constructor-taint rule + arg/param map).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional, Union

from ..ir.cfg import analyze_function
from ..ir.model import Assign, Attr, Call, FunctionIR, ModuleIR, Name, iter_calls, stmt_exprs
from ..rules.match import (
    match_propagator,
    match_sanitizer,
    match_sink,
    match_source,
    resolve_fqn,
)
from ..rules.model import Rules

FnKey = tuple[str, int]
SiteKey = tuple[int, int, int, int]

_BUILTINS = frozenset({
    "int", "float", "str", "bytes", "bool", "len", "print", "range", "list", "dict",
    "set", "tuple", "repr", "format", "open", "isinstance", "getattr", "setattr", "super",
    "enumerate", "zip", "map", "filter", "sorted", "min", "max", "sum", "abs", "type",
    "hasattr", "hash", "id", "iter", "next", "vars", "dir", "callable", "bytearray",
    "frozenset", "complex", "slice", "object", "property", "classmethod", "staticmethod",
    "reversed", "all", "any", "round", "divmod", "pow", "chr", "ord", "bin", "hex", "oct",
    "input", "globals", "locals", "exit", "quit",
    # common builtin exceptions (bare-name "constructor" calls)
    "Exception", "BaseException", "RuntimeError", "ValueError", "TypeError", "KeyError",
    "IndexError", "AttributeError", "StopIteration", "FileNotFoundError", "OSError",
    "IOError", "ImportError", "NotImplementedError", "AssertionError", "PermissionError",
    "ConnectionError", "TimeoutError", "LookupError", "ArithmeticError", "ZeroDivisionError",
    "UnicodeDecodeError", "NameError", "OverflowError",
})

# a receiver's value-origin: an external library value, a project class, a project function
# used as a value, or no evidence.
Origin = Union[str, tuple]  # "external" | "project-fn" | "unknown" | ("class", fqn)


@dataclass(frozen=True, slots=True)
class Binding:
    target: FnKey
    provenance: str                       # "import" | "local" | "oracle" | "method-recv"
    name: str
    kind: str = "function"                # function | constructor | method
    arg_to_param: tuple = ()              # call.args[i] -> callee param index (None if unmapped)
    receiver_param: Optional[int] = None  # 0 for method/constructor binds (self)
    over_approx: bool = False             # engine must union the fallback (constructor / field-escaping method)


@dataclass(slots=True)
class ClassInfo:
    fqn: str
    bases: list[str]
    methods: dict  # method name -> FnKey


@dataclass(slots=True)
class FnIndex:
    fn_of: dict[FnKey, FunctionIR] = field(default_factory=dict)
    module_of: dict[str, ModuleIR] = field(default_factory=dict)
    by_fqn: dict[str, FnKey] = field(default_factory=dict)
    by_name: dict[str, list[FnKey]] = field(default_factory=dict)
    classes: dict[str, ClassInfo] = field(default_factory=dict)
    globals: dict[str, Optional[str]] = field(default_factory=dict)
    project_tops: frozenset = frozenset()


def module_name(source_file: str) -> str:
    parts = source_file[:-3].split("/") if source_file.endswith(".py") else source_file.split("/")
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def site_key(call: Call) -> SiteKey:
    s = call.span
    return (s.start_line, s.start_col, s.end_line, s.end_col)


def fn_key(fn: FunctionIR) -> FnKey:
    return (fn.source_file, fn.span.start_line)


def _local_names(fn: FunctionIR) -> set[str]:
    if fn.defuse is None:
        analyze_function(fn)
    return set(fn.params) | {d.var for d in fn.defuse.defs}


def _shadow_imap(module: ModuleIR, fn: FunctionIR) -> dict[str, str]:
    locals_ = _local_names(fn)
    return {k: v for k, v in module.imports.items() if k not in locals_}


def _is_nested(fn: FunctionIR, others: list[FunctionIR]) -> bool:
    for o in others:
        if o is fn or o.source_file != fn.source_file:
            continue
        if o.span.start_line < fn.span.start_line and fn.span.end_line <= o.span.end_line:
            return True
    return False


def build_index(modules: list[ModuleIR]) -> FnIndex:
    idx = FnIndex()
    tops: set[str] = set()
    for module in modules:
        idx.module_of[module.source_file] = module
        tops.add(module_name(module.source_file).split(".", 1)[0])
        for fn in module.functions:
            idx.fn_of[fn_key(fn)] = fn
    idx.project_tops = frozenset(tops)

    for module in modules:
        mod = module_name(module.source_file)
        for clsname, bases in module.classes.items():
            idx.classes.setdefault(f"{mod}.{clsname}", ClassInfo(f"{mod}.{clsname}", list(bases), {}))
        for name, val in module.globals.items():
            idx.globals.setdefault(f"{mod}.{name}", val)
        for fn in module.functions:
            key = fn_key(fn)
            idx.by_name.setdefault(fn.name, []).append(key)
            if fn.enclosing_class:
                ci = idx.classes.get(f"{mod}.{fn.enclosing_class}")
                if ci is not None:
                    ci.methods.setdefault(fn.name, key)
            elif not _is_nested(fn, module.functions):
                idx.by_fqn.setdefault(f"{mod}.{fn.name}", key)
    for name in idx.by_name:
        idx.by_name[name].sort()
    return idx


def _origin_of_fqn(fqn: Optional[str], index: FnIndex) -> Origin:
    if fqn is None:
        return "unknown"
    if fqn in index.classes:
        return ("class", fqn)
    if fqn in index.globals:                       # a project object -> what it was built from
        return _origin_of_fqn(index.globals[fqn], index)
    if fqn in index.by_fqn:
        return "project-fn"
    top = fqn.split(".", 1)[0]
    return "external" if top not in index.project_tops else "unknown"


def _base_is_external(base_fqn: str, index: FnIndex) -> bool:
    """A class base like ``db.Model`` (where ``db`` is a SQLAlchemy instance) is external
    even though it resolves through a project package -- decide via the value-origin of the
    longest prefix that names a known object."""
    if base_fqn.split(".", 1)[0] not in index.project_tops:
        return True
    parts = base_fqn.split(".")
    for i in range(len(parts), 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in index.globals:
            return _origin_of_fqn(index.globals[prefix], index) == "external"
    return False


def _class_is_library_backed(fqn: str, index: FnIndex, seen: Optional[set] = None) -> bool:
    """True if the class or a transitive base inherits from a non-project (library) class,
    e.g. ``Article -> project Model -> db.Model``."""
    seen = seen if seen is not None else set()
    if fqn in seen:
        return False
    seen.add(fqn)
    ci = index.classes.get(fqn)
    if ci is None:
        return False
    for b in ci.bases:
        if b in index.classes:
            if _class_is_library_backed(b, index, seen):
                return True
        elif _base_is_external(b, index):
            return True
    return False


def _base_name(expr) -> Optional[str]:
    while isinstance(expr, Attr):
        expr = expr.value
    return expr.ident if isinstance(expr, Name) else None


def _local_types(fn: FunctionIR, module: ModuleIR, index: FnIndex) -> dict[str, Origin]:
    """Tier-1 flow-insensitive local typing: ``v = ClassName()`` / ``v = ext_call()``."""
    imap = _shadow_imap(module, fn)
    types: dict[str, Origin] = {}
    conflict: set[str] = set()
    for stmt in (fn.cfg.stmt_of.values() if fn.cfg else []):
        if isinstance(stmt, Assign) and len(stmt.targets) == 1 and isinstance(stmt.value, Call):
            func = stmt.value.func
            origin = _origin_of_fqn(resolve_fqn(func, imap), index)
            if origin == "external" and isinstance(func, Name):     # a same-module class?
                same = f"{module_name(module.source_file)}.{func.ident}"
                if same in index.classes:
                    origin = ("class", same)
            v = stmt.targets[0]
            if v in types and types[v] != origin:
                conflict.add(v)
            else:
                types[v] = origin
    for v in conflict:
        types.pop(v, None)
    return types


def _receiver_origin(base: str, fn: FunctionIR, module: ModuleIR, index: FnIndex) -> Origin:
    if base == "self" and fn.enclosing_class:
        cfqn = f"{module_name(module.source_file)}.{fn.enclosing_class}"
        return ("class", cfqn) if cfqn in index.classes else "unknown"
    lt = _local_types(fn, module, index)
    if base in lt:
        return lt[base]
    if base in module.globals:
        return _origin_of_fqn(module.globals[base], index)
    imap = _shadow_imap(module, fn)
    if base in imap:
        return _origin_of_fqn(imap[base], index)
    return "unknown"


def _arg_map(call: Call, callee_params: list[str], has_receiver: bool) -> tuple:
    """Map each call arg to the callee param index (self offset applied; kwargs by name)."""
    offset = 1 if has_receiver else 0
    pos_params = callee_params[offset:]
    kw = call.kw_names if call.kw_names else [None] * len(call.args)
    out: list[Optional[int]] = []
    pos_i = 0
    for i in range(len(call.args)):
        name = kw[i] if i < len(kw) else None
        if name is not None:
            out.append(callee_params.index(name) if name in callee_params else None)
        elif pos_i < len(pos_params):
            out.append(offset + pos_i)
            pos_i += 1
        else:
            out.append(None)                                 # *args overflow / arity mismatch
    return tuple(out)


def _make_binding(call: Call, target: FnKey, provenance: str, kind: str, index: FnIndex) -> Binding:
    fn = index.fn_of[target]
    # a receiver slot exists only if the first param is self/cls (so @staticmethod binds
    # without one and does not drop the real first arg).
    has_receiver = kind in ("method", "constructor") and bool(fn.params) and fn.params[0] in ("self", "cls")
    # a constructor always stores args on self; a method that writes self.x/d[k] can launder an
    # arg through an untracked channel -- both need the fallback floor so taint is not cleared.
    over_approx = kind == "constructor" or (kind == "method" and fn.field_escape)
    return Binding(target, provenance, fn.name, kind, _arg_map(call, fn.params, has_receiver),
                   0 if has_receiver else None, over_approx)


def _constructor_binding(call: Call, class_fqn: str, provenance: str, index: FnIndex) -> Optional[Binding]:
    ci = index.classes.get(class_fqn)
    if ci is not None and "__init__" in ci.methods:
        return _make_binding(call, ci.methods["__init__"], provenance, "constructor", index)
    return None  # no user __init__: metric-bound, engine over-approximates the result


def classify_site(
    call: Call, fn: FunctionIR, module: ModuleIR, index: FnIndex,
    oracle: dict[FnKey, frozenset], rules: Rules,
) -> tuple[str, Optional[Binding]]:
    imap = _shadow_imap(module, fn)
    if (match_sink(call, imap, rules) or match_sanitizer(call, imap, rules)
            or match_propagator(call, imap, rules) or match_source(call, imap, rules)):
        return "rule", None

    f = call.func
    if isinstance(f, Name):
        if f.ident in _local_names(fn):
            return "unknown-receiver", None                  # a callable variable
        if f.ident in module.imports:
            fqn = module.imports[f.ident]
            if fqn in index.by_fqn:
                return "bound-import", _make_binding(call, index.by_fqn[fqn], "import", "function", index)
            if fqn in index.classes:
                return "bound", _constructor_binding(call, fqn, "import", index)
            top = fqn.split(".", 1)[0]
            return ("external" if top not in index.project_tops else "unresolved-project"), None
        local = f"{module_name(module.source_file)}.{f.ident}"
        if local in index.by_fqn:
            return "bound-local", _make_binding(call, index.by_fqn[local], "local", "function", index)
        if local in index.classes:
            return "bound", _constructor_binding(call, local, "local", index)
        if f.ident in _BUILTINS:
            return "builtin", None
        return "unresolved-project", None

    if isinstance(f, Attr):
        base = _base_name(f.value)
        # Trust resolve_fqn only when the base is an imported name (a real module path); for a
        # local variable receiver its identity resolution (`s.run`) is spurious -- fall through
        # to the receiver-origin path, which types `s` from `s = Svc()`.
        if base is not None and base in imap:
            fqn = resolve_fqn(f, imap)
            if fqn is not None:
                if fqn in index.by_fqn:
                    return "bound-import", _make_binding(call, index.by_fqn[fqn], "import", "function", index)
                if fqn in index.classes:
                    return "bound", _constructor_binding(call, fqn, "import", index)
                if fqn.split(".", 1)[0] not in index.project_tops:
                    return "external", None
        origin = _receiver_origin(base, fn, module, index) if base else "unknown"
        if origin in ("external", "project-fn"):
            return "external", None
        if isinstance(origin, tuple) and origin[0] == "class":
            ci = index.classes.get(origin[1])
            if ci is not None and f.attr in ci.methods:
                return "bound", _make_binding(call, ci.methods[f.attr], "method-recv", "method", index)
            if ci is not None and _class_is_library_backed(origin[1], index):
                return "external", None                      # method inherited from a library base
            return "unresolved-project", None
        cands = sorted(k for k in index.by_name.get(f.attr, ()) if k in oracle.get(fn_key(fn), frozenset()))
        if len(cands) == 1:
            kind = "method" if index.fn_of[cands[0]].enclosing_class else "function"
            return "bound-oracle", _make_binding(call, cands[0], "oracle", kind, index)
        return "unknown-receiver", None

    return "unknown-receiver", None


def resolve_all_sites(
    modules: list[ModuleIR], index: FnIndex, oracle: dict[FnKey, frozenset], rules: Rules,
) -> tuple[dict[FnKey, dict[SiteKey, Binding]], list[dict]]:
    sites: dict[FnKey, dict[SiteKey, Binding]] = {}
    rows: list[dict] = []
    for module in modules:
        for fn in module.functions:
            fn_sites: dict[SiteKey, Binding] = {}
            for stmt in (fn.cfg.stmt_of.values() if fn.cfg else []):
                for expr in stmt_exprs(stmt):
                    for call in iter_calls(expr):
                        category, binding = classify_site(call, fn, module, index, oracle, rules)
                        if binding is not None:
                            fn_sites[site_key(call)] = binding
                        rows.append({
                            "file": fn.source_file, "line": call.span.start_line,
                            "col": call.span.start_col, "category": category,
                            "method": isinstance(call.func, Attr),
                            "tsk": (fn.source_file, site_key(call)),
                        })
            if fn_sites:
                sites[fn_key(fn)] = fn_sites
    rows.sort(key=lambda r: (r["file"], r["line"], r["col"]))
    return sites, rows


def binding_rate(rows: list[dict]) -> dict:
    """ADR-007 metrics. PCR = bound/(bound+unresolved-project) (oracle excluded from the
    numerator); UNK = unknown-receiver / method-call sites."""
    counts = Counter(r["category"] for r in rows)
    bound = counts.get("bound", 0) + counts.get("bound-import", 0) + counts.get("bound-local", 0)
    unresolved_project = counts.get("unresolved-project", 0)
    unknown = counts.get("unknown-receiver", 0)
    method_sites = sum(1 for r in rows if r.get("method"))
    total = len(rows)
    pcr = bound / (bound + unresolved_project) if (bound + unresolved_project) else 1.0
    unk = unknown / method_sites if method_sites else 0.0
    return {
        "counts": dict(counts), "total": total, "bound": bound,
        "bound_oracle": counts.get("bound-oracle", 0),
        "unresolved_project": unresolved_project, "unknown_receiver": unknown,
        "method_sites": method_sites, "PCR": pcr, "UNK": unk,
    }


_RESOLVED_CATEGORIES = frozenset({
    "rule", "builtin", "bound", "bound-import", "bound-local", "bound-oracle", "external",
})


def trr(rows: list[dict], tainted_sites: set) -> dict:
    """ADR-007 TRR: over call sites on a tainted path (a receiver/arg carries taint at the
    fixpoint), the fraction classified rule|builtin|bound|external -- 'on the paths that
    matter, do we know what the call is'. ``tainted_sites`` comes from ``run_project_full``."""
    rel = [r for r in rows if r.get("tsk") in tainted_sites]
    resolved = sum(1 for r in rel if r["category"] in _RESOLVED_CATEGORIES)
    return {"tainted_sites": len(rel), "resolved": resolved,
            "TRR": resolved / len(rel) if rel else 1.0}
