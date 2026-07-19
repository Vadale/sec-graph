"""Interprocedural driver: compute function summaries bottom-up over the call graph and
collect findings. Deterministic; no graphify (the optional oracle arrives as a plain dict).

Bottom-up Kleene iteration: SCCs (Tarjan, callees emitted before callers) are each iterated
to a fixpoint from the empty summary. A call resolved to a project function always uses that
function's current summary -- even while it is still empty mid-iteration -- so summaries only
grow (asserted). Unresolved calls take the over-approximating fallback in ``expr_taint``.
"""
from __future__ import annotations

from ..callgraph.resolve import FnKey, build_index, resolve_all_sites
from ..ir.model import ModuleIR
from ..rules.model import Rules
from .engine import TaintCtx, run_function_inter
from .model import EMPTY_SUMMARY, Finding, Summary


def tarjan_scc(nodes: list, succ: dict[FnKey, list[FnKey]]) -> list[list[FnKey]]:
    """Iterative Tarjan. Returns SCCs in reverse-topological order (callees before callers)."""
    counter = [0]
    index: dict = {}
    low: dict = {}
    stack: list = []
    on_stack: set = set()
    out: list[list] = []

    for root in nodes:
        if root in index:
            continue
        work = [(root, 0)]
        while work:
            node, i = work[-1]
            if i == 0:
                index[node] = low[node] = counter[0]
                counter[0] += 1
                stack.append(node)
                on_stack.add(node)
            recurse = False
            children = succ.get(node, [])
            while i < len(children):
                w = children[i]
                if w not in index:
                    work[-1] = (node, i + 1)
                    work.append((w, 0))
                    recurse = True
                    break
                if w in on_stack:
                    low[node] = min(low[node], index[w])
                i += 1
            if recurse:
                continue
            if low[node] == index[node]:
                scc = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    scc.append(w)
                    if w == node:
                        break
                out.append(scc)
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
    return out


def _summary_leq(old: Summary, new: Summary) -> bool:
    return (old.return_params <= new.return_params
            and old.return_origins <= new.return_origins
            and old.sink_params <= new.sink_params)


def run_project_full(
    modules: list[ModuleIR], rules: Rules, oracle: dict | None = None,
) -> tuple[list[Finding], set]:
    """Interprocedural taint. Returns (findings, tainted call sites) -- the latter feeds the
    TRR (taint-relevant resolution) metric in ``secgraph.callgraph``."""
    index = build_index(modules)
    sites, _rows = resolve_all_sites(modules, index, oracle or {}, rules)
    succ: dict[FnKey, list[FnKey]] = {
        k: sorted({b.target for b in sites.get(k, {}).values()}) for k in index.fn_of
    }

    summaries: dict[FnKey, Summary] = {}
    findings: dict[tuple, Finding] = {}
    tainted_sites: set = set()

    for scc in tarjan_scc(sorted(index.fn_of), succ):
        for k in scc:
            summaries[k] = EMPTY_SUMMARY
        cap = 4 + 4 * len(scc)
        for _ in range(cap):
            changed = False
            for k in sorted(scc):
                fn = index.fn_of[k]
                module = index.module_of[k[0]]
                ctx = TaintCtx(imap=module.imports, rules=rules, summaries=summaries,
                               sites=sites.get(k, {}), seed_params=True)
                fs, summ, ts = run_function_inter(fn, ctx)
                for f in fs:
                    findings.setdefault(f.key, f)
                tainted_sites |= ts
                assert _summary_leq(summaries[k], summ), f"non-monotone summary for {k} (bug)"
                if summ != summaries[k]:
                    summaries[k] = summ
                    changed = True
            if not changed:
                break
        else:
            raise AssertionError(f"SCC fixpoint exceeded cap ({cap}) for {scc} (bug)")

    return sorted(findings.values(), key=lambda f: f.key), tainted_sites


def run_project(modules: list[ModuleIR], rules: Rules, oracle: dict | None = None) -> list[Finding]:
    return run_project_full(modules, rules, oracle)[0]
