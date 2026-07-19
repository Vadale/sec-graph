"""Scoring (PROTOCOL §4-5). Mechanical: verdicts are taxonomy-constrained JSON, scored by EXACT match
against the hand-labelled truth. No keyword matching (the Part-2 scorer's `KW` list does not survive).
Primary endpoint = paired real/FP accuracy, exact McNemar. Everything else = bootstrap 95% CIs."""
from __future__ import annotations

import math
import random

SEV = {"low": 0, "medium": 1, "high": 2, "critical": 3}
NEAR = {frozenset({"insecure-cookie", "cookie-injection"})}   # one pre-declared near-miss pair


# ---- per-finding correctness (None verdict / parse error / net failure => wrong, not dropped) ----

def realfp_correct(v: dict, truth_real: bool) -> bool:
    verd = (v or {}).get("verdict")
    if verd not in ("real", "false-positive"):     # unsure / missing / error => wrong (intent-to-treat)
        return False
    return (verd == "real") == bool(truth_real)


def guard_correct(v: dict, truth_guard: str) -> bool | None:
    if truth_guard == "n/a":
        return None                                # excluded from guard_acc
    g = (v or {}).get("auth_guarded")
    if g == "yes":
        pred = "guarded"
    elif g == "no":
        pred = "unguarded"
    else:
        return False                               # unknown / missing => wrong
    return pred == truth_guard


def class_correct(v: dict, truth_class: str) -> bool:
    c = (v or {}).get("vuln_class")
    if not c:
        return False
    return c == truth_class or frozenset({c, truth_class}) in NEAR


def sev_dist(v: dict, truth_sev: str) -> int | None:
    s = (v or {}).get("severity")
    if s not in SEV or truth_sev not in SEV:
        return None
    return abs(SEV[s] - SEV[truth_sev])


# ---- statistics ------------------------------------------------------------------------------

def mcnemar_exact(pairs: list[tuple[bool, bool]]) -> dict:
    """Exact two-sided McNemar on paired (A_correct, B_correct). b = A right/B wrong, c = A wrong/B right."""
    b = sum(1 for a, x in pairs if a and not x)
    c = sum(1 for a, x in pairs if x and not a)
    n = b + c
    if n == 0:
        p = 1.0
    else:
        k = min(b, c)
        tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
        p = min(1.0, 2 * tail)
    return {"b_A_only": b, "c_B_only": c, "discordant": n, "p_value": round(p, 4)}


def bootstrap_ci(items: list, stat, n: int = 10000, seed: int = 7) -> tuple[float, float, float]:
    """Percentile 95% CI of `stat(sample)` over resamples of `items`. Returns (point, lo, hi)."""
    rng = random.Random(seed)
    point = stat(items)
    if not items:
        return (0.0, 0.0, 0.0)
    draws = []
    m = len(items)
    for _ in range(n):
        sample = [items[rng.randrange(m)] for _ in range(m)]
        draws.append(stat(sample))
    draws.sort()
    return (round(point, 4), round(draws[int(0.025 * n)], 4), round(draws[int(0.975 * n)], 4))


def acc(items: list[bool]) -> float:
    xs = [x for x in items if x is not None]
    return sum(1 for x in xs if x) / len(xs) if xs else 0.0
