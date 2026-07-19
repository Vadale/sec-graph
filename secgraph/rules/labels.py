"""Deterministic sensitive-data labelling: map an identifier to layers (credentials/pii) by a
word-based dictionary match, and classify a string literal as a secret (named formats first,
Shannon-entropy fallback charset-gated). Pure and graphify-free; returns ``(layers, confidence)``
so the taint engine -- not this layer -- mints the ``Origin`` (keeps rules independent of taint).

Word-based matching is the anti-flood rule (Fable): identifiers are tokenised (snake_case +
camelCase) and a dictionary term matches only as a whole token-run, so ``tokenizer`` /
``next_token`` never light up the credentials layer the way a substring match would.
"""
from __future__ import annotations

import re
from collections import Counter
from math import log2

from .model import Rules

_CONF_RANK = {"high": 3, "medium": 2, "low": 1}

# Known non-secret placeholder card numbers (documented test PANs) -- never label as PII.
_TEST_PANS = frozenset({
    "4111111111111111", "4242424242424242", "5555555555554444", "5105105105105100",
    "378282246310005", "371449635398431", "6011111111111117", "4012888888881881",
})

_CAMEL1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL2 = re.compile(r"([a-z0-9])([A-Z])")
_SPLIT = re.compile(r"[_\W]+")
_BASE64ISH = re.compile(r"[A-Za-z0-9+/=_-]+")
_HEX = re.compile(r"[0-9a-fA-F]+")
_HASH_LENGTHS = frozenset({32, 40, 64})   # md5 / sha1 / sha256 digests -- almost never a secret


def _tokens(name: str) -> list[str]:
    """Split ``accessToken`` / ``access_token`` / ``APIKey`` into lowercase word tokens."""
    s = _CAMEL2.sub(r"\1_\2", _CAMEL1.sub(r"\1_\2", name))
    return [t for t in _SPLIT.split(s.lower()) if t]


def _norm(name: str) -> str:
    """``_``-delimited token run with sentinels, so a term matches only on whole-token boundaries."""
    return "_" + "_".join(_tokens(name)) + "_"


def _ident_hit(norm: str, identifiers: tuple[str, ...]) -> bool:
    """A dictionary term matches ``norm`` as a whole token-run, tolerating a regular plural on
    its last token (``password`` matches ``passwords``, ``api_key`` matches ``api_keys``)."""
    for ident in identifiers:
        run = "_".join(_tokens(ident))
        if f"_{run}_" in norm or f"_{run}s_" in norm or f"_{run}es_" in norm:
            return True
    return False


def ident_label(name: str, rules: Rules) -> tuple[tuple[str, ...], str]:
    """(layers, confidence) for an identifier that names sensitive data, or ``((), "")``."""
    if not name or not rules.labels:
        return (), ""
    norm = _norm(name)
    layers = tuple(sorted(
        layer for layer, rule in rules.labels.items() if _ident_hit(norm, rule.identifiers)
    ))
    if not layers:
        return (), ""
    conf = min((rules.labels[l].confidence for l in layers), key=lambda c: _CONF_RANK.get(c, 2))
    return layers, conf


def _shannon(s: str) -> float:
    n = len(s)
    if n <= 1:
        return 0.0
    return -sum((c / n) * log2(c / n) for c in Counter(s).values())


def luhn(digits: str) -> bool:
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):   # rightmost = check digit (i=0, not doubled)
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def classify_secret(text: str, rules: Rules) -> tuple[tuple[str, ...], str, str]:
    """(layers, source_id, confidence) if ``text`` is a hardcoded secret/PAN, else ``((), "", "")``.

    Named formats (AWS/JWT/PEM/...) win at their declared confidence; a generic high-entropy
    fallback is charset- and length-gated (its charset excludes whitespace). Placeholder values
    (changeme, <...>, ${...}) are rejected up front."""
    sec = rules.secrets
    if sec is None or not text:
        return (), "", ""

    for p in sec.patterns:
        m = re.search(p.regex, text)
        if m is None:
            continue
        cand = m.group(0)
        if any(re.search(d, cand) for d in sec.deny_values):   # placeholder INSIDE the match span
            continue                                           # (a real secret elsewhere isn't suppressed)
        if p.validator == "luhn":
            digits = re.sub(r"\D", "", cand)
            if not (13 <= len(digits) <= 19 and digits not in _TEST_PANS and luhn(digits)):
                continue
        return p.layers, f"secret:{p.id}", p.confidence

    # generic entropy fallback: here the whole literal IS the candidate
    if any(re.search(d, text) for d in sec.deny_values):
        return (), "", ""
    if sec.min_length <= len(text) <= sec.max_length:
        if _BASE64ISH.fullmatch(text) and _shannon(text) >= sec.base64_threshold:
            return ("credentials",), "secret:high-entropy", sec.confidence
        if (_HEX.fullmatch(text) and len(text) not in _HASH_LENGTHS
                and any(c in "abcdefABCDEF" for c in text)     # pure-decimal run = an id, not a hex secret
                and _shannon(text) >= sec.hex_threshold):
            return ("credentials",), "secret:high-entropy-hex", sec.confidence
    return (), "", ""
