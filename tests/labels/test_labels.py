"""WP-C1: sensitive-data layers (credentials/PII) + the f-string taint fix.

Covers the pure matchers (word-based identifiers, secret classifier, Luhn), the f-string
lowering regression, and the four engine mint sites end-to-end via ``run_project``."""
from __future__ import annotations

from pathlib import Path

from secgraph.ir import build_project_ir
from secgraph.ir.lower import lower_source
from secgraph.ir.model import Literal, Unknown
from secgraph.rules import default_rules_dir, load_rules
from secgraph.rules.labels import classify_secret, ident_label, luhn
from secgraph.taint import run_project

RULES = load_rules(default_rules_dir())
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "labels"


# ---- pure matchers ---------------------------------------------------------------

def test_ident_label_word_based_credentials_and_pii() -> None:
    for name in ("password", "api_key", "accessToken", "client_secret", "PrivateKey"):
        assert ident_label(name, RULES)[0] == ("credentials",), name
    for name in ("email", "credit_card", "ssn", "phone_number"):
        assert ident_label(name, RULES)[0] == ("pii",), name


def test_ident_label_no_substring_false_positives() -> None:
    # the anti-flood rule: 'token'/'key'/'salt' bare, and words merely CONTAINING them, must not match
    for name in ("tokenizer", "next_token", "keyboard", "salter", "username", "key", "token", "saltiness"):
        assert ident_label(name, RULES) == ((), ""), name


def test_classify_secret_named_patterns() -> None:
    aws = classify_secret("AKIATESTKEY1234567AB", RULES)
    assert aws[0] == ("credentials",) and aws[1] == "secret:aws-access-key-id"
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
    assert classify_secret(jwt, RULES)[0] == ("credentials",)
    assert classify_secret("-----BEGIN RSA PRIVATE KEY-----", RULES)[0] == ("credentials",)


def test_classify_secret_rejects_placeholders_and_low_entropy() -> None:
    for junk in ("changeme", "your-api-key-here", "<token>", "${SECRET}", "hunter2", "example-key-value"):
        assert classify_secret(junk, RULES) == ((), "", ""), junk


def test_classify_secret_entropy_fallback() -> None:
    assert classify_secret("aGVsbG8td29ybGQtYmFzZTY0LXJhbmRvbS0xMjM0NTY3ODkw", RULES)[0] == ("credentials",)


def test_luhn_and_credit_card_layer() -> None:
    assert luhn("79927398713") and not luhn("79927398714")
    assert classify_secret("4532015112830366", RULES)[0] == ("pii",)          # Luhn-valid, not a test PAN
    assert classify_secret("4111111111111111", RULES) == ((), "", "")          # known placeholder PAN


# ---- f-string lowering regression ------------------------------------------------

def test_fstring_lowers_to_unknown_with_interpolation_child() -> None:
    mod = lower_source(b'def f(q):\n    return g(f"x = {q}")\n', "m.py")
    call = mod.functions[0].body[0].value          # g(...)
    arg = call.args[0]
    assert isinstance(arg, Unknown) and arg.kind == "fstring"
    assert any(getattr(c, "ident", None) == "q" for c in arg.children)  # {q} is a taint-carrying child


def test_plain_string_carries_text() -> None:
    mod = lower_source(b'X = "AKIATESTKEY1234567AB"\n', "m.py")
    assert mod.constants["X"] == "AKIATESTKEY1234567AB"
    body = lower_source(b'def f():\n    y = "hello"\n', "m.py").functions[0].body[0]
    assert isinstance(body.value, Literal) and body.value.text == "hello"


# ---- engine mint sites (end-to-end) ----------------------------------------------

def _findings():
    return run_project(build_project_ir(FIX), RULES)


def test_flagship_credentials_into_dangerous_sink() -> None:
    # login(): password = request.form['password'] -> execute(... password ...)
    fs = [f for f in _findings() if f.function == "login"]
    assert any("credentials" in f.layers and "dangerous-sink" in f.layers and f.cwe == "CWE-89" for f in fs)
    assert any("untrusted-input" in f.layers for f in fs)   # the same flow is also untrusted-input


def test_credential_named_parameter_is_a_source() -> None:
    fs = [f for f in _findings() if f.function == "store"]
    assert fs and all("credentials" in f.layers for f in fs)


def test_fstring_sqli_is_now_tainted() -> None:
    fs = [f for f in _findings() if f.function == "fstring_sqli"]
    assert any(f.cwe == "CWE-89" for f in fs)               # regression: was a false negative


def test_no_false_positive_on_tokenizer() -> None:
    assert not any(f.function == "tokenizer" for f in _findings())


def test_hardcoded_module_constant_secret_reaches_sink() -> None:
    fs = [f for f in _findings() if f.function == "use_key"]
    assert any("credentials" in f.layers and f.source_id.startswith("secret:") for f in fs)


def test_findings_are_deterministic() -> None:
    a = [(f.key, f.layers) for f in _findings()]
    b = [(f.key, f.layers) for f in _findings()]
    assert a == b


# ---- reviewer-driven precision/recall fixes --------------------------------------

def test_shadowing_local_does_not_leak_module_constant() -> None:
    # a local reassigned to an untainted value must not pull the module constant's secret
    assert not any(f.function == "refresh" for f in _findings())


def test_hashes_and_numeric_ids_are_not_secrets() -> None:
    for h in ("d41d8cd98f00b204e9800998ecf8427e",              # md5 (32 hex)
              "da39a3ee5e6b4b0d3255bfef95601890afd80709",        # sha1 (40 hex)
              "1234567890123456", "123456789012345678"):         # 16 / 18 digit ids (pure decimal)
        assert classify_secret(h, RULES) == ((), "", ""), h


def test_deny_only_suppresses_placeholder_within_the_match() -> None:
    assert classify_secret("AKIAIOSFODNN7EXAMPLE", RULES) == ((), "", "")           # canonical placeholder
    real = classify_secret("SELECT * FROM examples WHERE k='AKIAREAL1234567890AB'", RULES)
    assert real[0] == ("credentials",)                                             # real key not suppressed


def test_plural_identifiers_match() -> None:
    assert ident_label("passwords", RULES)[0] == ("credentials",)
    assert ident_label("api_keys", RULES)[0] == ("credentials",)
    assert ident_label("emails", RULES)[0] == ("pii",)
    assert ident_label("credit_cards", RULES)[0] == ("pii",)
