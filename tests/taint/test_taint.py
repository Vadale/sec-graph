"""Intraprocedural taint tests: SQLi/cmdi flagged, sanitizer suppresses, flow-sensitive
may-taint, determinism, and a project scan over the intra fixtures."""
from __future__ import annotations

from pathlib import Path

from secgraph.ir import analyze_module, lower_source
from secgraph.rules import default_rules_dir, load_rules
from secgraph.taint import run_module, scan_project

RULES = load_rules(default_rules_dir())
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "intra"


def _scan(src: bytes):
    return run_module(analyze_module(lower_source(src, "t.py")), RULES)


def test_intra_sqli_flagged() -> None:
    fs = _scan(
        b"from flask import request\n"
        b"import sqlite3\n"
        b"def u(conn):\n"
        b"    uid = request.args['id']\n"
        b"    conn.execute('SELECT * FROM t WHERE id = %s' % uid)\n"
    )
    assert any(
        f.sink_id == "py-sql-exec" and f.source_id == "flask-request-input" and f.cwe == "CWE-89"
        for f in fs
    )


def test_intra_cmdi_flagged() -> None:
    fs = _scan(
        b"from flask import request\n"
        b"import os\n"
        b"def r():\n"
        b"    c = request.args['c']\n"
        b"    os.system('x ' + c)\n"
    )
    assert any(f.sink_id == "py-os-command" and f.cwe == "CWE-78" for f in fs)


def test_sanitizer_on_the_path_suppresses() -> None:
    fs = _scan(
        b"from flask import request\n"
        b"import sqlite3\n"
        b"def s(conn):\n"
        b"    uid = int(request.args['id'])\n"
        b"    conn.execute('id = %d' % uid)\n"
    )
    assert fs == []


def test_flow_sensitive_may_taint() -> None:
    # sanitized only on the `if` path; the else path keeps taint -> still flagged
    fs = _scan(
        b"from flask import request\n"
        b"def f(flag, cur):\n"
        b"    x = request.args['id']\n"
        b"    if flag:\n"
        b"        x = int(x)\n"
        b"    cur.execute('id = %s' % x)\n"
    )
    assert any(f.sink_id == "py-sql-exec" for f in fs)


def test_no_source_no_finding() -> None:
    fs = _scan(b"def s(cur):\n    cur.execute('SELECT 1')\n")
    assert fs == []


def test_findings_are_deterministic() -> None:
    src = (
        b"from flask import request\n"
        b"import os\n"
        b"def r():\n"
        b"    c = request.args['c']\n"
        b"    os.system(c)\n"
    )
    assert [f.key for f in _scan(src)] == [f.key for f in _scan(src)]


def test_try_except_branch_does_not_kill_taint() -> None:
    # reviewer WP2 #1: try-body taint must survive an except-clause reassignment (Branch,
    # not a flat sequential list where the strong-update `x='0'` would kill it).
    fs = _scan(
        b"from flask import request\n"
        b"def f(cur):\n"
        b"    try:\n"
        b"        x = request.args['id']\n"
        b"    except Exception:\n"
        b"        x = '0'\n"
        b"    cur.execute('id = %s' % x)\n"
    )
    assert any(f.sink_id == "py-sql-exec" for f in fs)


def test_param_shadowing_import_is_not_a_source() -> None:
    # reviewer WP2 #4: a parameter named `request` is not flask.request -> no false positive
    fs = _scan(
        b"from flask import request\n"
        b"def handler(request, cur):\n"
        b"    cur.execute(request.args['id'])\n"
    )
    assert fs == []


def test_guarded_optional_import_is_resolved() -> None:
    # reviewer WP2 #2: an import under try/except (optional-dep idiom) still resolves
    fs = _scan(
        b"try:\n"
        b"    from flask import request\n"
        b"except ImportError:\n"
        b"    request = None\n"
        b"def u(cur):\n"
        b"    cur.execute(request.args['id'])\n"
    )
    assert any(f.sink_id == "py-sql-exec" for f in fs)


def test_scan_project_over_intra_fixtures() -> None:
    by_file: dict[str, list] = {}
    for f in scan_project(FIX, RULES):
        by_file.setdefault(f.source_file, []).append(f)
    assert any(f.cwe == "CWE-89" for f in by_file.get("vuln_sqli.py", []))
    assert any(f.cwe == "CWE-78" for f in by_file.get("vuln_cmdi.py", []))
    assert "safe_sanitized.py" not in by_file  # sanitized -> no findings
