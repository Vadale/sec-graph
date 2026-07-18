"""Tiny fixture app for sec-graph tests.

Intentionally contains one unsafe flow (untrusted HTTP input -> raw SQL) so the taint
engine has a known source->sink path to detect. This is a TEST TARGET, not shipped
code.
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    uid = request.args["id"]              # source: untrusted input
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE id = '%s'" % uid
    return conn.execute(query).fetchall()  # sink: SQL injection (for taint tests)
