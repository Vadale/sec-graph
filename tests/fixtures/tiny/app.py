"""Tiny fixture app for sec-graph tests.

Intentionally contains one unsafe flow: untrusted HTTP input flows across a file
boundary into a raw SQL query. This is a TEST TARGET, not shipped code. It gives the
analyzer a known cross-file source->sink path AND an import-evidenced function->function
`calls` edge (get_user -> run_query) for the graphify contract test.
"""
from flask import Flask, request

from db import run_query

app = Flask(__name__)


@app.route("/user")
def get_user():
    uid = request.args["id"]   # source: untrusted input
    return run_query(uid)      # cross-file call -> graphify `calls` edge; taint continues
