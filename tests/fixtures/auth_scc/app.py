"""Recursive SCC where the SAME source->sink is reachable via a guarded and an unguarded path.
The sink function calls back into the entry, so every function is in one SCC and the two path
variants are discovered across different fixpoint iterations -- the case where a keep-first
merge would freeze an early "guarded" verdict. The finding MUST be unguarded (an unauthed path
exists)."""
from flask import request
import sqlite3


def entry():
    q = request.args["q"]
    if current_user.is_admin:
        short_path(q)          # guarded path: call is inside the is_admin arm
    long_path(q)               # unguarded path: called unconditionally


def short_path(x):
    do_sink(x)


def long_path(x):
    mid(x)


def mid(x):
    do_sink(x)


def do_sink(x):
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT " + x)   # reached guarded (short_path) AND unguarded (long_path)
    entry()                       # back-edge -> one SCC over all these functions
