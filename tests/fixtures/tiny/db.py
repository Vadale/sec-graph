"""Data-access helper for the tiny fixture (contains the SQL sink).

Part of the sec-graph test target. `run_query` builds a SQL string by interpolating
its argument and executes it -- the sink end of the known cross-file taint path.
"""
import sqlite3


def run_query(uid):
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE id = '%s'" % uid   # tainted string
    return conn.execute(query).fetchall()                 # sink: SQL injection
