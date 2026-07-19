"""Cross-file sink for the methods fixture: raw SQL string interpolation."""
import sqlite3


def run_query(uid):
    conn = sqlite3.connect("x.db")
    return conn.execute("SELECT * FROM u WHERE id = '%s'" % uid)
