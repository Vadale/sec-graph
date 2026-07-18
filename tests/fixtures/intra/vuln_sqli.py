"""Intra-procedural SQL injection fixture (TEST TARGET, not shipped code)."""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args["id"]                                    # source
    conn = sqlite3.connect("app.db")
    conn.execute("SELECT * FROM users WHERE id = '%s'" % uid)   # sink: SQL injection
