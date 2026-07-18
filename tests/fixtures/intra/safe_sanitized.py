"""Sanitized (safe) fixture: int() neutralizes the input before the sink."""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/item")
def item():
    iid = int(request.args["id"])                              # sanitized
    conn = sqlite3.connect("app.db")
    conn.execute("SELECT * FROM items WHERE id = %d" % iid)    # not exploitable
