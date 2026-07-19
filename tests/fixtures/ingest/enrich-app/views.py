from flask import request
import sqlite3


def login_required(f):
    return f


@login_required
def secure_report():
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    return conn.execute("SELECT * FROM r WHERE q = '%s'" % q)          # sink L13, inside @login_required


def leak_password():
    password = request.form["password"]                               # credential source L17
    conn = sqlite3.connect("x.db")
    return conn.execute("SELECT * FROM u WHERE p = '%s'" % password)   # sink L19, unguarded
