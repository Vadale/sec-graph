"""Sensitive-data layer fixtures: credential-named values reaching a SQL sink, the modern
f-string SQLi idiom, and a false-positive guard (`next_token` must NOT be a credential)."""
from flask import request
import sqlite3


def login():
    password = request.form["password"]                       # untrusted-input + credentials
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT * FROM u WHERE p = '%s'" % password)  # credentials -> dangerous-sink (CWE-89)


def store(api_key):                                            # credential-named parameter
    conn = sqlite3.connect("x.db")
    conn.execute("INSERT INTO k VALUES ('%s')" % api_key)      # credentials -> dangerous-sink


def fstring_sqli():
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    conn.execute(f"SELECT * FROM t WHERE x = {q}")             # f-string SQLi (taint regression)


def tokenizer(next_token):                                     # FP guard: 'token' is not a credential
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT " + str(next_token))
