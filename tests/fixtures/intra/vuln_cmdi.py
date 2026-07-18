"""Intra-procedural command injection fixture (TEST TARGET, not shipped code)."""
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args["host"]        # source
    os.system("ping -c 1 " + host)     # sink: command injection
