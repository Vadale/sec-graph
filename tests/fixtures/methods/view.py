"""Method-hosted source: a class endpoint whose tainted param flows cross-file into a sink.
Regression fixture for the graph.json projection join (must annotate the `.get()` method node,
not just module-level functions)."""
from flask import request

from dao import run_query


class UserView:
    def get(self):
        uid = request.args["id"]
        return run_query(uid)
