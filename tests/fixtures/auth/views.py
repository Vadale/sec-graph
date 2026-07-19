"""Auth-barrier fixtures for unguarded-sink detection: a decorator guard, an early-return gate,
an in-arm check, a cross-hop decorator, and a genuinely unguarded sink. The `login_required`
stub and `current_user` stand-in only need the right NAMES -- detection is structural."""
from flask import request, abort
import sqlite3


def login_required(f):
    return f


class _User:
    is_authenticated = False
    is_admin = False


current_user = _User()


@login_required
def guarded_by_decorator():
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT " + q)                 # B1: guarded by @login_required


def guarded_by_gate():
    if not current_user.is_authenticated:
        abort(401)                              # failure arm terminates
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT " + q)                 # B3: guarded by the dominating gate


def guarded_in_arm():
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    if current_user.is_admin:
        conn.execute("SELECT " + q)             # B2: guarded, sink in the authorised arm


def unguarded_sink():
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT " + q)                 # UNGUARDED: no barrier on the path


@login_required
def guarded_cross_hop():
    _helper(request.args["id"])                 # barrier is on the caller; sink is in the callee


def _helper(x):
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT " + x)                 # guarded via guarded_cross_hop's decorator (_lift)


def not_a_gate():
    if current_user.is_authenticated:
        _log()                                  # no terminating arm -> does NOT gate
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT " + q)                 # UNGUARDED (soundness: a non-terminating if is no gate)


def inverted_gate():
    if current_user.is_authenticated:
        abort(401)                              # aborts when authorised -> passing means UN-authorised
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT " + q)                 # UNGUARDED (soundness: polarity must not flip)


def or_bypass():
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    if current_user.is_authenticated or app_debug:
        conn.execute("SELECT " + q)             # UNGUARDED: reachable when app_debug and anonymous


def or_bypass_gate():
    if current_user.is_authenticated or app_debug:
        pass
    else:
        return                                  # else-return does NOT prove authenticated
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT " + q)                 # UNGUARDED (compound-test gate must not credit)


def and_not_authed():
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    if app_flag and not current_user.is_authenticated:
        conn.execute("SELECT " + q)             # UNGUARDED: this arm runs only when NOT authed


def and_authed():
    q = request.args["q"]
    conn = sqlite3.connect("x.db")
    if current_user.is_admin and app_flag:
        conn.execute("SELECT " + q)             # GUARDED: admin AND flag => admin (sound to credit)
