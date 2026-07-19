"""A hardcoded secret in a module-level constant (the settings.py pattern) flowing to a sink,
plus a shadowing-local case that must NOT leak the constant's secret."""
SECRET_KEY = "AKIATESTKEY1234567AB"          # synthetic AWS-key-shaped test value (not real)
DEFAULT_TOKEN = "AKIA9876543210ZYXWVU"       # secret VALUE, but a non-credential-named constant


def use_key():
    conn = get_conn()
    return conn.execute("SELECT '%s'" % SECRET_KEY)   # hardcoded credential -> dangerous-sink


def refresh():
    DEFAULT_TOKEN = fetch_from_vault()                # untainted local SHADOWS the module constant
    conn = get_conn()
    return conn.execute("SELECT '%s'" % DEFAULT_TOKEN)  # must NOT leak the constant's secret
