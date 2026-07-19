"""The receiver `svc` is only known to be a Service via its parameter annotation (Tier-3)."""
from flask import request
from svc import Service


def handler(svc: Service):
    q = request.args["q"]              # source
    return svc.query(q)               # svc: Service  -> binds Service.query -> cross-file SQLi
