"""Synthetic bearer authentication. The operator is the local trust root."""
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path


class Denied(RuntimeError):
    pass


@dataclass(frozen=True)
class Principal:
    person: str
    roles: frozenset


class TestIdentityProvider:
    __test__ = False

    def __init__(self, enrollment):
        self._principals = {
            hashlib.sha256(v["token"].encode()).hexdigest(): Principal(v["person"], frozenset(v["roles"]))
            for v in enrollment.values()
        }

    def authenticate(self, token):
        if not isinstance(token, str):
            raise Denied("unauthenticated")
        principal = self._principals.get(hashlib.sha256(token.encode()).hexdigest())
        if principal is None:
            raise Denied("unauthenticated")
        return principal

    def eligible(self, person, role):
        return any(p.person == person and role in p.roles for p in self._principals.values())


def enrollment(path):
    path = Path(path)
    if path.exists():
        if path.stat().st_mode & 0o077:
            raise Denied("test_identity_file_must_be_private")
        return json.loads(path.read_text())
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    identities = {
        "requester": ("person-alex", ["requester"]),
        "approver-a": ("person-blair", ["requester", "approver"]),
        "approver-a-alias": ("person-blair", ["approver"]),
        "approver-b": ("person-casey", ["approver"]),
        "approver-c": ("person-drew", ["approver"]),
        "executor": ("service-executor", ["executor"]),
        "outsider": ("person-outsider", []),
    }
    data = {"integrity_key": secrets.token_hex(32), "instance": secrets.token_hex(16),
            "principals": {name: {"person": person, "roles": roles, "token": secrets.token_urlsafe(32)}
                           for name, (person, roles) in identities.items()}}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    return data
