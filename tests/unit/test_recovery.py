import copy
import pytest
from production_approval.authorization.identity import Denied
from production_approval.authorization.isolation import ACCOUNT, REGION
from production_approval.executor.service import Executor


class Gateway:
    def __init__(self, snapshot, instance):
        self.instance, self.current, self.calls = instance, copy.deepcopy(snapshot), 0

    def snapshot(self, _):
        return self.current

    def delete(self, *_):
        self.calls += 1
        return {"http_status": 204}

    def absent(self, _):
        return True


def approve_new(pilot, snapshot):
    vault, w, t, _ = pilot
    row = w.submit(t["requester"], snapshot, ACCOUNT, REGION, vault["instance"], "Explicit retry with new review")
    for approver in ["approver-a", "approver-b"]:
        w.decide(t[approver], row["id"], "approve")
    return row


def test_pre_api_failure_requires_new_request_and_fresh_approvals(pilot, snapshot, approved):
    vault, w, t, _ = pilot
    gateway = Gateway(snapshot, vault["instance"])
    gateway.current["LifeCycleState"] = "changed"
    with pytest.raises(Denied, match="resource_changed"):
        Executor(w, gateway).execute(t["executor"], approved["id"])
    assert w.status(t["requester"], approved["id"])["receipt"]["api_submitted"] is False
    gateway.current = snapshot
    with pytest.raises(Denied):
        Executor(w, gateway).execute(t["executor"], approved["id"])
    fresh = approve_new(pilot, snapshot)
    Executor(w, gateway).execute(t["executor"], fresh["id"])
    assert gateway.calls == 1


def test_indeterminate_api_failure_blocks_even_a_new_request(pilot, snapshot, approved):
    vault, w, t, _ = pilot
    gateway = Gateway(snapshot, vault["instance"])
    def timeout(*_):
        gateway.calls += 1
        raise TimeoutError()
    gateway.delete = timeout
    with pytest.raises(Denied):
        Executor(w, gateway).execute(t["executor"], approved["id"])
    fresh = approve_new(pilot, snapshot)
    with pytest.raises(Denied, match="indeterminate"):
        Executor(w, gateway).execute(t["executor"], fresh["id"])
    assert gateway.calls == 1


def test_expiry_between_claim_and_api_consumes_attempt(pilot, snapshot, approved):
    vault, w, t, clock = pilot
    gateway = Gateway(snapshot, vault["instance"])
    def slow_snapshot(_):
        clock[0] += 301
        return snapshot
    gateway.snapshot = slow_snapshot
    with pytest.raises(Denied, match="approval_expired_before_api_call"):
        Executor(w, gateway).execute(t["executor"], approved["id"])
    assert gateway.calls == 0
    assert w.status(t["requester"], approved["id"])["state"] == "FAILED"


def test_unconfirmed_deletion_is_failed_not_retried(pilot, snapshot, approved):
    vault, w, t, _ = pilot
    gateway = Gateway(snapshot, vault["instance"])
    gateway.absent = lambda _: False
    with pytest.raises(Denied, match="deletion_not_confirmed"):
        Executor(w, gateway).execute(t["executor"], approved["id"])
    with pytest.raises(Denied):
        Executor(w, gateway).execute(t["executor"], approved["id"])
    assert gateway.calls == 1


def test_audit_failure_prevents_execution(pilot, snapshot, approved, monkeypatch):
    vault, w, t, _ = pilot
    gateway = Gateway(snapshot, vault["instance"])
    def unavailable(*_):
        raise OSError("audit unavailable")
    monkeypatch.setattr(w.store, "event", unavailable)
    with pytest.raises(OSError):
        Executor(w, gateway).execute(t["executor"], approved["id"])
    assert gateway.calls == 0


def test_rejected_pending_request_is_terminal(pilot, deletion_request):
    _, w, t, _ = pilot
    w.decide(t["approver-a"], deletion_request["id"], "reject")
    with pytest.raises(Denied):
        w.decide(t["approver-b"], deletion_request["id"], "approve")
    with pytest.raises(Denied):
        w.claim(t["executor"], deletion_request["id"])
