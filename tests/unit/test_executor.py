import copy
from concurrent.futures import ThreadPoolExecutor
import threading
import pytest
from production_approval.authorization.identity import Denied
from production_approval.executor.service import Executor


class FakeEfs:
    def __init__(self, snapshot, instance):
        self.instance = instance
        self.current = copy.deepcopy(snapshot)
        self.calls = 0
        self.lock = threading.Lock()
    def snapshot(self, _):
        return copy.deepcopy(self.current)
    def delete(self, snapshot, request_id):
        with self.lock:
            self.calls += 1
        return {"aws_request_id": "local-fake", "execution_role": "simulated"}
    def absent(self, _):
        return True


def test_execution_and_receipt_without_credentials(pilot, snapshot, approved):
    vault, w, t, _ = pilot
    gateway = FakeEfs(snapshot, vault["instance"])
    receipt = Executor(w, gateway).execute(t["executor"], approved["id"])
    assert gateway.calls == 1
    assert receipt["approvers"] == ["person-blair", "person-casey"]
    assert receipt["payload_hash"] == approved["payload_hash"]
    assert not any("secret" in k.lower() or "accesskey" in k.lower() or "token" in k.lower() for k in receipt)
    with pytest.raises(Denied):
        Executor(w, gateway).execute(t["executor"], approved["id"])
    assert gateway.calls == 1


@pytest.mark.parametrize("mutation", ["FileSystemId", "AccessPointId", "Tags", "LifeCycleState"])
def test_target_change_consumes_attempt_without_deleting(pilot, snapshot, approved, mutation):
    vault, w, t, _ = pilot
    gateway = FakeEfs(snapshot, vault["instance"])
    gateway.current[mutation] = [] if mutation == "Tags" else "changed"
    with pytest.raises(Denied, match="resource_changed"):
        Executor(w, gateway).execute(t["executor"], approved["id"])
    assert gateway.calls == 0
    assert w.status(t["requester"], approved["id"])["state"] == "FAILED"
    gateway.current = snapshot
    with pytest.raises(Denied):
        Executor(w, gateway).execute(t["executor"], approved["id"])


def test_concurrent_executions_across_independent_workflows(pilot, snapshot, approved):
    from production_approval.approval.workflow import ApprovalWorkflow
    vault, w, t, _ = pilot
    gateway = FakeEfs(snapshot, vault["instance"])
    barrier = threading.Barrier(8)
    def attempt(_):
        barrier.wait()
        other = ApprovalWorkflow(w.store, w.identities, w.clock)
        try:
            return Executor(other, gateway).execute(t["executor"], approved["id"])
        except Denied:
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert sum(r is not None for r in results) == 1
    assert gateway.calls == 1


def test_two_approved_requests_for_same_resource_are_serialized(pilot, snapshot, approved):
    from production_approval.authorization.isolation import ACCOUNT, REGION
    vault, w, t, _ = pilot
    other = w.submit(t["requester"], snapshot, ACCOUNT, REGION, vault["instance"], "Explicit second request")
    for approver in ["approver-a", "approver-b"]:
        w.decide(t[approver], other["id"], "approve")
    gateway = FakeEfs(snapshot, vault["instance"])
    def execute(request_id):
        try:
            return Executor(w, gateway).execute(t["executor"], request_id)
        except Denied:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(execute, [approved["id"], other["id"]]))
    assert sum(r is not None for r in result) == 1
    assert gateway.calls == 1


@pytest.mark.parametrize("field,bad", [("account", "123457089012"), ("region", "eu-west-1"), ("instance", "another-instance")])
def test_wrong_environment_rejected(pilot, snapshot, field, bad):
    from production_approval.authorization.isolation import ACCOUNT, REGION
    vault, w, t, _ = pilot
    values = {"account": ACCOUNT, "region": REGION, "instance": vault["instance"]}
    values[field] = bad
    r = w.submit(t["requester"], snapshot, **values, justification="Negative test")
    for a in ["approver-a", "approver-b"]:
        w.decide(t[a], r["id"], "approve")
    gateway = FakeEfs(snapshot, vault["instance"])
    with pytest.raises(Denied, match="wrong_execution_environment"):
        Executor(w, gateway).execute(t["executor"], r["id"])
    assert gateway.calls == 0


def test_api_failure_is_not_retried(pilot, snapshot, approved):
    vault, w, t, _ = pilot
    gateway = FakeEfs(snapshot, vault["instance"])
    def fail(*_):
        gateway.calls += 1
        raise TimeoutError("indeterminate API result")
    gateway.delete = fail
    with pytest.raises(Denied, match="TimeoutError"):
        Executor(w, gateway).execute(t["executor"], approved["id"])
    assert w.status(t["requester"], approved["id"])["receipt"]["api_submitted"]
    with pytest.raises(Denied):
        Executor(w, gateway).execute(t["executor"], approved["id"])
    assert gateway.calls == 1
