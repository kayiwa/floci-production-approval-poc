import os
import socket
import pytest

from production_approval.authorization.isolation import assert_local_environment, ENDPOINT, REGION


@pytest.fixture(autouse=True)
def isolated_network(monkeypatch):
    # Every test starts with explicit local configuration; negative tests then
    # deliberately mutate it. No production credential file is ever loaded.
    for name in list(os.environ):
        if name.startswith("AWS_"):
            monkeypatch.delenv(name)
    for name, value in {
        "AWS_ENDPOINT_URL": ENDPOINT, "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test",
        "AWS_CONFIG_FILE": os.devnull, "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "AWS_EC2_METADATA_DISABLED": "true", "AWS_REGION": REGION, "AWS_DEFAULT_REGION": REGION,
    }.items():
        monkeypatch.setenv(name, value)
    assert_local_environment()
    connect, getaddrinfo = socket.socket.connect, socket.getaddrinfo
    def guarded_connect(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6) and address[:2] != ("127.0.0.1", 4570):
            raise AssertionError("Test attempted non-Floci network access")
        return connect(sock, address)
    def guarded_lookup(host, port, *args, **kwargs):
        if (host, port) != ("127.0.0.1", 4570):
            raise AssertionError("Test attempted non-Floci DNS/endpoint discovery")
        return getaddrinfo(host, port, *args, **kwargs)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_lookup)


@pytest.fixture
def pilot(tmp_path):
    from production_approval.authorization.identity import enrollment, TestIdentityProvider
    from production_approval.audit.store import Store
    from production_approval.approval.workflow import ApprovalWorkflow
    vault = enrollment(tmp_path/"identities.json")
    clock = [1800000000.0]
    workflow = ApprovalWorkflow(Store(tmp_path/"approvals.sqlite3", vault["integrity_key"]),
                                TestIdentityProvider(vault["principals"]), clock=lambda: clock[0])
    tokens = {k: v["token"] for k, v in vault["principals"].items()}
    return vault, workflow, tokens, clock


@pytest.fixture
def snapshot(pilot):
    from production_approval.executor.efs import tags
    from production_approval.authorization.isolation import ACCOUNT, REGION
    vault = pilot[0]
    return {"AccessPointId": "fsap-00000000000000001", "FileSystemId": "fs-00000000000000001",
            "AccessPointArn": f"arn:aws:elasticfilesystem:{REGION}:{ACCOUNT}:access-point/fsap-00000000000000001",
            "OwnerId": ACCOUNT, "LifeCycleState": "available", "Tags": tags(vault["instance"])}


@pytest.fixture
def deletion_request(pilot, snapshot):
    from production_approval.authorization.isolation import ACCOUNT, REGION
    vault, workflow, tokens, _ = pilot
    return workflow.submit(tokens["requester"], snapshot, ACCOUNT, REGION, vault["instance"], "Disposable pilot test")


@pytest.fixture
def approved(pilot, deletion_request):
    _, workflow, tokens, _ = pilot
    for person in ["approver-a", "approver-b"]:
        workflow.decide(tokens[person], deletion_request["id"], "approve")
    return workflow.status(tokens["requester"], deletion_request["id"])


@pytest.fixture
def floci(tmp_path):
    # Runs for each integration test, never silently skips to an AWS endpoint.
    assert_local_environment()
    from production_approval.service import local_service
    return local_service(tmp_path/"service")
