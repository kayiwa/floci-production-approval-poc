from pathlib import Path
import json
import os

from production_approval.authorization.identity import enrollment, TestIdentityProvider, Denied
from production_approval.authorization.isolation import LocalClients, ACCOUNT, REGION, assert_local_environment
from production_approval.audit.store import Store
from production_approval.approval.workflow import ApprovalWorkflow
from production_approval.executor.efs import FlociEfs, setup_executor
from production_approval.executor.service import Executor


class RequestService:
    def __init__(self, workflow, gateway):
        self._workflow, self._gateway = workflow, gateway

    def submit(self, token, access_point_id, justification, ttl=300):
        # Authenticate before AWS reads. The client supplies no identity, tags,
        # account, Region, operation, policy version or approved payload.
        principal = self._workflow.identities.authenticate(token)
        if "requester" not in principal.roles:
            raise Denied("role_forbidden")
        snapshot = self._gateway.snapshot(access_point_id)
        return self._workflow.submit(token, snapshot, ACCOUNT, REGION, self._gateway.instance, justification, ttl)


def local_service(directory):
    assert_local_environment()
    directory = Path(directory)
    vault = enrollment(directory/"test-identities.json")
    factory = LocalClients()
    store = Store(directory/"approvals.sqlite3", vault["integrity_key"])
    workflow = ApprovalWorkflow(store, TestIdentityProvider(vault["principals"]))
    # Bootstrap never returns these credentials through the request/approval API.
    broker_file = directory/"floci-broker.json"
    if broker_file.exists():
        if broker_file.stat().st_mode & 0o077:
            raise Denied("broker_credential_file_must_be_private")
        saved = json.loads(broker_file.read_text())
        broker = factory.admit_floci_credentials(saved["credentials"])
        role = saved["role"]
    else:
        broker, role = setup_executor(factory, vault["instance"])
        fd = os.open(broker_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"credentials": {"AccessKeyId": broker.key, "SecretAccessKey": broker.secret}, "role": role}, f)
    gateway = FlociEfs(factory, vault["instance"], broker, role)
    return vault, workflow, gateway, RequestService(workflow, gateway), Executor(workflow, gateway)
