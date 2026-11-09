from concurrent.futures import ThreadPoolExecutor
import json
import pytest
from production_approval.authorization.identity import Denied

pytestmark = pytest.mark.integration


def authorize(w, vault, request_id):
    for a in ["approver-a", "approver-b"]:
        w.decide(vault["principals"][a]["token"], request_id, "approve")


def test_real_floci_deletion_and_replay(floci):
    vault, w, efs, requests, executor = floci
    token = lambda name: vault["principals"][name]["token"]
    ap = efs.seed()
    row = requests.submit(token("requester"), ap["AccessPointId"], "Floci integration")
    with pytest.raises(Denied):
        executor.execute(token("executor"), row["id"])
    assert not efs.absent(ap["AccessPointId"])
    authorize(w, vault, row["id"])
    receipt = executor.execute(token("executor"), row["id"])
    assert receipt["http_status"] == 204 and efs.absent(ap["AccessPointId"])
    with pytest.raises(Denied):
        executor.execute(token("executor"), row["id"])
    serialized = json.dumps(receipt)
    for principal in vault["principals"].values():
        assert principal["token"] not in serialized
    assert "SecretAccessKey" not in serialized and "SessionToken" not in serialized


def test_marker_drift_prevents_real_deletion(floci):
    vault, w, efs, requests, executor = floci
    token = lambda name: vault["principals"][name]["token"]
    ap = efs.seed()
    row = requests.submit(token("requester"), ap["AccessPointId"], "Marker drift test")
    authorize(w, vault, row["id"])
    efs.factory.client("efs").untag_resource(ResourceId=ap["AccessPointId"], TagKeys=["ApprovalPOC"])
    with pytest.raises(Denied, match="missing_disposable_marker"):
        executor.execute(token("executor"), row["id"])
    assert not efs.absent(ap["AccessPointId"])
    assert w.status(token("requester"), row["id"])["state"] == "FAILED"


def test_unmarked_resource_and_invalid_id_cannot_be_requested(floci):
    vault, w, efs, requests, executor = floci
    ap = efs.seed()
    raw = efs.factory.client("efs")
    raw.untag_resource(ResourceId=ap["AccessPointId"], TagKeys=["PocInstance"])
    with pytest.raises(Denied):
        requests.submit(vault["principals"]["requester"]["token"], ap["AccessPointId"], "Must deny")
    with pytest.raises(Denied):
        requests.submit(vault["principals"]["requester"]["token"], "arn:aws:elasticfilesystem:us-east-1:123457089012:access-point/prod", "Must deny")


def test_concurrent_floci_execution_only_one_receipt(floci):
    vault, w, efs, requests, executor = floci
    t = lambda name: vault["principals"][name]["token"]
    ap = efs.seed()
    row = requests.submit(t("requester"), ap["AccessPointId"], "Race test")
    authorize(w, vault, row["id"])
    def execute(_):
        try:
            return executor.execute(t("executor"), row["id"])
        except Denied:
            return None
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(execute, range(6)))
    assert sum(r is not None for r in results) == 1
    assert efs.absent(ap["AccessPointId"])


def test_approval_for_one_target_preserves_another(floci):
    vault, w, efs, requests, executor = floci
    t = lambda name: vault["principals"][name]["token"]
    first, second = efs.seed(), efs.seed()
    row = requests.submit(t("requester"), first["AccessPointId"], "Approve only the first access point")
    authorize(w, vault, row["id"])
    executor.execute(t("executor"), row["id"])
    assert efs.absent(first["AccessPointId"])
    assert not efs.absent(second["AccessPointId"])
    other = requests.submit(t("requester"), second["AccessPointId"], "Second target has no approvals")
    with pytest.raises(Denied):
        executor.execute(t("executor"), other["id"])
    assert not efs.absent(second["AccessPointId"])


def test_parent_filesystem_tag_drift_invalidates_approval(floci):
    vault, w, efs, requests, executor = floci
    t = lambda name: vault["principals"][name]["token"]
    ap = efs.seed()
    row = requests.submit(t("requester"), ap["AccessPointId"], "Bind parent filesystem preconditions")
    authorize(w, vault, row["id"])
    efs.factory.client("efs").tag_resource(ResourceId=ap["FileSystemId"], Tags=[{"Key": "AdditionalState", "Value": "changed"}])
    with pytest.raises(Denied, match="resource_changed"):
        executor.execute(t("executor"), row["id"])
    assert not efs.absent(ap["AccessPointId"])
