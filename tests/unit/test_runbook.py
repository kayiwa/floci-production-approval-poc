from pathlib import Path
import json
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_runbook_structure_and_non_deployable_guard():
    doc = yaml.safe_load((ROOT/"runbooks/protected-efs-access-point-deletion.yaml").read_text())
    assert doc["schemaVersion"] == "0.3"
    steps = doc["mainSteps"]
    assert steps[0]["name"] == "designOnlyAbort" and steps[0]["onFailure"] == "Abort"
    namespace = {}
    exec(steps[0]["inputs"]["Script"], namespace)
    with pytest.raises(RuntimeError, match="DESIGN ONLY"):
        namespace["block"]({}, {})
    approval = next(s for s in steps if s["action"] == "aws:approve")
    assert approval["inputs"]["MinRequiredApprovals"] == 2
    assert len(set(approval["inputs"]["Approvers"])) == 3
    assert approval["timeoutSeconds"] == 300 and approval["onFailure"] == "Abort"
    assert set(doc["parameters"]) == {"RequestId"}
    assert "000000000000" in doc["assumeRole"] and "NOT_DEPLOYED" in doc["assumeRole"]
    assert not any(s["action"] == "aws:executeAwsApi" for s in steps)


@pytest.mark.parametrize("name,handler,valid", [
    ("decodeRequestHash", "decode", {"request_id": "request", "request_hash": "a"*64}),
    ("verifyDeletionReceipt", "verify", {"request_id": "request", "payload_hash": "a"*64, "outcome": "deleted"}),
])
def test_runbook_decode_checks_exact_request_and_receipt(name, handler, valid):
    doc = yaml.safe_load((ROOT/"runbooks/protected-efs-access-point-deletion.yaml").read_text())
    step = next(s for s in doc["mainSteps"] if s["name"] == name)
    namespace = {}
    exec(step["inputs"]["Script"], namespace)
    events = {"request_id": "request", "request_hash": "a"*64, "raw": json.dumps(valid)}
    assert namespace[handler](events, {})
    events["request_id"] = "another-request"
    with pytest.raises(ValueError):
        namespace[handler](events, {})
