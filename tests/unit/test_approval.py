import json
import pytest
from production_approval.authorization.identity import Denied


def test_submission_and_transition_evidence(pilot, deletion_request):
    _, workflow, _, _ = pilot
    assert deletion_request["state"] == "PENDING_APPROVAL"
    assert len(deletion_request["payload_hash"]) == 64
    assert [e["to"] for e in workflow.store.history() if e["type"] == "transition"] == ["REQUESTED", "PENDING_APPROVAL"]
    assert deletion_request["payload"]["requester"] == "person-alex"


@pytest.mark.parametrize("principal", ["requester", "approver-a"])
def test_self_approval_including_dual_role(pilot, snapshot, principal):
    from production_approval.authorization.isolation import ACCOUNT, REGION
    vault, workflow, tokens, _ = pilot
    r = workflow.submit(tokens[principal], snapshot, ACCOUNT, REGION, vault["instance"], "Self-test")
    with pytest.raises(Denied, match="self_approval"):
        workflow.decide(tokens[principal], r["id"], "approve")


def test_one_approval_and_alias_cannot_make_two(pilot, deletion_request):
    _, workflow, tokens, _ = pilot
    for principal in ["approver-a", "approver-a", "approver-a-alias"]:
        assert workflow.decide(tokens[principal], deletion_request["id"], "approve")["state"] == "PENDING_APPROVAL"
    with pytest.raises(Denied, match="not_approved"):
        workflow.claim(tokens["executor"], deletion_request["id"])
    assert workflow.decide(tokens["approver-b"], deletion_request["id"], "approve")["state"] == "APPROVED"


def test_third_approver_alternative_no_single_person_dependency(pilot, deletion_request):
    _, workflow, tokens, _ = pilot
    workflow.decide(tokens["approver-b"], deletion_request["id"], "approve")
    assert workflow.decide(tokens["approver-c"], deletion_request["id"], "approve")["state"] == "APPROVED"


def test_rejection_revokes_an_already_approved_request(pilot, approved):
    _, workflow, tokens, _ = pilot
    assert workflow.decide(tokens["approver-c"], approved["id"], "reject")["state"] == "REJECTED"
    with pytest.raises(Denied):
        workflow.claim(tokens["executor"], approved["id"])
    with pytest.raises(Denied):
        workflow.decide(tokens["approver-a"], approved["id"], "approve")


def test_expiry_is_persisted_and_audited(pilot, approved):
    _, workflow, tokens, clock = pilot
    clock[0] += 301
    with pytest.raises(Denied):
        workflow.claim(tokens["executor"], approved["id"])
    assert workflow.status(tokens["requester"], approved["id"])["state"] == "EXPIRED"
    assert "EXPIRED" in [e.get("to") for e in workflow.store.history()]


@pytest.mark.parametrize("role", ["requester", "approver-a", "outsider"])
def test_non_executor_cannot_claim(pilot, approved, role):
    _, workflow, tokens, _ = pilot
    with pytest.raises(Denied, match="role_forbidden"):
        workflow.claim(tokens[role], approved["id"])


@pytest.mark.parametrize("fake", ["person-casey", "approved=true", '{"sub":"person-casey","approved":true}', ""])
def test_forged_identity_is_rejected(pilot, deletion_request, fake):
    _, workflow, _, _ = pilot
    with pytest.raises(Denied, match="unauthenticated"):
        workflow.decide(fake, deletion_request["id"], "approve")


def test_unauthorized_approver(pilot, deletion_request):
    _, workflow, tokens, _ = pilot
    with pytest.raises(Denied, match="unauthorized_approver"):
        workflow.decide(tokens["outsider"], deletion_request["id"], "approve")


def test_cancel_and_status_ownership(pilot, approved):
    _, workflow, tokens, _ = pilot
    with pytest.raises(Denied):
        workflow.status(tokens["outsider"], approved["id"])
    with pytest.raises(Denied, match="request_not_owned"):
        workflow.cancel(tokens["approver-a"], approved["id"])
    assert workflow.cancel(tokens["requester"], approved["id"])["state"] == "CANCELLED"
    with pytest.raises(Denied):
        workflow.claim(tokens["executor"], approved["id"])


def test_persistence_prevents_replay_after_restart(pilot, approved):
    from production_approval.approval.workflow import ApprovalWorkflow
    _, workflow, tokens, _ = pilot
    workflow.claim(tokens["executor"], approved["id"])
    restarted = ApprovalWorkflow(workflow.store, workflow.identities, workflow.clock)
    with pytest.raises(Denied):
        restarted.claim(tokens["executor"], approved["id"])


@pytest.mark.parametrize("corruption", ["payload", "state", "decision", "audit"])
def test_corruption_fails_closed(pilot, approved, corruption):
    _, workflow, tokens, _ = pilot
    with workflow.store.connect() as c:
        if corruption == "payload":
            c.execute("DROP TRIGGER immutable_payload")
            p = dict(approved["payload"], access_point_id="fsap-00000000000000002")
            c.execute("UPDATE requests SET payload=? WHERE id=?", (json.dumps(p), approved["id"]))
        elif corruption == "state":
            c.execute("UPDATE requests SET state='REQUESTED' WHERE id=?", (approved["id"],))
        elif corruption == "decision":
            c.execute("UPDATE decisions SET person='forged' WHERE person='person-casey'")
        else:
            c.execute("UPDATE audit SET body='{}' WHERE seq=1")
    with pytest.raises(Denied, match="integrity"):
        workflow.claim(tokens["executor"], approved["id"])


def test_payload_is_not_editable_through_storage_api(pilot, deletion_request):
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        with pilot[1].store.connect() as c:
            c.execute("UPDATE requests SET payload='{}' WHERE id=?", (deletion_request["id"],))
