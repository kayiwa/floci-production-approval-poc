"""Local SSM-replaceable state adapter; no boto3 or AWS integration imports."""
import time
import uuid
from datetime import datetime, timezone

from production_approval.authorization.identity import Denied
from production_approval.audit.store import digest

POLICY = "local-two-human-v1"
OPERATION = "DeleteEfsAccessPoint"


def timestamp(now):
    return datetime.fromtimestamp(now, timezone.utc).isoformat()


def epoch(value):
    return datetime.fromisoformat(value).timestamp()


class ApprovalWorkflow:
    def __init__(self, store, identities, clock=time.time):
        self.store, self.identities, self.clock = store, identities, clock

    def call(self, token, role, request_id, function):
        result = None
        error = None
        with self.store.transaction() as c:
            actor = "unauthenticated"
            try:
                principal = self.identities.authenticate(token)
                actor = principal.person
                if role is not None and role not in principal.roles:
                    raise Denied("role_forbidden")
                result = function(c, principal)
            except Denied as e:
                error = e
                self.store.event(c, {"type": "denied", "request_id": request_id, "actor": actor,
                                     "reason": str(e), "timestamp": timestamp(self.clock())})
        if error:
            raise error
        return result

    def submit(self, token, snapshot, account, region, instance, justification, ttl=300):
        request_id = str(uuid.uuid4())
        def operation(c, principal):
            if not 0 < ttl <= 900 or not isinstance(justification, str) or not justification.strip() or len(justification) > 1000:
                raise Denied("invalid_request")
            now = self.clock()
            payload = {"request_id": request_id, "requester": principal.person, "account": account,
                       "region": region, "filesystem_id": snapshot["FileSystemId"],
                       "access_point_id": snapshot["AccessPointId"], "operation": OPERATION,
                       "resource_tags": snapshot["Tags"], "resource_snapshot": snapshot,
                       "instance": instance, "created_at": timestamp(now),
                       "approval_expires_at": timestamp(now+ttl), "policy_version": POLICY,
                       "justification": justification}
            self.store.create(c, payload)
            row = self.store.row(c, request_id)
            self.store.event(c, {"type": "transition", "request_id": request_id, "from": None,
                                 "to": "REQUESTED", "actor": principal.person, "timestamp": timestamp(now),
                                 "payload_hash": row["payload_hash"]})
            self.store.state(c, row, "PENDING_APPROVAL", principal.person, timestamp(now))
            return row
        return self.call(token, "requester", request_id, operation)

    def expire(self, c, row):
        if row["state"] in {"REQUESTED", "PENDING_APPROVAL", "APPROVED"} and self.clock() >= epoch(row["payload"]["approval_expires_at"]):
            self.store.state(c, row, "EXPIRED", "workflow", timestamp(self.clock()))

    def status(self, token, request_id):
        def operation(c, principal):
            row = self.store.row(c, request_id)
            if principal.person != row["payload"]["requester"] and "approver" not in principal.roles and "executor" not in principal.roles:
                raise Denied("request_not_owned")
            self.expire(c, row)
            return row
        # Authenticated role access is checked individually rather than a client role name.
        return self.call(token, None, request_id, operation)

    def decide(self, token, request_id, decision):
        # Authenticate before the self check, including a requester-only principal.
        def operation(c, principal):
            row = self.store.row(c, request_id)
            if principal.person == row["payload"]["requester"]:
                raise Denied("self_approval_forbidden")
            if "approver" not in principal.roles:
                raise Denied("unauthorized_approver")
            self.expire(c, row)
            if row["state"] not in {"PENDING_APPROVAL", "APPROVED"}:
                raise Denied("request_not_approvable")
            if decision not in {"approve", "reject"}:
                raise Denied("invalid_decision")
            existing = c.execute("SELECT decision FROM decisions WHERE request_id=? AND person=?", (request_id, principal.person)).fetchone()
            if existing and existing[0] == decision:
                self.store.event(c, {"type": "duplicate_decision", "request_id": request_id, "actor": principal.person,
                                     "timestamp": timestamp(self.clock())})
                return row
            if row["state"] == "APPROVED" and decision != "reject":
                raise Denied("quorum_already_closed")
            signed = [request_id, row["payload_hash"], principal.person, decision]
            c.execute("INSERT OR REPLACE INTO decisions VALUES (?,?,?,?)", (request_id, principal.person, decision, self.store.mac(signed)))
            self.store.event(c, {"type": "decision", "request_id": request_id, "actor": principal.person,
                                 "decision": decision, "payload_hash": row["payload_hash"], "timestamp": timestamp(self.clock())})
            if decision == "reject":
                self.store.state(c, row, "REJECTED", principal.person, timestamp(self.clock()))
            elif len(self.approvers(c, row)) >= 2:
                self.store.state(c, row, "APPROVED", "workflow", timestamp(self.clock()))
            return row
        return self.call(token, None, request_id, operation)

    def approvers(self, c, row):
        import hmac
        result = []
        for d in c.execute("SELECT * FROM decisions WHERE request_id=?", (row["id"],)):
            if not hmac.compare_digest(d["signature"], self.store.mac([row["id"], row["payload_hash"], d["person"], d["decision"]])):
                raise Denied("decision_integrity_failure")
            if d["decision"] != "approve" or d["person"] == row["payload"]["requester"] or not self.identities.eligible(d["person"], "approver"):
                raise Denied("invalid_approval")
            result.append(d["person"])
        return sorted(set(result))

    def cancel(self, token, request_id):
        def operation(c, principal):
            row = self.store.row(c, request_id)
            self.expire(c, row)
            if row["payload"]["requester"] != principal.person:
                raise Denied("request_not_owned")
            if row["state"] not in {"REQUESTED", "PENDING_APPROVAL", "APPROVED"}:
                raise Denied("cannot_cancel")
            self.store.state(c, row, "CANCELLED", principal.person, timestamp(self.clock()))
            return row
        return self.call(token, "requester", request_id, operation)

    def claim(self, token, request_id):
        def operation(c, principal):
            row = self.store.row(c, request_id)
            self.expire(c, row)
            p = row["payload"]
            if row["state"] != "APPROVED":
                raise Denied("request_not_approved_or_already_consumed")
            approvers = self.approvers(c, row)
            if p["operation"] != OPERATION or p["policy_version"] != POLICY or len(approvers) != 2:
                raise Denied("invalid_execution_authorization")
            resource = p["account"]+":"+p["region"]+":"+p["access_point_id"]
            previous = c.execute("SELECT request_id FROM claims WHERE resource=?", (resource,)).fetchone()
            if previous:
                old = self.store.row(c, previous[0])
                if old["state"] == "EXECUTING" or old["state"] == "COMPLETED" or (old["receipt"] or {}).get("api_submitted"):
                    raise Denied("resource_already_claimed_or_indeterminate")
            c.execute("INSERT OR REPLACE INTO claims VALUES (?,?)", (resource, request_id))
            receipt = {"request_id": request_id, "payload_hash": row["payload_hash"], "requester": p["requester"],
                       "approvers": approvers, "executor": principal.person, "claim_id": str(uuid.uuid4()),
                       "claimed_at": timestamp(self.clock()), "account": p["account"], "region": p["region"],
                       "filesystem_id": p["filesystem_id"], "access_point_id": p["access_point_id"],
                       "operation": OPERATION, "policy_version": POLICY, "api_submitted": False}
            self.store.state(c, row, "EXECUTING", principal.person, timestamp(self.clock()), receipt)
            return row
        return self.call(token, "executor", request_id, operation)

    def execution_event(self, token, request_id, state, additions):
        def operation(c, principal):
            row = self.store.row(c, request_id)
            if row["state"] != "EXECUTING" or state not in {"EXECUTING", "COMPLETED", "FAILED"}:
                raise Denied("invalid_execution_transition")
            receipt = dict(row["receipt"], **additions)
            self.store.state(c, row, state, principal.person, timestamp(self.clock()), receipt)
            return row
        return self.call(token, "executor", request_id, operation)
