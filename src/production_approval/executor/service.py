"""Executor takes only a request ID. No arbitrary API/ARN/command entry point."""
from production_approval.authorization.identity import Denied
from production_approval.authorization.isolation import ACCOUNT, REGION, ENDPOINT, assert_local_environment
from production_approval.approval.workflow import epoch, timestamp
from production_approval.audit.store import digest


class Executor:
    def __init__(self, workflow, gateway):
        self._workflow, self._gateway = workflow, gateway

    def execute(self, token, request_id):
        assert_local_environment()
        w = self._workflow
        row = w.claim(token, request_id)  # durable intent and one-attempt claim
        p = row["payload"]
        try:
            if p["account"] != ACCOUNT or p["region"] != REGION or p["instance"] != self._gateway.instance:
                raise Denied("wrong_execution_environment")
            current = self._gateway.snapshot(p["access_point_id"])
            if current["FileSystemId"] != p["filesystem_id"] or digest(current) != digest(p["resource_snapshot"]):
                raise Denied("resource_changed_new_approval_required")
            if w.clock() >= epoch(p["approval_expires_at"]):
                raise Denied("approval_expired_before_api_call")
            w.execution_event(token, request_id, "EXECUTING", {"api_submitted": True, "endpoint": ENDPOINT})
            result = self._gateway.delete(current, request_id)
            if not self._gateway.absent(p["access_point_id"]):
                raise Denied("deletion_not_confirmed")
            return w.execution_event(token, request_id, "COMPLETED", dict(result,
                completed_at=timestamp(w.clock()), outcome="deleted", resource_revalidated=True,
                target_absent=True, endpoint=ENDPOINT))["receipt"]
        except Exception as e:
            # Never retry after a failure, including an uncertain network outcome.
            # Error text is deliberately not serialized (it could contain secrets).
            reason = str(e) if isinstance(e, Denied) else type(e).__name__
            w.execution_event(token, request_id, "FAILED", {"error": reason, "failed_at": timestamp(w.clock()), "outcome": "failed"})
            raise Denied("execution_failed:"+reason) from e
