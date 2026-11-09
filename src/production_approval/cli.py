import argparse
import json
from pathlib import Path

from production_approval.authorization.identity import Denied
from production_approval.service import local_service

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description="Synthetic local-only multi-party EFS pilot")
    parser.add_argument("command", choices=["demo", "seed", "audit"])
    args = parser.parse_args()
    vault, workflow, efs, requests, executor = local_service(ROOT/".local")
    token = lambda name: vault["principals"][name]["token"]
    if args.command == "seed":
        print(json.dumps(efs.seed(), indent=2))
        return
    if args.command == "demo":
        target = efs.seed()
        row = requests.submit(token("requester"), target["AccessPointId"], "Delete this disposable Floci access point for the local pilot")
        request_id = row["id"]
        print("Created exact target:", target["AccessPointArn"])
        print("Request:", request_id, "payload hash:", row["payload_hash"])
        print("ALLOWED REQUESTED -> PENDING_APPROVAL: authenticated requester; exact disposable target")
        def denied(label, function):
            try:
                function()
            except Denied as e:
                print("DENIED", label, "control="+str(e))
            else:
                raise AssertionError("Expected denial: "+label)
        denied("execution without approval", lambda: executor.execute(token("executor"), request_id))
        denied("requester self-approval", lambda: workflow.decide(token("requester"), request_id, "approve"))
        workflow.decide(token("approver-a"), request_id, "approve")
        print("ALLOWED first approval: person-blair; state=PENDING_APPROVAL; quorum incomplete")
        denied("execution after one approval", lambda: executor.execute(token("executor"), request_id))
        workflow.decide(token("approver-b"), request_id, "approve")
        print("ALLOWED PENDING_APPROVAL -> APPROVED: person-casey; two distinct authorized non-requesters")
        receipt = executor.execute(token("executor"), request_id)
        assert efs.absent(target["AccessPointId"])
        print("ALLOWED APPROVED -> EXECUTING -> COMPLETED: atomic one-attempt claim; target revalidated; Floci deletion confirmed")
        denied("replay after completion", lambda: executor.execute(token("executor"), request_id))
        history = [e for e in workflow.store.history() if e.get("request_id") == request_id]
        print("AUDIT HISTORY")
        for e in history:
            print(json.dumps(e, sort_keys=True))
        print("DURABLE RECEIPT", json.dumps(receipt, indent=2))
        (ROOT/".local/last-receipt.json").write_text(json.dumps(receipt, indent=2)+"\n")
    events = workflow.store.history()
    (ROOT/".local/audit.jsonl").write_text("".join(json.dumps(e, sort_keys=True)+"\n" for e in events))
    if args.command == "audit":
        for event in events:
            print(json.dumps(event, sort_keys=True))


if __name__ == "__main__":
    main()
