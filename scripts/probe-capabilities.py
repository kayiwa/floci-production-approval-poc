"""Read/write probes against disposable Floci state, never real AWS."""
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from botocore.exceptions import ClientError
from production_approval.authorization.isolation import LocalClients, ACCOUNT, REGION, MARKER

root = Path(__file__).resolve().parents[1]
out = root / "docs/evidence"
out.mkdir(parents=True, exist_ok=True)
clients = LocalClients()
results = {"floci_version": "2.4.0", "image_digest": "sha256:3df9677724e36251801f3828ea0bdcc2818afa96d8ec53f1741eaffdaeb990e1", "endpoint": "http://127.0.0.1:4570", "account": ACCOUNT, "region": REGION, "operations": {}}
results["observed_at"] = datetime.now(timezone.utc).isoformat()
suffix = uuid.uuid4().hex[:12]


def probe(name, function):
    try:
        result = function()
        results["operations"][name] = {"implemented": True, "call_succeeded": True, "http_status": result.get("ResponseMetadata", {}).get("HTTPStatusCode")}
        print(name, "OK", flush=True)
        return result
    except ClientError as e:
        results["operations"][name] = {"implemented": e.response["Error"]["Code"] != "UnsupportedOperation", "call_succeeded": False, "code": e.response["Error"]["Code"], "message": e.response["Error"].get("Message", "")[:350]}
        print(name, results["operations"][name], flush=True)
        return None


efs = clients.client("efs")
tags = [{"Key": k, "Value": v} for k, v in MARKER.items()]
fs = probe("efs.CreateFileSystem", lambda: efs.create_file_system(CreationToken="poc-probe-"+suffix, Tags=tags))
if fs:
    ap = probe("efs.CreateAccessPoint", lambda: efs.create_access_point(FileSystemId=fs["FileSystemId"], ClientToken="poc-probe-"+suffix, Tags=tags))
    probe("efs.DescribeAccessPoints", lambda: efs.describe_access_points(FileSystemId=fs["FileSystemId"]))
    if ap:
        results["efs_sample"] = {k: v for k, v in ap.items() if k != "ResponseMetadata"}
        probe("efs.DeleteAccessPoint", lambda: efs.delete_access_point(AccessPointId=ap["AccessPointId"]))
        deleted = probe("efs.DescribeDeletedAccessPoint", lambda: efs.describe_access_points(AccessPointId=ap["AccessPointId"]))
        results["efs_deleted_absent"] = bool(deleted is not None and not deleted["AccessPoints"])

iam = clients.client("iam")
deny = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
probe("iam.CreatePolicy", lambda: iam.create_policy(PolicyName="poc-probe-"+suffix, PolicyDocument=deny))
sim = probe("iam.SimulateCustomPolicy", lambda: iam.simulate_custom_policy(PolicyInputList=[deny], ActionNames=["elasticfilesystem:DeleteAccessPoint"], ResourceArns=[f"arn:aws:elasticfilesystem:{REGION}:{ACCOUNT}:access-point/fsap-example"]))
if sim: results["iam_simulated_decision"] = sim["EvaluationResults"][0]["EvalDecision"]
user = "poc-probe-"+suffix
probe("iam.CreateUser", lambda: iam.create_user(UserName=user))
probe("iam.PutUserPolicy", lambda: iam.put_user_policy(UserName=user, PolicyName="deny-all", PolicyDocument=deny))
keys = probe("iam.CreateAccessKey", lambda: iam.create_access_key(UserName=user))
denied_creds = clients.admit_floci_credentials(keys["AccessKey"]) if keys else None
if fs and denied_creds:
    target = efs.create_access_point(FileSystemId=fs["FileSystemId"], ClientToken="poc-denied-"+suffix, Tags=tags)
    result = probe("iam.EffectiveDeny.EfsDelete", lambda: clients.client("efs", denied_creds).delete_access_point(AccessPointId=target["AccessPointId"]))
    results["efs_direct_deny_enforced"] = result is None and results["operations"]["iam.EffectiveDeny.EfsDelete"].get("code") in ["AccessDenied", "AccessDeniedException"]
    if result is None: efs.delete_access_point(AccessPointId=target["AccessPointId"])

role = "poc-executor-probe-"+suffix
trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"}]})
created = probe("iam.CreateRole", lambda: iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust))
sts = clients.client("sts")
probe("sts.GetCallerIdentity", lambda: sts.get_caller_identity())
if created:
    probe("sts.AssumeRole", lambda: sts.assume_role(RoleArn=created["Role"]["Arn"], RoleSessionName="poc-probe"))
    if denied_creds: probe("iam.EffectiveDeny.AssumeRole", lambda: clients.client("sts", denied_creds).assume_role(RoleArn=created["Role"]["Arn"], RoleSessionName="poc-denied"))

ssm = clients.client("ssm")
document = {"schemaVersion": "0.3", "description": "Capability probe only", "mainSteps": [{"name": "approve", "action": "aws:approve", "timeoutSeconds": 30, "onFailure": "Abort", "inputs": {"MinRequiredApprovals": 2, "Approvers": [f"arn:aws:iam::{ACCOUNT}:user/a", f"arn:aws:iam::{ACCOUNT}:user/b"]}}]}
name = "poc-approval-probe-"+suffix
probe("ssm.PutParameter", lambda: ssm.put_parameter(Name="/poc/probe/"+suffix, Value="synthetic", Type="String"))
probe("ssm.CreateDocument", lambda: ssm.create_document(Name=name, DocumentType="Automation", Content=json.dumps(document)))
execution = probe("ssm.StartAutomationExecution", lambda: ssm.start_automation_execution(DocumentName=name))
probe("ssm.SendAutomationSignal", lambda: ssm.send_automation_signal(AutomationExecutionId=execution["AutomationExecutionId"] if execution else str(uuid.uuid4()), SignalType="Approve"))
results["ssm_aws_approve_executed"] = False
if execution:
    probe("ssm.GetAutomationExecution", lambda: ssm.get_automation_execution(AutomationExecutionId=execution["AutomationExecutionId"]))

logs = clients.client("logs")
group = "/poc/approval/probe-"+suffix
probe("logs.CreateLogGroup", lambda: logs.create_log_group(logGroupName=group))
probe("logs.CreateLogStream", lambda: logs.create_log_stream(logGroupName=group, logStreamName="probe"))
probe("logs.PutLogEvents", lambda: logs.put_log_events(logGroupName=group, logStreamName="probe", logEvents=[{"timestamp": int(time.time()*1000), "message": "synthetic approval probe"}]))
events = probe("logs.GetLogEvents", lambda: logs.get_log_events(logGroupName=group, logStreamName="probe"))
results["logs_round_trip"] = bool(events and any(e["message"] == "synthetic approval probe" for e in events["events"]))
sns = clients.client("sns")
topic = probe("sns.CreateTopic", lambda: sns.create_topic(Name="poc-probe-"+suffix))
if topic: probe("sns.Publish", lambda: sns.publish(TopicArn=topic["TopicArn"], Message="synthetic approval probe"))
trail = clients.client("cloudtrail")
t = probe("cloudtrail.CreateTrail", lambda: trail.create_trail(Name="poc-probe-"+suffix, S3BucketName="poc-audit-not-real"))
if t: probe("cloudtrail.StartLogging", lambda: trail.start_logging(Name=t["Name"]))
history = probe("cloudtrail.LookupEvents", lambda: trail.lookup_events(MaxResults=10))
results["cloudtrail_returned_events"] = len(history.get("Events", [])) if history else None
results["cloudtrail_event_names"] = sorted(set(e.get("EventName", "unknown") for e in history.get("Events", []))) if history else []
db = clients.client("dynamodb")
table = "poc-probe-"+suffix
probe("dynamodb.CreateTable", lambda: db.create_table(TableName=table, KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}], AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST"))
probe("dynamodb.PutItem", lambda: db.put_item(TableName=table, Item={"id": {"S": "one"}}, ConditionExpression="attribute_not_exists(id)"))
probe("dynamodb.ConditionalDuplicate", lambda: db.put_item(TableName=table, Item={"id": {"S": "one"}}, ConditionExpression="attribute_not_exists(id)"))
results["dynamodb_condition_enforced"] = results["operations"]["dynamodb.ConditionalDuplicate"].get("code") == "ConditionalCheckFailedException"
if fs: probe("efs.DeleteFileSystem", lambda: efs.delete_file_system(FileSystemId=fs["FileSystemId"]))
(out/"floci-capabilities.json").write_text(json.dumps(results, indent=2, default=str)+"\n")
