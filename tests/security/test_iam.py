"""Offline policy analysis is NOT effective IAM authorization verification."""
import fnmatch
import json
from pathlib import Path
import uuid

import pytest
from botocore.exceptions import ClientError
from production_approval.authorization.isolation import ACCOUNT, REGION, LocalClients

ROOT = Path(__file__).resolve().parents[2]
TARGET = f"arn:aws:elasticfilesystem:{REGION}:{ACCOUNT}:access-point/fsap-00000000000000001"


def offline_decision(policy, action, resource, context=None):
    context = context or {}
    allowed = False
    for s in policy["Statement"]:
        actions = s["Action"] if isinstance(s["Action"], list) else [s["Action"]]
        resources = s["Resource"] if isinstance(s["Resource"], list) else [s["Resource"]]
        if not any(fnmatch.fnmatchcase(action.lower(), a.lower()) for a in actions) or not any(fnmatch.fnmatchcase(resource, r) for r in resources):
            continue
        if any(context.get(k) != v for k, v in s.get("Condition", {}).get("StringEquals", {}).items()):
            continue
        if s["Effect"] == "Deny":
            return "explicitDeny"
        allowed = True
    return "allowed" if allowed else "implicitDeny"


@pytest.mark.parametrize("role", ["requester", "approver"])
@pytest.mark.parametrize("action", ["elasticfilesystem:DeleteAccessPoint", "sts:AssumeRole", "iam:PutRolePolicy", "ssm:UpdateDocument", "logs:DeleteLogGroup"])
def test_requester_approver_boundaries_offline(role, action):
    p = json.loads((ROOT/f"infrastructure/iam/{role}.json").read_text())
    assert offline_decision(p, action, TARGET) == "explicitDeny"


def test_executor_exact_scope_and_marker_offline():
    p = json.loads((ROOT/"infrastructure/iam/executor.json").read_text())
    context = {"aws:ResourceTag/ApprovalPOC": "disposable", "aws:ResourceTag/PocInstance": "SYNTHETIC_INSTANCE"}
    assert offline_decision(p, "elasticfilesystem:DeleteAccessPoint", TARGET, context) == "allowed"
    assert offline_decision(p, "elasticfilesystem:DeleteAccessPoint", TARGET+"2", context) == "implicitDeny"
    assert offline_decision(p, "elasticfilesystem:DeleteAccessPoint", TARGET) == "implicitDeny"
    for action in ["eks:DeleteCluster", "iam:PutRolePolicy", "ssm:UpdateDocument", "elasticfilesystem:DeleteFileSystem"]:
        assert offline_decision(p, action, TARGET, context) == "implicitDeny"


@pytest.mark.integration
def test_floci_rejects_requester_assume_executor():
    f = LocalClients()
    iam = f.client("iam")
    name = "poc-deny-"+uuid.uuid4().hex[:12]
    iam.create_user(UserName=name)
    iam.put_user_policy(UserName=name, PolicyName="deny-assume", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"}]}))
    credentials = f.admit_floci_credentials(iam.create_access_key(UserName=name)["AccessKey"])
    role = "poc-role-"+uuid.uuid4().hex[:12]
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}))
    with pytest.raises(ClientError) as e:
        f.client("sts", credentials).assume_role(RoleArn=f"arn:aws:iam::{ACCOUNT}:role/{role}", RoleSessionName="negative-test")
    assert e.value.response["Error"]["Code"] == "AccessDenied"


@pytest.mark.integration
@pytest.mark.xfail(strict=True, raises=pytest.fail.Exception,
                   reason="Pinned Floci 2.4.0 does not enforce EFS REST IAM denial; documented emulator gap")
def test_floci_effective_efs_iam_deny_is_not_implemented(floci):
    _, _, efs, _, _ = floci
    ap = efs.seed()
    f = efs.factory
    iam = f.client("iam")
    name = "poc-efs-deny-"+uuid.uuid4().hex[:10]
    iam.create_user(UserName=name)
    iam.put_user_policy(UserName=name, PolicyName="deny-all", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}))
    credentials = f.admit_floci_credentials(iam.create_access_key(UserName=name)["AccessKey"])
    with pytest.raises(ClientError):
        f.client("efs", credentials).delete_access_point(AccessPointId=ap["AccessPointId"])
