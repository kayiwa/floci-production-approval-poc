"""The replaceable AWS API adapter. Every client is pinned to loopback Floci."""
import json
import re
import uuid

from botocore.exceptions import ClientError
from production_approval.authorization.identity import Denied
from production_approval.authorization.isolation import ACCOUNT, REGION, MARKER, assert_local_environment


def tags(instance):
    return [{"Key": k, "Value": v} for k, v in sorted(dict(MARKER, PocInstance=instance).items())]


def setup_executor(factory, instance):
    iam = factory.client("iam")
    broker_name, role_name = "poc-broker-"+instance, "poc-executor-"+instance
    broker_arn = f"arn:aws:iam::{ACCOUNT}:user/{broker_name}"
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{role_name}"
    try:
        iam.create_user(UserName=broker_name)
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": broker_arn}, "Action": "sts:AssumeRole"}]}
    try:
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    iam.put_user_policy(UserName=broker_name, PolicyName="assume-only-executor", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": role_arn}]}))
    iam.put_role_policy(RoleName=role_name, PolicyName="delete-poc-access-points", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "elasticfilesystem:DeleteAccessPoint",
        "Resource": f"arn:aws:elasticfilesystem:{REGION}:{ACCOUNT}:access-point/*",
        "Condition": {"StringEquals": {"aws:ResourceTag/PocInstance": instance, "aws:ResourceTag/ApprovalPOC": "disposable"}}}]}))
    # Synthetic credentials remain server-side; caller APIs never receive them.
    keys = iam.create_access_key(UserName=broker_name)["AccessKey"]
    return factory.admit_floci_credentials(keys), role_arn


class FlociEfs:
    def __init__(self, factory, instance, broker, role_arn):
        self.factory, self.instance, self._broker, self._role_arn = factory, instance, broker, role_arn

    def seed(self):
        assert_local_environment()
        efs = self.factory.client("efs")
        fs = efs.create_file_system(CreationToken="poc-"+uuid.uuid4().hex, Tags=tags(self.instance))
        ap = efs.create_access_point(FileSystemId=fs["FileSystemId"], ClientToken="poc-"+uuid.uuid4().hex, Tags=tags(self.instance))
        return self.snapshot(ap["AccessPointId"])

    def snapshot(self, access_point_id):
        assert_local_environment()
        if not isinstance(access_point_id, str) or not re.fullmatch(r"fsap-[0-9a-f]{8,17}", access_point_id):
            raise Denied("invalid_access_point_id")
        efs = self.factory.client("efs")
        response = efs.describe_access_points(AccessPointId=access_point_id)
        points = response["AccessPoints"]
        if len(points) != 1 or points[0]["AccessPointId"] != access_point_id:
            raise Denied("resource_not_found")
        ap = dict(points[0])
        ap["Tags"] = sorted(ap.get("Tags", []), key=lambda x: (x["Key"], x["Value"]))
        if (ap.get("OwnerId") != ACCOUNT or ap.get("AccessPointArn") !=
            f"arn:aws:elasticfilesystem:{REGION}:{ACCOUNT}:access-point/{access_point_id}"):
            raise Denied("wrong_resource_account_or_region")
        if ap.get("LifeCycleState") != "available":
            raise Denied("resource_not_available")
        if any({t["Key"]: t["Value"] for t in ap["Tags"]}.get(k) != v for k, v in dict(MARKER, PocInstance=self.instance).items()):
            raise Denied("missing_disposable_marker_or_wrong_instance")
        fs = efs.describe_file_systems(FileSystemId=ap["FileSystemId"])["FileSystems"]
        if len(fs) != 1 or fs[0].get("OwnerId") != ACCOUNT:
            raise Denied("filesystem_identity_mismatch")
        fs_tags = {t["Key"]: t["Value"] for t in fs[0].get("Tags", [])}
        if any(fs_tags.get(k) != v for k, v in dict(MARKER, PocInstance=self.instance).items()):
            raise Denied("filesystem_not_disposable")
        if fs[0].get("LifeCycleState") != "available":
            raise Denied("filesystem_not_available")
        ap["FileSystemPrecondition"] = {
            "FileSystemId": fs[0]["FileSystemId"], "OwnerId": fs[0]["OwnerId"],
            "LifeCycleState": fs[0]["LifeCycleState"],
            "Tags": sorted(fs[0].get("Tags", []), key=lambda x: (x["Key"], x["Value"]))}
        return ap

    def delete(self, snapshot, request_id):
        assert_local_environment()
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "elasticfilesystem:DeleteAccessPoint", "Resource": snapshot["AccessPointArn"]}]}
        assumed = self.factory.client("sts", self._broker).assume_role(
            RoleArn=self._role_arn, RoleSessionName="poc-"+request_id, DurationSeconds=900, Policy=json.dumps(policy))
        credentials = self.factory.admit_floci_credentials(assumed["Credentials"])
        result = self.factory.client("efs", credentials).delete_access_point(AccessPointId=snapshot["AccessPointId"])
        return {"aws_request_id": result["ResponseMetadata"].get("RequestId"),
                "http_status": result["ResponseMetadata"]["HTTPStatusCode"],
                "execution_role": assumed["AssumedRoleUser"]["Arn"]}

    def absent(self, access_point_id):
        try:
            return not self.factory.client("efs").describe_access_points(AccessPointId=access_point_id)["AccessPoints"]
        except ClientError as e:
            if e.response["Error"]["Code"] in {"AccessPointNotFound", "AccessPointNotFoundException"}:
                return True
            raise
