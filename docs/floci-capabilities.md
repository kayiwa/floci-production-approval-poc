# Floci capability assessment

Evaluated on 2026-11-09 against Floci **2.4.0**, revision `9be236e2890c2042a6bb819f1a9228be996acd90`, digest `sha256:3df9677724e36251801f3828ea0bdcc2818afa96d8ec53f1741eaffdaeb990e1`. A dedicated Podman container serves `http://127.0.0.1:4570`, account `000000000000`, Region `us-east-1`. No Floci CLI is required.

The current [service catalogue](https://floci.io/floci/services/) was used to discover candidates. Operation probes determine what this installed version actually does. A service name, an HTTP 200, or a saved runbook is not evidence that all its behavior is implemented.

| Service | Actual probes | Observed behavior | Pilot use / limit |
|---|---|---|---|
| EFS | CreateFileSystem, CreateAccessPoint, DescribeAccessPoints, DeleteAccessPoint, DeleteFileSystem; integration also describes filesystems and tags/untags resources | Create/read/delete succeeded; deletion returned 204; describing a deleted access point returned an empty list | Actual disposable metadata deletion; no NFS or data recovery tested |
| IAM | CreatePolicy, SimulateCustomPolicy, CreateUser, PutUserPolicy, CreateAccessKey, CreateRole; fixture also PutRolePolicy | Policy simulation returned `explicitDeny`; CRUD succeeded | Policy storage/simulation works; effective EFS authorization is a separate question |
| IAM on EFS | Signed DeleteAccessPoint using a newly created user with explicit deny-all, enforcement enabled | **Deletion succeeded (204)** | Effective direct EFS denial is unsupported in this configuration; strict expected-failure test records the gap |
| STS | GetCallerIdentity, AssumeRole using bootstrap, broker and explicitly denied user | Identity/assumption succeeded; denied user's AssumeRole returned `AccessDenied` | Emulated STS denial verified; not a full trust-policy/session-policy conformance suite |
| SSM | PutParameter, CreateDocument with Automation schema 0.3 | Both accepted | Document storage does not execute or validate every runbook action |
| SSM Automation | StartAutomationExecution, SendAutomationSignal | Both returned `UnsupportedOperation` | `aws:approve` cannot be exercised; replaced by the separate local workflow adapter |
| CloudWatch Logs | CreateLogGroup, CreateLogStream, PutLogEvents, GetLogEvents | Successful synthetic message round trip | Capability probe only; authoritative application audit is SQLite, not CloudWatch |
| SNS | CreateTopic, Publish | Accepted | No subscriber delivery, authenticated voting or notification reliability established |
| CloudTrail | CreateTrail, StartLogging, LookupEvents | APIs accepted; lookup returned **zero events** | Automatic EFS/STS evidence capture and durable trail delivery are not established |
| DynamoDB | CreateTable, PutItem with `attribute_not_exists`; duplicate conditional PutItem | First insert succeeded; second returned `ConditionalCheckFailedException` | Conditional insert works; distributed transactions not tested; workflow uses SQLite instead |

Raw sanitized results: [floci-capabilities.json](evidence/floci-capabilities.json). Rerun with `bash scripts/local-python.sh scripts/probe-capabilities.py` after starting the container. The probe creates only disposable emulator resources, leaves synthetic IAM/SSM/logging fixtures until reset, and never prints minted AWS secrets.

Floci documents [EFS as a metadata control plane](https://floci.io/floci/services/efs/), [SSM primarily as Parameter Store](https://floci.io/floci/services/ssm/), and [IAM enforcement with bypasses](https://floci.io/floci/services/iam/). In particular the `test` bootstrap identity bypasses enforcement. Our negative EFS test uses a generated non-bootstrap user, so its result cannot be explained by intentionally using `test/test` for deletion. Current documentation may describe behavior added after this pinned image.

## What each kind of evidence means

| Category | Established here | Not established |
|---|---|---|
| Executed through Floci | EFS metadata deletion and reread; STS assumption and denied assumption; API probes above | Production IAM, SSM approvals, CloudTrail delivery, actual EFS data effects |
| Local application/simulator | Synthetic authentication; canonical-person quorum; expiry; immutable hashes; one-attempt claims; resource checks; signed SQLite audit | Federated humans, tamper-proof host, distributed highly available state |
| Checked against AWS documentation | SSM schema/action design, approval settings, STS session-policy design, EFS deletion API and resource-tag IAM shape | Correct deployment or effective account policies |
| Not validated against real AWS | All production trust, identity, policy, orchestration, race/recovery and audit guarantees | No AWS account or Kubernetes cluster was contacted |

AWS references: [SSM approval action](https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-action-approve.html), [approval permissions](https://docs.aws.amazon.com/systems-manager/latest/userguide/running-automations-require-approvals.html), [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html), [EFS authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_efs.html). Documentation informs the migration design; it does not turn a local simulated boundary into a verified AWS control.
