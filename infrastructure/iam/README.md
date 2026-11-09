# IAM examples: design and local tests only

These JSON documents are not attached to a real account and are not a deployable access model. Every resource ARN uses synthetic account `000000000000`. `executor.json` uses one placeholder access-point ID and a synthetic instance marker. The offline test evaluator supports only the Action/Resource/StringEquals subset present here; it is not an IAM implementation or AWS Access Analyzer.

| File | Intended boundary | Important qualification |
|---|---|---|
| `requester.json` | EFS discovery; explicit denial of protected deletion, role assumption, IAM/runbook changes and audit writes/deletes | Normal production create/update permissions must be separately designed; this is only the pilot operation scope |
| `approver.json` | Illustration of narrowly scoped SSM signal permission; denies direct execution and control-plane policy edits | `SendAutomationSignal` is broader than Approve/Reject; do not deploy this as a complete approval policy |
| `executor.json` | Only DeleteAccessPoint on one exact ARN, with disposable and instance conditions | A production executor also needs tightly scoped reads/state/audit permissions; effective EFS enforcement is unverified here |
| `executor-trust-design.json` | Lambda service trust concept for a future executor | Does not authorize developers to assume the role; protect PassRole, function updates, invocation, layers, environment and dependency supply chain separately |

AWS lists access-point ARN scoping and resource-tag conditions for [EFS DeleteAccessPoint](https://docs.aws.amazon.com/service-authorization/latest/reference/list_efs.html). Tags alone are insufficient if the requester can change those tags. Protect environment/classification tags and every alternative privilege path in a real deployment.

The local fixture code creates an instance-specific broker IAM user and an executor role trusted only to that user. The broker can assume that role; the base role allows disposable access-point deletion for that instance, and the per-execution STS session policy specifies the exact approved ARN. These credentials remain internal to the operator process. This differs deliberately from the future Lambda service trust example.

Actual Floci tests verify `AccessDenied` for an explicitly denied AssumeRole. A deny-all generated IAM user **can delete an EFS access point** in Floci 2.4.0; that negative test is a strict expected failure. Neither policy simulation nor application denial proves effective EFS IAM enforcement. Only real-AWS tests in a separately authorized sandbox can establish that boundary.

STS sessions are time-limited credentials, not single-use capabilities. Exact ARN scoping limits the resource but does not authenticate two humans, prevent replay by itself, or stop a compromised executor from misusing an existing session. The trusted claim/approval layer remains required. [AWS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
