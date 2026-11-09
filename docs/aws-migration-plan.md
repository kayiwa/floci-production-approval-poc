# AWS migration design and readiness gaps

This is a design for future work. No AWS account, IAM policy, Terraform state or Kubernetes object was modified. The pilot is **not production-ready**, and changing its endpoint is not a migration path. A real deployment needs independently reviewed infrastructure and a separately authorized AWS sandbox validation stage.

## Proposed production shape

Use an authenticated request/approval service with canonical workforce identities, an immutable request store, a conditional execution ledger, and a separate executor workload. SSM Automation can supply the managed approval pause and orchestration. The executor still validates independent human evidence and consumes the exact request itself; SSM step order alone never authorizes deletion.

For a small operation allowlist, SSM plus a narrowly scoped guarded executor is a reasonable first production candidate. A separate approval broker/PAM could replace SSM if it can prove authenticated person-level quorum and signed operation-bound authorization. Generic temporary administrator access is unsuitable: it exposes more than the requested operation. No GitHub approval authority is required.

The normal developer role retains approved create/read/update operations according to a separately defined policy. Deny selected destructive actions on protected production resources to ordinary human roles and to all alternate paths those humans can acquire. Grant those actions only to the guarded executor and explicitly governed automation. IAM restricts the execution identity; the trusted approval layer establishes the quorum. Boundaries and session policies constrain permissions but do not count human approvals.

## SSM runbook design and guarantees

The [schema 0.3 YAML](../runbooks/protected-efs-access-point-deletion.yaml) is deliberately non-deployable: an unconditional first-step error and nonexistent synthetic roles/functions prevent it from being mistaken for an implementation. It models validation, a bounded three-principal approval list with `MinRequiredApprovals: 2`, timeout/rejection abort, post-approval validation, a guarded deletion function and evidence export. Only a request ID is accepted as a parameter; no caller-supplied role, operation, ARN or command is accepted.

The AWS [approval action](https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-action-approve.html) pauses for authenticated designated principals and returns their decisions. Its documented principal/count behavior must not be promoted into guarantees about underlying human independence. The following are additional requirements or unresolved AWS tests:

| Property | What native SSM/STS establishes | Additional control / required test |
|---|---|---|
| Two approvals | SSM supports a minimum approval count and designated principal list | Verify actual quorum/rejection/timeout with production identity forms; do not accept a boolean supplied by a client |
| Requester exclusion | No automatic canonical-person self-exclusion is established by this design | Compare authoritative requester subject with every approver's authoritative subject; test requester across all roles/aliases |
| Distinct underlying humans | Different role ARNs or sessions do not establish different people | Directory-backed immutable subject mapping, MFA, governed approver membership, no shared identities, aliases counted once |
| Bound parameters | Automation execution has its selected parameters/version; this is not a cross-execution resource authorization | Signed immutable request hash; post-approval reread; executor accepts ID/hash and independently retrieves state |
| One use | An execution/step reaching approval is not a global destructive-operation nonce | Conditional request/resource claim, terminal receipt and no transparent retries across executions |
| Replay prevention | STS credential expiry is a time bound, not a use counter | Never expose the session; maintain consumed capabilities across crashes, restores and duplicate automations |
| Runbook integrity | Access control on SSM documents and execution APIs is separate from approval | Pin numeric approved document version/hash, protect writers/default changes/share permissions, restrict alternate automation start |
| Direct API bypass | Approval does not remove EFS grants held elsewhere | Real effective IAM/SCP/permissions-boundary/trust tests across every developer and automation path |

`SendAutomationSignal` also exposes step-control signals such as StartStep and Resume. Do not infer that granting this API grants only Approve/Reject. The current authorization reference does not document a SignalType condition key; a broker may need to keep the underlying permission server-side. Every privileged handler must validate authorization even when invoked out of the expected sequence. [Signal API](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendAutomationSignal.html), [SSM authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ssm.html)

Restrict Automation's assume role to necessary validation/executor invocations and evidence access. Give it **no direct EFS delete permission**. Do not let requesters choose the role or substitute a function/version. The guarded deletion function must independently read trusted decisions, resolve people, check the exact payload hash/expiry, claim once and validate the target. Restrict invocation and protect its role, deployed version, aliases, code, layers, dependencies and environment. A helper's returned success flag is insufficient authorization.

The design explicitly decodes Lambda's JSON payload, checks the request/hash, and verifies the final deletion receipt. Local tests execute those small scripts but cannot establish SSM interpolation, IAM evaluation or Lambda runtime behavior. Test all of that in AWS before removing any non-deployment guard. [SSM Lambda action](https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-action-lamb.html)

SSM start requests can select documents/versions and execution options. The broker must permit only the approved workflow and disallow caller-chosen step entry, alternate documents, execution roles and parameters. Protect both IAM and broker input schemas; run an adversarial skip-to-delete test. [StartAutomationExecution](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_StartAutomationExecution.html)

## Identity, privilege and storage changes

| Area | Local evidence | Production requirement |
|---|---|---|
| Authentication | Random test bearer secrets mapped to canonical subjects | Validate workforce IdP signatures, issuer, audience, expiry, MFA and revocation server-side; never trust RoleSessionName or a self-asserted identity tag |
| Approver independence | Two distinct registry people, aliases collapse, requester excluded; three eligible people | IdP/directory-controlled subjects and membership; resolve every session to a human, separate requester/approver administration, prohibit shared accounts |
| Executor identity | Synthetic broker credentials stay inside Python; actual Floci STS assumption | Isolated workload role or broker-only role, tightly governed trust, no developer AssumeRole/PassRole or function/code modification paths |
| IAM enforcement | One actual deny-AssumeRole test; limited offline policy analysis; EFS denial is a known emulator failure | Effective AWS identity/resource/session/SCP/boundary evaluation; least-privilege reads and one exact target per execution |
| Request persistence | SQLite transactions, signed immutable payload | Durable restricted store; conditional writes/transactions and protection against unauthorized updates, restores and item deletion; no eventual TTL as an authorization check |
| Execution claim | Atomic one-attempt request/resource claim and conservative uncertain-outcome quarantine | Distributed conditional claim, durable pre-call intent, no automatic claim expiry, separately authorized recovery/reconciler |
| Resource binding | Fresh AP/parent snapshot, marker and exact environment comparisons | Protect target/tag mutations, revalidate, assess non-atomic EFS reread/delete race, verify behavior under real consistency/latency |
| Audit | Signed local transitions and receipt; logs round trip; CloudTrail lookup empty | Central tamper-resistant request/vote/claim/receipt journal plus actual CloudTrail events, delivery monitoring, independent log account and protected retention |
| Availability | Approval failures block only pilot calls | Isolate protection to selected high-risk actions; high availability, timeouts, alerts and controlled outage recovery; routine controllers must have no approval dependency |
| Administrator bypass | Host administrator can replace all controls | Protect organization/policy/deployment/directory/log admins; independent change approval and alerts; document root/organization authority as residual risk |

AWS session policies restrict a session in combination with the role's policies. They do not encode a two-human quorum or enforce one invocation. Broker credentials must never be returned to developers. Keep resource- and action-scoped sessions short, protect the execution ledger independently, and assume a compromised executor remains a serious privilege boundary. [STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)

AWS supports resource ARN and tag conditions for this EFS action, but classification tags must themselves be protected. Evaluate all grants, policies, role chains, PassRole, workload modification and alternate destructive APIs, rather than testing one JSON document. [EFS authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_efs.html)

## Audit and recovery

Retain the immutable request and hash, canonical requester/approvers and original authentication evidence, approval timestamps/expiry/policy version, document and executor versions, conditional claim ID, executor session/source identity, API request ID, exact account/Region/target, response, absence check and reconciliation outcome. Correlate these with CloudTrail rather than assuming an accepted trail configuration proves delivery. Use an independently administered retention destination with protected lifecycle/KMS access; verify ingest failure alerts and deletion resistance in AWS.

After a timeout or crash, quarantine the claim. Inspect CloudTrail and the actual resource using an independent read role; an absent access point is not by itself proof of which execution deleted it. Publish a reconciled receipt or a separately approved recovery request. Never restore consumed authorizations from backup as APPROVED. Test crashes before API submission, after submission, after deletion and during receipt persistence.

Deleting an access point has no automatic undo. Recreating one produces a different identity and needs a separately authorized change using recorded POSIX/root-directory settings and consumer references. The local EFS emulator does not test clients or data restoration. Production deletion behavior and connected clients require explicit validation. [DeleteAccessPoint](https://docs.aws.amazon.com/efs/latest/APIReference/API_DeleteAccessPoint.html)

Emergency recovery is separate from routine access: multiple authorized custodians, independent activation, a narrow exact operation, short lifetime, an incident ID, external immutable evidence and immediate alerting. For approval-service outages, design an independently controlled backup authorization path with dual custody and a consumed nonce, not a permanent one-person production admin role. This pilot deliberately implements no break-glass bypass. Root/organization administrators may still bypass account controls; governance and detection must address that residual rather than claiming it is technically impossible.

## Future operation adapters: not implemented

| Future protected action | Operation binding and enforcement required |
|---|---|
| Production EFS access-point deletion | Approved account/Region/AP/FS/hash, protected tags and competing mutators; dedicated AWS identity; verify consumers and recovery |
| EKS cluster deletion | Exact cluster ARN, account/Region and observed identity/state; IAM denial on human DeleteCluster paths, including IaC automation triggered by humans |
| Kubernetes namespace deletion | Exact cluster identity, namespace UID/resourceVersion and operation; selected admission boundary plus scoped executor RBAC; deny deletecollection and indirect bypasses |
| StatefulSet deletion | Exact cluster/namespace/name/UID/spec hash and deletion propagation; distinguish controllers from humans using authenticated service-account identities |
| PVC deletion | Exact UID, binding/PV/reclaim policy and storage impact; protect indirect deletion/reclaim paths and selected finalizer/owner changes |
| Protected database operation | Fixed typed operation, exact DB/environment/objects and expected state; database-specific authorization and transaction/precondition semantics, never arbitrary SQL |

Human identity must not be inferred from a resource label or user-agent. Future Kubernetes admission can use API-server authenticated user/service-account identity and a one-use approval reference bound to the actual request. Exempt only enumerated trusted controller identities for the reconciliation they require; deny human impersonation and workload/token/RBAC paths into those identities. Preserve ordinary pod replacement/deletion, EFS CSI provisioning/reclaim, Argo CD and required IaC automation explicitly. A human asking Argo or Terraform to perform a protected destructive action must not gain an exemption merely by laundering it through automation.

Select admission rules narrowly so failure blocks protected mutations without making routine reconciliation depend on a separate approval service. Validate garbage collection, eviction, scale-down, namespace finalization, storage reclaim and administrator bypass paths before any Kubernetes rollout. None of these cases are implemented or connected in this pilot.

## Follow-up gates

1. Agree the precise protected-operation inventory and normal developer/controller/IaC permissions; review ownership and emergency authority.
2. Implement production authentication and person-level independence in a separately isolated service; review trust and bypass paths.
3. Review real infrastructure code, document/executor version protection, immutable evidence and recovery design as a separate implementation.
4. Obtain explicit authorization for a disposable real-AWS sandbox. Run effective direct-denial, AssumeRole/PassRole, alternate-runbook/step, duplicate-human, session-policy, concurrency, replay, crash and CloudTrail tests there.
5. Rehearse outages, revocation, restore/reconciliation and emergency activation; independently assess residual administrator/executor compromise risks.
6. Only after those gates consider a narrowly scoped production pilot. Keep Kubernetes and broader platform implementation as separate follow-up work.
