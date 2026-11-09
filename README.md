# Local multi-party production authorization pilot

Two authenticated synthetic approvers authorize **one `DeleteEfsAccessPoint` request**. A trusted executor revalidates the exact disposable resource, atomically consumes the authorization, deletes it through Floci, and persists a receipt. Requesters receive neither an executor AWS session nor a general command interface.

**Local proof of concept, not production authorization.** Floci 2.4.0 cannot execute SSM Automation and did not enforce an EFS IAM deny in our negative test. The application enforces approval on its trusted execution path. Anyone controlling this workstation or calling the emulator directly can bypass that path. No real AWS account or Kubernetes cluster is used.

## Start and run

Requirements: Python 3.11 or newer, a running Podman engine, and the pinned Floci container image. Verified here with Python 3.15.2, boto3 1.43.126 and Floci 2.4.0. Install Python dependencies once:

```bash
git clone https://github.com/kayiwa/floci-production-approval-poc.git
cd floci-production-approval-poc
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
bash scripts/start-local.sh
bash scripts/run-tests.sh
bash scripts/run-demo.sh
```

`start-local.sh` runs the Floci image using Podman. A Floci CLI installation is not required. It publishes **only `127.0.0.1:4570`**, waits for a guarded synthetic STS identity check, and enables Floci's IAM enforcement option. It does not use `floci env` or source a host AWS profile. The image is pinned to:

```text
docker.io/floci/floci@sha256:3df9677724e36251801f3828ea0bdcc2818afa96d8ec53f1741eaffdaeb990e1
```

The demo prints denials without approval, self-approval denial, one-approval denial, a completed deletion, replay denial, every recorded transition, and its durable receipt. It creates fresh disposable resources on each run. Successful deletion removes the access point, not its filesystem. Floci provides EFS metadata APIs, not an NFS data plane. [Floci EFS documentation](https://floci.io/floci/services/efs/)

Other commands, from this directory:

```bash
# Independently probe supported APIs; writes sanitized capability evidence.
bash scripts/local-python.sh scripts/probe-capabilities.py

# Seed only; all tags and account/Region fields are supplied by the trusted code.
bash scripts/seed-resources.sh

# Verify and export the local audit chain.
bash scripts/local-python.sh -m production_approval.cli audit

# Run tests without needing the container, or run only actual Floci tests.
bash scripts/run-tests.sh -m 'not integration'
bash scripts/run-tests.sh -m integration

# Remove ONLY this pilot's labelled container and generated .local directory.
bash scripts/reset-local.sh
```

Reset destroys pilot approvals, identities, receipts and emulator fixtures. Save any evidence you want first. After reset, run start again. Floci uses disposable in-memory service state; if its container restarts and loses IAM/resource fixtures while `.local` persists, fail closed and reset the whole pilot. Do not repair it by importing real AWS credentials or changing the endpoint.

## Security boundaries

`scripts/local-python.sh` launches a child with an empty inherited environment and explicit synthetic credentials. It does not edit your shell, AWS files or kubeconfig. Direct module use fails closed unless the exact local endpoint, `test/test` bootstrap environment, synthetic account/Region, disabled credential files and disabled metadata discovery are configured. Nonempty AWS profiles, real-looking bootstrap credentials and ambient role/session credentials are rejected. The wrapper discards these inherited settings rather than using them.

All AWS clients use an explicit endpoint and explicit credentials, no proxies, no credential-provider fallback, and a destination check before each send. Only `http://127.0.0.1:4570` is allowed; other ports, `localhost`, public AWS endpoints and misleading hostname suffixes fail. Tests additionally restrict socket connections and DNS resolution to that literal address and port. No test requires actual AWS credentials.

The test identity registry assigns random bearer secrets to canonical people. Aliases for the same person count once. Three eligible approvers allow two-person approval without depending on a particular individual. A dual requester/approver cannot approve their own request. Requests accept a resource ID and justification; caller-supplied identity strings or approval flags have no authority.

| Logical role | Allowed application operations | Denied by the application |
|---|---|---|
| Requester | Submit; inspect own request; cancel before execution | Approve own request; claim execution; edit approvals/policy/audit |
| Approver | Inspect a request by ID; approve or reject | Substitute parameters; claim execution; impersonate another principal |
| Executor | Claim and execute an approved request ID | Unapproved, expired, consumed, changed or non-allowlisted requests |

These are logical boundaries in one Python process. The operator harness intentionally loads all test tokens from `.local/test-identities.json` (mode 0600). It does not demonstrate separate operating-system users, an Internet authentication service, or independent real humans. Production must replace this registry, isolate the executor process, and prevent developers from obtaining its identity. The bootstrap `test` identity is an emulator administrator. Requester-facing methods never return AWS credentials; the operator can still inspect process memory and local files.

## Approval persistence, execution and audit

SQLite stores immutable canonical request payloads and hashes, signed decisions, signed state/receipts, resource claims, and an HMAC-chained event log. `BEGIN IMMEDIATE` serializes competing claims; full synchronous commits persist intent before the external deletion. The executor checks the policy version, two distinct eligible non-requesters, expiration, payload integrity, target account/Region, filesystem and access-point identity, lifecycle state, tags and pilot instance.

Approval is consumed by one execution attempt. Failure before an API submission requires a **new request and fresh approvals**. A submitted API call with an uncertain result blocks further requests for the same target until explicit reconciliation; this pilot deliberately has no administrative unlock API. Crashes can leave `EXECUTING` records; they are never automatically replayed. Unavailable storage or broken audit integrity blocks new protected executions.

`.local/approvals.sqlite3` is the durable source. The demo also writes `.local/last-receipt.json` and `.local/audit.jsonl`. Events contain actor, request ID, timestamp, decision/transition or denial, and request hash; the receipt adds resource, canonical approvers, executor/session identity, claim, AWS request ID, endpoint and outcome. HMAC verification detects tested record mutations. This is not external, immutable evidence: an operator with the key, database and code can forge or roll back the whole environment.

EFS has no conditional resource-version parameter on its delete API. The reread detects observed drift; it cannot eliminate a competing administrator's change between read and delete or a change-and-restore sequence. That production residual needs control of all competing mutation paths. [AWS DeleteAccessPoint API](https://docs.aws.amazon.com/efs/latest/APIReference/API_DeleteAccessPoint.html)

## AWS designs and evidence

The schema 0.3 [SSM design](runbooks/protected-efs-access-point-deletion.yaml) has a two-approval step, bounded principals, five-minute timeout, post-approval checks, guarded executor and evidence export. It is intentionally non-deployable: the first step always aborts and every role/function reference is synthetic. Local tests parse its structure and exercise embedded validation scripts; they do not certify AWS runbook execution.

IAM policy examples are scoped illustrations. Offline policy tests are not AWS evaluation. Floci's actual STS deny test passes, but its EFS direct-denial test is a strict expected failure. IAM, STS and an SSM approval count alone do not prove independent human authorization or one-use execution. [AWS approval action](https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-action-approve.html), [STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)

- [Architecture and diagram](docs/architecture.md)
- [Observed Floci capabilities and API boundaries](docs/floci-capabilities.md)
- [Threat model and control evidence](docs/threat-model.md)
- [AWS migration and production readiness gaps](docs/aws-migration-plan.md)
- [Test results and recorded demo](docs/test-results.md)
- [IAM examples and limits](infrastructure/iam/README.md)
- [Terraform isolation](infrastructure/terraform/README.md)

Source: [kayiwa/floci-production-approval-poc](https://github.com/kayiwa/floci-production-approval-poc). This project is independent of any infrastructure repository or production Terraform state.
