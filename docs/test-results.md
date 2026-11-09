# Local test results

Observed 2026-11-09. The full suite collected **86 tests: 85 passed, 1 strict expected failure**, with zero unexpected failures or errors. Runtime was approximately 4.36 seconds. Python 3.15.2, pytest 9.2.0, boto3/botocore 1.43.126 and Floci 2.4.0 were used. [Runtime metadata](evidence/runtime.json)

```bash
bash scripts/reset-local.sh
bash scripts/start-local.sh
bash scripts/local-python.sh scripts/probe-capabilities.py
bash scripts/local-python.sh -m pytest --junitxml=docs/evidence/pytest.xml
bash scripts/run-demo.sh
```

Reset/start and the probe were successfully repeated on a clean pilot container. Only the dedicated container on `127.0.0.1:4570` was used for these integration tests. Other local containers were left untouched.

## Automated coverage

| Group | Result | Evidence and limits |
|---|---|---|
| Unit / offline / isolation | 78 passed | Submission; canonical-person quorum and alias collapse; requester self-approval including a dual-role principal; duplicate/unauthorized/forged votes; rejection; cancellation; expiry; payload/state/vote/audit tampering; resource drift; wrong account/Region/instance; atomic request/resource claims; restart replay; failed/uncertain execution quarantine; audit failure; runbook guard/parsing/scripts; limited offline IAM analysis |
| Actual Floci EFS | 6 passed | Real disposable metadata create/read/delete; unapproved request leaves target present; approved deletion returns 204 and target absent; replay denied; marker and parent tag drift block deletion; six-worker race has one successful receipt; approval for target A preserves target B |
| Actual Floci STS IAM denial | 1 passed | Generated non-bootstrap user's explicit deny caused AssumeRole AccessDenied |
| Actual Floci EFS IAM denial | 1 strict xfail | Deny-all generated IAM user still deleted the disposable access point: effective EFS deny is not enforced by this pinned emulator |

The expected failure test executes its negative check; it is not skipped without running. JUnit represents it as `<skipped type="pytest.xfail">`. Its marker accepts only the assertion failure for missing denial; unrelated runtime/API errors are not accepted as that known gap. If a future emulator enforces the deny, strict XPASS fails the suite and requires reassessment. The exported JUnit file omits the workstation hostname. [JUnit results](evidence/pytest.xml)

Twenty-five isolation cases verify exact endpoint allowlisting, profile/credential/config rejection, no endpoint or credential-chain fallback, and per-send destination/environment checks. Every test begins with explicit synthetic AWS settings. A socket/DNS backstop disallows connections except literal `127.0.0.1:4570`. No AWS CLI profiles, AWS SSO, public AWS clients or Kubernetes clients were used.

Shell syntax validation (`bash -n` on all six shell scripts) passed. JSON IAM examples and YAML runbook are parsed by tests. The schema 0.3 runbook's unconditional abort, two-of-three approval settings and embedded payload/receipt checking scripts are tested locally. No SSM service execution or complete AWS schema validation is claimed. Staged Git whitespace checks passed before each commit.

## Recorded demonstration

The [complete demo transcript](evidence/demo.txt) records:

- Request `12746980-fe72-4476-a0b0-a82e45404312`, requester `person-alex`.
- Exact access point `fsap-00833b03654b4be29`, filesystem `fs-7d0ae76ce30047bf9`, synthetic account `000000000000`, Region `us-east-1`.
- Immutable payload hash `8daaa9174c65e3bbcdfdc721eed9968e430f2441c6ac563a4c537fc5f8672b84`.
- Unapproved execution, requester self-approval, one-approval execution and completed-request replay all denied.
- Authenticated canonical approvers `person-blair` and `person-casey`; `APPROVED -> EXECUTING -> COMPLETED` with a persisted claim and API intent.
- STS-assumed synthetic executor session; Floci EFS response **204**, AWS-shaped request ID `77ad2907-7117-45fd-b780-203144a545bf`, and confirmed target absence.
- Signed transition/decision/denial history and receipt, without bearer secrets or AWS credentials.

Generated live operator files remain ignored under `.local`; the transcript is a sanitized export. Its evidence hashes correlate events in that local database. They cannot be independently authenticated from the public transcript alone because the HMAC key is intentionally excluded. Reset will destroy those local keys/state; the saved transcript remains descriptive evidence, not a production audit ledger.

## Capability probes and qualifications

The [API report](evidence/floci-capabilities.json) confirms EFS CRUD, IAM policy storage/simulation, STS, SSM parameter/document storage, Logs round trip, SNS publish, CloudTrail API acceptance, and DynamoDB conditional insertion. SSM StartAutomationExecution/SendAutomationSignal return `UnsupportedOperation`; `aws:approve` was never executed. CloudTrail lookup returned zero events, so automatic API auditing and trail retention remain unverified.

No result proves production AWS authorization. The quorum, immutability, one-use execution and audit controls are application/SQLite controls under a trusted workstation operator. IAM examples are not deployed, and effective EFS IAM denial remains a known Floci gap. No NFS data, real AWS resource or EKS/Kubernetes cluster was modified.
