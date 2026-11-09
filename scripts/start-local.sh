#!/usr/bin/env bash
set -euo pipefail
ENGINE=${POC_CONTAINER_ENGINE:-podman}
NAME=floci-production-approval-poc
IMAGE=docker.io/floci/floci@sha256:3df9677724e36251801f3828ea0bdcc2818afa96d8ec53f1741eaffdaeb990e1
if "$ENGINE" container exists "$NAME"; then
  test "$("$ENGINE" inspect "$NAME" --format '{{index .Config.Labels "io.approval-poc.project"}}')" = production-approval
  test "$("$ENGINE" inspect "$NAME" --format '{{.ImageName}}')" = "$IMAGE"
  "$ENGINE" start "$NAME" >/dev/null
else
  "$ENGINE" run --detach --name "$NAME" --label io.approval-poc.project=production-approval \
    --publish 127.0.0.1:4570:4566 --env FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true \
    --env AWS_ACCESS_KEY_ID=test --env AWS_SECRET_ACCESS_KEY=test --env AWS_EC2_METADATA_DISABLED=true "$IMAGE"
fi
PROJECT=$(cd -- "$(dirname -- "$0")/.." && pwd)
bash "$PROJECT/scripts/local-python.sh" "$PROJECT/scripts/wait-local.py"
echo 'Floci 2.4.0: http://127.0.0.1:4570 (disposable loopback-only pilot)'
