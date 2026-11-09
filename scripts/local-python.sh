#!/usr/bin/env bash
set -euo pipefail
PROJECT=$(cd -- "$(dirname -- "$0")/.." && pwd)
# Start a child with an explicit synthetic environment; never source host AWS files.
exec env -i PATH="$PATH" PYTHONPATH="$PROJECT/src" \
  AWS_ENDPOINT_URL=http://127.0.0.1:4570 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true \
  AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
  "$PROJECT/.venv/bin/python" "$@"
