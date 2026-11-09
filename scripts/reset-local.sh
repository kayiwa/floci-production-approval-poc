#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
ENGINE=${POC_CONTAINER_ENGINE:-podman}
NAME=floci-production-approval-poc
if "$ENGINE" container exists "$NAME"; then
  test "$("$ENGINE" inspect "$NAME" --format '{{index .Config.Labels "io.approval-poc.project"}}')" = production-approval
  "$ENGINE" rm --force "$NAME"
fi
# Remove only generated pilot state; do not touch AWS configuration or other demos.
.venv/bin/python - <<'PY'
from pathlib import Path
import shutil
p = Path('.local')
if p.is_symlink():
    raise SystemExit('Refusing to reset a symlink')
if p.exists():
    shutil.rmtree(p)
PY
echo 'Reset only the disposable pilot container and its .local state.'
