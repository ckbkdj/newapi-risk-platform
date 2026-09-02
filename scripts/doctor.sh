#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

section() {
  printf '\n===== %s =====\n' "$1"
}

section "working directory"
pwd

section "Docker"
if ! command -v docker >/dev/null 2>&1; then
  echo "docker: NOT FOUND"
  exit 1
fi
docker version --format 'client={{.Client.Version}} server={{.Server.Version}}' 2>&1 || true
docker compose version 2>&1 || true

section ".env validation (secrets are not printed)"
if [[ ! -f .env ]]; then
  echo ".env: MISSING"
else
  python3 - <<'PY'
from __future__ import annotations

import base64
from pathlib import Path

values = {}
for raw_line in Path('.env').read_text(encoding='utf-8').splitlines():
    line = raw_line.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    key, value = line.split('=', 1)
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    values[key.strip()] = value


def placeholder(value: str) -> bool:
    lowered = value.lower()
    return not value or lowered.startswith('replace-') or 'replace-with' in lowered or lowered in {'changeme', 'change-me'}

master = values.get('MASTER_KEY_B64', '')
try:
    master_ok = len(base64.b64decode(master, validate=True)) == 32
except Exception:
    master_ok = False

checks = {
    'HTTP_PORT': values.get('HTTP_PORT', '8080'),
    'BIND_ADDRESS': values.get('BIND_ADDRESS', '0.0.0.0'),
    'POSTGRES_PASSWORD': 'OK' if values.get('POSTGRES_PASSWORD') else 'MISSING',
    'MASTER_KEY_B64': 'OK' if master_ok else 'INVALID',
    'JWT_SECRET': 'OK' if len(values.get('JWT_SECRET', '').encode()) >= 32 and not placeholder(values.get('JWT_SECRET', '')) else 'INVALID',
    'BOOTSTRAP_ADMIN_USERNAME': values.get('BOOTSTRAP_ADMIN_USERNAME', 'admin'),
    'BOOTSTRAP_ADMIN_PASSWORD': 'OK' if len(values.get('BOOTSTRAP_ADMIN_PASSWORD', '')) >= 14 and not placeholder(values.get('BOOTSTRAP_ADMIN_PASSWORD', '')) else 'INVALID',
    'KAFKA_ENABLED': values.get('KAFKA_ENABLED', 'false'),
}
for key, value in checks.items():
    print(f'{key}={value}')
PY
fi

section "effective Compose configuration"
docker compose config --quiet 2>&1 && echo "compose_config=OK" || echo "compose_config=FAILED"

section "containers"
docker compose ps -a 2>&1 || true

section "published risk-platform port"
docker compose port risk-platform 8080 2>&1 || true

section "risk-platform state"
docker inspect --format 'status={{.State.Status}} running={{.State.Running}} exit={{.State.ExitCode}} restart={{.RestartCount}} started={{.State.StartedAt}} finished={{.State.FinishedAt}} error={{.State.Error}}' newapi-risk-platform 2>&1 || true

section "host listeners"
if command -v ss >/dev/null 2>&1; then
  ss -lntp 2>&1 | grep -E '(:8080|:18080|newapi|docker-proxy)' || true
elif command -v netstat >/dev/null 2>&1; then
  netstat -lntp 2>&1 | grep -E '(:8080|:18080|newapi|docker-proxy)' || true
else
  echo "Neither ss nor netstat is installed"
fi

section "risk-platform logs"
docker compose logs --tail=250 --no-color risk-platform 2>&1 || true

section "PostgreSQL logs"
docker compose logs --tail=120 --no-color postgres 2>&1 || true

section "Redis logs"
docker compose logs --tail=80 --no-color redis 2>&1 || true

section "common interpretations"
cat <<'EOF'
- configuration validation failed: run `bash scripts/init-env.sh`, then redeploy.
- PostgreSQL startup failed / password authentication failed: .env password and the existing named volume do not match.
- status=exited or status=restarting: the build succeeded, but the application process did not stay alive.
- published port is not 8080: use the port shown by `docker compose port risk-platform 8080`.
- no published port: risk-platform was not created or is using a different Compose project/file.
EOF
