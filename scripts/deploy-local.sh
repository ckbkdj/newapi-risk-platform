#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

for command in docker python3 curl; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "ERROR: ${command} is required" >&2
    exit 1
  }
done

docker compose version >/dev/null 2>&1 || {
  echo "ERROR: Docker Compose v2 is required; use 'docker compose', not the legacy 'docker-compose' binary" >&2
  exit 1
}

if [[ "${RESET_DATA:-0}" =~ ^(1|true|yes)$ ]]; then
  echo "RESET_DATA is enabled: PostgreSQL, Redis and Kafka named volumes will be deleted."
  docker compose down -v --remove-orphans || true
  FORCE_NEW_POSTGRES_PASSWORD=1 bash scripts/init-env.sh
else
  bash scripts/init-env.sh
fi

read -r HTTP_PORT BIND_ADDRESS < <(python3 - <<'PY'
from pathlib import Path

values = {}
for raw_line in Path('.env').read_text(encoding='utf-8').splitlines():
    line = raw_line.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    key, value = line.split('=', 1)
    value = value.strip().strip('"').strip("'")
    values[key.strip()] = value
print(values.get('HTTP_PORT', '8080'), values.get('BIND_ADDRESS', '0.0.0.0'))
PY
)

case "${BIND_ADDRESS}" in
  0.0.0.0|127.0.0.1|localhost|'') PROBE_HOST="127.0.0.1" ;;
  ::|'[::]') PROBE_HOST="[::1]" ;;
  *) PROBE_HOST="${BIND_ADDRESS}" ;;
esac

PROBE_URL="http://${PROBE_HOST}:${HTTP_PORT}"

echo "Validating Docker Compose configuration..."
docker compose config --quiet

# Export beats stale APP_COMMIT entries in .env; the running binary must identify
# the actual checkout being built. Source archives remain explicitly unknown.
if command -v git >/dev/null 2>&1 && git rev-parse --verify HEAD >/dev/null 2>&1; then
  export APP_COMMIT="$(git rev-parse --verify HEAD)"
fi

echo "Building and starting PostgreSQL, Redis and the risk platform..."
if ! docker compose up -d --build; then
  echo "ERROR: docker compose up failed" >&2
  docker compose ps -a || true
  docker compose logs --tail=200 --no-color || true
  exit 1
fi

echo "Published port:"
docker compose port risk-platform 8080 || true

echo "Waiting for ${PROBE_URL}/readyz ..."
ready=0
for attempt in $(seq 1 90); do
  if curl --noproxy '*' --fail --silent --show-error --max-time 2 "${PROBE_URL}/readyz" >/dev/null 2>&1; then
    ready=1
    break
  fi

  state="$(docker inspect --format '{{.State.Status}}' newapi-risk-platform 2>/dev/null || true)"
  if [[ "${state}" == "exited" || "${state}" == "dead" ]]; then
    break
  fi
  sleep 2
done

if [[ "${ready}" != "1" ]]; then
  echo "ERROR: the platform did not become ready at ${PROBE_URL}" >&2
  echo
  echo "=== docker compose ps -a ===" >&2
  docker compose ps -a >&2 || true
  echo
  echo "=== risk-platform state ===" >&2
  docker inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}} restart={{.RestartCount}} error={{.State.Error}}' newapi-risk-platform >&2 2>/dev/null || true
  echo
  echo "=== risk-platform logs ===" >&2
  docker compose logs --tail=250 --no-color risk-platform >&2 || true
  echo
  echo "=== postgres logs ===" >&2
  docker compose logs --tail=120 --no-color postgres >&2 || true
  echo
  echo "Run 'bash scripts/doctor.sh' for a complete diagnostic report." >&2
  exit 1
fi

health="$(curl --noproxy '*' --fail --silent --show-error --max-time 5 "${PROBE_URL}/healthz")"
printf '%s\n' "${health}"
if [[ "${APP_COMMIT:-unknown}" != "unknown" ]]; then
  printf '%s' "${health}" | python3 -c '
import json, sys
value = json.load(sys.stdin).get("build", {})
if value.get("commit") != sys.argv[1]:
    raise SystemExit("Running commit does not match checkout; check stale container or wrong probe route")
if value.get("input_contract") != "risk_audit_request.v2" or value.get("output_contract") != "risk_audit_output.v2":
    raise SystemExit("Running audit contract is not the expected version")
' "${APP_COMMIT}"
fi
echo
echo "Deployment is ready."
echo "Admin UI: ${PROBE_URL}/admin"
echo "Readiness: ${PROBE_URL}/readyz"
echo "Container status:"
docker compose ps
