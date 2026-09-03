#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

fail() {
  printf 'upgrade test failed: %s\n' "$*" >&2
  exit 1
}

REMOTE="${WORKDIR}/remote.git"
SEED="${WORKDIR}/seed"
DEPLOY="${WORKDIR}/deploy"
STUB_BIN="${WORKDIR}/bin"

mkdir -p "${SEED}" "${STUB_BIN}"
git init --bare "${REMOTE}" >/dev/null
git -C "${SEED}" init -b main >/dev/null
git -C "${SEED}" config user.name "Upgrade Test"
git -C "${SEED}" config user.email "upgrade-test@example.invalid"

mkdir -p "${SEED}/scripts"
cp "${SOURCE_ROOT}/scripts/upgrade.sh" "${SEED}/scripts/upgrade.sh"
cat >"${SEED}/scripts/init-env.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ -f .env ]] || printf 'GENERATED=true\n' >.env
SH
cat >"${SEED}/scripts/deploy-local.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$(git rev-parse HEAD)" >.deploy-test-commit
SH
cat >"${SEED}/.gitignore" <<'EOF'
.env
.upgrade-backups/
.deploy-test-commit
EOF
printf 'version-one\n' >"${SEED}/app.txt"
chmod 0755 "${SEED}/scripts/upgrade.sh" "${SEED}/scripts/init-env.sh" "${SEED}/scripts/deploy-local.sh"
git -C "${SEED}" add .
git -C "${SEED}" commit -m "initial deployment" >/dev/null
git -C "${SEED}" remote add origin "${REMOTE}"
git -C "${SEED}" push -u origin main >/dev/null

git clone --branch main "${REMOTE}" "${DEPLOY}" >/dev/null
git -C "${DEPLOY}" config user.name "Upgrade Test Deploy"
git -C "${DEPLOY}" config user.email "upgrade-deploy@example.invalid"
printf 'SECRET=preserved-value\n' >"${DEPLOY}/.env"

cat >"${STUB_BIN}/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != "compose" ]]; then
  exit 1
fi
case "${2:-}" in
  version|config)
    exit 0
    ;;
  ps)
    # No running PostgreSQL service in this isolated test; the upgrade must
    # safely skip the database dump while retaining every other guard.
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
SH
chmod 0755 "${STUB_BIN}/docker"

printf 'version-two\n' >"${SEED}/app.txt"
git -C "${SEED}" add app.txt
git -C "${SEED}" commit -m "remote update" >/dev/null
git -C "${SEED}" push origin main >/dev/null
TARGET_COMMIT="$(git -C "${SEED}" rev-parse HEAD)"

(
  cd "${DEPLOY}"
  PATH="${STUB_BIN}:${PATH}" BACKUP_DATABASE=1 bash scripts/upgrade.sh main >/tmp/newapi-risk-upgrade-success.log
)

[[ "$(cat "${DEPLOY}/app.txt")" == "version-two" ]] || fail "fast-forward content was not installed"
[[ "$(cat "${DEPLOY}/.env")" == "SECRET=preserved-value" ]] || fail ".env was not preserved"
[[ "$(cat "${DEPLOY}/.deploy-test-commit")" == "${TARGET_COMMIT}" ]] || fail "deployment did not run at the target commit"

manifest="$(find "${DEPLOY}/.upgrade-backups" -mindepth 2 -maxdepth 2 -name manifest.json -print -quit)"
[[ -n "${manifest}" && -s "${manifest}" ]] || fail "upgrade manifest was not created"
python3 - "${manifest}" "${TARGET_COMMIT}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
assert manifest["status"] == "success", manifest
assert manifest["target_commit"] == sys.argv[2], manifest
assert manifest["database_backup"] == "", manifest
PY

printf 'local dirty change\n' >>"${DEPLOY}/app.txt"
if (
  cd "${DEPLOY}"
  PATH="${STUB_BIN}:${PATH}" bash scripts/upgrade.sh main >/tmp/newapi-risk-upgrade-dirty.log 2>&1
); then
  fail "dirty working tree was accepted"
fi
grep -Fq 'working tree is not clean' /tmp/newapi-risk-upgrade-dirty.log || fail "dirty-tree refusal was not explicit"
git -C "${DEPLOY}" checkout -- app.txt

printf 'local-only\n' >"${DEPLOY}/local-only.txt"
git -C "${DEPLOY}" add local-only.txt
git -C "${DEPLOY}" commit -m "local divergent commit" >/dev/null
printf 'remote-only\n' >"${SEED}/remote-only.txt"
git -C "${SEED}" add remote-only.txt
git -C "${SEED}" commit -m "remote divergent commit" >/dev/null
git -C "${SEED}" push origin main >/dev/null

if (
  cd "${DEPLOY}"
  PATH="${STUB_BIN}:${PATH}" bash scripts/upgrade.sh main >/tmp/newapi-risk-upgrade-diverged.log 2>&1
); then
  fail "diverged history was accepted"
fi
grep -Fq 'remote history is not a fast-forward' /tmp/newapi-risk-upgrade-diverged.log || fail "divergence refusal was not explicit"

echo "safe Git upgrade workflow checks passed"
