#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

REMOTE="${GIT_REMOTE:-origin}"
CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
TARGET_BRANCH="${1:-${TARGET_BRANCH:-${CURRENT_BRANCH}}}"
BACKUP_DATABASE="${BACKUP_DATABASE:-1}"
ROLLBACK_ON_FAILURE="${ROLLBACK_ON_FAILURE:-1}"
ALLOW_BRANCH_SWITCH="${ALLOW_BRANCH_SWITCH:-0}"
ALLOW_DIRTY_WORKTREE="${ALLOW_DIRTY_WORKTREE:-0}"
LOCK_FILE="${UPGRADE_LOCK_FILE:-${ROOT_DIR}/.git/newapi-risk-upgrade.lock}"

log() {
  printf '[upgrade] %s\n' "$*"
}

fail() {
  printf '[upgrade] ERROR: %s\n' "$*" >&2
  exit 1
}

truthy() {
  [[ "${1:-}" =~ ^(1|true|yes|on)$ ]]
}

for command in git docker python3 curl flock; do
  command -v "${command}" >/dev/null 2>&1 || fail "${command} is required"
done
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "run this script inside the Git repository"

exec 9>"${LOCK_FILE}"
flock -n 9 || fail "another upgrade is already running"

[[ -n "${CURRENT_BRANCH}" ]] || fail "detached HEAD is not supported"
[[ -n "${TARGET_BRANCH}" ]] || fail "target branch is empty"

if ! truthy "${ALLOW_DIRTY_WORKTREE}"; then
  dirty="$(git status --porcelain --untracked-files=normal)"
  [[ -z "${dirty}" ]] || {
    printf '%s\n' "${dirty}" >&2
    fail "working tree is not clean; commit, stash, or remove local changes first"
  }
fi

if [[ "${CURRENT_BRANCH}" != "${TARGET_BRANCH}" ]]; then
  truthy "${ALLOW_BRANCH_SWITCH}" || fail "current branch is ${CURRENT_BRANCH}; set ALLOW_BRANCH_SWITCH=1 to switch to ${TARGET_BRANCH}"
  if git show-ref --verify --quiet "refs/heads/${TARGET_BRANCH}"; then
    git switch "${TARGET_BRANCH}"
  else
    git fetch --prune "${REMOTE}" "refs/heads/${TARGET_BRANCH}:refs/remotes/${REMOTE}/${TARGET_BRANCH}"
    git switch --track -c "${TARGET_BRANCH}" "${REMOTE}/${TARGET_BRANCH}"
  fi
  CURRENT_BRANCH="${TARGET_BRANCH}"
fi

log "fetching ${REMOTE}/${TARGET_BRANCH}"
git fetch --prune "${REMOTE}" "refs/heads/${TARGET_BRANCH}:refs/remotes/${REMOTE}/${TARGET_BRANCH}"

OLD_COMMIT="$(git rev-parse HEAD)"
TARGET_COMMIT="$(git rev-parse "${REMOTE}/${TARGET_BRANCH}")"
git merge-base --is-ancestor "${OLD_COMMIT}" "${TARGET_COMMIT}" ||
  fail "remote history is not a fast-forward from ${OLD_COMMIT}; manual review is required"

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
BACKUP_DIR="${ROOT_DIR}/.upgrade-backups/${timestamp}-${OLD_COMMIT:0:12}"
mkdir -p "${BACKUP_DIR}"
printf '%s\n' "${OLD_COMMIT}" >"${BACKUP_DIR}/old-commit"
printf '%s\n' "${TARGET_COMMIT}" >"${BACKUP_DIR}/target-commit"
printf '%s\n' "${TARGET_BRANCH}" >"${BACKUP_DIR}/branch"

ENV_EXISTED=0
if [[ -f .env ]]; then
  ENV_EXISTED=1
  cp -p .env "${BACKUP_DIR}/env.backup"
  chmod 600 "${BACKUP_DIR}/env.backup"
fi

DB_BACKUP=""
if truthy "${BACKUP_DATABASE}"; then
  if docker compose ps --status running --services 2>/dev/null | grep -Fxq postgres; then
    DB_BACKUP="${BACKUP_DIR}/postgres.dump"
    log "creating PostgreSQL custom-format backup"
    if ! docker compose exec -T postgres sh -lc \
      'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_dump -U "${POSTGRES_USER:-risk}" -d "${POSTGRES_DB:-risk}" -Fc' \
      >"${DB_BACKUP}"; then
      rm -f "${DB_BACKUP}"
      fail "database backup failed; code was not changed"
    fi
    [[ -s "${DB_BACKUP}" ]] || fail "database backup is empty; code was not changed"
    chmod 600 "${DB_BACKUP}"
  else
    log "PostgreSQL container is not running; database backup skipped"
  fi
else
  log "database backup disabled by BACKUP_DATABASE=${BACKUP_DATABASE}"
fi

write_manifest() {
  local status="$1"
  STATUS="${status}" OLD_COMMIT="${OLD_COMMIT}" TARGET_COMMIT="${TARGET_COMMIT}" \
  TARGET_BRANCH="${TARGET_BRANCH}" DB_BACKUP="${DB_BACKUP}" \
  python3 - "${BACKUP_DIR}/manifest.json" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

payload = {
    "status": os.environ["STATUS"],
    "branch": os.environ["TARGET_BRANCH"],
    "old_commit": os.environ["OLD_COMMIT"],
    "target_commit": os.environ["TARGET_COMMIT"],
    "database_backup": os.environ.get("DB_BACKUP", ""),
    "recorded_at": datetime.now(timezone.utc).isoformat(),
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
PY
}

rollback() {
  local original_error="$1"
  write_manifest "failed; rollback started"
  if ! truthy "${ROLLBACK_ON_FAILURE}"; then
    fail "${original_error}; automatic rollback is disabled; backup: ${BACKUP_DIR}"
  fi

  log "deployment failed; rolling code back to ${OLD_COMMIT}"
  git reset --hard "${OLD_COMMIT}"
  if [[ "${ENV_EXISTED}" == "1" ]]; then
    cp -p "${BACKUP_DIR}/env.backup" .env
    chmod 600 .env
  else
    rm -f .env
  fi

  if bash scripts/deploy-local.sh; then
    write_manifest "failed; code and containers rolled back"
    printf '[upgrade] Original upgrade failed: %s\n' "${original_error}" >&2
    printf '[upgrade] Code/container rollback succeeded. Database migrations are intentionally not reversed.\n' >&2
    printf '[upgrade] Backup directory: %s\n' "${BACKUP_DIR}" >&2
    exit 1
  fi

  write_manifest "failed; rollback deployment also failed"
  printf '[upgrade] ERROR: upgrade and rollback deployment both failed\n' >&2
  printf '[upgrade] Backup directory: %s\n' "${BACKUP_DIR}" >&2
  printf '[upgrade] Inspect with: docker compose ps -a && docker compose logs --tail=300 --no-color\n' >&2
  exit 1
}

if [[ "${OLD_COMMIT}" == "${TARGET_COMMIT}" ]]; then
  log "already at ${TARGET_COMMIT}; configuration and deployment will still be verified"
else
  log "fast-forwarding ${OLD_COMMIT} -> ${TARGET_COMMIT}"
  git merge --ff-only "${REMOTE}/${TARGET_BRANCH}" || fail "fast-forward merge failed"
fi

if ! bash scripts/init-env.sh; then
  rollback "environment migration failed"
fi
if ! docker compose config --quiet; then
  rollback "Docker Compose validation failed"
fi
if ! bash scripts/deploy-local.sh; then
  rollback "container build, startup, or readiness validation failed"
fi

write_manifest "success"
log "upgrade complete"
log "branch: ${TARGET_BRANCH}"
log "commit: $(git rev-parse HEAD)"
log "backup: ${BACKUP_DIR}"
if [[ -n "${DB_BACKUP}" ]]; then
  log "database backup: ${DB_BACKUP}"
fi
