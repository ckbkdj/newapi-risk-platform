#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

rendered="$(mktemp)"
trap 'rm -f "${rendered}"' EXIT

python3 scripts/render-e2e-v29.py scripts/e2e-legacy.sh >"${rendered}"
bash "${rendered}"
