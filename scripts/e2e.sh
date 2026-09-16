#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

rendered="$(mktemp)"
trap 'rm -f "${rendered}"' EXIT

python3 scripts/render-e2e-v29.py scripts/e2e-legacy.sh >"${rendered}"
# v29 separates ambiguous credential access (review/fail-open) from explicit
# public disclosure/exfiltration (hard block). Only update the dedicated public
# log fixture; other REVIEW assertions keep their semantic-review meaning.
sed -i '/own-secret-public-log\.json/s/CYBER_CREDENTIAL_ACCESS_REVIEW/CYBER_CREDENTIAL_ACCESS_DISABLED/' "${rendered}"
bash "${rendered}"
