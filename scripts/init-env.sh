#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

command -v python3 >/dev/null 2>&1 || {
  echo "ERROR: python3 is required to initialize .env" >&2
  exit 1
}

python3 - <<'PY'
from __future__ import annotations

import base64
import os
import re
import secrets
from pathlib import Path

root = Path.cwd()
template_path = root / ".env.example"
env_path = root / ".env"

if not template_path.exists():
    raise SystemExit("ERROR: .env.example was not found")

created = not env_path.exists()
text = template_path.read_text(encoding="utf-8") if created else env_path.read_text(encoding="utf-8")


def parse_values(source: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        result[key] = value
    return result


def is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        not lowered
        or lowered.startswith("replace-")
        or lowered.startswith("replace_with")
        or "replace-with" in lowered
        or lowered in {"changeme", "change-me", "password", "secret"}
    )


def set_value(source: str, key: str, value: str) -> str:
    pattern = re.compile(rf"(?m)^{re.escape(key)}=.*$")
    replacement = f"{key}={value}"
    if pattern.search(source):
        return pattern.sub(lambda _match: replacement, source, count=1)
    suffix = "" if source.endswith("\n") else "\n"
    return source + suffix + replacement + "\n"


values = parse_values(text)
generated: dict[str, str] = {}
warnings: list[str] = []
errors: list[str] = []

# Port and bind defaults are repaired without exposing any secret.
try:
    port = int(values.get("HTTP_PORT", "8080"))
except ValueError:
    port = 8080
if port < 1 or port > 65535:
    port = 8080
text = set_value(text, "HTTP_PORT", str(port))
if not values.get("BIND_ADDRESS", "").strip():
    text = set_value(text, "BIND_ADDRESS", "0.0.0.0")

force_new_postgres = os.environ.get("FORCE_NEW_POSTGRES_PASSWORD", "").lower() in {"1", "true", "yes"}
postgres_password = values.get("POSTGRES_PASSWORD", "")
if force_new_postgres or not postgres_password:
    postgres_password = secrets.token_hex(24)
    text = set_value(text, "POSTGRES_PASSWORD", postgres_password)
    generated["POSTGRES_PASSWORD"] = postgres_password
elif is_placeholder(postgres_password):
    warnings.append(
        "POSTGRES_PASSWORD is still an example value. It was preserved to avoid breaking an already initialized PostgreSQL volume. "
        "For a fresh deployment, run RESET_DATA=1 bash scripts/deploy-local.sh."
    )

master_value = values.get("MASTER_KEY_B64", "")
master_valid = False
if not is_placeholder(master_value):
    try:
        master_valid = len(base64.b64decode(master_value, validate=True)) == 32
    except Exception:
        master_valid = False
if is_placeholder(master_value):
    master_value = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    text = set_value(text, "MASTER_KEY_B64", master_value)
    generated["MASTER_KEY_B64"] = "generated"
elif not master_valid:
    errors.append("MASTER_KEY_B64 exists but is invalid; it must be base64 for exactly 32 bytes")

jwt_value = values.get("JWT_SECRET", "")
if is_placeholder(jwt_value):
    jwt_value = secrets.token_hex(32)
    text = set_value(text, "JWT_SECRET", jwt_value)
    generated["JWT_SECRET"] = "generated"
elif len(jwt_value.encode("utf-8")) < 32:
    errors.append("JWT_SECRET exists but is shorter than 32 bytes")

admin_user = values.get("BOOTSTRAP_ADMIN_USERNAME", "").strip() or "admin"
text = set_value(text, "BOOTSTRAP_ADMIN_USERNAME", admin_user)
admin_password = values.get("BOOTSTRAP_ADMIN_PASSWORD", "")
if is_placeholder(admin_password):
    admin_password = secrets.token_urlsafe(24)
    text = set_value(text, "BOOTSTRAP_ADMIN_PASSWORD", admin_password)
    generated["BOOTSTRAP_ADMIN_PASSWORD"] = admin_password
elif len(admin_password) < 14:
    errors.append("BOOTSTRAP_ADMIN_PASSWORD exists but is shorter than 14 characters")

if errors:
    for error in errors:
        print(f"ERROR: {error}")
    raise SystemExit(1)

env_path.write_text(text, encoding="utf-8")
os.chmod(env_path, 0o600)

print(f"Environment file: {env_path}")
print(f"HTTP endpoint: http://127.0.0.1:{port}")
print(f"Admin username: {admin_user}")
if "BOOTSTRAP_ADMIN_PASSWORD" in generated:
    print(f"Admin password: {generated['BOOTSTRAP_ADMIN_PASSWORD']}")
    print("Save this password now. It is written to .env and will not be printed on later runs.")
else:
    print("Admin password: existing value preserved in .env")
for warning in warnings:
    print(f"WARNING: {warning}")
PY
