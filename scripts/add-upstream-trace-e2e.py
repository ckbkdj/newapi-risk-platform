from pathlib import Path

path = Path(__file__).resolve().parents[1] / "scripts/e2e.sh"
text = path.read_text(encoding="utf-8")


def once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    text = text.replace(old, new, 1)

once(
    "  --data-binary '{\"model\":\"stream-late-error\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"safe stream request\"}]}'",
    "  -H 'X-Request-ID: e2e-stream-late' \\\n  --data-binary '{\"model\":\"stream-late-error\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"safe stream request\"}]}'",
    "late stream request id",
)
once(
    "  --data-binary '{\"model\":\"stream-normal\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"safe normal stream request\"}]}'",
    "  -H 'X-Request-ID: e2e-stream-normal' \\\n  --data-binary '{\"model\":\"stream-normal\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"safe normal stream request\"}]}'",
    "normal stream request id",
)
once(
    "     grep -Fq 'e2e-own-secret-self-service' \"${WORKDIR}/traces.json\" && \\\n     grep -Fq 'e2e-audit-failover' \"${WORKDIR}/traces.json\"; then",
    "     grep -Fq 'e2e-own-secret-self-service' \"${WORKDIR}/traces.json\" && \\\n     grep -Fq 'e2e-stream-late' \"${WORKDIR}/traces.json\" && \\\n     grep -Fq 'e2e-stream-normal' \"${WORKDIR}/traces.json\" && \\\n     grep -Fq 'e2e-audit-failover' \"${WORKDIR}/traces.json\"; then",
    "trace wait condition",
)
once(
    '''attempts = fm.get("audit_attempts", [])
if len(attempts) != 6 or not attempts[-1].get("success"):
    raise RuntimeError(f"attempt diagnostics missing: {attempts}")
PY''',
    '''attempts = fm.get("audit_attempts", [])
if len(attempts) != 6 or not attempts[-1].get("success"):
    raise RuntimeError(f"attempt diagnostics missing: {attempts}")

stream_late = next((item for item in items if item.get("request_id") == "e2e-stream-late"), None)
if not stream_late:
    raise RuntimeError("late-stream trace missing")
late_meta = stream_late.get("metadata", {})
if stream_late.get("decision") != "error" or stream_late.get("risk_code") != "UPSTREAM_STREAM_ERROR":
    raise RuntimeError(f"late-stream final outcome is wrong: {stream_late}")
if late_meta.get("failure_stage") != "upstream_stream":
    raise RuntimeError(f"late-stream failure stage is wrong: {late_meta}")
if late_meta.get("upstream_error_reason") != "late stream failure":
    raise RuntimeError(f"late-stream upstream reason missing: {late_meta}")
if late_meta.get("error_reason") != "late stream failure":
    raise RuntimeError(f"final error reason was contaminated by audit reason: {late_meta}")
if late_meta.get("audit_reason") == late_meta.get("error_reason"):
    raise RuntimeError(f"benign audit reason incorrectly became final error: {late_meta}")
if late_meta.get("stream_error_semantics") != "logical_555_after_headers":
    raise RuntimeError(f"late-stream logical 555 semantics missing: {late_meta}")

stream_normal = next((item for item in items if item.get("request_id") == "e2e-stream-normal"), None)
if not stream_normal:
    raise RuntimeError("normal-stream trace missing")
normal_meta = stream_normal.get("metadata", {})
if stream_normal.get("decision") != "allow" or int(stream_normal.get("http_status", 0)) != 200:
    raise RuntimeError(f"normal stream should remain allowed: {stream_normal}")
for key in ("error_reason", "failure_stage", "stream_error_semantics", "upstream_error_reason"):
    if normal_meta.get(key):
        raise RuntimeError(f"normal stream was polluted with {key}: {normal_meta}")
PY''',
    "stream trace metadata assertions",
)

path.write_text(text, encoding="utf-8")
print("upstream trace E2E regression applied")
