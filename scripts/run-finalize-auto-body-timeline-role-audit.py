from pathlib import Path

script_path = Path(__file__).with_name("finalize-auto-body-timeline-role-audit.py")
source = script_path.read_text(encoding="utf-8")


def remove_labeled_call(program: str, label: str) -> str:
    label_position = program.index(f'"{label}"')
    start = program.rfind("e2e = replace_once(", 0, label_position)
    if start < 0:
        raise SystemExit(f"{label}: replace call start not found")
    end = program.index("\n)\n", label_position) + len("\n)\n")
    return program[:start] + program[end:]


# PR #13 already contains a longer source-attribution assertion block than the
# original staged patch expected. Replace the entire stable too-large section
# after all other finalization edits instead of matching a short subsequence.
source = remove_labeled_call(source, "E2E hard limit trace assertion")
source = remove_labeled_call(source, "E2E automatic large request trace assertions")

code = compile(source, str(script_path), "exec")
exec(code, {"__name__": "__main__", "__file__": str(script_path)})

root = script_path.parents[1]
e2e_path = root / "scripts/e2e.sh"
e2e = e2e_path.read_text(encoding="utf-8")
start_marker = 'too_large = next((item for item in items if item.get("request_id") == "e2e-request-too-large"), None)\n'
end_marker = 'rule_item = next((item for item in items if item.get("request_id") == "e2e-rule-explainability"), None)\n'
start = e2e.find(start_marker)
end = e2e.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("stable E2E request-limit assertion boundaries not found")

replacement = r'''too_large = next((item for item in items if item.get("request_id") == "e2e-request-too-large"), None)
if not too_large:
    raise RuntimeError("REQUEST_TOO_LARGE trace is missing")
metadata = too_large.get("metadata", {})
if int(too_large.get("request_bytes", 0)) <= 1048576:
    raise RuntimeError(f"oversized request bytes were not persisted: {too_large}")
if int(metadata.get("request_body_limit_bytes", 0)) != 1048576:
    raise RuntimeError(f"oversized request hard limit missing: {metadata}")
if int(metadata.get("request_body_over_limit_bytes", 0)) <= 0:
    raise RuntimeError(f"oversized request overage missing: {metadata}")
if metadata.get("request_body_size_exact") is not True:
    raise RuntimeError(f"Content-Length request should have exact size: {metadata}")
if metadata.get("error_origin") != "risk_gateway" or metadata.get("failure_stage") != "gateway_ingress":
    raise RuntimeError(f"REQUEST_TOO_LARGE source/stage is ambiguous: {metadata}")
if metadata.get("request_body_limit_mode") != "auto_hard_ceiling" or metadata.get("limit_config") != "REQUEST_HARD_MAX_BYTES":
    raise RuntimeError(f"REQUEST_TOO_LARGE hard-ceiling owner/mode is missing: {metadata}")
if metadata.get("failure_component") != "request_body_guard":
    raise RuntimeError(f"REQUEST_TOO_LARGE owning guard is missing: {metadata}")
if metadata.get("audit_started") is not False or metadata.get("upstream_started") is not False:
    raise RuntimeError(f"REQUEST_TOO_LARGE must state that audit/upstream were not called: {metadata}")
if not metadata.get("request_body_remediation"):
    raise RuntimeError(f"REQUEST_TOO_LARGE remediation is missing: {metadata}")

auto_large = next((item for item in items if item.get("request_id") == "e2e-newapi-auto-large"), None)
if not auto_large:
    raise RuntimeError("automatic actual-size request trace is missing")
alm = auto_large.get("metadata", {})
if auto_large.get("decision") != "allow" or int(auto_large.get("http_status", 0)) != 200:
    raise RuntimeError(f"automatic actual-size request was not allowed: {auto_large}")
if auto_large.get("newapi_request_id") != "e2e-newapi-auto-large" or alm.get("request_id_source") != "x_oneapi_request_id":
    raise RuntimeError(f"native NewAPI request ID correlation missing: {auto_large}")
if alm.get("request_body_limit_mode") != "auto_actual_size" or int(alm.get("request_body_effective_limit_bytes", 0)) <= 131072:
    raise RuntimeError(f"automatic request body admission metadata missing: {alm}")
if int(alm.get("request_body_hard_limit_bytes", 0)) != 1048576:
    raise RuntimeError(f"automatic request hard ceiling missing: {alm}")
if alm.get("large_request_slot") is not True or alm.get("audit_started") is not True or alm.get("upstream_started") is not True:
    raise RuntimeError(f"large request stage diagnostics missing: {alm}")

'''
e2e_path.write_text(e2e[:start] + replacement + e2e[end:], encoding="utf-8")
