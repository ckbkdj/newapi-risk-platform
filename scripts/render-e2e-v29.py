#!/usr/bin/env python3
from pathlib import Path
import sys

source = Path(sys.argv[1] if len(sys.argv) > 1 else "scripts/e2e-legacy.sh")
text = source.read_text(encoding="utf-8")


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"v29 E2E migration anchor count={count}, expected 1: {old[:120]!r}")
    text = text.replace(old, new, 1)


def fail_open_status(filename: str) -> None:
    old = f'assert_status 555 "${{status}}" "${{WORKDIR}}/{filename}"'
    new = (
        f'assert_status 200 "${{status}}" "${{WORKDIR}}/{filename}"\n'
        f'contains "${{WORKDIR}}/{filename}" \'mock provider success\''
    )
    replace_once(old, new)


# These are ordinary operations or model-only uncertainty. Under v29 they must
# reach upstream rather than become a synthetic 555.
for filename in (
    "precision-replay.json",
    "precision-persistence.json",
    "precision-key.json",
    "precision-local-log.json",
    "long-block-response.json",
    "model-block.json",
    "audit-http-401.json",
    "audit-invalid.json",
):
    fail_open_status(filename)

# Remove obsolete blocked-risk assertions that follow the now-allowed cases.
for obsolete in (
    'contains "${WORKDIR}/long-block-response.json" \'CYBER_MOCK_MODEL_BLOCK\'\n',
    'contains "${WORKDIR}/model-block.json" \'CYBER_MOCK_MODEL_BLOCK\'\n',
    'contains "${WORKDIR}/audit-http-401.json" \'AUDIT_MODEL_ERROR\'\n',
    'contains "${WORKDIR}/audit-invalid.json" \'AUDIT_MODEL_ERROR\'\n',
):
    replace_once(obsolete, "")

replace_once(
'''  expected_status=200
  if [[ "${case_name}" != lower-bound ]]; then expected_status=555; fi
  assert_status "${expected_status}" "${status}" "${WORKDIR}/incident-${case_name}-response.json"''',
'''  expected_status=200
  # Routine AOSP/ADB/admin false positives are uncertain and therefore allowed.
  # The mixed case contains an explicit hidden-backdoor operation and remains a
  # confirmed rule block.
  if [[ "${case_name}" == mixed ]]; then expected_status=555; fi
  assert_status "${expected_status}" "${status}" "${WORKDIR}/incident-${case_name}-response.json"
  if [[ "${expected_status}" == 200 ]]; then
    contains "${WORKDIR}/incident-${case_name}-response.json" 'mock provider success'
  fi'''
)

replace_once(
'''  expected_status=555
  assert_status "${expected_status}" "${status}" "${WORKDIR}/boundary-${case_name}-response.json"''',
'''  # The boundary fixtures deliberately represent false positives, invalid
  # evidence, or verifier uncertainty. None is confirmed policy evidence.
  expected_status=200
  assert_status "${expected_status}" "${status}" "${WORKDIR}/boundary-${case_name}-response.json"
  contains "${WORKDIR}/boundary-${case_name}-response.json" 'mock provider success' '''
)

# Audit model failures remain visible in attempt diagnostics, but are no longer
# converted to AUDIT_MODEL_ERROR/555 after the retry/fallback chain is exhausted.
replace_once(
'''errors = [item for item in items if item.get("risk_code") == "AUDIT_MODEL_ERROR"]
if not errors:
    raise RuntimeError("AUDIT_MODEL_ERROR trace is missing")
classes = {item.get("metadata", {}).get("audit_error_class") for item in errors}
if "invalid_json" not in classes:
    raise RuntimeError(f"invalid_json audit diagnostic missing: {classes}")
if "authentication" not in classes:
    raise RuntimeError(f"authentication audit diagnostic missing: {classes}")
for item in errors:
    metadata = item.get("metadata", {})
    if not metadata.get("audit_reason") or not metadata.get("error_reason"):
        raise RuntimeError(f"audit error trace is missing readable reason: {item}")
if not any(item.get("metadata", {}).get("audit_http_status") == 401 for item in errors):
    raise RuntimeError("audit HTTP status 401 was not persisted")''',
'''uncertain = [
    item for item in items
    if item.get("decision") == "allow"
    and item.get("metadata", {}).get("audit_source") == "model_error_fail_open_v29"
]
if not uncertain:
    raise RuntimeError("v29 audit-uncertainty allow trace is missing")
classes = {
    attempt.get("error_class")
    for item in uncertain
    for attempt in item.get("metadata", {}).get("audit_attempts", [])
    if attempt.get("error_class")
}
if "invalid_json" not in classes:
    raise RuntimeError(f"invalid_json retry diagnostic missing: {classes}")
if "authentication" not in classes:
    raise RuntimeError(f"authentication retry diagnostic missing: {classes}")
for item in uncertain:
    metadata = item.get("metadata", {})
    if int(item.get("http_status", 0)) != 200 or metadata.get("upstream_started") is not True:
        raise RuntimeError(f"audit uncertainty did not fail open: {item}")
    if not metadata.get("audit_attempts"):
        raise RuntimeError(f"audit uncertainty lost attempt diagnostics: {item}")'''
)

replace_once(
'''# These synthetic primary review/block results must no longer be overturned
# by a second model just because their framing is routine engineering.
for name in ("aosp", "adb", "admin"):
    row = next((i for i in items if i.get("request_id") == "e2e-incident-" + name), None)
    assert row and row.get("http_status")==555, (name,row)
    m=row.get("metadata",{})
    assert m.get("audit_effective_decision")=="block" and m.get("upstream_started") is False, (name,m)
    assert not m.get("audit_policy_adjustment"), (name,m)

for name in ("history", "instruction", "ui", "mixed", "adopted", "failure"):
    row=next((i for i in items if i.get("request_id")=="e2e-boundary-"+name),None)
    assert row and row.get("http_status")==555, (name,row)
    m=row.get("metadata",{})
    assert m.get("audit_input_contract")=="risk_audit_request.v2" and m.get("upstream_started") is False, (name,m)
    if name in ("instruction","failure"):
        assert m.get("audit_category")=="audit_infrastructure" and m.get("audit_completed") is False, (name,m)
    else:
        assert not m.get("audit_error_class") and m.get("audit_semantic_review_calls")==0, (name,m)
    assert m.get("audit_semantic_review_status")!="overturned", (name,m)''',
'''# Routine engineering false positives and any verifier uncertainty are
# observable allows. Only the explicit hidden-backdoor mixed case is blocked.
for name in ("aosp", "adb", "admin"):
    row = next((i for i in items if i.get("request_id") == "e2e-incident-" + name), None)
    assert row and row.get("http_status")==200 and row.get("decision")=="allow", (name,row)
    m=row.get("metadata",{})
    assert m.get("upstream_started") is True, (name,m)
    assert m.get("audit_source") in {"model_uncertainty_fail_open_v29", "model_error_fail_open_v29"}, (name,m)

mixed = next((i for i in items if i.get("request_id") == "e2e-incident-mixed"), None)
assert mixed and mixed.get("http_status")==555 and mixed.get("decision")=="block", mixed
assert mixed.get("metadata",{}).get("upstream_started") is False, mixed

for name in ("history", "instruction", "ui", "mixed", "adopted", "failure"):
    row=next((i for i in items if i.get("request_id")=="e2e-boundary-"+name),None)
    assert row and row.get("http_status")==200 and row.get("decision")=="allow", (name,row)
    m=row.get("metadata",{})
    assert m.get("audit_input_contract")=="risk_audit_request.v2" and m.get("upstream_started") is True, (name,m)'''
)

replace_once(
'''model_block = next((item for item in items if item.get("request_id") == "e2e-model-block-evidence"), None)
if not model_block:
    raise RuntimeError("semantic model block trace is missing")
model_meta = model_block.get("metadata", {})
if model_block.get("decision") != "block" or model_block.get("risk_code") != "CYBER_MOCK_MODEL_BLOCK":
    raise RuntimeError(f"unexpected semantic model block: {model_block}")
if model_meta.get("audit_source") != "model" or model_meta.get("audit_model_decision") != "block":
    raise RuntimeError(f"model decision diagnostics missing: {model_meta}")
if model_meta.get("audit_model_evidence") != "model-audit-block":
    raise RuntimeError(f"exact model evidence missing: {model_meta}")
if model_meta.get("audit_model_evidence_verified") is not True:
    raise RuntimeError(f"model evidence was not verified: {model_meta}")
if "⟦model-audit-block⟧" not in str(model_meta.get("audit_model_evidence_context", "")):
    raise RuntimeError(f"model evidence context missing: {model_meta}")
if model_meta.get("audit_trigger_input") != "model-audit-block" or not model_meta.get("audit_trigger_context"):
    raise RuntimeError(f"generic trigger fields missing: {model_meta}")
if not model_meta.get("audit_reason") or not model_meta.get("audit_model_user_guidance"):
    raise RuntimeError(f"model block reason/guidance missing: {model_meta}")
model_attempts = model_meta.get("audit_attempts", [])
if not model_attempts or model_attempts[-1].get("decision") != "block" or model_attempts[-1].get("evidence") != "model-audit-block":
    raise RuntimeError(f"successful attempt decision/evidence missing: {model_attempts}")''',
'''model_block = next((item for item in items if item.get("request_id") == "e2e-model-block-evidence"), None)
if not model_block:
    raise RuntimeError("model uncertainty trace is missing")
model_meta = model_block.get("metadata", {})
if model_block.get("decision") != "allow" or int(model_block.get("http_status", 0)) != 200:
    raise RuntimeError(f"noncanonical model-only block must fail open: {model_block}")
if model_meta.get("audit_source") != "model_uncertainty_fail_open_v29" or model_meta.get("upstream_started") is not True:
    raise RuntimeError(f"model fail-open diagnostics missing: {model_meta}")'''
)

replace_once(
'''long_block_meta = long_items["e2e-long-block"].get("metadata", {})
if long_block_meta.get("audit_model_evidence") != "model-audit-block" or long_block_meta.get("audit_model_evidence_verified") is not True:
    raise RuntimeError(f"chunked model block evidence missing: {long_block_meta}")
if int(long_block_meta.get("audit_model_evidence_chunk_index", 0)) < 1 or int(long_block_meta.get("audit_model_evidence_chunk_count", 0)) < 2:
    raise RuntimeError(f"chunked model evidence location missing: {long_block_meta}")''',
'''long_block = long_items["e2e-long-block"]
long_block_meta = long_block.get("metadata", {})
if long_block.get("decision") != "allow" or int(long_block.get("http_status", 0)) != 200:
    raise RuntimeError(f"chunked noncanonical model block did not fail open: {long_block}")
if long_block_meta.get("upstream_started") is not True:
    raise RuntimeError(f"chunked fail-open did not reach upstream: {long_block_meta}")'''
)

sys.stdout.write(text)
