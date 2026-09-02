from pathlib import Path

root = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


types = root / "internal/platform/types.go"
replace_once(
    types,
    '''type AuditAttempt struct {
\tProfileID   int64  `json:"profile_id"`
\tProfileName string `json:"profile_name"`
\tModel       string `json:"model"`
\tAttempt     int    `json:"attempt"`
\tSuccess     bool   `json:"success"`
\tErrorClass  string `json:"error_class,omitempty"`
\tHTTPStatus  int    `json:"http_status,omitempty"`
\tReason      string `json:"reason,omitempty"`
}
''',
    '''type AuditAttempt struct {
\tProfileID   int64   `json:"profile_id"`
\tProfileName string  `json:"profile_name"`
\tModel       string  `json:"model"`
\tAttempt     int     `json:"attempt"`
\tSuccess     bool    `json:"success"`
\tDecision    string  `json:"decision,omitempty"`
\tRiskCode    string  `json:"risk_code,omitempty"`
\tConfidence  float64 `json:"confidence,omitempty"`
\tEvidence    string  `json:"evidence,omitempty"`
\tErrorClass  string  `json:"error_class,omitempty"`
\tHTTPStatus  int     `json:"http_status,omitempty"`
\tReason      string  `json:"reason,omitempty"`
}
''',
    "audit attempt result fields",
)

failover = root / "internal/platform/audit_failover.go"
replace_once(
    failover,
    '''\t\t\tif err == nil {
\t\t\t\tmetadata.Attempts = append(metadata.Attempts, attemptRecord)
\t\t\t\treturn decision, profile, metadata, nil
\t\t\t}
''',
    '''\t\t\tif err == nil {
\t\t\t\tattemptRecord.Decision = decision.Decision
\t\t\t\tattemptRecord.RiskCode = decision.RiskCode
\t\t\t\tattemptRecord.Confidence = decision.Confidence
\t\t\t\tattemptRecord.Reason = decision.Reason
\t\t\t\tattemptRecord.Evidence = decision.Evidence
\t\t\t\tmetadata.Attempts = append(metadata.Attempts, attemptRecord)
\t\t\t\treturn decision, profile, metadata, nil
\t\t\t}
''',
    "successful audit attempt details",
)

web = root / "internal/platform/web/index.html"
replace_once(
    web,
    '''          ['实际审计模型',item.metadata?.audit_profile_name||item.metadata?.audit_model||'-'], ['模型调用次数',item.metadata?.audit_model_attempts||'-'], ['模型重试次数',item.metadata?.audit_model_retries||0], ['备用模型切换',item.metadata?.audit_fallback_count||0], ['模型链',(item.metadata?.audit_models_tried||[]).join(' → ')||'-'],
''',
    '''          ['实际审计模型',item.metadata?.audit_profile_name||item.metadata?.audit_model||'-'], ['模型调用次数',item.metadata?.audit_model_attempts||'-'], ['模型重试次数',item.metadata?.audit_model_retries||0], ['备用模型切换',item.metadata?.audit_fallback_count||0], ['模型链',(item.metadata?.audit_models_tried||[]).join(' → ')||'-'],
          ['审计尝试详情',(item.metadata?.audit_attempts||[]).map(a=>`${a.profile_name||a.model||'-'} #${a.attempt}: ${a.success?(a.decision||'success'):(a.error_class||'error')}${a.risk_code?` / ${a.risk_code}`:''}${a.evidence?` / 证据 ${a.evidence}`:''}${a.reason?` / ${a.reason}`:''}`).join(' | ')||'-'],
''',
    "web audit attempt details",
)

e2e = root / "scripts/e2e.sh"
replace_once(
    e2e,
    '''if not model_meta.get("audit_reason") or not model_meta.get("audit_model_user_guidance"):
    raise RuntimeError(f"model block reason/guidance missing: {model_meta}")

long_items =''',
    '''if not model_meta.get("audit_reason") or not model_meta.get("audit_model_user_guidance"):
    raise RuntimeError(f"model block reason/guidance missing: {model_meta}")
model_attempts = model_meta.get("audit_attempts", [])
if not model_attempts or model_attempts[-1].get("decision") != "block" or model_attempts[-1].get("evidence") != "model-audit-block":
    raise RuntimeError(f"successful attempt decision/evidence missing: {model_attempts}")

long_items =''',
    "E2E attempt evidence assertion",
)

doc = root / "docs/audit-block-evidence.md"
replace_once(
    doc,
    '''  "audit_model_evidence_verified": true,
  "audit_trigger_input": "export another user's API key"
}
''',
    '''  "audit_model_evidence_verified": true,
  "audit_trigger_input": "export another user's API key",
  "audit_attempts": [
    {
      "profile_name": "cyber",
      "model": "Qwen3.8-27B",
      "attempt": 1,
      "success": true,
      "decision": "block",
      "risk_code": "CYBER_CREDENTIAL_THEFT",
      "confidence": 0.99,
      "reason": "The request asks to export another user's credential.",
      "evidence": "export another user's API key"
    }
  ]
}
''',
    "documentation attempt example",
)

print("audit attempt details applied")
