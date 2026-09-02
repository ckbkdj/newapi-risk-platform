from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str, label: str) -> None:
    file_path = ROOT / path
    text = file_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match in {path}, found {count}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


# ---------------------------------------------------------------------------
# Runtime configuration: request-side chunking, never model-side truncation.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/config.go",
    "\tAuditPromptTruncateTokens      int\n\tSSELineMaxBytes                int\n",
    "\tAuditContextTargetTokens       int\n"
    "\tAuditFallbackChunkBytes        int\n"
    "\tAuditChunkOverlapBytes         int\n"
    "\tAuditChunkConcurrency          int\n"
    "\tAuditMaxChunks                 int\n"
    "\tSSELineMaxBytes                int\n",
    "config struct chunk fields",
)
replace_once(
    "internal/platform/config.go",
    "\t\tAuditTextMaxBytes:              envInt(\"AUDIT_TEXT_MAX_BYTES\", 2*1024*1024),\n"
    "\t\tAuditOutputMaxTokens:           envInt(\"AUDIT_OUTPUT_MAX_TOKENS\", 128),\n"
    "\t\tAuditDisableThinking:           envBool(\"AUDIT_DISABLE_THINKING\", true),\n"
    "\t\tAuditLongContextThresholdBytes: envInt(\"AUDIT_LONG_CONTEXT_THRESHOLD_BYTES\", 128*1024),\n"
    "\t\tAuditLongContextTimeout:        envDuration(\"AUDIT_LONG_CONTEXT_TIMEOUT\", 120*time.Second),\n"
    "\t\tAuditPromptTruncateTokens:      envInt(\"AUDIT_PROMPT_TRUNCATE_TOKENS\", 260000),\n",
    "\t\tAuditTextMaxBytes:              envInt(\"AUDIT_TEXT_MAX_BYTES\", 8*1024*1024),\n"
    "\t\tAuditOutputMaxTokens:           envInt(\"AUDIT_OUTPUT_MAX_TOKENS\", 128),\n"
    "\t\tAuditDisableThinking:           envBool(\"AUDIT_DISABLE_THINKING\", true),\n"
    "\t\tAuditLongContextThresholdBytes: envInt(\"AUDIT_LONG_CONTEXT_THRESHOLD_BYTES\", 128*1024),\n"
    "\t\tAuditLongContextTimeout:        envDuration(\"AUDIT_LONG_CONTEXT_TIMEOUT\", 120*time.Second),\n"
    "\t\tAuditContextTargetTokens:       envInt(\"AUDIT_CONTEXT_TARGET_TOKENS\", envInt(\"AUDIT_PROMPT_TRUNCATE_TOKENS\", 260000)),\n"
    "\t\tAuditFallbackChunkBytes:        envInt(\"AUDIT_FALLBACK_CHUNK_BYTES\", 192*1024),\n"
    "\t\tAuditChunkOverlapBytes:         envInt(\"AUDIT_CHUNK_OVERLAP_BYTES\", 4096),\n"
    "\t\tAuditChunkConcurrency:          envInt(\"AUDIT_CHUNK_CONCURRENCY\", 2),\n"
    "\t\tAuditMaxChunks:                 envInt(\"AUDIT_MAX_CHUNKS\", 64),\n",
    "config load chunk fields",
)
replace_once(
    "internal/platform/config.go",
    "\tif c.AuditTextMaxBytes < 4096 || c.AuditTextMaxBytes > 2*1024*1024 {\n"
    "\t\tproblems = append(problems, \"AUDIT_TEXT_MAX_BYTES must be between 4 KiB and 2 MiB\")\n"
    "\t}\n"
    "\tif c.AuditOutputMaxTokens < 32 || c.AuditOutputMaxTokens > 1024 {\n"
    "\t\tproblems = append(problems, \"AUDIT_OUTPUT_MAX_TOKENS must be between 32 and 1024\")\n"
    "\t}\n"
    "\tif c.AuditLongContextThresholdBytes < 4096 || c.AuditLongContextThresholdBytes > c.AuditTextMaxBytes {\n"
    "\t\tproblems = append(problems, \"AUDIT_LONG_CONTEXT_THRESHOLD_BYTES must be between 4 KiB and AUDIT_TEXT_MAX_BYTES\")\n"
    "\t}\n"
    "\tif c.AuditLongContextTimeout < time.Second || c.AuditLongContextTimeout > 10*time.Minute {\n"
    "\t\tproblems = append(problems, \"AUDIT_LONG_CONTEXT_TIMEOUT must be between 1s and 10m\")\n"
    "\t}\n"
    "\tif c.AuditPromptTruncateTokens < 1024 || c.AuditPromptTruncateTokens > 1000000 {\n"
    "\t\tproblems = append(problems, \"AUDIT_PROMPT_TRUNCATE_TOKENS must be between 1024 and 1000000\")\n"
    "\t}\n",
    "\tif c.AuditTextMaxBytes < 4096 || c.AuditTextMaxBytes > 16*1024*1024 {\n"
    "\t\tproblems = append(problems, \"AUDIT_TEXT_MAX_BYTES must be between 4 KiB and 16 MiB\")\n"
    "\t}\n"
    "\tif c.AuditOutputMaxTokens < 32 || c.AuditOutputMaxTokens > 1024 {\n"
    "\t\tproblems = append(problems, \"AUDIT_OUTPUT_MAX_TOKENS must be between 32 and 1024\")\n"
    "\t}\n"
    "\tif c.AuditLongContextThresholdBytes < 256 || c.AuditLongContextThresholdBytes > c.AuditTextMaxBytes {\n"
    "\t\tproblems = append(problems, \"AUDIT_LONG_CONTEXT_THRESHOLD_BYTES must be between 256 bytes and AUDIT_TEXT_MAX_BYTES\")\n"
    "\t}\n"
    "\tif c.AuditLongContextTimeout < time.Second || c.AuditLongContextTimeout > 10*time.Minute {\n"
    "\t\tproblems = append(problems, \"AUDIT_LONG_CONTEXT_TIMEOUT must be between 1s and 10m\")\n"
    "\t}\n"
    "\tif c.AuditContextTargetTokens < 1024 || c.AuditContextTargetTokens > 1000000 {\n"
    "\t\tproblems = append(problems, \"AUDIT_CONTEXT_TARGET_TOKENS must be between 1024 and 1000000\")\n"
    "\t}\n"
    "\tif c.AuditFallbackChunkBytes < 1024 || c.AuditFallbackChunkBytes > c.AuditTextMaxBytes {\n"
    "\t\tproblems = append(problems, \"AUDIT_FALLBACK_CHUNK_BYTES must be between 1024 and AUDIT_TEXT_MAX_BYTES\")\n"
    "\t}\n"
    "\tif c.AuditChunkOverlapBytes < 0 || c.AuditChunkOverlapBytes >= c.AuditFallbackChunkBytes/2 {\n"
    "\t\tproblems = append(problems, \"AUDIT_CHUNK_OVERLAP_BYTES must be non-negative and less than half of AUDIT_FALLBACK_CHUNK_BYTES\")\n"
    "\t}\n"
    "\tif c.AuditChunkConcurrency < 1 || c.AuditChunkConcurrency > 16 {\n"
    "\t\tproblems = append(problems, \"AUDIT_CHUNK_CONCURRENCY must be between 1 and 16\")\n"
    "\t}\n"
    "\tif c.AuditMaxChunks < 2 || c.AuditMaxChunks > 256 {\n"
    "\t\tproblems = append(problems, \"AUDIT_MAX_CHUNKS must be between 2 and 256\")\n"
    "\t}\n",
    "config validation chunk fields",
)

# ---------------------------------------------------------------------------
# Audit engine wiring and trace metadata.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/audit.go",
    "\tpromptTruncateTokens      int\n\trefreshInterval           time.Duration\n",
    "\tcontextTargetTokens      int\n"
    "\tfallbackChunkBytes       int\n"
    "\tchunkOverlapBytes        int\n"
    "\tchunkConcurrency         int\n"
    "\tmaxAuditChunks           int\n"
    "\trefreshInterval          time.Duration\n",
    "audit engine chunk fields",
)
replace_once(
    "internal/platform/audit.go",
    "\t\tpromptTruncateTokens:      cfg.AuditPromptTruncateTokens,\n"
    "\t\trefreshInterval:           cfg.RulesRefreshInterval,\n",
    "\t\tcontextTargetTokens:      cfg.AuditContextTargetTokens,\n"
    "\t\tfallbackChunkBytes:       cfg.AuditFallbackChunkBytes,\n"
    "\t\tchunkOverlapBytes:        cfg.AuditChunkOverlapBytes,\n"
    "\t\tchunkConcurrency:         cfg.AuditChunkConcurrency,\n"
    "\t\tmaxAuditChunks:           cfg.AuditMaxChunks,\n"
    "\t\trefreshInterval:          cfg.RulesRefreshInterval,\n",
    "audit engine chunk initialization",
)
replace_once(
    "internal/platform/audit.go",
    "\tdecision, err := e.callModel(ctx, profile, text)\n"
    "\tresult.Model = profile.Model\n"
    "\tif err != nil {\n"
    "\t\terrorClass, auditHTTPStatus, reason := auditModelErrorDetails(err)\n"
    "\t\tresult.ErrorClass = errorClass\n"
    "\t\tresult.AuditHTTPStatus = auditHTTPStatus\n"
    "\t\tif route.FailClosed || profile.FailClosed {\n"
    "\t\t\tresult.AuditDecision = AuditDecision{\n"
    "\t\t\t\tDecision:   DecisionBlock,\n"
    "\t\t\t\tRiskCode:   \"AUDIT_MODEL_ERROR\",\n"
    "\t\t\t\tCategory:   \"audit_infrastructure\",\n"
    "\t\t\t\tConfidence: 1,\n"
    "\t\t\t\tReason:     reason,\n"
    "\t\t\t\tSource:     \"platform\",\n"
    "\t\t\t}\n",
    "\tdecision, callMetadata, err := e.callModel(ctx, profile, text)\n"
    "\tresult.Model = profile.Model\n"
    "\tresult.AuditMode = callMetadata.Mode\n"
    "\tresult.AuditChunkCount = callMetadata.ChunkCount\n"
    "\tresult.AuditChunkBytes = callMetadata.ChunkBytes\n"
    "\tresult.AuditRequestedTokens = callMetadata.RequestedTokens\n"
    "\tresult.AuditContextWindowTokens = callMetadata.ContextWindowTokens\n"
    "\tresult.AuditRetryCount = callMetadata.RetryCount\n"
    "\tif err != nil {\n"
    "\t\terrorClass, auditHTTPStatus, reason := auditModelErrorDetails(err)\n"
    "\t\tresult.ErrorClass = errorClass\n"
    "\t\tresult.AuditHTTPStatus = auditHTTPStatus\n"
    "\t\triskCode := \"AUDIT_MODEL_ERROR\"\n"
    "\t\tif errorClass == \"context_length\" || errorClass == \"input_too_large\" {\n"
    "\t\t\triskCode = \"AUDIT_CONTEXT_TOO_LARGE\"\n"
    "\t\t}\n"
    "\t\tif route.FailClosed || profile.FailClosed {\n"
    "\t\t\tresult.AuditDecision = AuditDecision{\n"
    "\t\t\t\tDecision:   DecisionBlock,\n"
    "\t\t\t\tRiskCode:   riskCode,\n"
    "\t\t\t\tCategory:   \"audit_infrastructure\",\n"
    "\t\t\t\tConfidence: 1,\n"
    "\t\t\t\tReason:     reason,\n"
    "\t\t\t\tSource:     \"platform\",\n"
    "\t\t\t}\n",
    "audit call metadata and context error",
)
replace_once(
    "internal/platform/audit.go",
    "func (e *AuditEngine) callModel(\n",
    "func (e *AuditEngine) callModelOnce(\n",
    "rename single model call",
)
replace_once(
    "internal/platform/audit.go",
    "\tsystemPrompt := strings.TrimSpace(profile.SystemPrompt)\n"
    "\tif systemPrompt == \"\" {\n"
    "\t\tsystemPrompt = DefaultAuditSystemPrompt\n"
    "\t}\n"
    "\tsystemPrompt = appendFastAuditDirective(systemPrompt)\n"
    "\tpayload := map[string]any{\n"
    "\t\t\"model\":       profile.Model,\n"
    "\t\t\"temperature\": 0,\n"
    "\t\t\"max_tokens\":  e.outputMaxTokens,\n"
    "\t\t\"messages\": []map[string]string{\n"
    "\t\t\t{\"role\": \"system\", \"content\": systemPrompt},\n"
    "\t\t\t{\"role\": \"user\", \"content\": e.auditUserContent(profile, text)},\n"
    "\t\t},\n"
    "\t}\n",
    "\tpayload := map[string]any{\n"
    "\t\t\"model\":       profile.Model,\n"
    "\t\t\"temperature\": 0,\n"
    "\t\t\"max_tokens\":  e.outputMaxTokens,\n"
    "\t\t\"messages\":    e.auditMessages(profile, text),\n"
    "\t}\n",
    "audit single-call messages",
)
replace_once(
    "internal/platform/audit.go",
    "\t\tif json.Unmarshal(profile.Extra, &extra) == nil {\n"
    "\t\t\tfor key, value := range extra {\n"
    "\t\t\t\tswitch key {\n",
    "\t\tif json.Unmarshal(profile.Extra, &extra) == nil {\n"
    "\t\t\tfor key, value := range extra {\n"
    "\t\t\t\tif isInternalAuditExtraKey(key) {\n"
    "\t\t\t\t\tcontinue\n"
    "\t\t\t\t}\n"
    "\t\t\t\tswitch key {\n",
    "strip internal audit extras",
)

replace_once(
    "internal/platform/types.go",
    "type AuditResult struct {\n"
    "\tAuditDecision\n"
    "\tPromptHMAC      string        `json:\"prompt_hmac\"`\n"
    "\tTextBytes       int           `json:\"text_bytes\"`\n"
    "\tLatency         time.Duration `json:\"-\"`\n"
    "\tModel           string        `json:\"model,omitempty\"`\n"
    "\tErrorClass      string        `json:\"error_class,omitempty\"`\n"
    "\tAuditHTTPStatus int           `json:\"audit_http_status,omitempty\"`\n"
    "}\n",
    "type AuditResult struct {\n"
    "\tAuditDecision\n"
    "\tPromptHMAC               string        `json:\"prompt_hmac\"`\n"
    "\tTextBytes                int           `json:\"text_bytes\"`\n"
    "\tLatency                  time.Duration `json:\"-\"`\n"
    "\tModel                    string        `json:\"model,omitempty\"`\n"
    "\tErrorClass               string        `json:\"error_class,omitempty\"`\n"
    "\tAuditHTTPStatus          int           `json:\"audit_http_status,omitempty\"`\n"
    "\tAuditMode                string        `json:\"audit_mode,omitempty\"`\n"
    "\tAuditChunkCount          int           `json:\"audit_chunk_count,omitempty\"`\n"
    "\tAuditChunkBytes          int           `json:\"audit_chunk_bytes,omitempty\"`\n"
    "\tAuditRequestedTokens     int           `json:\"audit_requested_tokens,omitempty\"`\n"
    "\tAuditContextWindowTokens int           `json:\"audit_context_window_tokens,omitempty\"`\n"
    "\tAuditRetryCount          int           `json:\"audit_retry_count,omitempty\"`\n"
    "}\n",
    "audit result long-context metadata",
)

replace_once(
    "internal/platform/gateway.go",
    "\tif auditResult.AuditHTTPStatus > 0 {\n"
    "\t\ttrace.Metadata[\"audit_http_status\"] = auditResult.AuditHTTPStatus\n"
    "\t}\n"
    "\tauditDuration.WithLabelValues(slug).Observe(auditResult.Latency.Seconds())\n",
    "\tif auditResult.AuditHTTPStatus > 0 {\n"
    "\t\ttrace.Metadata[\"audit_http_status\"] = auditResult.AuditHTTPStatus\n"
    "\t}\n"
    "\tif auditResult.AuditMode != \"\" {\n"
    "\t\ttrace.Metadata[\"audit_mode\"] = auditResult.AuditMode\n"
    "\t}\n"
    "\tif auditResult.AuditChunkCount > 0 {\n"
    "\t\ttrace.Metadata[\"audit_chunk_count\"] = auditResult.AuditChunkCount\n"
    "\t}\n"
    "\tif auditResult.AuditChunkBytes > 0 {\n"
    "\t\ttrace.Metadata[\"audit_chunk_bytes\"] = auditResult.AuditChunkBytes\n"
    "\t}\n"
    "\tif auditResult.AuditRequestedTokens > 0 {\n"
    "\t\ttrace.Metadata[\"audit_requested_tokens\"] = auditResult.AuditRequestedTokens\n"
    "\t}\n"
    "\tif auditResult.AuditContextWindowTokens > 0 {\n"
    "\t\ttrace.Metadata[\"audit_context_window_tokens\"] = auditResult.AuditContextWindowTokens\n"
    "\t}\n"
    "\tif auditResult.AuditRetryCount > 0 {\n"
    "\t\ttrace.Metadata[\"audit_retry_count\"] = auditResult.AuditRetryCount\n"
    "\t}\n"
    "\tauditDuration.WithLabelValues(slug).Observe(auditResult.Latency.Seconds())\n",
    "gateway long-context metadata",
)

# ---------------------------------------------------------------------------
# Parse upstream context-limit errors so chunk sizing can use actual counts.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/audit_diagnostics.go",
    "\t\"net\"\n\t\"strings\"\n",
    "\t\"net\"\n\t\"regexp\"\n\t\"strconv\"\n\t\"strings\"\n",
    "diagnostics imports",
)
replace_once(
    "internal/platform/audit_diagnostics.go",
    "type AuditModelCallError struct {\n"
    "\tClass      string\n"
    "\tHTTPStatus int\n"
    "\tMessage    string\n"
    "\tCause      error\n"
    "}\n",
    "type AuditModelCallError struct {\n"
    "\tClass            string\n"
    "\tHTTPStatus       int\n"
    "\tMessage          string\n"
    "\tCause            error\n"
    "\tMaxContextTokens int\n"
    "\tRequestedTokens  int\n"
    "}\n",
    "diagnostics context token fields",
)
replace_once(
    "internal/platform/audit_diagnostics.go",
    "func auditHTTPStatusError(status int, body []byte) error {\n"
    "\tclass := \"http_status\"\n"
    "\tswitch {\n"
    "\tcase status == 401 || status == 403:\n"
    "\t\tclass = \"authentication\"\n"
    "\tcase status == 404:\n"
    "\t\tclass = \"endpoint_or_model_not_found\"\n"
    "\tcase status == 408:\n"
    "\t\tclass = \"timeout\"\n"
    "\tcase status == 429:\n"
    "\t\tclass = \"rate_limited\"\n"
    "\tcase status >= 500:\n"
    "\t\tclass = \"audit_server_error\"\n"
    "\t}\n"
    "\tmessage := fmt.Sprintf(\"audit model returned HTTP %d\", status)\n"
    "\tif detail := auditHTTPErrorDetail(body); detail != \"\" {\n"
    "\t\tmessage += \": \" + detail\n"
    "\t}\n"
    "\treturn newAuditModelCallError(class, status, message, nil)\n"
    "}\n",
    "func auditHTTPStatusError(status int, body []byte) error {\n"
    "\tclass := \"http_status\"\n"
    "\tswitch {\n"
    "\tcase status == 401 || status == 403:\n"
    "\t\tclass = \"authentication\"\n"
    "\tcase status == 404:\n"
    "\t\tclass = \"endpoint_or_model_not_found\"\n"
    "\tcase status == 408:\n"
    "\t\tclass = \"timeout\"\n"
    "\tcase status == 429:\n"
    "\t\tclass = \"rate_limited\"\n"
    "\tcase status >= 500:\n"
    "\t\tclass = \"audit_server_error\"\n"
    "\t}\n"
    "\tdetail := auditHTTPErrorDetail(body)\n"
    "\tmessage := fmt.Sprintf(\"audit model returned HTTP %d\", status)\n"
    "\tif detail != \"\" {\n"
    "\t\tmessage += \": \" + detail\n"
    "\t}\n"
    "\tmaxContextTokens := 0\n"
    "\trequestedTokens := 0\n"
    "\tif (status == 400 || status == 413 || status == 422) && looksLikeAuditContextLength(message) {\n"
    "\t\tclass = \"context_length\"\n"
    "\t\tmaxContextTokens, requestedTokens = parseAuditContextTokenCounts(message)\n"
    "\t}\n"
    "\treturn &AuditModelCallError{\n"
    "\t\tClass:            class,\n"
    "\t\tHTTPStatus:       status,\n"
    "\t\tMessage:          sanitizeAuditDiagnostic(message),\n"
    "\t\tMaxContextTokens: maxContextTokens,\n"
    "\t\tRequestedTokens:  requestedTokens,\n"
    "\t}\n"
    "}\n",
    "classify context-limit response",
)
replace_once(
    "internal/platform/audit_diagnostics.go",
    "func auditHTTPErrorDetail(body []byte) string {\n",
    "var auditContextMaxPatterns = []*regexp.Regexp{\n"
    "\tregexp.MustCompile(`(?i)maximum context length(?: is|:|=)?[^0-9]{0,40}([0-9][0-9,]*)`),\n"
    "\tregexp.MustCompile(`(?i)max(?:imum)?[_ ](?:model|context)[_ ](?:len|length)(?: is|:|=)?[^0-9]{0,40}([0-9][0-9,]*)`),\n"
    "\tregexp.MustCompile(`(?i)context window(?: is|:|=)?[^0-9]{0,40}([0-9][0-9,]*)`),\n"
    "}\n"
    "\n"
    "var auditRequestedTokenPatterns = []*regexp.Regexp{\n"
    "\tregexp.MustCompile(`(?i)(?:you requested|your request has|request has|sequence length(?: is|:|=)?|input length(?: is|:|=)?)[^0-9]{0,40}([0-9][0-9,]*)`),\n"
    "\tregexp.MustCompile(`(?i)([0-9][0-9,]*)\\s+input tokens`),\n"
    "}\n"
    "\n"
    "func looksLikeAuditContextLength(value string) bool {\n"
    "\tlower := strings.ToLower(value)\n"
    "\tfor _, marker := range []string{\n"
    "\t\t\"maximum context length\",\n"
    "\t\t\"context window\",\n"
    "\t\t\"max_model_len\",\n"
    "\t\t\"too many tokens\",\n"
    "\t\t\"prompt is too long\",\n"
    "\t\t\"input is too long\",\n"
    "\t\t\"token limit\",\n"
    "\t\t\"tokens exceed\",\n"
    "\t} {\n"
    "\t\tif strings.Contains(lower, marker) {\n"
    "\t\t\treturn true\n"
    "\t\t}\n"
    "\t}\n"
    "\treturn false\n"
    "}\n"
    "\n"
    "func parseAuditContextTokenCounts(value string) (maxContextTokens int, requestedTokens int) {\n"
    "\tfor _, pattern := range auditContextMaxPatterns {\n"
    "\t\tif match := pattern.FindStringSubmatch(value); len(match) == 2 {\n"
    "\t\t\tmaxContextTokens = parseAuditTokenNumber(match[1])\n"
    "\t\t\tif maxContextTokens > 0 {\n"
    "\t\t\t\tbreak\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\t}\n"
    "\tfor _, pattern := range auditRequestedTokenPatterns {\n"
    "\t\tif match := pattern.FindStringSubmatch(value); len(match) == 2 {\n"
    "\t\t\trequestedTokens = parseAuditTokenNumber(match[1])\n"
    "\t\t\tif requestedTokens > 0 {\n"
    "\t\t\t\tbreak\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\t}\n"
    "\treturn maxContextTokens, requestedTokens\n"
    "}\n"
    "\n"
    "func parseAuditTokenNumber(value string) int {\n"
    "\tparsed, err := strconv.Atoi(strings.ReplaceAll(value, \",\", \"\"))\n"
    "\tif err != nil || parsed < 1 {\n"
    "\t\treturn 0\n"
    "\t}\n"
    "\treturn parsed\n"
    "}\n"
    "\n"
    "func isAuditContextLengthError(err error) bool {\n"
    "\tvar callError *AuditModelCallError\n"
    "\treturn errors.As(err, &callError) && callError.Class == \"context_length\"\n"
    "}\n"
    "\n"
    "func auditContextTokenCounts(err error) (maxContextTokens int, requestedTokens int) {\n"
    "\tvar callError *AuditModelCallError\n"
    "\tif errors.As(err, &callError) {\n"
    "\t\treturn callError.MaxContextTokens, callError.RequestedTokens\n"
    "\t}\n"
    "\treturn 0, 0\n"
    "}\n"
    "\n"
    "func auditHTTPErrorDetail(body []byte) string {\n",
    "insert context-limit parsers",
)
replace_once(
    "internal/platform/audit_diagnostics.go",
    "\tcase \"AUDIT_MODEL_ERROR\":\n"
    "\t\treturn \"审计模型调用或返回格式异常\"\n"
    "\tcase \"AUDIT_REVIEW_REQUIRED\":\n",
    "\tcase \"AUDIT_MODEL_ERROR\":\n"
    "\t\treturn \"审计模型调用或返回格式异常\"\n"
    "\tcase \"AUDIT_CONTEXT_TOO_LARGE\":\n"
    "\t\treturn \"审计请求超过模型上下文且分段审计仍无法完成\"\n"
    "\tcase \"AUDIT_REVIEW_REQUIRED\":\n",
    "trace reason for context limit",
)

# ---------------------------------------------------------------------------
# Request configuration defaults.
# ---------------------------------------------------------------------------
replace_once(
    ".env.example",
    "# Audit input is measured in UTF-8 bytes, not model tokens. Two MiB is large\n"
    "# enough to carry a native Qwen3.8 262,144-token request for normal text.\n"
    "# Qwen3.8 has 262,144 total tokens, so the gateway caps the rendered audit\n"
    "# prompt at 260,000 tokens and reserves room for the policy JSON output.\n"
    "AUDIT_TEXT_MAX_BYTES=2097152\n"
    "AUDIT_OUTPUT_MAX_TOKENS=128\n"
    "AUDIT_DISABLE_THINKING=true\n"
    "AUDIT_LONG_CONTEXT_THRESHOLD_BYTES=131072\n"
    "AUDIT_LONG_CONTEXT_TIMEOUT=120s\n"
    "AUDIT_PROMPT_TRUNCATE_TOKENS=260000\n",
    "# These are request-layer settings; the audit model deployment is unchanged.\n"
    "# The platform first sends the complete prompt. If the model reports a\n"
    "# context-limit error, every byte is re-audited in overlapping chunks. No\n"
    "# truncate_prompt_tokens option is sent to the model.\n"
    "AUDIT_TEXT_MAX_BYTES=8388608\n"
    "AUDIT_OUTPUT_MAX_TOKENS=128\n"
    "AUDIT_DISABLE_THINKING=true\n"
    "AUDIT_LONG_CONTEXT_THRESHOLD_BYTES=131072\n"
    "AUDIT_LONG_CONTEXT_TIMEOUT=120s\n"
    "AUDIT_CONTEXT_TARGET_TOKENS=260000\n"
    "AUDIT_FALLBACK_CHUNK_BYTES=196608\n"
    "AUDIT_CHUNK_OVERLAP_BYTES=4096\n"
    "AUDIT_CHUNK_CONCURRENCY=2\n"
    "AUDIT_MAX_CHUNKS=64\n",
    "environment request-side audit defaults",
)
replace_once(
    "docker-compose.yml",
    "      AUDIT_TEXT_MAX_BYTES: ${AUDIT_TEXT_MAX_BYTES:-2097152}\n"
    "      AUDIT_OUTPUT_MAX_TOKENS: ${AUDIT_OUTPUT_MAX_TOKENS:-128}\n"
    "      AUDIT_DISABLE_THINKING: ${AUDIT_DISABLE_THINKING:-true}\n"
    "      AUDIT_LONG_CONTEXT_THRESHOLD_BYTES: ${AUDIT_LONG_CONTEXT_THRESHOLD_BYTES:-131072}\n"
    "      AUDIT_LONG_CONTEXT_TIMEOUT: ${AUDIT_LONG_CONTEXT_TIMEOUT:-120s}\n"
    "      AUDIT_PROMPT_TRUNCATE_TOKENS: ${AUDIT_PROMPT_TRUNCATE_TOKENS:-260000}\n",
    "      AUDIT_TEXT_MAX_BYTES: ${AUDIT_TEXT_MAX_BYTES:-8388608}\n"
    "      AUDIT_OUTPUT_MAX_TOKENS: ${AUDIT_OUTPUT_MAX_TOKENS:-128}\n"
    "      AUDIT_DISABLE_THINKING: ${AUDIT_DISABLE_THINKING:-true}\n"
    "      AUDIT_LONG_CONTEXT_THRESHOLD_BYTES: ${AUDIT_LONG_CONTEXT_THRESHOLD_BYTES:-131072}\n"
    "      AUDIT_LONG_CONTEXT_TIMEOUT: ${AUDIT_LONG_CONTEXT_TIMEOUT:-120s}\n"
    "      AUDIT_CONTEXT_TARGET_TOKENS: ${AUDIT_CONTEXT_TARGET_TOKENS:-260000}\n"
    "      AUDIT_FALLBACK_CHUNK_BYTES: ${AUDIT_FALLBACK_CHUNK_BYTES:-196608}\n"
    "      AUDIT_CHUNK_OVERLAP_BYTES: ${AUDIT_CHUNK_OVERLAP_BYTES:-4096}\n"
    "      AUDIT_CHUNK_CONCURRENCY: ${AUDIT_CHUNK_CONCURRENCY:-2}\n"
    "      AUDIT_MAX_CHUNKS: ${AUDIT_MAX_CHUNKS:-64}\n",
    "compose request-side audit defaults",
)

# Existing .env migration.
init_path = ROOT / "scripts/init-env.sh"
init_text = init_path.read_text(encoding="utf-8")
old_defaults = '''audit_defaults = {
    "AUDIT_TEXT_MAX_BYTES": "2097152",
    "AUDIT_OUTPUT_MAX_TOKENS": "128",
    "AUDIT_DISABLE_THINKING": "true",
    "AUDIT_LONG_CONTEXT_THRESHOLD_BYTES": "131072",
    "AUDIT_LONG_CONTEXT_TIMEOUT": "120s",
    "AUDIT_PROMPT_TRUNCATE_TOKENS": "260000",
}
'''
new_defaults = '''audit_defaults = {
    "AUDIT_TEXT_MAX_BYTES": "8388608",
    "AUDIT_OUTPUT_MAX_TOKENS": "128",
    "AUDIT_DISABLE_THINKING": "true",
    "AUDIT_LONG_CONTEXT_THRESHOLD_BYTES": "131072",
    "AUDIT_LONG_CONTEXT_TIMEOUT": "120s",
    "AUDIT_CONTEXT_TARGET_TOKENS": values.get("AUDIT_PROMPT_TRUNCATE_TOKENS", "260000"),
    "AUDIT_FALLBACK_CHUNK_BYTES": "196608",
    "AUDIT_CHUNK_OVERLAP_BYTES": "4096",
    "AUDIT_CHUNK_CONCURRENCY": "2",
    "AUDIT_MAX_CHUNKS": "64",
}
'''
if init_text.count(old_defaults) != 1:
    raise SystemExit("init-env audit defaults anchor not found")
init_text = init_text.replace(old_defaults, new_defaults, 1)
init_text = init_text.replace(
    'if key == "AUDIT_TEXT_MAX_BYTES" and current == "262144":\n',
    'if key == "AUDIT_TEXT_MAX_BYTES" and current in {"262144", "2097152"}:\n',
    1,
)
init_text = init_text.replace(
    '"AUDIT_TEXT_MAX_BYTES was upgraded from the historical 256 KiB default to 2 MiB for Qwen3.8 long-context audit."',
    '"AUDIT_TEXT_MAX_BYTES was upgraded to 8 MiB so the request layer can segment and audit the complete prompt."',
    1,
)
init_path.write_text(init_text, encoding="utf-8")

# CI environment assertions and migration fixture.
ci_path = ROOT / ".github/workflows/ci.yml"
ci_text = ci_path.read_text(encoding="utf-8")
ci_text = ci_text.replace("assert values['AUDIT_TEXT_MAX_BYTES'] == '2097152'", "assert values['AUDIT_TEXT_MAX_BYTES'] == '8388608'", 1)
ci_text = ci_text.replace("assert values['AUDIT_PROMPT_TRUNCATE_TOKENS'] == '260000'", "assert values['AUDIT_CONTEXT_TARGET_TOKENS'] == '260000'\n          assert values['AUDIT_FALLBACK_CHUNK_BYTES'] == '196608'\n          assert values['AUDIT_CHUNK_OVERLAP_BYTES'] == '4096'\n          assert values['AUDIT_CHUNK_CONCURRENCY'] == '2'\n          assert values['AUDIT_MAX_CHUNKS'] == '64'", 1)
ci_text = ci_text.replace("              'AUDIT_PROMPT_TRUNCATE_TOKENS',", "              'AUDIT_CONTEXT_TARGET_TOKENS',\n              'AUDIT_FALLBACK_CHUNK_BYTES',\n              'AUDIT_CHUNK_OVERLAP_BYTES',\n              'AUDIT_CHUNK_CONCURRENCY',\n              'AUDIT_MAX_CHUNKS',", 1)
ci_text = ci_text.replace("assert values['AUDIT_TEXT_MAX_BYTES'] == '2097152'", "assert values['AUDIT_TEXT_MAX_BYTES'] == '8388608'", 1)
ci_text = ci_text.replace("assert values['AUDIT_PROMPT_TRUNCATE_TOKENS'] == '260000'", "assert values['AUDIT_CONTEXT_TARGET_TOKENS'] == '260000'\n          assert values['AUDIT_FALLBACK_CHUNK_BYTES'] == '196608'\n          assert values['AUDIT_CHUNK_OVERLAP_BYTES'] == '4096'\n          assert values['AUDIT_CHUNK_CONCURRENCY'] == '2'\n          assert values['AUDIT_MAX_CHUNKS'] == '64'", 1)
ci_path.write_text(ci_text, encoding="utf-8")

# ---------------------------------------------------------------------------
# Deterministic E2E model: verify no-thinking and force a context error for a
# long request so the complete middle section must be found by chunk audit.
# ---------------------------------------------------------------------------
replace_once(
    "cmd/mockprovider/main.go",
    "type chatRequest struct {\n"
    "\tModel    string `json:\"model\"`\n"
    "\tStream   bool   `json:\"stream\"`\n"
    "\tMessages []struct {\n",
    "type chatRequest struct {\n"
    "\tModel              string         `json:\"model\"`\n"
    "\tStream             bool           `json:\"stream\"`\n"
    "\tMaxTokens          int            `json:\"max_tokens\"`\n"
    "\tChatTemplateKwargs map[string]any `json:\"chat_template_kwargs\"`\n"
    "\tMessages           []struct {\n",
    "mock request fast-mode fields",
)
replace_once(
    "cmd/mockprovider/main.go",
    "\ttext := strings.ToLower(messageText(request))\n"
    "\tuserText := strings.ToLower(userMessageText(request))\n"
    "\tif strings.Contains(text, \"you classify upstream model failures\") {\n",
    "\ttext := strings.ToLower(messageText(request))\n"
    "\tuserText := strings.ToLower(userMessageText(request))\n"
    "\tif strings.Contains(strings.ToLower(request.Model), \"qwen\") {\n"
    "\t\tenableThinking, ok := request.ChatTemplateKwargs[\"enable_thinking\"].(bool)\n"
    "\t\tpreserveThinking, preserveOK := request.ChatTemplateKwargs[\"preserve_thinking\"].(bool)\n"
    "\t\tif !ok || enableThinking || !preserveOK || preserveThinking || request.MaxTokens != 128 {\n"
    "\t\t\twriteJSON(w, http.StatusBadRequest, map[string]any{\n"
    "\t\t\t\t\"error\": map[string]any{\"message\": \"Qwen fast audit request parameters are missing\"},\n"
    "\t\t\t})\n"
    "\t\t\treturn\n"
    "\t\t}\n"
    "\t\tif len(userText) > 3500 {\n"
    "\t\t\twriteJSON(w, http.StatusBadRequest, map[string]any{\n"
    "\t\t\t\t\"error\": map[string]any{\n"
    "\t\t\t\t\t\"message\": fmt.Sprintf(\n"
    "\t\t\t\t\t\t\"This model's maximum context length is 4096 tokens. However, your request has %d input tokens\",\n"
    "\t\t\t\t\t\tlen(userText)+300,\n"
    "\t\t\t\t\t),\n"
    "\t\t\t\t},\n"
    "\t\t\t})\n"
    "\t\t\treturn\n"
    "\t\t}\n"
    "\t}\n"
    "\tif strings.Contains(text, \"you classify upstream model failures\") {\n",
    "mock context limit and no-thinking validation",
)

# Test profile uses a Qwen name and a small synthetic context target.
replace_once(
    "docker-compose.test.yml",
    "      AUDIT_DEFAULT_MODEL: audit-small\n"
    "      AUDIT_DEFAULT_TIMEOUT: 5s\n"
    "      AUDIT_DEFAULT_BLOCK_THRESHOLD: \"0.65\"\n",
    "      AUDIT_DEFAULT_MODEL: qwen3.8-audit-mock\n"
    "      AUDIT_DEFAULT_TIMEOUT: 5s\n"
    "      AUDIT_DEFAULT_BLOCK_THRESHOLD: \"0.65\"\n"
    "      AUDIT_CONTEXT_TARGET_TOKENS: \"3000\"\n"
    "      AUDIT_FALLBACK_CHUNK_BYTES: \"1024\"\n"
    "      AUDIT_CHUNK_OVERLAP_BYTES: \"64\"\n"
    "      AUDIT_CHUNK_CONCURRENCY: \"2\"\n"
    "      AUDIT_MAX_CHUNKS: \"32\"\n",
    "test compose long-context settings",
)

# E2E long safe and dangerous-middle requests.
replace_once(
    "scripts/e2e.sh",
    "contains \"${WORKDIR}/allow.json\" 'mock provider success'\n\n\nfor index in $(seq 1 10); do\n",
    "contains \"${WORKDIR}/allow.json\" 'mock provider success'\n\n"
    "python3 - \"${WORKDIR}/long-safe.json\" \"${WORKDIR}/long-block.json\" <<'PY'\n"
    "import json\n"
    "import sys\n"
    "safe = \"safe-segment-\" * 900\n"
    "blocked = (\"safe-prefix-\" * 450) + \" model-audit-block \" + (\"safe-suffix-\" * 450)\n"
    "for path, content in ((sys.argv[1], safe), (sys.argv[2], blocked)):\n"
    "    with open(path, \"w\", encoding=\"utf-8\") as handle:\n"
    "        json.dump({\"model\": \"normal\", \"messages\": [{\"role\": \"user\", \"content\": content}]}, handle)\n"
    "PY\n\n"
    "status=\"$(curl --silent --show-error -o \"${WORKDIR}/long-safe-response.json\" -w '%{http_code}' \\\n"
    "  \"${gateway}\" \"${gateway_auth[@]}\" \\\n"
    "  -H 'X-Request-ID: e2e-long-safe' \\\n"
    "  --data-binary @\"${WORKDIR}/long-safe.json\")\"\n"
    "assert_status 200 \"${status}\" \"${WORKDIR}/long-safe-response.json\"\n"
    "contains \"${WORKDIR}/long-safe-response.json\" 'mock provider success'\n\n"
    "status=\"$(curl --silent --show-error -o \"${WORKDIR}/long-block-response.json\" -w '%{http_code}' \\\n"
    "  \"${gateway}\" \"${gateway_auth[@]}\" \\\n"
    "  -H 'X-Request-ID: e2e-long-block' \\\n"
    "  --data-binary @\"${WORKDIR}/long-block.json\")\"\n"
    "assert_status 555 \"${status}\" \"${WORKDIR}/long-block-response.json\"\n"
    "contains \"${WORKDIR}/long-block-response.json\" 'CYBER_MOCK_MODEL_BLOCK'\n\n\n"
    "for index in $(seq 1 10); do\n",
    "insert chunked audit E2E requests",
)
replace_once(
    "scripts/e2e.sh",
    "if not any(item.get(\"metadata\", {}).get(\"audit_http_status\") == 401 for item in errors):\n"
    "    raise RuntimeError(\"audit HTTP status 401 was not persisted\")\n"
    "PY\n",
    "if not any(item.get(\"metadata\", {}).get(\"audit_http_status\") == 401 for item in errors):\n"
    "    raise RuntimeError(\"audit HTTP status 401 was not persisted\")\n"
    "long_items = {item.get(\"request_id\"): item for item in items if item.get(\"request_id\") in {\"e2e-long-safe\", \"e2e-long-block\"}}\n"
    "if set(long_items) != {\"e2e-long-safe\", \"e2e-long-block\"}:\n"
    "    raise RuntimeError(f\"long-context traces missing: {set(long_items)}\")\n"
    "for request_id, item in long_items.items():\n"
    "    metadata = item.get(\"metadata\", {})\n"
    "    if metadata.get(\"audit_mode\") != \"chunked_after_context_limit\":\n"
    "        raise RuntimeError(f\"{request_id} did not use chunked audit: {metadata}\")\n"
    "    if int(metadata.get(\"audit_chunk_count\", 0)) < 2:\n"
    "        raise RuntimeError(f\"{request_id} did not audit multiple chunks: {metadata}\")\n"
    "    if int(metadata.get(\"audit_requested_tokens\", 0)) <= int(metadata.get(\"audit_context_window_tokens\", 0)):\n"
    "        raise RuntimeError(f\"{request_id} lacks parsed context-limit counts: {metadata}\")\n"
    "PY\n",
    "validate chunked audit traces",
)

# Request-layer documentation only; no model deployment changes.
(ROOT / "docs/qwen38-fast-audit.md").write_text(r'''# Qwen3.8 请求层长上下文快速审计

这次只修改风控平台调用审计模型的请求方式，不要求修改 Qwen3.8 / vLLM 的部署参数。

Qwen3.8 的 262,144 tokens 是系统提示词、用户内容、聊天模板和模型输出的总窗口，不是 262,144 个纯输入 token。平台把目标 prompt 容量设为 260,000 tokens，并把输出压到 128 tokens。

## 正常请求路径

```text
完整请求文本
  → 本地 Cyber 规则
  → 一次完整审计模型请求
  → Qwen no-thinking
  → 直接输出紧凑 JSON
```

平台对 Qwen 审计请求强制发送：

```json
{
  "temperature": 0,
  "max_tokens": 128,
  "chat_template_kwargs": {
    "enable_thinking": false,
    "preserve_thinking": false
  }
}
```

用户内容末尾还会追加 `/no_think` 作为旧模板兼容兜底。模型必须直接返回：

```json
{"decision":"allow|block|review","risk_code":"","category":"","confidence":0.99,"reason":"brief"}
```

## 超过上下文时如何处理

平台不会再发送 `truncate_prompt_tokens`，也不会只保留开头或结尾。静默截断会漏审中间内容，容易被绕过。

实际流程是：

```text
先提交完整文本
  ↓
模型明确返回 context-length 错误
  ↓
解析 maximum context / requested tokens
  ↓
按实际比例计算分段大小，额外保留 10% 安全余量
  ↓
按 UTF-8 安全边界切分，分段之间默认重叠 4096 bytes
  ↓
最多 2 段并行审计
  ↓
任意一段 block → 整个请求 block
任意一段 review 且无 block → 整个请求 review
所有段 allow → 整个请求 allow
```

如果上游错误没有提供 token 数量，平台退回到 192 KiB 的保守分段；若某一段仍然超限，分段大小减半后自动重试，最多四轮。任何分段失败时，fail-closed 路由返回 555，不会把未完整审计的请求放给真实上游。

## 风控平台参数

```env
AUDIT_TEXT_MAX_BYTES=8388608
AUDIT_OUTPUT_MAX_TOKENS=128
AUDIT_DISABLE_THINKING=true
AUDIT_LONG_CONTEXT_THRESHOLD_BYTES=131072
AUDIT_LONG_CONTEXT_TIMEOUT=120s
AUDIT_CONTEXT_TARGET_TOKENS=260000
AUDIT_FALLBACK_CHUNK_BYTES=196608
AUDIT_CHUNK_OVERLAP_BYTES=4096
AUDIT_CHUNK_CONCURRENCY=2
AUDIT_MAX_CHUNKS=64
```

这些参数只作用于 `newapi-risk-platform → 审计模型` 的请求，不改变 Qwen 服务本身。

## 模型名是别名时

模型名称包含 `qwen` 时会自动启用 no-thinking。如果你的 vLLM served-model-name 被改成了 `audit-fast` 等别名，在审计 Profile 的 Extra 中填写：

```json
{
  "_risk_qwen_fast_mode": true
}
```

`_risk_` 开头的字段只供平台内部使用，不会传给模型服务。

## Trace 中可见

超限分段后，请求追踪 Metadata 会记录：

```text
audit_mode=chunked_after_context_limit
audit_chunk_count
audit_chunk_bytes
audit_requested_tokens
audit_context_window_tokens
audit_retry_count
```

因此 Web 端可以确认某条请求是否发生过超限、切了多少段，以及模型报告的最大/实际 token 数。

## 延迟说明

关闭 thinking 会显著减少无用输出和 `AUDIT_MODEL_ERROR`，但无法消除长输入的 prefill。未超限请求只调用模型一次；只有模型明确报告上下文超限时才分段，因此不会给普通请求增加额外 tokenizer 请求或第二次预检查。
''', encoding="utf-8")

# The request-side chunker must allow small synthetic E2E contexts and must not
# accidentally return allow when the parent context cancels before all chunks.
long_path = ROOT / "internal/platform/audit_long_context.go"
long_text = long_path.read_text(encoding="utf-8")
long_text = long_text.replace("chunkBytes <= 4096", "chunkBytes <= 1024")
long_text = long_text.replace("chunkBytes < 4096", "chunkBytes < 1024")
long_text = long_text.replace("chunkBytes = 4096", "chunkBytes = 1024")
long_text = long_text.replace("if chunkBytes < 4096 {", "if chunkBytes < 1024 {")
long_text = long_text.replace("\tallowConfidence := 1.0\n\n\tfor result := range results {\n", "\tallowConfidence := 1.0\n\tcompleted := 0\n\n\tfor result := range results {\n\t\tcompleted++\n")
long_text = long_text.replace(
    "\tif strongestReview != nil {\n\t\treturn decorateChunkDecision(strongestReview.decision, strongestReview.index, len(chunks)), nil\n\t}\n\treturn AuditDecision{\n",
    "\tif strongestReview != nil {\n\t\treturn decorateChunkDecision(strongestReview.decision, strongestReview.index, len(chunks)), nil\n\t}\n\tif completed < len(chunks) {\n\t\treturn AuditDecision{}, newAuditModelCallError(\"connection\", 0, \"chunked audit was canceled before every chunk completed\", ctx.Err())\n\t}\n\treturn AuditDecision{\n",
)
long_path.write_text(long_text, encoding="utf-8")

print("request-side chunk audit patch applied")
