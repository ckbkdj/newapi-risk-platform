from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


root = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Runtime configuration
# ---------------------------------------------------------------------------
config_path = root / "internal/platform/config.go"
config = config_path.read_text(encoding="utf-8")
config = replace_once(
    config,
    "\tAuditTextMaxBytes            int\n\tSSELineMaxBytes              int\n",
    "\tAuditTextMaxBytes                 int\n"
    "\tAuditOutputMaxTokens              int\n"
    "\tAuditDisableThinking              bool\n"
    "\tAuditLongContextThresholdBytes    int\n"
    "\tAuditLongContextTimeout           time.Duration\n"
    "\tAuditPromptTruncateTokens         int\n"
    "\tSSELineMaxBytes                   int\n",
    "config struct audit fields",
)
config = replace_once(
    config,
    "\t\tAuditTextMaxBytes:            envInt(\"AUDIT_TEXT_MAX_BYTES\", 256*1024),\n"
    "\t\tSSELineMaxBytes:              envInt(\"SSE_LINE_MAX_BYTES\", 1024*1024),\n",
    "\t\tAuditTextMaxBytes:                 envInt(\"AUDIT_TEXT_MAX_BYTES\", 2*1024*1024),\n"
    "\t\tAuditOutputMaxTokens:              envInt(\"AUDIT_OUTPUT_MAX_TOKENS\", 128),\n"
    "\t\tAuditDisableThinking:              envBool(\"AUDIT_DISABLE_THINKING\", true),\n"
    "\t\tAuditLongContextThresholdBytes:    envInt(\"AUDIT_LONG_CONTEXT_THRESHOLD_BYTES\", 128*1024),\n"
    "\t\tAuditLongContextTimeout:           envDuration(\"AUDIT_LONG_CONTEXT_TIMEOUT\", 120*time.Second),\n"
    "\t\tAuditPromptTruncateTokens:         envInt(\"AUDIT_PROMPT_TRUNCATE_TOKENS\", 260000),\n"
    "\t\tSSELineMaxBytes:                   envInt(\"SSE_LINE_MAX_BYTES\", 1024*1024),\n",
    "config load audit fields",
)
config = replace_once(
    config,
    "\tif c.AuditTextMaxBytes < 4096 || c.AuditTextMaxBytes > 2*1024*1024 {\n"
    "\t\tproblems = append(problems, \"AUDIT_TEXT_MAX_BYTES must be between 4 KiB and 2 MiB\")\n"
    "\t}\n"
    "\tif c.SSELineMaxBytes < 64*1024 || c.SSELineMaxBytes > 8*1024*1024 {\n",
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
    "\t}\n"
    "\tif c.SSELineMaxBytes < 64*1024 || c.SSELineMaxBytes > 8*1024*1024 {\n",
    "config validation audit fields",
)
config_path.write_text(config, encoding="utf-8")

# ---------------------------------------------------------------------------
# Audit request construction
# ---------------------------------------------------------------------------
audit_path = root / "internal/platform/audit.go"
audit = audit_path.read_text(encoding="utf-8")
audit = replace_once(
    audit,
    "CTF or sandbox work, authorized testing, and high-level discussion unless the requested outcome supplies harmful\n"
    "operational capability against real systems or victims. Return one compact JSON object only:\n"
    "{\"decision\":\"allow|block|review\",\"risk_code\":\"CYBER_* or empty\",\"category\":\"...\",\"confidence\":0.0,\"reason\":\"brief\"}`",
    "CTF or sandbox work, authorized testing, and high-level discussion unless the requested outcome supplies harmful\n"
    "operational capability against real systems or victims. Do not reveal chain-of-thought and do not emit <think>\n"
    "blocks, Markdown, or explanatory prose. Return the final compact JSON object immediately. Keep reason under 120\n"
    "characters:\n"
    "{\"decision\":\"allow|block|review\",\"risk_code\":\"CYBER_* or empty\",\"category\":\"...\",\"confidence\":0.0,\"reason\":\"brief\"}`",
    "default audit prompt fast-output directive",
)
audit = replace_once(
    audit,
    "\tmaxTextBytes    int\n\trefreshInterval time.Duration\n",
    "\tmaxTextBytes                 int\n"
    "\toutputMaxTokens              int\n"
    "\tdisableThinking              bool\n"
    "\tlongContextThresholdBytes    int\n"
    "\tlongContextTimeout           time.Duration\n"
    "\tpromptTruncateTokens         int\n"
    "\trefreshInterval              time.Duration\n",
    "audit engine fields",
)
audit = replace_once(
    audit,
    "\t\tmaxTextBytes:    cfg.AuditTextMaxBytes,\n"
    "\t\trefreshInterval: cfg.RulesRefreshInterval,\n",
    "\t\tmaxTextBytes:              cfg.AuditTextMaxBytes,\n"
    "\t\toutputMaxTokens:           cfg.AuditOutputMaxTokens,\n"
    "\t\tdisableThinking:           cfg.AuditDisableThinking,\n"
    "\t\tlongContextThresholdBytes: cfg.AuditLongContextThresholdBytes,\n"
    "\t\tlongContextTimeout:        cfg.AuditLongContextTimeout,\n"
    "\t\tpromptTruncateTokens:      cfg.AuditPromptTruncateTokens,\n"
    "\t\trefreshInterval:           cfg.RulesRefreshInterval,\n",
    "audit engine initialization",
)
audit = replace_once(
    audit,
    "\tsystemPrompt := strings.TrimSpace(profile.SystemPrompt)\n"
    "\tif systemPrompt == \"\" {\n"
    "\t\tsystemPrompt = DefaultAuditSystemPrompt\n"
    "\t}\n"
    "\tpayload := map[string]any{\n"
    "\t\t\"model\":       profile.Model,\n"
    "\t\t\"temperature\": 0,\n"
    "\t\t\"max_tokens\":  300,\n"
    "\t\t\"messages\": []map[string]string{\n"
    "\t\t\t{\"role\": \"system\", \"content\": systemPrompt},\n"
    "\t\t\t{\"role\": \"user\", \"content\": text},\n"
    "\t\t},\n"
    "\t}\n",
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
    "audit payload defaults",
)
audit = replace_once(
    audit,
    "\tif len(profile.Extra) > 0 {\n"
    "\t\tvar extra map[string]any\n"
    "\t\tif json.Unmarshal(profile.Extra, &extra) == nil {\n"
    "\t\t\tfor key, value := range extra {\n"
    "\t\t\t\tswitch key {\n"
    "\t\t\t\tcase \"model\", \"messages\", \"stream\":\n"
    "\t\t\t\t\tcontinue\n"
    "\t\t\t\tdefault:\n"
    "\t\t\t\t\tpayload[key] = value\n"
    "\t\t\t\t}\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\t}\n"
    "\tencoded, err := json.Marshal(payload)\n",
    "\tif len(profile.Extra) > 0 {\n"
    "\t\tvar extra map[string]any\n"
    "\t\tif json.Unmarshal(profile.Extra, &extra) == nil {\n"
    "\t\t\tfor key, value := range extra {\n"
    "\t\t\t\tswitch key {\n"
    "\t\t\t\tcase \"model\", \"messages\", \"stream\":\n"
    "\t\t\t\t\tcontinue\n"
    "\t\t\t\tdefault:\n"
    "\t\t\t\t\tpayload[key] = value\n"
    "\t\t\t\t}\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\t}\n"
    "\te.applyFastAuditDefaults(profile, payload)\n"
    "\tencoded, err := json.Marshal(payload)\n",
    "audit payload finalization",
)
audit = replace_once(
    audit,
    "\ttimeout := time.Duration(profile.TimeoutMS) * time.Millisecond\n"
    "\tif timeout <= 0 {\n"
    "\t\ttimeout = 8 * time.Second\n"
    "\t}\n",
    "\ttimeout := e.auditRequestTimeout(profile, len(text))\n",
    "audit dynamic timeout",
)
audit_path.write_text(audit, encoding="utf-8")

# ---------------------------------------------------------------------------
# Compose and environment defaults
# ---------------------------------------------------------------------------
compose_path = root / "docker-compose.yml"
compose = compose_path.read_text(encoding="utf-8")
compose = replace_once(
    compose,
    "      AUDIT_TEXT_MAX_BYTES: ${AUDIT_TEXT_MAX_BYTES:-262144}\n"
    "      SSE_LINE_MAX_BYTES: ${SSE_LINE_MAX_BYTES:-1048576}\n",
    "      AUDIT_TEXT_MAX_BYTES: ${AUDIT_TEXT_MAX_BYTES:-2097152}\n"
    "      AUDIT_OUTPUT_MAX_TOKENS: ${AUDIT_OUTPUT_MAX_TOKENS:-128}\n"
    "      AUDIT_DISABLE_THINKING: ${AUDIT_DISABLE_THINKING:-true}\n"
    "      AUDIT_LONG_CONTEXT_THRESHOLD_BYTES: ${AUDIT_LONG_CONTEXT_THRESHOLD_BYTES:-131072}\n"
    "      AUDIT_LONG_CONTEXT_TIMEOUT: ${AUDIT_LONG_CONTEXT_TIMEOUT:-120s}\n"
    "      AUDIT_PROMPT_TRUNCATE_TOKENS: ${AUDIT_PROMPT_TRUNCATE_TOKENS:-260000}\n"
    "      SSE_LINE_MAX_BYTES: ${SSE_LINE_MAX_BYTES:-1048576}\n",
    "compose audit environment",
)
compose_path.write_text(compose, encoding="utf-8")

env_path = root / ".env.example"
env = env_path.read_text(encoding="utf-8")
env = replace_once(
    env,
    "AUDIT_DEFAULT_TIMEOUT=8s\n"
    "AUDIT_DEFAULT_BLOCK_THRESHOLD=0.65\n\n"
    "ERROR_HTTP_STATUS=555\n"
    "REQUEST_MAX_BYTES=8388608\n"
    "RESPONSE_INSPECT_MAX_BYTES=2097152\n"
    "AUDIT_TEXT_MAX_BYTES=262144\n",
    "AUDIT_DEFAULT_TIMEOUT=8s\n"
    "AUDIT_DEFAULT_BLOCK_THRESHOLD=0.65\n\n"
    "# Audit input is measured in UTF-8 bytes, not model tokens. Two MiB is large\n"
    "# enough to carry a native Qwen3.8 262,144-token request for normal text.\n"
    "# Qwen3.8 has 262,144 total tokens, so the gateway caps the rendered audit\n"
    "# prompt at 260,000 tokens and reserves room for the policy JSON output.\n"
    "AUDIT_TEXT_MAX_BYTES=2097152\n"
    "AUDIT_OUTPUT_MAX_TOKENS=128\n"
    "AUDIT_DISABLE_THINKING=true\n"
    "AUDIT_LONG_CONTEXT_THRESHOLD_BYTES=131072\n"
    "AUDIT_LONG_CONTEXT_TIMEOUT=120s\n"
    "AUDIT_PROMPT_TRUNCATE_TOKENS=260000\n\n"
    "ERROR_HTTP_STATUS=555\n"
    "REQUEST_MAX_BYTES=8388608\n"
    "RESPONSE_INSPECT_MAX_BYTES=2097152\n",
    "environment audit defaults",
)
env_path.write_text(env, encoding="utf-8")

# ---------------------------------------------------------------------------
# Replace the placeholder guide that was intentionally committed before the
# implementation branch existed.
# ---------------------------------------------------------------------------
doc_path = root / "docs/qwen38-fast-audit.md"
doc_path.write_text(
    """# Qwen3.8 长上下文快速审计\n\n"
    "Qwen3.8-27B 的原生上下文是 **262,144 tokens**，不是 272K 输入 tokens。\n"
    "模型上下文计算包含系统提示词、用户输入、聊天模板和输出，因此不能把\n"
    "262,144 个输入 token 全部塞满后再要求模型继续输出。风控平台默认把\n"
    "渲染后的审计 Prompt 上限设为 **260,000 tokens**，并保留约 2,144 tokens\n"
    "给模板和 128-token 的最终 JSON。\n\n"
    "## 风控平台参数\n\n"
    "```env\n"
    "AUDIT_TEXT_MAX_BYTES=2097152\n"
    "AUDIT_OUTPUT_MAX_TOKENS=128\n"
    "AUDIT_DISABLE_THINKING=true\n"
    "AUDIT_LONG_CONTEXT_THRESHOLD_BYTES=131072\n"
    "AUDIT_LONG_CONTEXT_TIMEOUT=120s\n"
    "AUDIT_PROMPT_TRUNCATE_TOKENS=260000\n"
    "```\n\n"
    "`AUDIT_TEXT_MAX_BYTES` 是请求抽取后的 UTF-8 字节上限，不是 token 数。旧值\n"
    "262,144 只相当于 256 KiB，无法代表 Qwen3.8 的 262K token 窗口。\n\n"
    "对于模型名中包含 `Qwen` 的审计 Profile，平台会强制发送：\n\n"
    "```json\n"
    "{\n"
    "  \"temperature\": 0,\n"
    "  \"max_tokens\": 128,\n"
    "  \"chat_template_kwargs\": {\n"
    "    \"enable_thinking\": false,\n"
    "    \"preserve_thinking\": false\n"
    "  }\n"
    "}\n"
    "```\n\n"
    "对于模型名中包含 `Qwen3.8` / `qwen38` 的 vLLM Profile，还会发送：\n\n"
    "```json\n"
    "{\n"
    "  \"truncate_prompt_tokens\": 260000,\n"
    "  \"truncation_side\": \"left\"\n"
    "}\n"
    "```\n\n"
    "这会保留最新的请求内容并确保留出输出空间。超过 260,000 prompt tokens 的\n"
    "最早部分会被 vLLM 截断，因此需要对超长多轮会话做到零丢失时，应在 NewAPI\n"
    "侧分段或使用分块审计，而不是把 262,144 当成纯输入上限。\n\n"
    "## 推荐的专用 vLLM 审计实例\n\n"
    "```yaml\n"
    "services:\n"
    "  qwen38-audit:\n"
    "    image: vllm/vllm-openai:qwen38-x86_64-cu129\n"
    "    gpus: all\n"
    "    ipc: host\n"
    "    shm_size: 64gb\n"
    "    volumes:\n"
    "      - /opt/models:/models:ro\n"
    "    command:\n"
    "      - --model\n"
    "      - /models/Qwen3.8-27B\n"
    "      - --served-model-name\n"
    "      - qwen3.8-27b\n"
    "      - --tensor-parallel-size\n"
    "      - \"2\"\n"
    "      - --dtype\n"
    "      - bfloat16\n"
    "      - --max-model-len\n"
    "      - \"262144\"\n"
    "      - --gpu-memory-utilization\n"
    "      - \"0.95\"\n"
    "      - --enable-chunked-prefill\n"
    "      - --max-num-batched-tokens\n"
    "      - \"65536\"\n"
    "      - --max-num-seqs\n"
    "      - \"2\"\n"
    "      - --enable-prefix-caching\n"
    "      - --reasoning-parser\n"
    "      - qwen3\n"
    "      - --api-key\n"
    "      - ${VLLM_API_KEY}\n"
    "```\n\n"
    "如果启动日志提示 KV cache 不足，可先把 `--max-num-seqs` 降到 `1`；仍不足\n"
    "时再尝试 `--kv-cache-dtype fp8`。专用审计实例不建议启用 MTP speculative\n"
    "decoding，因为输出只有约 100 tokens，节省的 decode 时间很小，反而会占用\n"
    "长上下文所需的显存。\n\n"
    "## 审计模型 Profile\n\n"
    "后台填写：\n\n"
    "```text\n"
    "Base URL: http://QWEN_HOST:8000/v1\n"
    "Model:    qwen3.8-27b\n"
    "Timeout:  120000 ms\n"
    "Extra:    {}\n"
    "```\n\n"
    "只要模型名包含 `qwen3.8`，无需在 Extra 中重复写 no-thinking 参数。\n\n"
    "## 验证 no-thinking\n\n"
    "```bash\n"
    "curl -sS http://QWEN_HOST:8000/v1/chat/completions \\\n"
    "  -H \"Authorization: Bearer $VLLM_API_KEY\" \\\n"
    "  -H 'Content-Type: application/json' \\\n"
    "  -d '{\n"
    "    \"model\": \"qwen3.8-27b\",\n"
    "    \"messages\": [\n"
    "      {\"role\": \"system\", \"content\": \"Return only JSON: {\\\"ok\\\":true}\"},\n"
    "      {\"role\": \"user\", \"content\": \"test\"}\n"
    "    ],\n"
    "    \"temperature\": 0,\n"
    "    \"max_tokens\": 32,\n"
    "    \"chat_template_kwargs\": {\n"
    "      \"enable_thinking\": false,\n"
    "      \"preserve_thinking\": false\n"
    "    }\n"
    "  }'\n"
    "```\n\n"
    "返回内容中不应出现 `<think>` 或 `reasoning_content`，并应直接包含最终 JSON。\n\n"
    "## 延迟边界\n\n"
    "关闭 thinking 只会消除输出阶段的长推理。262K 输入仍必须完成 prefill，无法\n"
    "做到 200–500ms。正常短请求应走小模型或规则快速通道，只有长文本或 Review\n"
    "请求再进入 Qwen3.8-27B。\n"
    """,
    encoding="utf-8",
)

print("Qwen3.8 fast-audit patch applied")
