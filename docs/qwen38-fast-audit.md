# Qwen3.8 长上下文快速审计

"
    "Qwen3.8-27B 的原生上下文是 **262,144 tokens**，不是 272K 输入 tokens。
"
    "模型上下文计算包含系统提示词、用户输入、聊天模板和输出，因此不能把
"
    "262,144 个输入 token 全部塞满后再要求模型继续输出。风控平台默认把
"
    "渲染后的审计 Prompt 上限设为 **260,000 tokens**，并保留约 2,144 tokens
"
    "给模板和 128-token 的最终 JSON。

"
    "## 风控平台参数

"
    "```env
"
    "AUDIT_TEXT_MAX_BYTES=2097152
"
    "AUDIT_OUTPUT_MAX_TOKENS=128
"
    "AUDIT_DISABLE_THINKING=true
"
    "AUDIT_LONG_CONTEXT_THRESHOLD_BYTES=131072
"
    "AUDIT_LONG_CONTEXT_TIMEOUT=120s
"
    "AUDIT_PROMPT_TRUNCATE_TOKENS=260000
"
    "```

"
    "`AUDIT_TEXT_MAX_BYTES` 是请求抽取后的 UTF-8 字节上限，不是 token 数。旧值
"
    "262,144 只相当于 256 KiB，无法代表 Qwen3.8 的 262K token 窗口。

"
    "对于模型名中包含 `Qwen` 的审计 Profile，平台会强制发送：

"
    "```json
"
    "{
"
    "  "temperature": 0,
"
    "  "max_tokens": 128,
"
    "  "chat_template_kwargs": {
"
    "    "enable_thinking": false,
"
    "    "preserve_thinking": false
"
    "  }
"
    "}
"
    "```

"
    "对于模型名中包含 `Qwen3.8` / `qwen38` 的 vLLM Profile，还会发送：

"
    "```json
"
    "{
"
    "  "truncate_prompt_tokens": 260000,
"
    "  "truncation_side": "left"
"
    "}
"
    "```

"
    "这会保留最新的请求内容并确保留出输出空间。超过 260,000 prompt tokens 的
"
    "最早部分会被 vLLM 截断，因此需要对超长多轮会话做到零丢失时，应在 NewAPI
"
    "侧分段或使用分块审计，而不是把 262,144 当成纯输入上限。

"
    "## 推荐的专用 vLLM 审计实例

"
    "```yaml
"
    "services:
"
    "  qwen38-audit:
"
    "    image: vllm/vllm-openai:qwen38-x86_64-cu129
"
    "    gpus: all
"
    "    ipc: host
"
    "    shm_size: 64gb
"
    "    volumes:
"
    "      - /opt/models:/models:ro
"
    "    command:
"
    "      - --model
"
    "      - /models/Qwen3.8-27B
"
    "      - --served-model-name
"
    "      - qwen3.8-27b
"
    "      - --tensor-parallel-size
"
    "      - "2"
"
    "      - --dtype
"
    "      - bfloat16
"
    "      - --max-model-len
"
    "      - "262144"
"
    "      - --gpu-memory-utilization
"
    "      - "0.95"
"
    "      - --enable-chunked-prefill
"
    "      - --max-num-batched-tokens
"
    "      - "65536"
"
    "      - --max-num-seqs
"
    "      - "2"
"
    "      - --enable-prefix-caching
"
    "      - --reasoning-parser
"
    "      - qwen3
"
    "      - --api-key
"
    "      - ${VLLM_API_KEY}
"
    "```

"
    "如果启动日志提示 KV cache 不足，可先把 `--max-num-seqs` 降到 `1`；仍不足
"
    "时再尝试 `--kv-cache-dtype fp8`。专用审计实例不建议启用 MTP speculative
"
    "decoding，因为输出只有约 100 tokens，节省的 decode 时间很小，反而会占用
"
    "长上下文所需的显存。

"
    "## 审计模型 Profile

"
    "后台填写：

"
    "```text
"
    "Base URL: http://QWEN_HOST:8000/v1
"
    "Model:    qwen3.8-27b
"
    "Timeout:  120000 ms
"
    "Extra:    {}
"
    "```

"
    "只要模型名包含 `qwen3.8`，无需在 Extra 中重复写 no-thinking 参数。

"
    "## 验证 no-thinking

"
    "```bash
"
    "curl -sS http://QWEN_HOST:8000/v1/chat/completions \
"
    "  -H "Authorization: Bearer $VLLM_API_KEY" \
"
    "  -H 'Content-Type: application/json' \
"
    "  -d '{
"
    "    "model": "qwen3.8-27b",
"
    "    "messages": [
"
    "      {"role": "system", "content": "Return only JSON: {\"ok\":true}"},
"
    "      {"role": "user", "content": "test"}
"
    "    ],
"
    "    "temperature": 0,
"
    "    "max_tokens": 32,
"
    "    "chat_template_kwargs": {
"
    "      "enable_thinking": false,
"
    "      "preserve_thinking": false
"
    "    }
"
    "  }'
"
    "```

"
    "返回内容中不应出现 `<think>` 或 `reasoning_content`，并应直接包含最终 JSON。

"
    "## 延迟边界

"
    "关闭 thinking 只会消除输出阶段的长推理。262K 输入仍必须完成 prefill，无法
"
    "做到 200–500ms。正常短请求应走小模型或规则快速通道，只有长文本或 Review
"
    "请求再进入 Qwen3.8-27B。
"
    