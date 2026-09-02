# Qwen3.8 长上下文快速审计

Qwen3.8-27B 的原生上下文是 **262,144 tokens**，不是 272K 个纯输入 token。上下文计算同时包含系统提示词、用户输入、聊天模板和模型输出。因此不能先塞满 262,144 个输入 token，再要求模型继续生成结果。

风控平台默认把渲染后的审计 Prompt 上限设为 **260,000 tokens**，预留约 2,144 tokens 给聊天模板和最多 128 tokens 的最终政策 JSON。

## 风控平台参数

```env
AUDIT_TEXT_MAX_BYTES=2097152
AUDIT_OUTPUT_MAX_TOKENS=128
AUDIT_DISABLE_THINKING=true
AUDIT_LONG_CONTEXT_THRESHOLD_BYTES=131072
AUDIT_LONG_CONTEXT_TIMEOUT=120s
AUDIT_PROMPT_TRUNCATE_TOKENS=260000
```

`AUDIT_TEXT_MAX_BYTES` 是从请求中抽取出的 UTF-8 文本字节上限，不是 token 数。旧值 `262144` 仅代表 256 KiB，不能代表 Qwen3.8 的 262K-token 上下文。默认提升到 2 MiB，以免风控层先于模型截掉长请求。

对于模型名中包含 `Qwen` 的审计 Profile，平台会强制发送：

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

对于模型名中包含 `Qwen3.8`、`qwen3_8` 或 `qwen38` 的 vLLM Profile，还会发送：

```json
{
  "truncate_prompt_tokens": 260000,
  "truncation_side": "left"
}
```

这样会保留最新请求内容并确保模型有空间输出。超过 260,000 prompt tokens 时，vLLM 会从最早部分开始截断。要求超长多轮会话完全零丢失时，必须做分块审计，不能把 262,144 当成纯输入额度。

## 推荐的专用 vLLM 审计实例

```yaml
services:
  qwen38-audit:
    image: vllm/vllm-openai:qwen38-x86_64-cu129
    container_name: qwen38-audit
    restart: unless-stopped
    ipc: host
    shm_size: 64gb
    environment:
      CUDA_VISIBLE_DEVICES: "0,1"
    volumes:
      - /opt/models:/models:ro
    ports:
      - "18080:8000"
    command:
      - --model
      - /models/Qwen3.8-27B
      - --served-model-name
      - qwen3.8-27b
      - --tensor-parallel-size
      - "2"
      - --dtype
      - bfloat16
      - --max-model-len
      - "262144"
      - --gpu-memory-utilization
      - "0.95"
      - --enable-chunked-prefill
      - --max-num-batched-tokens
      - "65536"
      - --max-num-seqs
      - "1"
      - --enable-prefix-caching
      - --reasoning-parser
      - qwen3
      - --api-key
      - ${VLLM_API_KEY}
```

`--max-num-seqs 1` 是“保证单次请求尽量吃满 262K”的配置。确认 KV cache 仍有明显余量后，可改成 `2` 提高吞吐；不要直接使用 `8` 承载巨型上下文。需要商业并发时，优先增加审计实例副本。

如果启动日志提示 KV cache 不足，再测试 `--kv-cache-dtype fp8`。专用审计实例不建议启用 MTP speculative decoding：审计输出只有约 100 tokens，decode 节省很小，而长上下文更需要显存。

## 审计模型 Profile

后台填写：

```text
Base URL: http://QWEN_HOST:8000/v1
Model:    qwen3.8-27b
Timeout:  120000 ms
Extra:    {}
```

只要模型名称包含 `qwen3.8`，无需在 Extra 中重复配置 no-thinking。对于超过 128 KiB 的审计文本，平台会自动把请求超时下限提高到 120 秒；短请求仍使用 Profile 自己的超时。

## 直接验证 no-thinking

```bash
curl -sS http://QWEN_HOST:8000/v1/chat/completions \
  -H "Authorization: Bearer $VLLM_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "qwen3.8-27b",
    "messages": [
      {"role": "system", "content": "Return only JSON: {\"ok\":true}"},
      {"role": "user", "content": "test"}
    ],
    "temperature": 0,
    "max_tokens": 32,
    "chat_template_kwargs": {
      "enable_thinking": false,
      "preserve_thinking": false
    }
  }'
```

返回中不应出现 `<think>`；`choices[0].message.content` 应直接包含最终 JSON。

## 延迟边界

关闭 thinking 只消除输出阶段的长推理，不能消除 262K 输入的 prefill。完整 262K 审计不可能稳定在 200–500ms。商业低延迟路径应先走本地规则或更小模型，只有长文本、Review 或规则无法判定的请求再进入 Qwen3.8-27B。
