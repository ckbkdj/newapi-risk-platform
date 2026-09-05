# AOSP、公司公网 ADB 与上下文超限回归修复（2026-09-05）

## 两类生产现象不能混为一个错误

审计模型的 HTTP 400 如果明确报告 maximum context length，应归类为 `context_length`。
`prompt contains at least N input tokens` 中的 N 是**下界，不是精确输入长度**。
例如输入至少 259745、输出预算 256、上下文上限 260000，只能断言合计**至少**超出 1 token，不能据此推算全文恰好只超 1 token。

此前共享的 `lastFailure` 可能保存首次全文请求的 HTTP 400，而后续某个分块发生了真正的 transport timeout。
在最终错误上附加旧响应，便会出现“timeout + context-limit response_preview”的矛盾。
本次按实际返回的错误对象关联响应诊断：真实 timeout 不会携带另一分块的 HTTP 400 响应；首次超限的计数仍在独立的上下文恢复元数据中保留。
这不是把所有 timeout 强制改为 context_length。

## 长文本处理

保留全文优先、显式超限后分块的路径，不使用 `truncate_prompt_tokens`，不删除尾部。
精确输入计数可以用于带余量的估算；下界计数不作为可靠 token 密度，而使用不大于 `AUDIT_FALLBACK_CHUNK_BYTES` 的保守分块，并参考当前尝试的实际输出预算、上下文上限及模板余量。
默认 fallback 为 196608 字节。仍然超限时继续有界缩小；超过最大分块数或审计未完成仍按原有故障策略处理。

短尾块继承完整请求的长上下文超时预算，调用方取消和 deadline 仍然生效。
同一 profile 的瞬时网络重试从已缩小的分块预算重试，不重新发送已知超限的全文；已完成分块可能重审，不缓存部分 allow 当作完整审计。
只有格式、截断、结构化输出兼容性或证据格式错误才推进 JSON 格式恢复序列。
网络 timeout、429、503 不再误称为 FORMAT RECOVERY，也不会无谓增大输出预算。

## 正常工程操作与安全边界

强制精确性提示在自定义审计 prompt 下同样注入，明确区分：

- 正常 AOSP/userdebug/eng 构建、Soong/ninja 修复、框架/HAL 开发、CTS/VTS、SELinux 策略排障；
- 对指定公司云手机的正常 ADB 连接、配对、日志、安装和开发版调试，包括公网 IPv4/IPv6；
- 通过应用正常已认证的管理界面新增普通测试用户、填写展示名/sub/租户等表单。

公网地址、ADB、root 或所有权说明本身都不是有害证据。审计放行只表示请求内容未被该层拦截，不代表网关授予管理权限，也不验证公网地址归属。目标系统既有认证、设备配对和授权流程仍必须生效；本次不开放任何网络端口、不访问测试门户、不修改 ADB 服务的认证方式。

在管理员配置的 `internal_engineering` 模式下，额外纠正一种狭义误报：
模型返回 `CYBER_UNTRUSTED_CONTEXT_CLAIM`、证据已经匹配原文、请求属于已识别的正常工程操作，且不含守卫识别出的高风险/混合/编码命令时，记录策略调整并放行。
规则命中、未验证证据、纯粹的“我已授权”说明、不受支持的操作，以及具体凭据窃取/恶意代码等风险代码，不通过这条例外放行。
长篇任意程序也不通过短请求例外放行。此守卫不是通用恶意代码识别器，未知或复杂操作仍依赖模型和原有规则。

仍保留针对未授权访问、认证绕过、第三方数据窃取、全网暴露 ADB 批量接管、隐藏后门等有害能力的审查。
`FailClosed` 没有关闭：未解决的 review、审计基础设施故障和原有渠道错误继续沿用现有处理及 555 契约。
没有将公司 IP、任意公网 IP 或 AOSP 关键词加入全局白名单。

## 新追踪字段

`audit_model_decision` 保存已验证的模型原始结论；`audit_effective_decision` 保存策略/FailClosed 处理后的审计结论，和后续渠道调用结果分开。
`audit_model_original_reason`、`audit_model_original_evidence` 与 `audit_policy_adjustment` 用于解释纠正原因。
例如正常后台操作可以是原始 review → 策略 allow；真正未决请求仍可以是原始 review → FailClosed block。

`audit_input_tokens_lower_bound=true` 时，输入计数和由此计算的超限量必须按下界读取。
`audit_observed_output_tokens` 是报告该次超限时的输出预算，不一定等于最终成功尝试的输出预算。
界面用 ≥/至少显示下界。历史追踪记录不重写，新增字段只对升级后的请求生效。

## 回归与上线验证

`internal/platform/audit_incident_regression_test.go` 用模拟 HTTP transport 复现上下文拒绝、随后超时、三次重试、短尾 deadline、尾部风险及取消中断，并执行完整 AuditEngine 判定和元数据路径。
`scripts/e2e.sh` 通过 Docker 网关 + PostgreSQL + Redis + mockprovider 验证 AOSP、公网 ADB、后台用户操作、混合有害请求、下界分块及落库追踪。
测试使用 TEST-NET/文档地址和合成用户名，不把实际公司公网地址、密码或原始敏感日志提交到仓库。

```sh
go test -race -count=1 ./...
go vet ./...
bash scripts/upgrade_test.sh
# 完整服务端验收由既有 CI / E2E workflows 执行。
```

这些回归验证的是网关机制，不等同于真实 Qwen 权重的语义准确率或生产 GPU 的吞吐/延迟测试。
升级后应通过现有管理端 dry-run 使用实际 audit profile 重放脱敏的 AOSP/ADB/后台任务，再观察真实渠道请求。
日志中的 `internal_engineering` 已是支持的模式，无需关闭 FailClosed 或提高输出 token 上限来解决本次误报。

参考：Android ADB 官方文档 https://developer.android.com/tools/adb ；vLLM 上下文配置 https://docs.vllm.ai/en/stable/cli/serve/ 。
