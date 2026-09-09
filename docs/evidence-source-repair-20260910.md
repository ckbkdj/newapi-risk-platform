# v8：缺失原文引用的有界恢复与送审输入诊断

基线 `f2b860898825d2f4bbe23f237df5b8e2caf0065c` / v7。事故日志显示：已提取7656字节、2条用户消息，发送1次模型请求，模型返回完整可解析的block，但引用的英文句子未在实际证据源中匹配。不是“没有用户输入”的证据，也没有显示输出token截断。完整7656字节原请求和真实模型请求体未提供，不能断言具体原因一定是模型编造；翻译、概括、错误引用其他范围等同样可能。

## 根因与边界

v7的 `callCyberGroundedModel` 在原文引用校验报错时立即返回。下游将invalid_evidence转成终态cyber_evidence_unresolved，因此原有“弱操作证据校核”根本进不去。保守拒绝避免了不合规结果漏审，但没有给可恢复的引用错误一次修复机会。

JSON Schema约束字段结构，不证明引用来自用户数据。保持原文校验：不采用语义相似、翻译匹配、拼接或只匹配长引用前缀。已有ASCII大小写/外围引用符号规范化未扩大。

## 实现

- 在解析合法block/review但引用无效时，允许一次新调用重新分类和取证。校正指令仅放system；不把错误引用、旧类别、旧理由作为事实喂回模型，也不把它们追加到request_text。
- 原送审文档及任务锚点保持不变，引用仍只能来自解码后的request_text。request_context用于理解任务，不替代原文定位；未送审的developer/tools/instructions不加入证据源。
- 修复后的allow仍须满足置信度/类别一致性、原双审计和完整Fusion策略。主审错误→修复allow→新复核allow共3次调用；复核错误→修复allow仍保留此前主审。真实操作拒绝不可被后来allow撤销。
- 证据修复与弱操作校核共用同一候选至多一次额外调用，不嵌套、不递归。重复错误、弱依据、空引用、格式错误、超时、取消、预算耗尽都拒绝；证据恢复失败为cyber_evidence_unresolved，不能进入外层重试/备用模型直到allow。
- 原始失败和修复结果分别记录在audit_semantic_reviews[].attempts；新增evidence_repair_corrected/confirmed/error状态。原错误候选的evidence_verified保持false。
- 明确已有连接表和代理记录按源端口关联不自动等于主动探测；扫描、主动枚举、绕过和混合禁用任务仍受原规则/模型约束。未设置Clash/language_server/IP/命令名请求白名单。补齐network_probing等风险类别与allow冲突检查。
- 调用前检查实际user消息文档非空、request_text与证据源字节一致、任务锚点一致；失败为cyber_input_integrity，不发送此请求。
- 新增audit_model_inputs，记录最多32条实际发送尝试的call、profile_id、phase、request_text_bytes、evidence_source_bytes、context计数、payload_bytes、source_matches_request_text及带密钥HMAC指纹。超额显示audit_model_inputs_truncated，不误报调用数。无正文、端点或密钥值。指纹相同用于判断文档是否变化；不是证明远端tokenizer/模型注意力覆盖的证据。

HTTP 555、六字段输出、256初始输出tokens、thinking=false、已有分块、共享预算、120秒总期限、并发、规则终态否决均保留。没有新增数据库迁移。

## 回归与验收

先在v7源码运行新增事故测试，主审/复核无匹配引用都复现终态拒绝；修改后正常对照要求实际完成新校核及双审计，不删掉证据检查。

新增Go回归覆盖原文保持、翻译/概括引用、忽略控制消息、重复无效引用、空引用、编造尾部、缺字段/冲突JSON、置信度/类别冲突、截断、超时、取消、共享预算、有效拒绝、Fusion否决、仅锚点引用、数据完整性和日志上限/隐私。原“绝不恢复无效证据”的测试改为“两次无效后不能继续碰第三次allow”，保留拒绝断言；已验证真实拒绝仍1次即终止。

新增 `scripts/e2e-audit-evidence-repair.py`：12项HTTP/SSE机制对照，与全部既有E2E一起执行；检查200/555、上游未启动、送审文档一致、原始/修复记录及完整输出。Mock仅模拟模型结果，未连接用户代理/数据库/SSH或生产Qwen，不代表真实模型准确率或完整事故回放已通过。真实Qwen评估仍需用户环境复测，不能承诺零幻觉/零误拦。无标签明文密码检测不是此次修复范围。

## 部署

在已有项目根目录运行：

```bash
RESET_DATA=0 BACKUP_DATABASE=1 ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main
```

外置数据库独立备份；不删除卷。以新请求运行构建的commit和 `cyber-deny-qwen27b.v8` 为准。旧日志不会重写。检查audit_model_inputs：实际派发的request_text非空、source_matches_request_text=true，校核前后document_hmac应相同，phase区分primary/verifier/evidence_repair/grounding。仅此无法证明远端模型从未忽略文本。
