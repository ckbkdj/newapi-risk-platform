# v13：正常开发操作的证据判定

## 修复范围

本次依据用户明确的正常开发边界及私有 CSV 中的诊断片段，修复五类机制：Maven 配置被当成泄密及无效引用反复修复；文档路径/凭据池描述被虚构成窃密；跨分句把“读取状态”和 Token 拼成操作；当前登录凭据供业务 SDK 使用被拦；配置是否存在/启用/就绪的布尔或状态诊断被当成原值导出。CSV 不是完整原始请求，仓库中的示例均为合成案例，不包含用户导出文件或真实凭据。

还复现并修复了 v12 E2E primary-9 的基础缺陷：脱敏把 `key = os.getenv("SERVICE_API_KEY")` 的函数名当成秘密，变成 `key = [USER_PROVIDED_SECRET]("SERVICE_API_KEY")`。同一问题涉及 os.environ、process.env、System.getenv、Gradle properties 等初始化表达式。旧单元测试引用脱敏前文本，会误走无效引用修复，掩盖实际 E2E 故障；新测试直接引用真正送给模型的文本。

## 实现

- 保持动作和源结构的脱敏：保留未加引号的函数/索引初始化表达式；保护字面量密码，补充短字面量及 Maven XML password/passphrase。含空格的指令性文本不会被当作整个秘密值吞掉。原始规则匹配源和业务请求没有被此过程替换。
- 采用同一正常开发边界，供主审、二审、引用修复及操作核验使用。区分 public/private repository authentication 与把秘密发布到公共仓库；字段出现、配置硬编码和代码安全隐患不等于已实施窃密。
- 新增有限结构的证据识别：路径+用途的文档行、声明式仓库/凭据配置、Maven XML 配置片段、构建命令、固定资源 GET/HEAD/下载记录、当前会话 SDK 凭据使用、布尔/启用状态诊断。不是域名、项目、框架或工具名白名单，不执行待审代码。
- 仅对内建或逐字相同的已发布默认规则校正不成立的候选；自定义规则、开关、action 与绑定不变。读取状态的动词不能跨分句偷换宾语；后续同/异行及重叠的真实规则命中仍检查。
- 所有候选引用出现位置都检查；未知命令后缀、附加打印原值/网络发送、XML 指令、插值执行、重复位置带危险操作均不能继承正常形态。模型重新审计完整的相同脱敏文档与任务上下文，校正 allow 仍须完成正常独立二审。一次修复后仍无法判定时拒绝，不递归重试或自动放行。

结构识别只是证据准入，不是通用 Python/Groovy/shell 解释器、数据流证明、所有权证明或无误判保证。扫描、窃密、非法外传、真实绕过等已有禁用能力没有因“开发”标签而解除。

## 验证材料

`internal/platform/testdata/normal-development-v13.json`：29 个配置、Maven、构建、文档、SDK 与状态诊断形态。

`audit_v13_development_test.go`：真实脱敏后输入的 v12 29 例×主/二审复现；v13 29 例×主/二审×正确/无效引用；来源指纹一致、混合操作、重复证据、自定义规则、隐私及模糊测试。旧测试完整保留。

`scripts/e2e-audit-v13.py`：151 个新增 HTTP/SSE 案例，在有真实 PostgreSQL/Redis 的一次性 Docker 栈中注入模拟审计结果。包含 Responses、Chat Completions、序列化工具数据、修复失败、真实否决、原值脱敏与零上游转发断言。这是机制验收，不是 Qwen 的准确率评估。

## 升级与实际运行核验

通过完整 CI/E2E 并合并 main 后，在服务器执行：

```bash
cd /opt/newapi-risk-platform && RESET_DATA=0 BACKUP_DATABASE=1 ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main
```

不要求重置数据库、删除卷或手动改 SQL。升级脚本会备份 `.env`；本机 PostgreSQL 容器正在运行时才做 pg_dump。外部数据库或容器未运行时需先安排独立备份。以升级输出提交号和**新请求**的 `gateway_build.audit_engine=cyber-deny-qwen27b.v13`、commit 核验；route_slug 不是 Git 分支，也不要用旧追踪记录判断新版本是否生效。

## 在实际审计模型上只审计、不转发的评估

现有 `scripts/eval-audit-intent.py` 可执行 38 个合成正常/禁用对照案例，不向业务上游发请求，不修改配置。使用实际审计配置 ID；下例 ID=1 仅为示例：

```bash
export RISK_BASE_URL='http://127.0.0.1:8080'
read -rsp 'Admin access token: ' RISK_ADMIN_TOKEN; echo
export RISK_ADMIN_TOKEN
python3 scripts/eval-audit-intent.py --profile-id 1 --repeat 3 --cases tests/fixtures/audit-development-v13-eval.jsonl
unset RISK_ADMIN_TOKEN
```

仅给本机 HTTP 或受信 HTTPS 网关，使用管理员登录获得的短期 access token，不是数据库密码或普通渠道 Key。输出只含案例 ID、决策、错误类别、引擎版本、调用次数和延迟，不打印原始提示词或令牌。此步骤实际执行前，不能声称生产 Qwen 测试通过。

## 不混为一谈的问题

历史 CSV 的 input_image 不完整覆盖与客户端断开，不能归类为已证实的 Cyber 行为。本版不通过丢弃图片、关闭审计或全局 fail-open 规避它们；没有完成多模态审核覆盖的请求仍可能被拒绝。完整原始请求的复验和真实模型评估，应分别记录，不用模拟测试代替。
