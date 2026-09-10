# v12：正常本地凭据读取与 Android 签名研发

## 请求与范围

用户明确要求：本地开发读取 Key 属于常规操作，不能仅据此判泄露。附件是 v10 的 Get-NetTCPConnection -State Listen 误判追踪，不是完整原始请求，也没有提供新的实际 Key 读取原始日志。因此本次凭据用例是按用户新边界构造的合成回归，不能说成已回放真实凭据事故。

基线为 main `e7ff134e461c4ccb0ceacc4c6253967a45822af3` / v11。保留其转义工具JSON、macOS挂载输出假nmap、完整PowerShell状态管道和Android/AOSP专业研发修复；没有覆盖或重复撤回 #30。

## 已定位与修改

旧内置 `CYBER_CREDENTIAL_ACCESS_DISABLED` 及默认DB `CYBER_CREDENTIAL_ACCESS_REVIEW` 都可能把“从配置读取API Key”直接变成规则拒绝。后者虽名为 REVIEW，严格模式仍将其终态否决。原操作证据校核只覆盖提供凭据、终端输入和认证设计，未覆盖一般配置加载及SDK环境读取。

v12 将正常配置读取送入完整语义审计，而不是直接视作攻击。仅对内置/精确未修改的010种子表达式做证据准入修正，不更新DB、不更改启用状态/动作、不覆盖自定义模式。模型若只引用普通读取、环境变量访问、签名材料加载或被掩码配置字段，允许已有的一次同原文操作校核；纠正allow仍完成正常双审计。重复错误、输出失败、超时和不确定仍555。真实规则/有效操作拒绝仍终态，不能通过备用模型或Fusion洗成allow。

策略区分三件事：
- 来源：本项目现有配置/签名材料与他人、隐藏系统凭据。
- 用途：正常认证/构建/签名与冒用、绕过。
- 去向：程序内使用/本地选定配置读取与公开日志/无关外传。

读取本身不是泄露；业务许可也不意味着日志可以记录原值。读取Key不是需要用户改写为防御目标的请求。单凭“本地开发”不能为其他禁用操作提供白名单。stdout/工具结果中敏感值仍走现有脱敏，本轮没有执行任何客户Key读取。

## 覆盖例子与限制

覆盖中文/英文配置读取，.env、环境变量、Python os.getenv/os.environ/load_dotenv、Node process.env、Java/Kotlin System.getenv、Go os.Getenv、.NET环境API、Gradle keystoreProperties/providers、服务挂载凭据、AOSP platform.pk8 签名加载、apksigner/keytool，以及 cat/Get-Content/printenv/Get-Item 的有限完整命令形态。

完整命令包含管道、重定向、动态代码或未知后缀时，不继承普通读命令形态。短证据全部出现位置都要检查，有界扫描失败不会自动授权。对象位于否定词与公开日志之间时不能丢失否定；双重否定、肯定转折与实际外传仍拒绝。该语法门禁不是完整shell解析器、来源授权证明或通用数据流分析。

纯粹未说明来源用途的模糊读取、未知命令/介质/超容量输入仍可能需要复核或故障拒绝；不能承诺任意本地开发请求均通过。权限由目标系统决定，不因审计allow授予文件或设备访问权限。

## 回归与验证

先新增用例并在v11观察到配置读Key的规则拒绝及模型错误无法进入校核；再修复。已有测试中的两条“read API key from config必须规则拒绝”与用户最新边界冲突，移入正常双审计用例，保留并强化读取后公开日志、隐藏/他人秘密、混合扫描、权限绕过及自定义规则拒绝对照，没有删除安全拒绝测试。

公共合成语料为 `internal/platform/testdata/local-credential-development.json`，单元测试校验与语料一致。完整E2E新增每条正常、主审误判、复核误判三组，以及失败有界、有效拒绝、HTTP两种接口、SSE、脱敏等对照。执行全量race、vet、服务构建、升级脚本、诊断隐私及旧v11 Android/转义套件，按实际最终运行结果验收。

官方事实依据（并非对生产模型的验证）：
- Microsoft Get-NetTCPConnection：查询已有TCP连接状态，不是该命令本身主动建连扫描。https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection
- Android app signing：构建流程需要签名密钥及keystore配置，建议与共享构建文件隔离。https://developer.android.com/studio/publish/app-signing
- AOSP sign builds：发布签名使用受保护的私钥材料。https://source.android.com/docs/core/ota/sign_builds

无真实Qwen回放、无生产部署、无数据库/服务器登录；不将机制测试当成真实模型准确率。

## 部署

无数据库迁移；不改模型绑定，不删除数据卷。在项目目录执行：

```bash
RESET_DATA=0 BACKUP_DATABASE=1 ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main
```

外部数据库独立备份。以新请求的实际运行commit与 `cyber-deny-qwen27b.v12`核验。v11已有65项Android/桌面HTTP/SSE测试仍完整保留。
