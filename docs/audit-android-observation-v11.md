# v11：转义边界、本机观察与专业 Android 研发

## 事故来源与判定边界

基线为 `9d8b1ea44559fd6e662a07ae11a4400f9458bffe` / v10。用户提供的磁盘日志显示 `\\n` 后紧接 `map auto_home` 被内置正则截成 `nmap`，模型调用为零；新 Markdown 附件则显示 `Get-NetTCPConnection -State Listen ... | Where-Object` 被模型当成主动端口探测，发生在60分块中的第4块。后者引用存在，但仅凭现有状态查询不能成立主动建连。附件不是完整原始请求，不能认定整条历史一定安全。

Microsoft 文档明确 Get-NetTCPConnection 获取当前 TCP 连接；Android 官方将 dumpsys、logcat、dumpstate 用于系统诊断，并说明 AOSP 构建流程。下列研发矩阵是本次新增的工程验收范围，不冒充附件原文，也不承诺生产模型零误报。

## 修复

### 工具数据与规则边界

只在已知 TOOL_DATA 边界，对完整、无重复键、无尾随数据的 JSON 文档做有界解码和文本投影。保留全部键、字符串、标量、数组、嵌套内容，内部 role/system/type 字段仍是资料，不升级为控制消息。解码最多4层序列化包装、32层投影深度，并受请求剩余容量及取消约束。普通路径、任意代码、坏 JSON 和未证明为 JSON 的文本不做全局反转义。

原始文本仍用于规则匹配，自定义规则原先能命中的内容不能因规范化消失。存在解码时，另对模型送审视图匹配规则，使 `\\nnmap` 或 Unicode 转义中的真实扫描命令同样暴露。规则命中日志标记 `audit_rule_input_view=raw_input|decoded_tool_text`；`audit_serialized_tool_documents` 记录解码的文档数量。模型引用匹配使用其实际送审的解码/脱敏视图，主审、校核和复核的文档仍逐字节一致。

没有完整 JSON 结构的旧文本只对“转义换行末尾的 n + 完整数值挂载表行 map auto_home”判为不成立的候选，仍检查后续/重叠命中并完整送模型，不给 macOS、df、挂载路径或 nmap 整体白名单。真实 nmap 命令与混合任务保留拒绝。

### 观察与研发证据校核

增加有限命令语法检查：Get-NetTCPConnection/Get-NetUDPEndpoint/Get-Process/Get-Date，以及受限的 Where-Object 数值/枚举过滤和展示管道；df、mount 无参数状态输出；ADB getprop、logcat -d、dumpsys 常用只读形态、pm list/path、settings get；AOSP source/lunch/m、Gradle 标准构建任务和普通源码检索。短引用必须落在完整的合格命令中，复合命令每段都检查；未知命令、可执行管道、脚本替换、远程 CIM、写入选项不会按被动形态处理。文档还覆盖有限的构建声明、属性记录和 AVC/编译错误引文。

这只是将不能单独证明违规的候选交给既有的一次操作校核，不是命令授权或直接 allow。相同送审数据及任务锚点保留；校正 allow 仍需原有新调用复核；反复弱依据、无效输出或调用失败保持555审计故障；有效操作拒绝、管理员规则、Fusion否决、预算及期限保持。不存在 Android/AOSP/localhost/自有/测试的全请求免审。

正常范围：Soong/Android.bp/BoardConfig、Gradle/BuildConfig/NDK/JNI、AIDL/Binder、HAL/VINTF、资源 overlay、普通编译测试、RIL/Telephony源码与日志、ANR/tombstone/已有Perfetto trace、权限拒绝诊断。真正窃密、漏洞利用、主动扫描、绕过认证/安全控制、动态Hook等仍按业务政策拒绝；不能用研发标签覆盖它们。

## 验证

先在v10复现转义磁盘误命中、本机观察证据锁定和搜索工具名误命中。新增单元/回归涵盖原始与两层JSON、恶意同胞字段、内部伪造role字段、秘密脱敏、自定义规则、编码真实扫描、主审/复核错误、重复错误、真实否决、取消、容量和深度。

`tests/fixtures/audit-android-development-v11.jsonl` 提供51个合成样例（39个正常、12个必须拒绝）。正常对照必须完整双审计；拒绝对照必须不转发。`scripts/e2e-audit-v11.py` 在隔离mock栈执行这套样例及额外恢复/HTTP/SSE对照，主套件继续包含所有既有回归。Mock只验证机制，不验证Qwen语义准确率。没有真实用户数据/公司地址/密钥提交到仓库。

生产Qwen回放可使用已有 `scripts/eval-audit-intent.py`（dry-run，不调用业务上游），显式提供 RISK_BASE_URL、RISK_ADMIN_TOKEN：

```bash
python3 scripts/eval-audit-intent.py --profile-id 1 \
  --cases tests/fixtures/audit-android-development-v11.jsonl --repeat 3
```

评估输出只记录样例ID、判定、故障类别、构建及耗时，不打印口令或请求正文。本次没有连接生产Qwen、服务器或数据库，也没有回放缺失的完整原请求。图片/未知类型、超长历史、真实模型误判及客户端断开不能据此宣称全部解决。

## 部署

引擎 `cyber-deny-qwen27b.v11`，无数据库迁移，不修改模型绑定，不删除数据卷。

```bash
cd /opt/newapi-risk-platform
RESET_DATA=0 BACKUP_DATABASE=1 ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main
```

以新请求的运行构建验证；外置数据库独立备份。代码提交、CI/E2E成功、生产升级和真实模型验收分别报告。

## 官方语义参考

- Microsoft Get-NetTCPConnection: https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection
- Android dumpsys: https://developer.android.com/tools/dumpsys
- AOSP bug reports: https://source.android.com/docs/core/tests/debug/read-bug-reports
- AOSP build: https://source.android.com/docs/setup/build/building
- Go regexp word boundaries: https://go.dev/src/regexp/syntax/doc.go
