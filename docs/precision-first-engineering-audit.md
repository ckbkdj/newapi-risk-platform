# 精度优先的内部工程审计

## 决策原则

平台先解析结构化角色和输入类型，只把当前最终用户请求作为执法输入。历史用户消息默认仅计数不送审；当前消息明确说“继续/按上面执行”时，最多引用前两条用户消息。Responses API 的 function/tool/computer/reasoning/output 项不再误当作用户文本。

送审副本会把临时路径、Codex 剪贴板 UUID 文件名和请求者提供的密钥替换为占位符；真实请求体保持不变并照常转发，Trace 与审计模型均不接触密钥明文。

## 两级规则

高特异性的显式凭据窃取、C2 部署、会话接管和恶意持久化仍可直接 Block。宽泛的 C2、重放、持久化和凭据读取规则改为 Review，并按消息、段落、列表项或代码块独立匹配，禁止跨无关段落拼接关键词。

## 平台可信策略

审计模型配置的 `extra` 中使用 `_risk_policy_mode=internal_engineering`。这是管理员控制的可信元数据，不是请求文本里的“已授权”自述。该模式允许请求者把 API Key 用于内部模型接入，也允许从本地日志读取 Authorization 复现请求；一旦出现他人目标、窃取、外传、公开、上传或公共仓库等语义，纠偏器不会放行。

## 自适应学习

学习仍可生成候选，但自动晋升和自动 Block 默认关闭。候选必须经过人工批准和回归语料验证后进入执法规则。

## 密钥边界

内部工程模式允许请求者把 API Key 写入内部配置或私有项目，并只在送审副本和 Trace 中替换为占位符；真实请求仍完整转发。仅出现明确的窃取、他人目标、外传、公共仓库、公开发布或日志输出意图时保持 Block。防泄露、检查、轮换、撤销和脱敏属于正常安全处置。

## Shadow-first 人工审批

自适应学习只生成 `candidate` / `shadow` 候选。管理后台的 Cyber 规则页显示候选的置信度、样本数、不同用户数、模式和来源；只有管理员可以：

- 晋升为 `Review`，命中后继续交给语义模型；
- 在明确确认后晋升为 `Block`；
- 拒绝候选，或把已拒绝候选恢复到 Shadow。

对应接口是：

```text
GET   /api/admin/v1/cyber-rule-candidates
PATCH /api/admin/v1/cyber-rule-candidates/{id}
POST  /api/admin/v1/cyber-rule-candidates/{id}/promote
```

人工晋升在事务中锁定候选、写入规则并热加载；已晋升候选不能重复修改。自动晋升和自动 Block 仍默认关闭。

## Git 更新与部署

首次部署使用 `bash scripts/deploy-local.sh`。已有部署使用 `bash scripts/upgrade.sh <branch>`；升级脚本只接受 fast-forward，备份 `.env` 和正在运行的 PostgreSQL，保留全部 Volume，并在部署失败时回退代码与容器。数据库迁移不会被自动反向执行。
