-- Narrow the seeded generic data-exfiltration rule so ordinary product/data-platform
-- export design does not become a terminal Cyber veto through long-range word
-- composition such as "导出限制 ... 数据库连接 ... 容量目标". Strong exfiltration
-- verbs remain terminal, while generic export/extract verbs require a concrete
-- unauthorized/third-party target relationship. Other credential/exfiltration
-- rules and the semantic audit remain unchanged.
UPDATE cyber_rules
SET pattern=$risk$(?is)(?:(?:\b(?:exfiltrate|steal|smuggle)\b|(?:外传|窃取|偷运|盗取)).{0,180}(?:\b(?:database(?:\s+dump)?|customer data|source code|documents?|secrets?|files?|records?)\b|(?:数据库(?:数据|内容|备份|转储)?|客户数据|用户数据|源代码|文档|秘密|文件|记录|业务数据))|(?:\b(?:export|extract|dump)\b|(?:导出|提取|转储)).{0,160}(?:\b(?:database(?:\s+dump)?|customer data|source code|documents?|secrets?|files?|records?)\b|(?:数据库(?:数据|内容|备份|转储)?|客户数据|用户数据|源代码|文档|秘密|文件|记录|业务数据)).{0,160}(?:\b(?:victim|other users?|another tenant|target (?:system|server|tenant|company|repository|database)|someone else(?:'s)?)\b|(?:受害者|他人(?:数据|文件|数据库)?|其他(?:用户|租户|公司)|目标(?:系统|服务器|租户|公司|仓库|数据库)))|(?:\b(?:victim|other users?|another tenant|target (?:system|server|tenant|company|repository|database)|someone else(?:'s)?)\b|(?:受害者|他人(?:数据|文件|数据库)?|其他(?:用户|租户|公司)|目标(?:系统|服务器|租户|公司|仓库|数据库))).{0,160}(?:\b(?:export|extract|dump)\b|(?:导出|提取|转储)).{0,160}(?:\b(?:database(?:\s+dump)?|customer data|source code|documents?|secrets?|files?|records?)\b|(?:数据库(?:数据|内容|备份|转储)?|客户数据|用户数据|源代码|文档|秘密|文件|记录|业务数据)))$risk$,
    description='Blocks high-confidence unauthorized data exfiltration. Ordinary report/data exports, pagination, row limits, archive jobs, capacity planning, database-connection limits, and other routine product/data-platform export operations are not sufficient evidence by themselves.',
    updated_at=now()
WHERE code='CYBER_DATA_EXFILTRATION';
