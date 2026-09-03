-- Precision-first policy for engineering traffic.
UPDATE cyber_rules SET
    pattern='(?is)(?:\b(?:steal|dump|exfiltrat(?:e|ing)|harvest|grab)\b|(?:窃取|盗取|外传|偷取)).{0,80}(?:\b(?:passwords?|credentials?|session cookies?|access tokens?|refresh tokens?|api keys?|private keys?|seed phrases?|mnemonics?)\b|(?:密码|凭据|会话(?:Cookie|令牌)|访问令牌|刷新令牌|API.?Key|私钥|助记词))',
    action='block',
    description='Explicit theft, harvesting, dumping, or exfiltration of authentication material.'
WHERE code='CYBER_CREDENTIAL_THEFT';
-- statement-breakpoint
INSERT INTO cyber_rules
(code,name,description,category,pattern,pattern_type,action,priority,enabled)
VALUES
('CYBER_CREDENTIAL_ACCESS_REVIEW','Ambiguous credential access for semantic review','Reading, extracting, or locating credentials can be legitimate debugging or harmful access; require semantic review.','credential_access','(?is)(?:\b(?:extract|read|locate|find|recover|parse)\b|(?:提取|读取|定位|查找|恢复|解析)).{0,80}(?:\b(?:credentials?|access tokens?|refresh tokens?|api keys?|authorization|bearer|cookies?)\b|(?:凭据|访问令牌|刷新令牌|API.?Key|Authorization|Bearer|Cookie))','regex','review',1998,TRUE),
('CYBER_EXPLICIT_C2_DEPLOYMENT','Explicit C2 deployment','Explicitly building, deploying, hosting, or configuring command-and-control infrastructure.','command_and_control','(?is)(?:\b(?:build|deploy|host|configure|stand up)\b|(?:构建|搭建|部署|托管|配置)).{0,48}(?:\b(?:c2|command[ -]?and[ -]?control|beacon|implant)\b|(?:命令(?:与|和)?控制|信标|植入体)).{0,64}(?:\b(?:server|framework|channel|callback|tasking|redirector)\b|(?:服务器|框架|通道|回连|任务下发|重定向器))','regex','block',1952,TRUE),
('CYBER_EXPLICIT_SESSION_TAKEOVER','Explicit session-token takeover','Using stolen cookies or session tokens to authenticate as another party.','credential_access','(?is)(?:\b(?:steal|replay|use|inject)\b|(?:窃取|重放|使用|注入)).{0,64}(?:\b(?:session cookies?|session tokens?|jwt|bearer token|oauth token)\b|(?:会话(?:Cookie|令牌)|JWT|Bearer|OAuth令牌)).{0,80}(?:\b(?:take over|login as|impersonate|bypass authentication)\b|(?:接管|冒充|登录他人|绕过认证))','regex','block',1996,TRUE),
('CYBER_EXPLICIT_MALICIOUS_PERSISTENCE','Explicit malicious persistence','Installing a backdoor, implant, or malware startup mechanism on a target.','persistence','(?is)(?:\b(?:install|deploy|create|configure)\b|(?:安装|部署|创建|配置)).{0,64}(?:\b(?:backdoor|implant|malware|webshell|trojan)\b|(?:后门|植入体|恶意软件|WebShell|木马)).{0,80}(?:\b(?:autostart|survive reboot|startup|scheduled task|cron|systemd|registry run)\b|(?:开机自启|重启后存活|启动项|计划任务))','regex','block',1956,TRUE)
ON CONFLICT(code) DO UPDATE SET
    name=EXCLUDED.name,description=EXCLUDED.description,category=EXCLUDED.category,
    pattern=EXCLUDED.pattern,pattern_type=EXCLUDED.pattern_type,action=EXCLUDED.action,
    priority=EXCLUDED.priority,enabled=TRUE,updated_at=now();
-- statement-breakpoint
UPDATE cyber_rules SET
    pattern='(?is)(?:\b(?:command[ -]?and[ -]?control|c2|beacon|implant)\b|(?:命令(?:与|和)?控制|信标|植入体))[^\r\n]{0,64}(?:\b(?:server|framework|channel|callback|tasking|redirector)\b|(?:服务器|框架|通道|回连|任务下发|重定向器))',
    action='review',
    description='C2 terminology with nearby infrastructure terminology; semantic model must confirm operational malicious intent.'
WHERE code='CYBER_C2_INFRASTRUCTURE';
-- statement-breakpoint
UPDATE cyber_rules SET
    pattern='(?is)(?:\b(?:hijack|take over|steal|replay)\b|(?:劫持|接管|窃取|重放))[^\r\n]{0,64}(?:\b(?:session cookies?|session tokens?|jwt|bearer token|oauth token)\b|(?:会话(?:Cookie|令牌|凭据)|Cookie|JWT|Bearer|OAuth令牌))',
    action='review',
    description='Potential authenticated-session takeover; generic event/message replay is excluded and semantic review is required.'
WHERE code='CYBER_SESSION_HIJACKING';
-- statement-breakpoint
UPDATE cyber_rules SET
    pattern='(?is)(?:\b(?:survive reboot|autostart|startup persistence|scheduled task persistence|startup item|registry run)\b|(?:开机自启|重启后存活|计划任务持久化|启动项|注册表Run键))[^\r\n]{0,96}(?:\b(?:target|host|victim|implant|backdoor|malware)\b|(?:目标|主机|受害者|植入体|后门|恶意软件))?',
    action='review',
    description='Startup or implant persistence semantics; ordinary data/state/config/address persistence is excluded.'
WHERE code='CYBER_PERSISTENCE';
-- statement-breakpoint
UPDATE settings SET value='false'::jsonb,updated_at=now()
WHERE key IN ('cyber_adaptive_auto_promote','cyber_adaptive_auto_block');
-- statement-breakpoint
UPDATE audit_profiles SET extra=
    jsonb_set(
      jsonb_set(
        jsonb_set(COALESCE(extra,'{}'::jsonb),'{_risk_policy_mode}','"internal_engineering"'::jsonb,TRUE),
        '{_risk_allow_user_provided_secrets}','true'::jsonb,TRUE),
      '{_risk_allow_local_debug_credentials}','true'::jsonb,TRUE),
    updated_at=now()
WHERE is_default=TRUE AND NOT (COALESCE(extra,'{}'::jsonb) ? '_risk_policy_mode');
