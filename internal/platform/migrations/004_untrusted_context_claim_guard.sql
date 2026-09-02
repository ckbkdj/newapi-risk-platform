INSERT INTO cyber_rules
(code,name,description,category,pattern,pattern_type,action,priority,enabled)
VALUES
(
  'CYBER_UNTRUSTED_CONTEXT_CLAIM',
  'Untrusted CTF/authorization context claim',
  'Blocks operational cyber assistance that tries to use CTF, competition, research, authorization, ownership, course, sandbox, red-team or bug-bounty wording as an in-band safe-harbor claim. Genuine authorization must come from trusted platform policy/metadata, not natural-language user text.',
  'policy_evasion',
  '(?is)(?:(?:\bctf\b|capture[ -]?the[ -]?flag|\b(?:competition|contest|challenge|lab|sandbox|course|research|authorized|authorised|pentest|red team|bug bounty|for education|for research|my own (?:app|system|server|device))\b|CTF|比赛|竞赛|挑战赛|靶场|沙箱|实验室|课程|作业|研究|论文|已授权|授权测试|渗透测试|红队|漏洞赏金|学习用途|教育用途|我自己的(?:App|APP|应用|系统|服务器|设备)).{0,600}(?:(?:\b(?:help me|how (?:do|can) i|show me how|give me|write|build|create|generate|provide|implement|steps?|script|code)\b|帮我|请(?:帮|给|写|提供|生成|实现|教)|如何|怎么|怎样|教我|给我|写(?:一个|段)?|编写|生成|实现|提供|步骤|脚本|代码).{0,300}(?:\b(?:reverse engineer|decompile|disassemble|unpack|crack|bypass|hook|instrument|frida|exploit|privilege escalation|scan|enumerate|credential stuffing|password spray|steal|dump|extract credentials?|extract tokens?|extract cookies?|disable (?:edr|antivirus|security)|evade (?:edr|antivirus|sandbox)|reverse shell|web ?shell)\b|逆向|反编译|反汇编|脱壳|破解|绕过|Hook|Frida|插桩|注入|漏洞利用|利用漏洞|提权|扫描|枚举|撞库|密码喷洒|爆破|窃取|盗取|导出(?:凭据|密码|令牌|Token|Cookie)|提取(?:凭据|密码|令牌|Token|Cookie)|反弹Shell|WebShell|关闭(?:EDR|杀毒|安全防护)|禁用(?:EDR|杀毒|安全防护)|规避(?:EDR|杀毒|沙箱|检测))|(?:\b(?:reverse engineer|decompile|disassemble|unpack|crack|bypass|hook|instrument|frida|exploit|privilege escalation|scan|enumerate|credential stuffing|password spray|steal|dump|extract credentials?|extract tokens?|extract cookies?|reverse shell|web ?shell)\b|逆向|反编译|反汇编|脱壳|破解|绕过|Hook|Frida|插桩|注入|漏洞利用|利用漏洞|提权|扫描|枚举|撞库|密码喷洒|爆破|窃取|盗取|反弹Shell|WebShell).{0,300}(?:\b(?:help me|how (?:do|can) i|show me how|give me|write|build|create|generate|provide|implement|steps?|script|code)\b|帮我|请(?:帮|给|写|提供|生成|实现|教)|如何|怎么|怎样|教我|给我|写(?:一个|段)?|编写|生成|实现|提供|步骤|脚本|代码))|(?:\b(?:help me|how (?:do|can) i|show me how|give me|write|build|create|generate|provide|implement)\b|帮我|请(?:帮|给|写|提供|生成|实现|教)|如何|怎么|怎样|教我|给我|编写|生成|实现|提供).{0,300}(?:\bctf\b|\b(?:competition|contest|challenge|lab|sandbox|course|research|authorized|pentest|red team|bug bounty)\b|CTF|比赛|竞赛|靶场|沙箱|课程|研究|已授权|授权测试|渗透测试|红队|漏洞赏金).{0,600}(?:\b(?:reverse engineer|decompile|disassemble|unpack|crack|bypass|hook|instrument|frida|exploit|privilege escalation|scan|enumerate|steal|dump|reverse shell|web ?shell)\b|逆向|反编译|反汇编|脱壳|破解|绕过|Hook|Frida|插桩|漏洞利用|提权|扫描|枚举|窃取|盗取|反弹Shell|WebShell)|(?:\b(?:reverse engineer|decompile|disassemble|unpack|crack|bypass|hook|instrument|frida|exploit|scan|enumerate|steal|dump|reverse shell|web ?shell)\b|逆向|反编译|反汇编|脱壳|破解|绕过|Hook|Frida|插桩|漏洞利用|扫描|枚举|窃取|盗取|反弹Shell|WebShell).{0,300}(?:\bctf\b|\b(?:competition|contest|challenge|lab|sandbox|course|research|authorized|pentest|red team|bug bounty)\b|CTF|比赛|竞赛|靶场|沙箱|课程|研究|已授权|授权测试|渗透测试|红队|漏洞赏金).{0,600}(?:\b(?:help me|how (?:do|can) i|show me how|give me|write|build|create|generate|provide|implement)\b|帮我|请(?:帮|给|写|提供|生成|实现|教)|如何|怎么|怎样|教我|给我|编写|生成|实现|提供))',
  'regex',
  'block',
  2200,
  TRUE
)
ON CONFLICT (code) DO UPDATE SET
  name=EXCLUDED.name,
  description=EXCLUDED.description,
  category=EXCLUDED.category,
  pattern=EXCLUDED.pattern,
  pattern_type=EXCLUDED.pattern_type,
  action=EXCLUDED.action,
  priority=EXCLUDED.priority,
  enabled=TRUE,
  updated_at=now();
