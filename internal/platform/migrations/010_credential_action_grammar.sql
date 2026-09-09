-- Precision repair for the shipped v4/v5 credential candidate. Keep operator
-- edits, action, priority, description and enabled/disabled state unchanged.
-- English verbs must govern a credential object; read-only is an adjective.
UPDATE cyber_rules
SET pattern=$pattern$(?is)(?:\b(?:extract|read|locate|find|recover|parse)(?:[ \t\r\n]+|[(:][ \t]*)["\']?(?:(?:the|a|an|my|your|our|their|his|her|all|any|own|hidden|stored|saved|raw|plaintext|plain-text|current|local|user|users|admin|administrator|only)[ \t\r\n]+){0,8}\b(?:credentials?|access[ _-]tokens?|refresh[ _-]tokens?|api[ _.-]?keys?|authorization|bearer|cookies?)\b|(?:提取|读取|定位|查找|恢复|解析).{0,80}(?:凭据|访问令牌|刷新令牌|API[ _.-]?Key|Authorization|Bearer|Cookie))$pattern$, updated_at=now()
WHERE code='CYBER_CREDENTIAL_ACCESS_REVIEW'
  AND pattern_type='regex'
  AND pattern=$pattern$(?is)(?:\b(?:extract|read|locate|find|recover|parse)\b|(?:提取|读取|定位|查找|恢复|解析)).{0,80}(?:\b(?:credentials?|access tokens?|refresh tokens?|api keys?|authorization|bearer|cookies?)\b|(?:凭据|访问令牌|刷新令牌|API.?Key|Authorization|Bearer|Cookie))$pattern$;
