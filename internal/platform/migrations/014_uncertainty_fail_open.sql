-- v29 uncertainty policy: a rule whose design contract is semantic review must
-- never be converted into a direct HTTP 555 veto. Migration 009 historically
-- promoted every enabled rule to action=block; restore the intended review
-- actions for both fresh installs and already-upgraded databases.
UPDATE cyber_rules
SET action='review', updated_at=now()
WHERE code IN (
    'CYBER_UNTRUSTED_CONTEXT_CLAIM',
    'CYBER_CREDENTIAL_ACCESS_REVIEW',
    'CYBER_REVERSE_SHELL',
    'CYBER_C2_INFRASTRUCTURE',
    'CYBER_SESSION_HIJACKING',
    'CYBER_PERSISTENCE',
    'CYBER_PRIVILEGE_ESCALATION',
    'CYBER_EXPLOIT_CHAIN',
    'CYBER_WEB_INJECTION_EXPLOIT',
    'CYBER_RECON_SCANNING',
    'CYBER_KUBERNETES_TAKEOVER',
    'CYBER_CONTAINER_ESCAPE',
    'CYBER_MODEL_JAILBREAK',
    'CYBER_PROMPT_INJECTION',
    'CYBER_SYSTEM_PROMPT_EXTRACTION',
    'CYBER_AGENT_TOOL_ABUSE',
    'CYBER_MODEL_EXTRACTION',
    'CYBER_AI_OUTPUT_MANIPULATION'
)
AND enabled=TRUE;
