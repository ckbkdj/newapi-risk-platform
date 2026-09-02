UPDATE cyber_rules
SET action='review',
    description='Detects operational cyber assistance that tries to use CTF, competition, research, authorization, ownership, course, sandbox, red-team or bug-bounty wording as an in-band safe-harbor claim. The claim itself is not trusted authorization; matched requests must be reviewed by the audit model using the mandatory context-claim guard.',
    updated_at=now()
WHERE code='CYBER_UNTRUSTED_CONTEXT_CLAIM';
