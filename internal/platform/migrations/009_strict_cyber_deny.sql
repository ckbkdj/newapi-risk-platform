-- User-requested business deny policy. Existing enabled Cyber rules are a deny
-- list, not model-overridable candidates. Disabled rules remain disabled.
UPDATE cyber_rules SET action='block', updated_at=now()
WHERE enabled=TRUE AND action<>'block';
-- statement-breakpoint
UPDATE audit_profiles SET fail_closed=TRUE, extra=
 jsonb_set(jsonb_set(jsonb_set((CASE WHEN jsonb_typeof(extra)='object' THEN extra ELSE '{}'::jsonb END),
 '{_risk_policy_mode}','"cyber_deny"'::jsonb,TRUE),
 '{_risk_allow_user_provided_secrets}','false'::jsonb,TRUE),
 '{_risk_allow_local_debug_credentials}','false'::jsonb,TRUE),updated_at=now();
-- statement-breakpoint
UPDATE routes SET fail_closed=TRUE,updated_at=now() WHERE fail_closed=FALSE;
