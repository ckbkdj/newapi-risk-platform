# v15: script and functional-test evidence

## Policy boundary

A script is a delivery mechanism, not a violation category. Ordinary UI opening,
clicking, typing, assertions, build checks and functional regression tests require
normal complete auditing. No browser, framework, file, historical title,
localhost address or "test/research/authorized" declaration is a request allowlist.
Actual prohibited capabilities (including the configured scanning, injection,
security-control bypass, credential theft/exfiltration and ChatGPT web automation
restrictions) retain terminal HTTP 555. Business restrictions are not a claim that
every such task is illegal or malicious under another provider's policy.

An exported trace contains selected evidence and diagnostics, not the full script
or complete original request. It can establish a false rejection rationale, but
cannot certify an unseen script or retrospectively approve every request.

## Changes

1. Exact shipped security-evasion rule: validate the object of "close". Browser
   windows followed by an identifier-list file are not IDS/IPS security controls.
   Every security target in a greedy match must be checked; a preceding genuine
   Defender/IDS operation cannot be hidden by a later ids.txt reference.
2. Default credential rule: preview/build-result reads cannot be joined across
   JSON fields to typed numeric max_tokens/max_output_tokens-style keys. All
   credential-like terms in the candidate must be accounted for; actual secret
   targets, unknown values and later real actions are not exempted. Raw escaped
   spellings and the existing bounded decoded tool projection are both checked.
3. Exact shipped prompt-injection rule: a finite untrusted-page warning followed
   by a description of hard-blocked tool shortcuts is not an instruction to
   perform prompt injection. This is a local relationship check, not trust in
   tool output or removal of the warning text. Other/overlapping matches remain.
4. Model evidence: finite browser-coordinate, literal UI click and test-runner
   quotations in automation categories can enter ONE existing grounding check.
   The request_text and request_context remain identical. Every quote occurrence
   is inspected within bounded limits. A corrected allow still requires normal
   second-pass verification; a valid operation denial is never overturned.
5. The normal-development boundary is shared by primary, verifier, evidence
   repair and operation-grounding prompts. The six-field output contract,
   Qwen fast-audit settings, full input coverage and finite retries are unchanged.

No schema migration, operator-rule mutation, production profile change or
fail-open option is introduced. Custom rules keep their exact semantics, even
when a stored action was allow/review. v14 accepted-request capacity, per-call
and optional total timeouts, cancellation and concurrency limits remain.

## Validation

`internal/platform/testdata/script-development-v15.json` contains anonymized
synthetic shapes, NOT user script contents. Unit/integration tests inject primary
and verifier false candidates, repeated weak evidence, unavailable/invalid repair,
valid terminal denials, mixed forbidden actions, same/later overlapping matches,
escaped tool history and custom rules. Input HMAC equality proves correction did
not substitute or omit data. `FuzzV15ScriptEvidenceBounds` checks offset bounds.

`scripts/e2e.sh` explicitly invokes `scripts/e2e-audit-v15.py` after all previous
suites, including v14 long-request HTTP/SSE cases. The v15 suite uses only a
separate inert mock model/profile in the disposable loopback stack. Neither mock
success nor rule tests measure the production Qwen model's accuracy or latency.

## Upgrade and verify

After merge to main, use the existing upgrade path:

```bash
cd /opt/newapi-risk-platform && RESET_DATA=0 BACKUP_DATABASE=1 ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main
```

Check NEW request metadata for `gateway_build.audit_engine=cyber-deny-qwen27b.v15`
and the deployed main commit. Preserve .env and database volumes. The upgrade's
automatic database backup only covers a running local PostgreSQL container;
back up an external database separately. Old trace records retain their original
version/verdict. Completed auditing followed by CLIENT_DISCONNECT is a connection
failure, not a new Cyber violation and not a problem this patch claims to solve.
