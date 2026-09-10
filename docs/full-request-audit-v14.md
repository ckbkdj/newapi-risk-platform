# v14: complete auditing of accepted long requests

## What changed

The implicit 2 MiB admission ceiling and the fixed 256 HTTP / 128 verification
call ceilings no longer reject an otherwise accepted request. Every actual
chunk plan reserves its required work, including all configured reviewers and
bounded evidence recovery. Spent calls are not reset on re-chunking or fallback.
The existing finite retry/fallback and context-recovery loops, overflow checks,
coverage validation, evidence validation, and actual Cyber denials remain.
An error or an unfinished chunk can NEVER authorize upstream forwarding.

`AUDIT_MAX_CHUNKS=0` (new default) plans every accepted text chunk. A positive
value is an explicit operator cap. Upgrade migrates the known historical 64 and
256 defaults to 0; other positive caps are preserved. The old checkpoint limit
of 128 completed allows is removed; checkpoints remain request/profile scoped
and contain only fully verified chunks, not primary-only results.

`AUDIT_REQUEST_TIMEOUT=0s` (new default) removes the cumulative 120-second audit
deadline, not individual HTTP call timeouts. A positive operator value provides
a total audit timeout. Caller cancellation/deadline still cancels all work.
`AUDIT_LONG_CONTEXT_TIMEOUT=120s` remains a PER-CALL timeout for long input.

`AUDIT_MODEL_CONCURRENCY=16` limits physical audit HTTP calls across requests in
one gateway process. Waiters obey caller cancellation. The per-call timeout
starts AFTER acquiring a slot; the slot is released before any verifier or
repair begins. Existing per-request chunk concurrency remains 2 by default.
This is resource scheduling, not a content allowlist. Several gateway replicas
have separate limits and must be sized for shared model capacity.

## Configuration and limits

```dotenv
AUDIT_MAX_CHUNKS=0
AUDIT_REQUEST_TIMEOUT=0s
AUDIT_MODEL_CONCURRENCY=16
```

Keep `REQUEST_HARD_MAX_BYTES`, `AUDIT_TEXT_MAX_BYTES`, memory and concurrency
protection. The default HTTP hard ceiling remains 64 MiB; this change is not
infinite-memory or infinite-input support. Explicit extraction/ingress limits,
unsupported media, failed model calls, and real prohibited operations can still
refuse requests, with their own diagnostic category. No database migration,
policy-rule mutation, fail-open switch, or truncation of audited history.
The deprecated `audit_capacity_text_limit_bytes=0` means that no secondary
capacity preflight applies. Actual chunk count, completed/reused chunks,
HTTP/review budgets and calls remain visible in trace metadata.

## Upgrade from main

After this revision has passed CI and been merged:

```bash
cd /opt/newapi-risk-platform && RESET_DATA=0 BACKUP_DATABASE=1 ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main
```

This re-builds/re-deploys the service, not just the checkout. The upgrade keeps
`.env` secrets; automatic pg_dump applies only to a running local PostgreSQL
container. Arrange a separate backup for external PostgreSQL. Do not delete
volumes or force-reset a dirty checkout. Check NEW request metadata for
`cyber-deny-qwen27b.v14` and the actual deployed main commit.

## Scope of verification

Regression cases include accepted text above 2 MiB and above 256 chunks,
context-window reduction, complete two-pass counts, terminal denial in the tail,
invalid tail, caller cancellation, configurable total deadline, global slot
limits and one-slot verification, finite work plans and integer overflow.
The disposable Docker E2E retains earlier normal-development and genuine-denial
controls, and adds HTTP/SSE requests that require more than 256 chunks after
model context recovery. Model responses are synthetic, not production Qwen
accuracy, latency or full-capacity benchmarks.

The supplied trace with 22 completed chunks already has an allow verdict and
records CLIENT_DISCONNECT after upstream started. This capacity change does NOT
claim to fix that client/proxy timeout. No early success headers or upstream
requests are sent to keep a connection alive before the audit decision. A caller
or reverse proxy waiting for a long synchronous audit needs an appropriate
waiting timeout; extending server capacity cannot recover a closed connection.
