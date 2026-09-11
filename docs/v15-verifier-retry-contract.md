# v15 required-verifier recovery acceptance criteria

This document describes acceptance criteria, not a claim that a particular run
has passed or that production Qwen requests have been replayed.

The `scripts/e2e-audit-v15.py` required-verifier fixtures must account for
bounded output-format recovery separately from HTTP retries and context-length
re-chunking. A persistent invalid-JSON verifier may require two complete
primary/verifier pairs (four HTTP calls, two semantic reviews). A service error
with `retry_count=0` is not an output-format error. Context-length recovery uses
the existing finite re-chunk plan and may cancel parallel work.

For every failure mode, both HTTP and SSE requests must continue to satisfy:

- HTTP status 555, with no business-upstream request started.
- `audit_effective_decision=block` and `audit_completed=false`.
- No completed chunk or cached primary allow may stand in for the failed
  required verifier.
- Exact expected failure class; bounded calls and re-chunk attempts.
- No fallback profile, skipped required verification or automatic allow.

Keep all previous normal-development, source-grounding, terminal-denial,
custom-rule and mixed-operation cases. Merge only after complete final-head CI
and Docker E2E pass. Use a squash merge to exclude temporary assembly history.
