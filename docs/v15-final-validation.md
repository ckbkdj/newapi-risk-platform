# Final v15 validation

This change intentionally triggers a fresh complete CI and Docker E2E run on
the latest PR #33 head after the bounded verifier retry-accounting repair.
It is not a statement that tests have passed.

Acceptance requires all existing suites, all 88 v15 HTTP/SSE cases, full
fail-closed checks, and container smoke validation. Invalid output, unavailable
required verification, and exhausted context recovery must return HTTP 555,
leave auditing incomplete, and never start the business upstream. No original
normal-development or genuine-operation denial cases may be skipped.

A squash merge is permitted only after the exact final head has both CI and
E2E successful and the main base has not changed. Read the actual workflow
results and the merged main commit to verify publication. The isolated
maintenance workflow is not part of this PR's source tree.
