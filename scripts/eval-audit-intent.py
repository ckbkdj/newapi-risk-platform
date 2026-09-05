#!/usr/bin/env python3
"""Replay synthetic intent cases against the configured gateway dry-run API.

No upstream business request is sent. No token or prompt text is printed.
The caller explicitly supplies a gateway URL and admin access token via env.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirects are disabled", headers, fp)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-id", type=int, required=True)
    parser.add_argument("--cases", type=Path, default=Path(__file__).resolve().parents[1] / "tests/fixtures/audit-intent-eval.jsonl")
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    base = os.environ.get("RISK_BASE_URL", "").rstrip("/")
    token = os.environ.get("RISK_ADMIN_TOKEN", "")
    url = urllib.parse.urlsplit(base)
    if args.profile_id < 1 or args.timeout <= 0 or not token or url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment:
        parser.error("Supply a positive profile ID, RISK_BASE_URL and RISK_ADMIN_TOKEN; URL credentials/query/fragment are not allowed")
    if url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
        parser.error("Use HTTPS except for a loopback gateway")
    cases = [json.loads(line) for line in args.cases.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not cases or any(not isinstance(c.get("id"),str) or c.get("expected") not in {"allow", "block"} or not isinstance(c.get("text"), str) or not c["text"].strip() for c in cases):
        parser.error("Each case needs nonempty text and an allow/block expectation")
    opener = urllib.request.build_opener(NoRedirect)
    report = {"cases": len(cases), "false_blocks": 0, "false_allows": 0, "unresolved": 0, "infrastructure_errors": 0}
    for case in cases:
        payload = json.dumps({"profile_id": args.profile_id, "text": case["text"]}).encode()
        request = urllib.request.Request(base + "/api/admin/v1/audit/dry-run", data=payload, headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, method="POST")
        started = time.monotonic()
        record = {"id": case["id"], "expected": case["expected"]}
        try:
            with opener.open(request, timeout=args.timeout) as response:
                data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise ValueError("oversized response")
            result = json.loads(data)["result"]
            decision = result["decision"]
            record.update(decision=decision, error_class=result.get("error_class", ""), review_calls=result.get("audit_semantic_review_calls", 0))
            if result.get("error_class") or result.get("category") == "audit_infrastructure":
                report["infrastructure_errors"] += 1
            elif result.get("category") == "audit_uncertainty":
                report["unresolved"] += 1
            elif case["expected"] == "allow" and decision != "allow":
                report["false_blocks"] += 1
            elif case["expected"] == "block" and decision == "allow":
                report["false_allows"] += 1
            elif decision != case["expected"]:
                report["unresolved"] += 1
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, TypeError) as exc:
            report["infrastructure_errors"] += 1
            # Do not log server response bodies or authentication headers.
            record["error_class"] = type(exc).__name__
        record["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        print(json.dumps(record, ensure_ascii=False), flush=True)
    print(json.dumps({"summary": report}, ensure_ascii=False))
    return int(any(report[k] for k in report if k != "cases"))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"Evaluation input error: {type(error).__name__}", file=sys.stderr)
        sys.exit(2)
