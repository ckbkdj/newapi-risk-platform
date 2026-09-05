#!/usr/bin/env python3
"""Create a local allowlisted diagnostic bundle; never upload or export raw prompts.

Read-only health/runtime/profile queries, selected Docker/git metadata, optional
local trace JSON. --evaluate invokes dry-run ONLY with explicitly supplied,
manually sanitized and labelled JSONL cases (or shipped synthetic fixtures).
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import getpass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 8 * 1024 * 1024
HEX = re.compile(r"^[a-f0-9]{7,64}$")
DECISIONS = {"allow", "review", "block"}
CONTRACTS = {"risk_audit_request.v2", "risk_audit_output.v2", "output-resilience-fusion.v1"}
LABELS = {"high", "medium", "low", "numeric", "numeric_string", "qualitative"}
ERRORS = {"invalid_json", "invalid_schema", "invalid_evidence", "invalid_semantic_evidence", "ambiguous_output", "timeout", "connection", "response_read", "response_format", "response_too_large", "output_limits", "output_truncated", "empty_response", "invalid_decision", "structured_output_unsupported", "context_length", "input_too_large", "authentication", "endpoint_or_model_not_found", "rate_limited", "audit_server_error", "http_status", "fusion_incomplete", "fusion_configuration", "fusion_profile_unavailable", "semantic_review_budget", "semantic_verifier_configuration", "semantic_verifier_unavailable", "retry_budget_exhausted", "unknown"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirect disabled", headers, fp)


def number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and abs(value) <= 1e15 else None


def select(obj, numeric=(), boolean=(), categorical=None):
    """Only predeclared keys and typed values leave the process."""
    if not isinstance(obj, dict):
        return {}
    result = {}
    for k in numeric:
        n = number(obj.get(k))
        if n is not None:
            result[k] = n
    for k in boolean:
        if isinstance(obj.get(k), bool):
            result[k] = obj[k]
    for k, choices in (categorical or {}).items():
        if isinstance(obj.get(k), str) and obj[k] in choices:
            result[k] = obj[k]
        elif k in obj:
            result[k] = "other"
    return result


def build_view(obj):
    if not isinstance(obj, dict):
        return {}
    out = select(obj, categorical={"input_contract": CONTRACTS, "output_contract": CONTRACTS, "audit_engine": CONTRACTS})
    for k in ("commit", "instance"):
        value = obj.get(k, "")
        if isinstance(value, str) and (HEX.fullmatch(value) or value in {"unknown", "dev"}):
            out[k] = value
    # Custom version strings could contain accidental credentials: export shape only.
    out["version_present"] = bool(obj.get("version"))
    return out


def output_shape(raw):
    if not isinstance(raw, str):
        return {}
    shape = {"bytes": len(raw.encode())}
    try:
        obj = json.loads(raw)
    except (ValueError, RecursionError):
        shape["json_valid"] = False
        return shape
    shape["json_valid"] = True
    if isinstance(obj, dict):
        shape.update(select(obj, categorical={"decision": DECISIONS}))
        confidence = obj.get("confidence")
        shape["confidence_type"] = type(confidence).__name__
        if isinstance(confidence, str) and confidence.strip().lower() in LABELS:
            shape["confidence_label"] = confidence.strip().lower()
        shape["field_types"] = {k: type(obj[k]).__name__ for k in ("decision", "risk_code", "confidence", "evidence", "request_evidence", "harm_type") if k in obj}
        evidence = obj.get("evidence", "")
        # Export presence of KNOWN obsolete gateway instructions, not user content.
        if isinstance(evidence, str):
            shape["legacy_instruction_evidence"] = evidence.strip() in {"[MANDATORY AUDIT OUTPUT]", "Return only the compact policy JSON object now", "Return only the compact policy JSON object now."}
    return shape


def trace_view(obj, depth=0):
    if not isinstance(obj, dict) or depth > 6:
        return {}
    numeric = ("audit_profile_id", "profile_id", "attempt", "audit_http_calls", "audit_semantic_review_calls", "audit_model_attempts", "audit_model_retries", "audit_chunk_count", "audit_chunk_bytes", "audit_intent_bytes", "audit_input_tokens", "audit_context_window_tokens", "output_max_tokens", "response_content_bytes", "http_status", "audit_output_max_tokens", "timeline_duration_ms", "audit_latency_ms", "text_bytes")
    out = select(obj, numeric, ("success", "upstream_started", "audit_completed", "audit_decision_adjusted", "audit_model_evidence_verified", "disagreement"), {
        "decision": DECISIONS, "audit_effective_decision": DECISIONS, "audit_model_decision": DECISIONS,
        "error_class": ERRORS, "audit_error_class": ERRORS, "candidate_error": ERRORS,
        "audit_input_contract": CONTRACTS, "audit_output_contract": CONTRACTS,
        "confidence_kind": LABELS, "confidence_label": LABELS, "audit_model_confidence_kind": LABELS, "audit_model_confidence_label": LABELS,
        "status": {"confirmed", "overturned", "unresolved", "error", "consensus", "adjudicated"},
        "audit_semantic_review_status": {"confirmed", "overturned", "unresolved", "error", "consensus", "adjudicated"},
        "audit_policy_mode": {"strict", "internal_engineering"},
        "finish_reason": {"stop", "length", "max_tokens", "tool_calls"},
        "output_mode": {"json_schema", "json_object", "vllm_structured_json", "guided_json", "prompt_only"},
    })
    for k in ("response_preview", "audit_response_preview"):
        if k in obj:
            out[k + "_shape"] = output_shape(obj[k])
    if "gateway_build" in obj:
        out["gateway_build"] = build_view(obj["gateway_build"])
    for k in ("metadata", "result", "candidate", "outcome", "fusion", "adjudicator"):
        if isinstance(obj.get(k), dict):
            out[k] = trace_view(obj[k], depth + 1)
    for k in ("audit_attempts", "audit_semantic_reviews", "attempts", "votes"):
        if isinstance(obj.get(k), list):
            out[k] = [trace_view(row, depth + 1) for row in obj[k][:32]]
    return out


def bounded_json(path):
    with path.open("rb") as handle:
        data = handle.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("Input exceeds limit")
    return json.loads(data)


def command(args):
    try:
        result = subprocess.run(args, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=False)
        if result.returncode:
            return None
        return result.stdout[:LIMIT].decode("utf-8", "replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return None


def local_metadata():
    data = {}
    commit = command(["git", "rev-parse", "HEAD"])
    if commit and HEX.fullmatch(commit):
        data["checkout_commit"] = commit
    dirty = command(["git", "status", "--porcelain", "--untracked-files=no"])
    if dirty is not None:
        data["tracked_worktree_dirty"] = bool(dirty)
    raw = command(["docker", "inspect", "--format", '{{json .State.Status}} {{json .Image}} {{json .RestartCount}}', "newapi-risk-platform"])
    if raw:
        parts = raw.split()
        if len(parts) == 3:
            try:
                status, image, restarts = map(json.loads, parts)
                if status in {"created", "running", "paused", "restarting", "removing", "exited", "dead"}:
                    data["container_status"] = status
                if isinstance(image, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", image):
                    data["container_image_id"] = image
                if number(restarts) is not None:
                    data["container_restarts"] = restarts
            except (ValueError, TypeError):
                pass
    return data


def gateway_base(value):
    parts = urllib.parse.urlsplit(value.rstrip("/"))
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Invalid gateway URL")
    if parts.scheme == "http" and parts.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Use HTTPS for non-loopback gateways")
    return value.rstrip("/")


def default_base():
    # Read ONLY a validated published port. Never source .env as executable code.
    port = "8080"
    try:
        with (ROOT / ".env").open(encoding="utf-8") as handle:
            lines = handle.read(65536).splitlines()
        for line in lines:
            if line.startswith("HTTP_PORT="):
                candidate = line.split("=", 1)[1].strip().strip("\"'")
                if candidate.isdigit() and 0 < int(candidate) < 65536:
                    port = candidate
    except OSError:
        pass
    return "http://127.0.0.1:" + port


class Client:
    def __init__(self, base, token, timeout):
        self.base, self.token, self.timeout = gateway_base(base), token, timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)

    def request(self, path, payload=None, auth=True):
        headers = {"Cache-Control": "no-cache", "Accept": "application/json"}
        if auth and self.token:
            headers["Authorization"] = "Bearer " + self.token
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, headers=headers, data=data)
        with self.opener.open(request, timeout=self.timeout) as response:
            data = response.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError("Oversized response")
        return json.loads(data)


def profile_view(profile, salt):
    out = select(profile, ("id", "timeout_ms", "retry_count", "block_threshold"), ("enabled", "fail_closed", "is_default", "api_key_configured"))
    for k in ("endpoint", "model", "system_prompt"):
        value = profile.get(k, "")
        if isinstance(value, str):
            out[k + "_fingerprint"] = hmac.new(salt, value.encode(), hashlib.sha256).hexdigest()[:20]
            out[k + "_bytes"] = len(value.encode())
    extra = profile.get("extra", {})
    if isinstance(extra, dict):
        out["extra"] = select(extra, ("_risk_verifier_profile_id", "_risk_fusion_adjudicator_profile_id", "max_tokens"), ("_risk_qwen_fast_mode",), {"_risk_policy_mode": {"strict", "internal_engineering"}, "_risk_structured_output_mode": {"auto", "json_schema", "json_object", "vllm_structured_json", "prompt_only"}})
        ids = extra.get("_risk_fusion_profile_ids")
        if isinstance(ids, list) and len(ids) <= 3 and all(isinstance(n, int) and 0 < n < 2**53 for n in ids):
            out["extra"]["_risk_fusion_profile_ids"] = ids
    return out


def evaluate(client, profiles, cases_path, repeats):
    with cases_path.open("rb") as handle:
        raw = handle.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("Cases file too large")
    cases = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
    if not 1 <= len(cases) <= 100 or len(cases) * len(profiles) * repeats > 600:
        raise ValueError("Evaluation budget exceeds 100 cases or 600 dry-runs")
    if any(not isinstance(c, dict) or c.get("expected") not in {"allow", "block"} or not isinstance(c.get("text"), str) or not c["text"].strip() or len(c["text"].encode()) > 1024*1024 for c in cases):
        raise ValueError("Cases require manually labelled allow/block and nonempty text")
    rows, summaries = [], []
    for profile in profiles:
        counts = collections.Counter(false_blocks=0, false_allows=0, unresolved=0, infrastructure_errors=0, correct=0)
        times, total_calls = [], 0
        for repeat in range(repeats):
            for index, case in enumerate(cases):
                # Positional IDs keep user-chosen IDs/names/secrets out of the report.
                record = {"profile_id": profile, "case_index": index, "repeat": repeat, "expected": case["expected"]}
                started = time.monotonic()
                try:
                    result = client.request("/api/admin/v1/audit/dry-run", {"profile_id": profile, "text": case["text"]})["result"]
                    decision = result.get("decision")
                    record["result"] = trace_view(result)
                    total_calls += int(number(result.get("audit_http_calls")) or 0)
                    if decision not in DECISIONS or result.get("error_class") or result.get("category") == "audit_infrastructure":
                        counts["infrastructure_errors"] += 1
                    elif decision == "review" or result.get("category") == "audit_uncertainty":
                        counts["unresolved"] += 1
                    elif case["expected"] == "allow" and decision != "allow":
                        counts["false_blocks"] += 1
                    elif case["expected"] == "block" and decision == "allow":
                        counts["false_allows"] += 1
                    else:
                        counts["correct"] += 1
                except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
                    counts["infrastructure_errors"] += 1
                    record["collection_error"] = type(exc).__name__
                elapsed = round((time.monotonic() - started) * 1000)
                times.append(elapsed)
                record["elapsed_ms"] = elapsed
                rows.append(record)
        ordered = sorted(times)
        summaries.append({"profile_id": profile, "requests": len(times), **counts, "http_calls": total_calls, "p50_ms": ordered[(len(ordered)-1)//2], "p95_ms": ordered[min(len(ordered)-1, math.ceil(.95*len(ordered))-1)]})
    return {"summary": summaries, "results": rows, "note": "No automatic winner. Repeated cases are not independent accuracy samples; compare false allows, false blocks, unresolved, failures and latency together."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("RISK_BASE_URL") or default_base())
    parser.add_argument("--prompt-token", action="store_true", help="Read admin token without echo; token is never saved")
    parser.add_argument("--trace-file", type=Path, help="Local JSON trace or JSON array; raw text is not included")
    parser.add_argument("--evaluate", action="store_true", help="Explicitly run model dry-run replay (consumes tokens)")
    parser.add_argument("--profile-id", type=int, action="append", help="Repeat for a profile comparison; max 5")
    parser.add_argument("--cases", type=Path, default=ROOT / "tests/fixtures/audit-intent-eval.jsonl")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--output", type=Path, default=ROOT / ("audit-diagnostics-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".zip"))
    args = parser.parse_args()
    token = os.environ.get("RISK_ADMIN_TOKEN", "")
    if args.prompt_token:
        token = getpass.getpass("Admin access token (not saved): ")
    profiles = list(dict.fromkeys(args.profile_id or []))
    if len(profiles) > 5 or any(n < 1 for n in profiles) or not 1 <= args.repeats <= 5 or not 0 < args.timeout <= 600:
        parser.error("Use up to 5 positive profile IDs, 1-5 repeats, and timeout <=600")
    if args.evaluate and (not token or not profiles):
        parser.error("--evaluate requires admin token and --profile-id")
    client = Client(args.base_url, token, args.timeout)
    salt = secrets.token_bytes(32)  # Not included in bundle; prevents dictionary lookup of endpoint/prompt hashes.
    report = {"schema": "risk_diagnostics.v1", "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(), "local": local_metadata(), "health_samples": [], "collection_errors": [], "privacy": "Allowlisted typed metadata only; no .env, credentials, endpoints, system prompts, raw request text or evidence. Review before sharing. No upload performed."}
    client.timeout = min(args.timeout, 10)
    for _ in range(3):
        try:
            report["health_samples"].append(build_view(client.request("/healthz", auth=False).get("build")))
        except (OSError, ValueError, TypeError, AttributeError, RecursionError) as exc:
            report["collection_errors"].append({"stage": "health", "class": type(exc).__name__, "http_status": getattr(exc, "code", None) if isinstance(exc, urllib.error.HTTPError) else None})
    if token:
        try:
            runtime = client.request("/api/admin/v1/runtime")
            report["runtime"] = select(runtime, ("error_http_status", "request_max_bytes", "request_hard_max_bytes", "audit_text_max_bytes", "audit_text_effective_limit_bytes", "trace_queue_depth", "trace_dropped", "audit_output_max_tokens", "audit_long_context_timeout_ms", "audit_chunk_concurrency", "audit_fallback_chunk_bytes", "audit_max_chunks"), ("audit_disable_thinking", "postgres_healthy", "kafka_enabled", "raw_prompt_storage_enabled"))
            report["runtime"]["build"] = build_view(runtime.get("build"))
            report["profiles"] = [profile_view(p, salt) for p in client.request("/api/admin/v1/audit-profiles").get("items", [])[:100]]
            report["routes"] = [select(p, ("id", "audit_profile_id"), ("enabled", "fail_closed")) for p in client.request("/api/admin/v1/routes").get("items", [])[:100]]
        except (OSError, ValueError, TypeError, AttributeError, RecursionError) as exc:
            report["collection_errors"].append({"stage": "admin", "class": type(exc).__name__, "http_status": getattr(exc, "code", None) if isinstance(exc, urllib.error.HTTPError) else None})
    report["admin_metadata_collected"] = "profiles" in report
    if args.trace_file:
        data = bounded_json(args.trace_file)
        records = data if isinstance(data, list) else [data]
        report["traces"] = [trace_view(t) for t in records[:100]]
    builds = {sample.get("commit") for sample in report["health_samples"] if sample.get("commit")}
    report["multiple_commits_observed"] = len(builds) > 1
    checkout = report["local"].get("checkout_commit")
    report["checkout_runtime_mismatch"] = bool(checkout and builds and builds != {checkout})
    report["expected_contract_observed"] = bool(report["health_samples"]) and all(s.get("input_contract") == "risk_audit_request.v2" and s.get("output_contract") == "risk_audit_output.v2" for s in report["health_samples"])
    if args.evaluate:
        client.timeout = args.timeout
        report["evaluation"] = evaluate(client, profiles, args.cases, args.repeats)
    # No overwrite; owner-only file. Fixed archive member names prevent path leaks.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as file:
        with zipfile.ZipFile(file, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("diagnostics.json", json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))
            archive.writestr("README.txt", "Read diagnostics.json before sharing. No upload was performed. Three health probes cannot prove all load-balanced replicas are current. Normal collection is read-only; explicit evaluation uses model dry-run and may write audit events. No production business action is executed.\n")
    print("Created:", args.output)
    print("Review the JSON, then share the ZIP. Raw prompts/evidence and credentials are intentionally absent.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print("Diagnostic collection failed:", type(exc).__name__, file=sys.stderr)
        sys.exit(2)
