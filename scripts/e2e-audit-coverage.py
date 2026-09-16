#!/usr/bin/env python3
"""Disposable mock-stack regression only; never run against production."""
import json
import os
import time
import urllib.error
import urllib.request

BASE = os.environ['BASE_URL']
TOKEN = os.environ['RISK_ADMIN_TOKEN']
ROUTE_KEY = os.environ['ROUTE_KEY']


def call(path, payload=None, token=TOKEN, request_id=None):
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
    if request_id:
        headers['X-Request-ID'] = request_id
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(BASE + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


# Review rules and incomplete audit coverage are evidence that more verification
# would be useful, not authorization to synthesize HTTP 555. Only a confirmed
# block may stop the gateway. Non-text coverage remains visible in trace data.
status, rule = call('/api/admin/v1/cyber-rules', {
    'id': 0, 'code': 'CYBER_COVERAGE_GUARD_REVIEW', 'name': 'E2E coverage review',
    'category': 'credential_access', 'description': 'Synthetic review regression',
    'pattern': 'coverage-guard-(?:safe|unsafe)', 'pattern_type': 'regex',
    'action': 'review', 'priority': 9999, 'enabled': True,
})
assert status == 200, (status, rule)
requests = [
    ('e2e-coverage-positive', {'messages': [{'role':'user', 'content':'coverage-guard-unsafe'}]}, 200),
    ('e2e-coverage-rule-safe', {'messages': [{'role':'user', 'content':'coverage-guard-safe'}]}, 200),
    ('e2e-coverage-negative', {'messages': [{'role':'user', 'content':'Change a button label'}]}, 200),
    ('e2e-coverage-model', {'messages': [{'role':'user', 'content':'coverage-model-only-unsafe'}]}, 200),
    ('e2e-coverage-image', {'messages': [{'role':'user', 'content':[{'type':'image_url','image_url':{'url':'https://image.invalid/synthetic.png'}}]}]}, 200),
    ('e2e-coverage-mixed', {'messages': [{'role':'user','content':[{'type':'text','text':'Explain this'},{'type':'image_url','image_url':{'url':'https://image.invalid/synthetic.png'}}]}]}, 200),
    ('e2e-coverage-tool', {'input':[{'type':'function_call_output','call_id':'synthetic','output':'done'}]}, 200),
]
for request_id, payload, expected in requests:
    payload['model'] = 'normal'
    status, response = call('/gateway/mock-main/v1/chat/completions', payload, ROUTE_KEY, request_id)
    assert status == expected, (request_id, status, response)
    assert 'mock provider success' in json.dumps(response), (request_id, response)

# Trace persistence is asynchronous. Poll only the disposable local stack.
expected_ids = {item[0] for item in requests}
for _ in range(30):
    status, response = call('/api/admin/v1/traces?limit=100')
    assert status == 200, response
    rows = response.get('items', [])
    traces = {row.get('request_id'): row for row in rows}
    if expected_ids <= traces.keys():
        break
    time.sleep(.3)
else:
    raise AssertionError('coverage traces not persisted')

for request_id in expected_ids:
    row = traces[request_id]
    meta = row['metadata']
    assert row.get('http_status') == 200 and row.get('decision') == 'allow', (request_id, row)
    assert meta.get('upstream_started') is True, (request_id, meta)

    if request_id in ('e2e-coverage-image', 'e2e-coverage-mixed'):
        assert meta.get('audit_coverage_status') == 'incomplete', (request_id, meta)
        issues = set(meta.get('audit_coverage_issues') or [])
        assert 'unsupported_nontext_content' in issues, (request_id, meta)
        assert meta.get('audit_source') == 'coverage_fail_open_v29', (request_id, meta)
    elif request_id == 'e2e-coverage-tool':
        # A tool result with no user intent is also coverage uncertainty. It may
        # fail open before any model call, but must still reach upstream.
        assert meta.get('audit_coverage_status') == 'incomplete', (request_id, meta)
        assert meta.get('audit_source') == 'coverage_fail_open_v29', (request_id, meta)
    elif request_id in ('e2e-coverage-positive', 'e2e-coverage-rule-safe'):
        # Review is semantic-only. A model/verifier may run, but the review rule
        # itself must never be the source of a hard block.
        assert meta.get('audit_source') != 'rule' or row.get('decision') != 'block', (request_id, meta)

print('Coverage uncertainty, review rules and non-text gaps fail open with truthful diagnostics')
