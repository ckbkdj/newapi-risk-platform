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


# Create a candidate-only rule, never a final truth label. Mock primary returns
# allow; only the fresh semantic verifier interprets the synthetic harm marker.
status, rule = call('/api/admin/v1/cyber-rules', {
    'id': 0, 'code': 'CYBER_COVERAGE_GUARD_REVIEW', 'name': 'E2E coverage review',
    'category': 'credential_access', 'description': 'Synthetic review regression',
    'pattern': 'coverage-guard-(?:safe|unsafe)', 'pattern_type': 'regex',
    'action': 'review', 'priority': 99999, 'enabled': True,
})
assert status == 200, (status, rule)
requests = [
    ('e2e-coverage-positive', {'messages': [{'role':'user', 'content':'coverage-guard-unsafe'}]}, 555),
    ('e2e-coverage-negative', {'messages': [{'role':'user', 'content':'coverage-guard-safe'}]}, 200),
    ('e2e-coverage-image', {'messages': [{'role':'user', 'content':[{'type':'image_url','image_url':{'url':'https://image.invalid/synthetic.png'}}]}]}, 555),
    ('e2e-coverage-mixed', {'messages': [{'role':'user','content':[{'type':'text','text':'Explain this'},{'type':'image_url','image_url':{'url':'https://image.invalid/synthetic.png'}}]}]}, 555),
    ('e2e-coverage-tool', {'input':[{'type':'function_call_output','call_id':'synthetic','output':'done'}]}, 555),
]
for request_id, payload, expected in requests:
    payload['model'] = 'normal'
    status, response = call('/gateway/mock-main/v1/chat/completions', payload, ROUTE_KEY, request_id)
    assert status == expected, (request_id, status, response)
    if request_id not in ('e2e-coverage-positive', 'e2e-coverage-negative'):
        assert 'AUDIT_INPUT_COVERAGE_INCOMPLETE' in json.dumps(response), (request_id, response)

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
    meta = traces[request_id]['metadata']
    if request_id == 'e2e-coverage-negative':
        assert meta['upstream_started'] is True and meta['audit_completed'] is True, meta
        assert meta['audit_semantic_review_calls'] == 1, meta
    else:
        assert meta.get('upstream_started') is False, meta
        if request_id == 'e2e-coverage-positive':
            assert meta['audit_model_decision'] == 'allow', meta
            assert meta['audit_semantic_review_status'] == 'escalated', meta
            assert meta['audit_http_calls'] == 2, meta
        else:
            assert meta['audit_coverage_status'] == 'incomplete', meta
            assert meta['audit_completed'] is False and meta['audit_http_calls'] == 0, meta
print('Coverage gateway HTTP 200/555, upstream exclusion and verifier escalation passed')
