#!/usr/bin/env python3
import json
import os
import urllib.error
import urllib.request

BASE = os.environ['BASE_URL']
USERNAME = os.environ['VIEWER_USERNAME']
PASSWORD = os.environ['VIEWER_PASSWORD']


def request(path, method='GET', payload=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        raw = error.read()
        return error.code, json.loads(raw) if raw else None

status, login = request('/api/admin/v1/login', 'POST', {'username': USERNAME, 'password': PASSWORD})
assert status == 200, (status, login)
assert login['user']['role'] == 'viewer', login
token = login['access_token']

for path in [
    '/api/admin/v1/me',
    '/api/admin/v1/dashboard',
    '/api/admin/v1/runtime',
    '/api/admin/v1/routes',
    '/api/admin/v1/audit-profiles',
    '/api/admin/v1/cyber-rules',
    '/api/admin/v1/cyber-rule-candidates',
    '/api/admin/v1/traces?limit=1',
    '/api/admin/v1/settings',
    '/api/admin/v1/tracking-clients',
]:
    code, body = request(path, token=token)
    assert code == 200, (path, code, body)

# Every mutating admin route is rejected by RBAC before request-body parsing or
# object lookup, so a viewer cannot modify state even by calling APIs directly.
mutations = [
    ('POST', '/api/admin/v1/routes', {}),
    ('DELETE', '/api/admin/v1/routes/1', None),
    ('POST', '/api/admin/v1/audit-profiles', {}),
    ('DELETE', '/api/admin/v1/audit-profiles/1', None),
    ('POST', '/api/admin/v1/cyber-rules', {}),
    ('DELETE', '/api/admin/v1/cyber-rules/1', None),
    ('PATCH', '/api/admin/v1/cyber-rule-candidates/1', {}),
    ('POST', '/api/admin/v1/cyber-rule-candidates/1/promote', {}),
    ('POST', '/api/admin/v1/audit/dry-run', {'text': 'safe'}),
    ('PUT', '/api/admin/v1/settings/storage', {}),
    ('POST', '/api/admin/v1/tracking-clients', {}),
]
for method, path, payload in mutations:
    code, body = request(path, method, payload, token)
    assert code == 403, (method, path, code, body)
    assert body and body.get('error', {}).get('code') == 'forbidden', (method, path, body)

print('Viewer RBAC: all observation GETs succeeded; all mutating admin routes returned 403')
