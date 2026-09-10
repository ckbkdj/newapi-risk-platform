#!/usr/bin/env python3
"""Disposable loopback mock-stack tests; never calls the production audit model."""
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = os.environ['BASE_URL'].rstrip('/')
ADMIN = os.environ['RISK_ADMIN_TOKEN']
ROUTE = os.environ['ROUTE_KEY']
if urllib.parse.urlsplit(BASE).hostname not in {'localhost', '127.0.0.1', '::1'}:
    raise SystemExit('Only the disposable loopback mock stack is supported')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'Redirect disabled', headers, fp)

OPENER = urllib.request.build_opener(NoRedirect)

def call(path, payload=None, token=ADMIN, request_id=None, stream=False):
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
    if request_id:
        headers['X-Request-ID'] = request_id
    req = urllib.request.Request(BASE + path, headers=headers,
        data=None if payload is None else json.dumps(payload).encode())
    try:
        with OPENER.open(req, timeout=30) as response:
            return response.status, response.read().decode() if stream else json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)

def trace_for(request_id):
    for _ in range(40):
        status, data = call('/api/admin/v1/traces?limit=1&request_id=' + urllib.parse.quote(request_id))
        assert status == 200, data
        rows = data.get('items', [])
        if rows and rows[0].get('request_id') == request_id:
            return rows[0]['metadata']
        time.sleep(.1)
    raise AssertionError('trace missing: ' + request_id)

# Execute the actual migration against a TEMP table in one rolled-back session.
# This proves old seeded rows change, while custom patterns, unrelated rules,
# enablement and actions are preserved. It does not mutate live route/rule data.
root = Path(__file__).resolve().parents[1]
migration = (root / 'internal/platform/migrations/010_credential_action_grammar.sql').read_text()
new, old = re.findall(r'\$pattern\$(.*?)\$pattern\$', migration)
q = lambda s: "'" + s.replace("'", "''") + "'"
rows = [('seed', 'CYBER_CREDENTIAL_ACCESS_REVIEW', old, 'block', True),
        ('custom', 'CYBER_CREDENTIAL_ACCESS_REVIEW', 'operator-custom-pattern', 'block', True),
        ('other', 'ORG_OTHER_RULE', old, 'block', True),
        ('disabled', 'CYBER_CREDENTIAL_ACCESS_REVIEW', old, 'review', False)]
values = ','.join('(' + ','.join(q(x) for x in row[:4]) + ',' + str(row[4]).lower() + ')' for row in rows)
transaction = """BEGIN;
CREATE TEMP TABLE cyber_rules(test_id text, code text, pattern text, action text, enabled boolean, pattern_type text DEFAULT 'regex', updated_at timestamptz);
INSERT INTO cyber_rules(test_id,code,pattern,action,enabled) VALUES """ + values + ';\n' + migration + f"""
DO $check$ BEGIN
IF NOT EXISTS(SELECT 1 FROM cyber_rules WHERE test_id='seed' AND pattern={q(new)} AND enabled AND action='block') THEN RAISE EXCEPTION 'seed not upgraded'; END IF;
IF NOT EXISTS(SELECT 1 FROM cyber_rules WHERE test_id='custom' AND pattern='operator-custom-pattern') THEN RAISE EXCEPTION 'custom pattern overwritten'; END IF;
IF NOT EXISTS(SELECT 1 FROM cyber_rules WHERE test_id='other' AND pattern={q(old)}) THEN RAISE EXCEPTION 'unrelated rule modified'; END IF;
IF NOT EXISTS(SELECT 1 FROM cyber_rules WHERE test_id='disabled' AND pattern={q(new)} AND NOT enabled AND action='review') THEN RAISE EXCEPTION 'enablement/action changed'; END IF;
END $check$;
ROLLBACK;
"""
result = subprocess.run(['docker', 'compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.test.yml',
    'exec', '-T', 'postgres', 'sh', '-c', 'exec psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-risk}" -d "${POSTGRES_DB:-risk}"'],
    input=transaction, text=True, capture_output=True, timeout=30, cwd=root)
assert result.returncode == 0, result.stderr
status, data = call('/api/admin/v1/cyber-rules')
assert status == 200, data
seed = next(r for r in data['items'] if r['code'] == 'CYBER_CREDENTIAL_ACCESS_REVIEW')
assert seed['pattern'] == new, 'startup did not apply migration 010'

command = 'netstat -ano -p tcp | Select-String ":8088 |:8200 |:9200 |:9201 |:9400 "'
guidance = 'Documentation, conceptual examples, model selection, and read-only guidance do not require an API key.'

def tool_payload(cmd):
    return {'input': [{'role':'user','content':'Diagnose ordinary server startup'},
                      {'type':'function_call','name':'exec_command','arguments':json.dumps({'cmd':cmd,'workdir':'C:/workspace/demo'})}],
            'text': {'format': {'type':'text'}}}

def incorrect_model(text, failure=False):
    return {'input': 'accuracy-mechanism-fixture local-observation-mechanism\n' + text +
            ('\naccuracy-grounding-unavailable' if failure else '')}

cases = [
    ('netstat', {'input':command}, 200, 2),
    ('tool-netstat', tool_payload(command), 200, 2),
    ('ss', {'input':'ss -lntp'}, 200, 2),
    ('passive-text', {'input':'Codex CLI 读取本地端口运行测试'}, 200, 2),
    ('guidance', {'input':guidance}, 200, 2),
    ('read-docs', {'input':'Read the documentation about an API key'}, 200, 2),
    ('probe', {'input':command + '\nActively probe local ports for tests'}, 555, 0),
    ('scan', tool_payload(command + '; nmap synthetic.invalid'), 555, 0),
    ('creds', {'input':guidance + '\nRead only the API key'}, 555, 0),
    ('model-observation', incorrect_model(command), 200, 3),
    ('model-guidance', incorrect_model(guidance), 200, 3),
    ('model-failure', incorrect_model(command, True), 555, 3),
]
for name, payload, expected, calls in cases:
    request_id = 'e2e-observation-' + name
    payload['model'] = 'normal'
    status, data = call('/gateway/mock-main/v1/responses', payload, ROUTE, request_id)
    assert status == expected, (name, status, data)
    meta = trace_for(request_id)
    assert meta['gateway_build']['audit_engine'] == 'cyber-deny-qwen27b.v12', meta
    assert meta['audit_http_calls'] == calls and meta['upstream_started'] == (expected == 200), (name, meta)
    if calls == 0:
        assert meta['audit_source'] == 'rule', meta
    if expected == 200:
        assert meta['audit_completed'] is True, meta
    if name in {'model-observation','model-guidance'}:
        assert any(r.get('status') == 'grounding_corrected' for r in meta['audit_semantic_reviews']), meta
    if name == 'model-failure':
        assert meta['audit_error_class'] == 'cyber_operation_unresolved' and meta['audit_completed'] is False, meta

request_id = 'e2e-observation-stream'
payload = dict(tool_payload(command), model='stream-normal', stream=True)
status, text = call('/gateway/mock-main/v1/responses', payload, ROUTE, request_id, stream=True)
assert status == 200 and '[DONE]' in text and 'event: error' not in text, text
meta = trace_for(request_id)
assert meta['audit_http_calls'] == 2 and meta['upstream_started'] is True, meta
print('Local observation: actual migration/custom-rule preservation + 13 HTTP/SSE normal/deny/failure cases passed')
