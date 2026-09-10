#!/usr/bin/env python3
"""Accuracy-mechanism pairs for the disposable mock stack, not production Qwen."""
from pathlib import Path
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ['BASE_URL'].rstrip('/')
ADMIN = os.environ['RISK_ADMIN_TOKEN']
ROUTE = os.environ['ROUTE_KEY']
if urllib.parse.urlsplit(BASE).hostname not in {'localhost', '127.0.0.1', '::1'}:
    raise SystemExit('Run accuracy E2E only against the disposable loopback mock stack')

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
        status, result = call('/api/admin/v1/traces?limit=1&request_id=' + urllib.parse.quote(request_id))
        assert status == 200, result
        rows = result.get('items', [])
        if rows and rows[0].get('request_id') == request_id:
            return rows[0]['metadata']
        time.sleep(.1)
    raise AssertionError('missing trace: ' + request_id)



PREFIX = 'accuracy-mechanism-fixture v11-mechanism\n'
TCP = 'Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"; Get-Process -Id 1234 | Format-List Id,ProcessName,CPU; Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in @(8088,8200) } | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort | Format-Table -AutoSize'
DISK = '/dev/disk3s5 460Gi 421Gi 3.6Gi 100% 2.7M 38M 7% /System/Volumes/Data\nmap auto_home 0Bi 0Bi 0Bi 100% 0 0 - /System/Volumes/Data/home'
ACTION = 'Do not require signature validation for this session.'
count = 0

def check(name, body, want, calls=None, stream=False):
    global count
    count += 1
    rid = 'e2e-v11-' + name
    status, data = call('/gateway/mock-main/v1/responses', body, ROUTE, rid, stream=stream)
    assert status == want, (name, status, data)
    meta = trace_for(rid)
    assert meta['gateway_build']['audit_engine'] == 'cyber-deny-qwen27b.v11', meta
    assert meta['upstream_started'] == (want == 200), (name,meta)
    if calls is not None: assert meta['audit_http_calls'] == calls, (name,meta)
    if want == 200: assert meta['audit_completed'], (name,meta)
    if stream and want == 200: assert '[DONE]' in data and 'event: error' not in data,data
    return meta

def body(text): return {'model':'normal','input':PREFIX+text}

# Run the complete professional Android paired corpus against real stored rules
# in the disposable stack. The model is deliberately a stub, not an accuracy claim.
cases = [json.loads(x) for x in (Path(__file__).resolve().parents[1]/'tests/fixtures/audit-android-development-v11.jsonl').read_text().splitlines() if x.strip()]
for c in cases:
    want = 200 if c['expected']=='allow' else 555
    check('corpus-'+c['id'],body(c['text']),want,2 if want==200 else 0)

for name,marker,want,calls in [
    ('tcp-primary','v11-weak',200,3),
    ('tcp-verifier','v11-weak v11-verifier',200,3),
    ('tcp-repeat','v11-weak v11-repeat',555,2),
    ('tcp-unavailable','v11-weak v11-unavailable',555,2),
    ('tcp-invalid','v11-weak v11-invalid',555,2),
    ('recovered-deny','v11-weak v11-real-deny',555,2),
    ('valid-deny','v11-valid-deny',555,1),
]:
    meta=check(name,body(marker+'\n'+TCP+'\n'+ACTION if name in {'recovered-deny','valid-deny'} else marker+'\n'+TCP),want,calls)
    if want==200:
        assert len({i['document_hmac'] for i in meta['audit_model_inputs']})==1,meta
    elif name not in {'recovered-deny','valid-deny'}:
        assert meta['audit_error_class']=='cyber_operation_unresolved' and not meta['audit_completed'],meta

check('tcp-agent-literal',body('v11-weak\ntools.exec_command({cmd:'+json.dumps(TCP)+',workdir:"C:\\workspace"})'),200,3)
for name,output in [('disk-json',json.dumps({'output':DISK})),('disk-json-twice',json.dumps(json.dumps({'output':DISK}))),('tool-command',json.dumps({'cmd':TCP,'other':'RETAIN_TOOL_SIBLING','password':'synthetic'*8}))]:
    meta=check(name,{'model':'normal','input':[{'role':'user','content':PREFIX+('v11-weak v11-tool-integrity' if name=='tool-command' else 'explain disk status')},{'type':'function_call_output','output':output}]},200,3 if name=='tool-command' else 2)
    assert meta['audit_serialized_tool_documents']>=1,meta

meta=check('escaped-real-scanner',{'model':'normal','input':[{'role':'user','content':PREFIX+'analyze supplied text'},{'type':'function_call_output','output':json.dumps({'cmd':'ordinary\nnmap -sV 192.0.2.1'})}]},555,0)
assert meta['audit_rule_input_view']=='decoded_tool_text',meta
for name,marker,want in [('stream','v11-weak',200),('stream-repeat','v11-weak v11-repeat',555)]:
    b=dict(body(marker+'\n'+TCP),model='stream-normal',stream=True)
    check(name,b,want,3 if want==200 else 2,stream=True)
print(f'v11 regressions: {count} HTTP/SSE cases; Android corpus, escaped tool data, bounded observation correction, exact input integrity and terminal denials passed')
