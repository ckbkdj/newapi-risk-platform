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
        with OPENER.open(req, timeout=180) as response:
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



# Mutate only the disposable localhost mock stack; never a production model.
status, profile = call('/api/admin/v1/audit-profiles', {
    'id':0,'name':'v14 full request fixture','model':'qwen-v14-plan',
    'endpoint':'http://mock-provider:18081/audit/v1','api_key':'','system_prompt':'',
    'timeout_ms':5000,'block_threshold':.9,'retry_count':0,'fallback_profile_ids':[],
    'enabled':True,'fail_closed':True,'is_default':False,'extra':{}})
assert status==200, profile
status,route = call('/api/admin/v1/routes', {
    'id':0,'slug':'v14-full','name':'v14 full request fixture','base_url':'http://mock-provider:18081',
    'provider':'generic','auth_mode':'none','secret_header':'','upstream_secret':'',
    'inbound_key':ROUTE,'audit_profile_id':profile['id'],'enabled':True,'fail_closed':True,
    'request_timeout_ms':10000,'max_concurrency':4,'rate_limit_rps':100,'rate_limit_burst':100})
assert status==200, route
count=0
for ending,want in [('V14_TAIL_OK',200),('synthetic prohibited operation',555),('V14_TAIL_INVALID',555)]:
    for stream in [False,True]:
        count+=1
        rid='e2e-v14-full-'+str(count)
        text='x'*620000+'\n'+ending
        body={'model':'stream-normal' if stream else 'normal','stream':stream}
        endpoint='chat/completions' if stream else 'responses'
        if stream: body['messages']=[{'role':'user','content':text}]
        else: body['input']=text
        status,data=call('/gateway/v14-full/v1/'+endpoint,body,ROUTE,rid,stream)
        assert status==want,(rid,status,data)
        meta=trace_for(rid)
        assert meta['gateway_build']['audit_engine']=='cyber-deny-qwen27b.v14',meta
        assert meta['audit_chunk_count']>256 and meta['audit_http_calls']>256,meta
        assert meta['upstream_started']==(want==200),meta
        assert meta.get('audit_capacity_text_limit_bytes',0)==0,meta
        if want==200:
            assert meta['audit_completed'] and meta['audit_chunks_completed']==meta['audit_chunk_count'],meta
            assert meta['audit_http_calls']>=2*meta['audit_chunk_count'],meta
            if stream: assert '[DONE]' in data and 'event: error' not in data,data
        elif ending=='V14_TAIL_INVALID':
            assert not meta['audit_completed'] and meta.get('audit_error_class'),meta
        else:
            assert meta['audit_effective_decision']=='block' and not meta.get('audit_error_class'),meta
print('v14 full requests: 6 HTTP/SSE >256-chunk context-recovery, complete-audit, invalid-tail and terminal-tail-veto cases passed')
