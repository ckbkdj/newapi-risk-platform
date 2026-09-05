#!/usr/bin/env python3
"""CI-only mutations of a disposable mock stack; NOT a production diagnostic."""
import json
import os
import urllib.request
import urllib.error

base = os.environ['BASE_URL']
token = os.environ['RISK_ADMIN_TOKEN']
def post(path, payload):
    request=urllib.request.Request(base+path, data=json.dumps(payload).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
    with urllib.request.urlopen(request,timeout=30) as response:return json.load(response)
def profile(model,extra=None,id=0):
    return post('/api/admin/v1/audit-profiles',{'id':id,'name':'E2E '+model,'model':model,'endpoint':'http://mock-provider:18081/audit/v1','api_key':'','system_prompt':'','timeout_ms':5000,'block_threshold':.9,'retry_count':0,'fallback_profile_ids':[],'enabled':True,'fail_closed':True,'is_default':False,'extra':extra or {}})
a=profile('fusion-allow-a')['id']
b=profile('fusion-allow-b')['id']
deny=profile('fusion-deny')['id']
broken=profile('fusion-broken')['id']
root=0
for name,panel,arbiter,decision,status,error in [
    ('consensus',[a,b],None,'allow','consensus',''),
    ('disagreement',[a,deny],None,'block','unresolved',''),
    ('adjudication',[a,deny],b,'allow','adjudicated',''),
    ('incomplete',[a,broken],None,'block','error','fusion_incomplete'),
]:
    extra={'_risk_policy_mode':'internal_engineering','_risk_fusion_profile_ids':panel}
    if arbiter:extra['_risk_fusion_adjudicator_profile_id']=arbiter
    root=profile('fusion-primary',extra,root)['id']
    result=post('/api/admin/v1/audit/dry-run',{'profile_id':root,'text':'model-audit-block'})['result']
    assert result['decision']==decision,(name,result)
    assert result.get('error_class','')==error,(name,result)
    assert result['audit_semantic_reviews'][0]['fusion']['status']==status,(name,result)
    assert result['gateway_build']['audit_engine']=='output-resilience-fusion.v1'
print('Fusion consensus, disagreement, adjudication and invalid vote E2E passed')
