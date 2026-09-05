#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('diagnostics', Path(__file__).with_name('collect-audit-diagnostics.py'))
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)

class DiagnosticsPrivacyTests(unittest.TestCase):
    def test_no_credentials_or_raw_text_leave_trace_view(self):
        secret = 'SECRET_SENTINEL_abcdefghijklmnop'
        trace = {'model':secret,'endpoint':secret,'reason':secret,'evidence':secret,
                 'audit_reason':secret,'metadata':{'audit_response_preview':json.dumps({'decision':'allow','confidence':'high','evidence':secret,'reason':secret})},
                 'audit_attempts':[{'reason':secret,'model':secret,'error_class':secret}],
                 'audit_model_decision':secret,'gateway_build':{'commit':secret,'version':secret},
                 'fusion':{'votes':[{'profile_id':2,'outcome':{'decision':'allow','reason':secret}}]}}
        encoded=json.dumps(diag.trace_view(trace))
        self.assertNotIn(secret,encoded)
        self.assertIn('high',encoded)
        self.assertIn('other',encoded)
    def test_profile_extra_allowlist(self):
        secret='secret-key-in-endpoint'
        profile={'id':1,'endpoint':secret,'model':secret,'api_key':secret,'system_prompt':secret,'extra':{'Authorization':secret,'_risk_policy_mode':'internal_engineering','_risk_fusion_profile_ids':[2,3]}}
        result=diag.profile_view(profile,b'test-only-salt')
        self.assertNotIn(secret,json.dumps(result))
        self.assertEqual(result['extra']['_risk_fusion_profile_ids'],[2,3])
        self.assertEqual(result['endpoint_fingerprint'],result['model_fingerprint'])
    def test_legacy_evidence_and_bad_types(self):
        value=diag.output_shape(json.dumps({'decision':'block','confidence':True,'evidence':'[MANDATORY AUDIT OUTPUT]'}))
        self.assertTrue(value['legacy_instruction_evidence'])
        self.assertEqual(value['confidence_type'],'bool')
    def test_safe_url(self):
        for base in ('http://public.example','https://user:pw@example.com','https://example.com?token=abc'):
            with self.assertRaises(ValueError):diag.gateway_base(base)
        self.assertEqual(diag.gateway_base('http://127.0.0.1:8080/'),'http://127.0.0.1:8080')
    def test_depth_bounded(self):
        obj={'metadata':{'metadata':{'metadata':{'reason':'secret'}}}}
        self.assertNotIn('secret',json.dumps(diag.trace_view(obj)))

if __name__=='__main__':unittest.main()
