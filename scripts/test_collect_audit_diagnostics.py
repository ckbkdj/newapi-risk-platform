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
    def test_coverage_diagnostics_are_allowlisted(self):
        secret = 'SECRET_SENTINEL_coverage'
        result = diag.trace_view({'audit_coverage_status':'incomplete', 'audit_coverage_issues':['unsupported_input_content', secret, {'secret':secret}], 'error_class':'input_coverage', 'audit_semantic_review_status':'escalated'})
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result['audit_coverage_issues'], ['unsupported_input_content', 'other', 'other'])
        self.assertEqual(result['error_class'], 'input_coverage')
        self.assertEqual(result['audit_semantic_review_status'], 'escalated')
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

    def test_coverage_paths_and_grounding_are_shape_only(self):
        secret = "PRIVATE_SENTINEL"
        result = diag.trace_view({"audit_policy_mode":"cyber_deny", "audit_decision_finalized":True,
            "audit_coverage_details":[{"path":"$.input[3].content[1]", "type":"input_image", "role":"USER", "code":"unsupported_input_content"},
                                      {"path":"$."+secret,"type":secret,"role":secret,"code":secret}],
            "audit_semantic_reviews":[{"status":"grounding_corrected", "candidate_error":"non_operational_evidence", "reason":secret}]})
        self.assertNotIn(secret,json.dumps(result))
        self.assertEqual(result["audit_coverage_details"][0]["path"],"$.input[3].content[1]")
        self.assertNotIn("path",result["audit_coverage_details"][1])
        self.assertEqual(result["audit_semantic_reviews"][0]["status"],"grounding_corrected")
        self.assertEqual(result["audit_policy_mode"],"cyber_deny")

    def test_model_inputs_export_only_shape_and_keyed_fingerprints(self):
        secret = "SOURCE_AND_SECRET_SENTINEL"
        result = diag.trace_view({"audit_model_inputs_truncated": True, "audit_model_inputs":[
            {"call":1, "phase":"evidence_repair", "request_text_bytes":7656, "evidence_source_bytes":7656,
             "source_matches_request_text":True, "document_hmac":"a"*64, "request_text":secret, "endpoint":secret},
            {"phase":secret, "document_hmac":secret}, secret],
             "audit_semantic_reviews":[{"status":"evidence_repair_corrected", "candidate_error":"invalid_evidence"}]})
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result["audit_model_inputs"][0]["request_text_bytes"],7656)
        self.assertEqual(result["audit_model_inputs"][0]["document_hmac"],"a"*64)
        self.assertTrue(result["audit_model_inputs_truncated"])
        self.assertEqual(result["audit_semantic_reviews"][0]["status"],"evidence_repair_corrected")

    def test_csv_failure_diagnostics_do_not_export_driver_errors(self):
        secret = 'DRIVER_SECRET_SENTINEL'
        result = diag.trace_view({'audit_error_class':'audit_profile_lookup_failed',
            'audit_failure_stage':'profile', 'audit_requested_profile_id':1, 'audit_input_partial':True,
            'audit_stage_timings_ms':{'extraction':12,'profile':5000,secret:30},
            'driver_error':secret,'reason':secret,'retryable':True,'security_violation':False})
        self.assertNotIn(secret,json.dumps(result))
        self.assertEqual(result['audit_error_class'],'audit_profile_lookup_failed')
        self.assertEqual(result['audit_stage_timings_ms'],{'extraction':12,'profile':5000})
        self.assertFalse(result['security_violation'])

if __name__=='__main__':unittest.main()
