#!/usr/bin/env python3
"""Real gateway unified model egress PII, including RAG and MCP Sampling; synthetic data only.

The optional Analyzer fixture checks the official HTTP contract, not Presidio NLP accuracy.
"""
import argparse
import concurrent.futures
import http.server
import json
from pathlib import Path
import threading
import unittest

import gateway_faults
import rag_llm_profile
import sampling_profile
import security_content_profile
from rag_llm_profile import RagLlmFixture

SENSITIVE = '张三联系alice@example.com，电话13800138000，地址192.0.2.1'


class Analyzer(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        with self.server.lock:
            self.server.requests.append(request)
        if request['text'] != 'gateway PII readiness check':
            self.server.started.set()
            if self.server.hold:
                self.server.release.wait(5)
        mode = self.server.mode
        if mode == 'disconnect':
            self.close_connection = True
            return
        text = request['text']
        needle = 'alice@example.com'
        results = []
        if needle in text:
            start = text.index(needle)
            results = [{'entity_type': 'EMAIL_ADDRESS', 'start': start, 'end': start + len(needle), 'score': .95}]
        if mode == 'bad-index':
            results = [{'entity_type': 'EMAIL_ADDRESS', 'start': 0, 'end': 999999, 'score': .9}]
        body = json.dumps(results).encode()
        if mode == 'invalid':
            body = b'not-json-sensitive-upstream-error'
        if mode == 'oversize':
            body = b'x' * 4096
        try:
            self.send_response(503 if mode == 'status' else 200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class Pii(RagLlmFixture):
    def setUp(self):
        super().setUp()
        self.audit = self.directory / 'audit'
        self.audit.mkdir(mode=0o700)
        self.config['config']['securityAudit'] = {'directory': str(self.audit)}
        self.pii = {'enabled': True, 'mode': 'enforce', 'backend': 'native'}
        self.system['security']['pii'] = self.pii

    def sidecar(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Analyzer)
        server.daemon_threads = True
        server.requests, server.mode, server.hold = [], 'ok', False
        server.lock, server.started, server.release = threading.Lock(), threading.Event(), threading.Event()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def close():
            server.release.set()
            server.shutdown()
            server.server_close()
            thread.join(5)
        self.addCleanup(close)
        self.pii.update(backend='presidio', presidioEndpoint=f'http://127.0.0.1:{server.server_port}',
                        policy={'entities': {'EMAIL_ADDRESS': {'action': 'replace', 'value': '[EMAIL_ADDRESS]'}}},
                        timeoutMs=1000, maxResponseBytes=1024)
        return server

    def begin_pii(self):
        self.start()
        status, body = self.ingest(SENSITIVE)
        self.assertEqual(status, 201, body)

    def masked(self):
        return '张三联系[EMAIL_ADDRESS]，电话[PHONE_NUMBER]，地址[IP_ADDRESS]'

    def assert_model_denied(self, reply):
        status, headers, body = reply
        self.assertNotEqual(status, 200, body)
        self.assertNotIn('x-aisp-context-id', headers)
        self.assertNotIn(b'alice@example.com', body)
        self.assertFalse(self.model.requests)

    def test_rag_returns_authorized_source_and_model_receives_masked_payload(self):
        self.begin_pii()
        context, result = self.context()
        text = ''.join(chunk['content'] for chunk in result['chunks'])
        self.assertEqual(text, SENSITIVE)
        self.assertTrue(all(chunk['sourceOrigin']['kind'] == 'lifecycle' for chunk in result['chunks']))
        self.assertEqual(self.generate(context, result)[0], 200)
        self.assertEqual(self.model.requests[-1][2]['messages'][-1]['content'], self.masked())
        audit = ''.join(p.read_text() for p in self.audit.glob('segment-*.jsonl'))
        self.assertIn('piiInspection', audit)
        self.assertNotIn('alice@example.com', audit + (self.directory / 'gateway.log').read_text())
        self.evidence[self.id()] = {'actualModelCalls': 1, 'maskedModelInput': True, 'provenanceRetained': True}

    def test_disabled_preserves_compatible_content_without_sidecar(self):
        self.pii.update(enabled=False, backend='presidio', presidioEndpoint='invalid')
        self.begin_pii()
        context, result = self.context()
        self.assertEqual(result['chunks'][0]['content'], SENSITIVE)
        self.assertEqual(self.generate(context, result)[0], 200)
        self.assertEqual(self.model.requests[-1][2]['messages'][-1]['content'], SENSITIVE)

    def observe(self, mode):
        self.pii.update(mode=mode, policy={'entities': {'EMAIL_ADDRESS': {'action': 'block'}}})
        self.begin_pii()
        context, result = self.context()
        self.assertEqual(result['chunks'][0]['content'], SENSITIVE)
        self.assertEqual(self.generate(context, result)[0], 200)
        self.assertEqual(self.model.requests[-1][2]['messages'][-1]['content'], SENSITIVE)
        audit = ''.join(p.read_text() for p in self.audit.glob('segment-*.jsonl'))
        self.assertIn('EMAIL_ADDRESS', audit)
        self.assertNotIn('alice@example.com', audit)

    def test_shadow_does_not_modify_or_block(self):
        self.observe('shadow')

    def test_audit_does_not_modify_or_block(self):
        self.observe('audit')

    def test_block_keeps_authorized_rag_return_but_prevents_model_dispatch(self):
        self.pii['policy'] = {'entities': {'EMAIL_ADDRESS': {'action': 'block'}}}
        self.begin_pii()
        reply = self.generate(*self.context())
        self.assert_model_denied(reply)
        self.assertEqual(reply[0], 403)

    def test_authorization_denials_never_invoke_detector(self):
        server = self.sidecar()
        self.deny('modelInvoke')
        self.begin_pii()
        before = len(server.requests)
        for token in (None, self.gateway.token(tenant='tenant-b'), True):
            self.assert_model_denied(self.generate(*self.context(), token=token))
        self.assertEqual(len(server.requests), before)

    def test_presidio_wire_offsets_preserve_chinese_and_rewrite_model_input(self):
        server = self.sidecar()
        self.begin_pii()
        context, result = self.context()
        self.assertEqual(result['chunks'][0]['content'], SENSITIVE)
        self.assertEqual(self.generate(context, result)[0], 200)
        self.assertNotIn('alice@example.com', json.dumps(self.model.requests))
        self.assertEqual(server.requests[-1]['entities'], ['EMAIL_ADDRESS'])
        self.assertFalse(server.requests[-1]['return_decision_process'])

    def test_presidio_errors_fail_closed_without_raw_error_echo(self):
        server = self.sidecar()
        self.begin_pii()
        for mode in ('status', 'invalid', 'bad-index', 'oversize', 'disconnect'):
            with self.subTest(mode=mode):
                server.mode = mode
                reply = self.generate(*self.context())
                self.assert_model_denied(reply)
                self.assertNotIn(b'sensitive-upstream-error', reply[2])

    def test_presidio_timeout_is_not_unchecked_passthrough(self):
        server = self.sidecar()
        self.pii['timeoutMs'] = 100
        self.begin_pii()
        server.hold = True
        self.assert_model_denied(self.generate(*self.context()))

    def test_presidio_unavailable_at_startup_is_rejected(self):
        server = self.sidecar()
        server.mode = 'status'
        with self.assertRaises(RuntimeError):
            self.start()
        self.assertFalse(self.model.requests)

    def test_failed_hot_candidate_preserves_the_previous_enforce_policy(self):
        self.pii['policy'] = {'entities': {'EMAIL_ADDRESS': {'action': 'block'}}}
        self.begin_pii()
        server = self.sidecar()
        server.mode = 'status'
        self.reload(successful=False)
        self.assertTrue(server.requests)
        self.assert_model_denied(self.generate(*self.context()))
        server.mode = 'ok'
        self.reload()
        reply = self.generate(*self.context())
        self.assertEqual(reply[0], 200, reply)
        self.assertNotIn('alice@example.com', self.model.requests[-1][2]['messages'][-1]['content'])

    def test_dependency_egress_rejection_precedes_any_analyzer_request(self):
        server = self.sidecar()
        target = f'127.0.0.1:{self.backend.server_port}'
        self.system['security']['dependencyEgress'] = {
            'requireTls': False, 'destinations': {'qdrant': [target], 'embedding': [target]}}
        with self.assertRaises(RuntimeError):
            self.start()
        self.assertEqual(server.requests, [])

    def test_business_metadata_named_security_audit_is_not_a_policy(self):
        target = f'127.0.0.1:{self.backend.server_port}'
        self.config['config']['dependencyEgress'] = {
            'requireTls': False, 'destinations': {'qdrant': [target], 'embedding': [target]}}
        metadata = {'securityAudit': {'businessLabel': 'ordinary-metadata'}}
        self.system['llm']['models'][0]['overrides'] = {'metadata': metadata}
        self.begin_pii()
        reply = self.generate(*self.context())
        self.assertEqual(reply[0], 200, reply)
        self.assertEqual(self.model.requests[-1][2]['metadata'], metadata)
        self.assertEqual(self.model.requests[-1][2]['messages'][-1]['content'], self.masked())

    def test_global_dependency_denial_preserves_previous_policy_on_reload(self):
        self.pii['policy'] = {'entities': {'EMAIL_ADDRESS': {'action': 'block'}}}
        target = f'127.0.0.1:{self.backend.server_port}'
        self.config['config']['dependencyEgress'] = {
            'requireTls': False, 'destinations': {'qdrant': [target], 'embedding': [target]}}
        self.begin_pii()
        self.system['security']['remotePdp'] = {'endpoint': 'https://unapproved.invalid/pdp'}
        self.system['security']['dynamicAuthorization'] = {'policyVersion': 'rejected-candidate'}
        self.reload(successful=False)
        reply = self.generate(*self.context())
        self.assertEqual(reply[0], 403)
        self.assert_model_denied(reply)

    def test_changed_policy_builds_new_engine_and_invalid_candidate_preserves_it(self):
        self.pii['policy'] = {'entities': {'EMAIL_ADDRESS': {'action': 'block'}}}
        self.begin_pii()
        old_context, old_result = self.context()
        self.assert_model_denied(self.generate(old_context, old_result))
        self.pii['policy']['entities']['EMAIL_ADDRESS'] = {'action': 'replace', 'value': '[EMAIL_ADDRESS]'}
        self.reload()
        self.assert_model_denied(self.generate(old_context, old_result))
        context, result = self.context()
        reply = self.generate(context, result)
        self.assertEqual(reply[0], 200, reply)
        self.assertNotIn('alice@example.com', self.model.requests[-1][2]['messages'][-1]['content'])
        self.pii['customRules'] = {'EMPLOYEE_ID': '('}
        self.pii['policy']['entities']['EMPLOYEE_ID'] = {'action': 'block'}
        self.reload(successful=False)
        reply = self.generate(context, result)
        self.assertEqual(reply[0], 200, reply)
        self.assertEqual(len(self.model.requests), 2)
        self.assertNotIn('alice@example.com', self.model.requests[-1][2]['messages'][-1]['content'])

    def test_required_content_audit_failure_prevents_model_dispatch(self):
        server = self.sidecar()
        self.system['security']['requiredAudit'] = {'actionTypes': ['modelInvoke']}
        self.begin_pii()
        server.hold = True
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            reply = pool.submit(self.generate, *self.context())
            self.assertTrue(server.started.wait(3))
            self.audit.rename(self.audit.with_suffix('.unavailable'))
            server.release.set()
            result = reply.result(5)
        self.assert_model_denied(result)
        self.assertNotEqual(result[0], 200)

    def test_configuration_update_cancels_inflight_detector_and_invalidates_context(self):
        server = self.sidecar()
        self.begin_pii()
        context, result = self.context()
        server.started.clear()
        server.hold = True
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.generate, context, result)
            self.assertTrue(server.started.wait(3))
            self.pii['enabled'] = False
            self.reload()
            server.release.set()
            self.assert_model_denied(pending.result(5))
        self.assertNotEqual(self.generate(context, result)[0], 200)
        _, result = self.context()
        self.assertEqual(result['chunks'][0]['content'], SENSITIVE)

    def test_direct_model_checks_history_system_and_tool_results_with_json_arguments(self):
        self.system['security'].pop('crossComponent', None)
        self.start()
        body = {'model': 'local', 'messages': [
            {'role': 'system', 'content': 'alice@example.com'},
            {'role': 'assistant', 'tool_calls': [{'id': 'c', 'type': 'function',
                'function': {'name': 'lookup', 'arguments': '{"email":"alice@example.com"}'}}]},
            {'role': 'tool', 'tool_call_id': 'c', 'content': 'alice@example.com'},
            {'role': 'user', 'content': SENSITIVE}]}
        reply = self.call(self.gateway.model_port, '/v1/chat/completions', body)
        self.assertEqual(reply[0], 200, reply)
        sent = self.model.requests[-1][2]
        self.assertNotIn('alice@example.com', json.dumps(sent))
        self.assertEqual(sent['messages'][0]['role'], 'system')
        self.assertEqual(sent['messages'][2]['tool_call_id'], 'c')
        self.assertEqual(json.loads(sent['messages'][1]['tool_calls'][0]['function']['arguments'])['email'], '[EMAIL_ADDRESS]')

    def test_supported_formats_send_only_business_text_to_analyzer(self):
        server = self.sidecar()
        self.system['security'].pop('crossComponent', None)
        self.model.RequestHandlerClass = security_content_profile.Model
        self.model.mode = 'safe'
        self.start()
        counts = {}
        for path, fields in [
            ('/v1/chat/completions', {'messages': [{'role': 'user', 'content': SENSITIVE}]}),
            ('/v1/messages', {'max_tokens': 100,
                             'messages': [{'role': 'user', 'content': [{'type': 'text', 'text': SENSITIVE}]}]}),
            ('/v1/responses', {'input': [{'type': 'message', 'role': 'user',
                                       'content': [{'type': 'input_text', 'text': SENSITIVE}]}]}),
        ]:
            with self.subTest(path=path):
                before = len(server.requests)
                body = dict(model='local', stream=False, **fields)
                reply = self.call(self.gateway.model_port, path, body)
                self.assertEqual(reply[0], 200, reply)
                texts = [r['text'] for r in server.requests[before:]]
                self.assertEqual(texts, [SENSITIVE])
                self.assertNotIn('alice@example.com', json.dumps(self.model.requests[-1][1]))
                counts[path] = len(texts)
        self.assertEqual(len(self.model.requests), 3)
        self.evidence[self.id()] = {'detectorCallsPerRequest': counts, 'actualModelCalls': 3,
                                   'readinessExcluded': True, 'modelEmailMasked': True}

    def test_business_fields_and_unknown_roles_cannot_bypass_pii_as_controls(self):
        self.system['security'].pop('crossComponent', None)
        self.start()
        for extra, role in [
            ({'metadata': {'model': 'alice@example.com', 'role': 'user', 'stream': False}}, 'user'),
            ({'user': 'alice@example.com'}, 'user'),
            ({'stop': ['alice@example.com']}, 'user'),
            ({'tools': [{'type': 'function', 'function': {'name': 'lookup', 'description': 'alice@example.com'}}]}, 'user'),
            ({'tools': [{'type': 'function', 'function': {'name': 'lookup', 'parameters': {
                'type': 'object', 'properties': {'email': {'type': 'string', 'default': 'alice@example.com'}}}}}]}, 'user'),
            ({'vendor_extension': {'email': 'alice@example.com'}}, 'user'),
            ({'stream_options': {'include_usage': True, 'extension': 'alice@example.com'}}, 'user'),
            ({}, 'alice@example.com'),
        ]:
            with self.subTest(extra=extra, role=role):
                body = {'model': 'local', 'messages': [{'role': role, 'content': 'safe'}], **extra}
                reply = self.call(self.gateway.model_port, '/v1/chat/completions', body)
                self.assert_model_denied(reply)
        audit = ''.join(p.read_text() for p in self.audit.glob('segment-*.jsonl'))
        events = [json.loads(line)['event'] for line in audit.splitlines()]
        inspections = [event for event in events if event.get('kind') == 'piiInspection']
        self.assertEqual(len(inspections), 8)
        self.assertTrue(all(e['details']['entities'].get('EMAIL_ADDRESS', 0) > 0 for e in inspections))
        self.assertNotIn('alice@example.com', audit)

    def test_request_byte_limits_still_include_excluded_controls(self):
        self.system['security'].pop('crossComponent', None)
        self.pii['maxTextBytes'] = 64
        self.start()
        body = {'model': 'local', 'stream': False, 'messages': [{'role': 'user', 'content': 'x'}]}
        self.assert_model_denied(self.call(self.gateway.model_port, '/v1/chat/completions', body))
        audit = ''.join(p.read_text() for p in self.audit.glob('segment-*.jsonl'))
        self.assertIn('InputLimit', audit)
        self.pii.update(maxTextBytes=4096, maxOutputBytes=64)
        self.reload()
        self.assert_model_denied(self.call(self.gateway.model_port, '/v1/chat/completions', body))
        audit = ''.join(p.read_text() for p in self.audit.glob('segment-*.jsonl'))
        self.assertIn('OutputLimit', audit)

    def test_enrichment_is_checked_after_it_is_added_to_the_request(self):
        self.config.setdefault('policies', []).append({
            'name': {'name': 'pii-enrichment', 'namespace': 'internal'},
            'target': {'route': {'name': f"ai-system:{self.system['name']}:llm:request", 'namespace': 'internal'}},
            'policy': {'ai': {'prompts': {'prepend': [{'role': 'system', 'content': 'alice@example.com'}]}}}})
        self.begin_pii()
        self.assertEqual(self.generate(*self.context())[0], 200)
        self.assertEqual(self.model.requests[-1][2]['messages'][0]['content'], '[EMAIL_ADDRESS]')

    def test_each_retry_sends_only_the_checked_payload(self):
        class RetryModel(rag_llm_profile.Model):
            def do_POST(handler):
                if not handler.server.requests:
                    body = json.loads(handler.rfile.read(int(handler.headers['Content-Length'])))
                    with handler.server.condition:
                        handler.server.requests.append((handler.path, dict(handler.headers), body))
                    handler.send_response(503)
                    handler.send_header('Content-Length', '0')
                    handler.end_headers()
                    return
                super().do_POST()
        self.model.RequestHandlerClass = RetryModel
        self.config.setdefault('policies', []).append({
            'name': {'name': 'pii-retry', 'namespace': 'internal'},
            'target': {'route': {'name': f"ai-system:{self.system['name']}:llm:request", 'namespace': 'internal'}},
            'policy': {'retry': {'attempts': 2, 'codes': [503]}}})
        self.begin_pii()
        reply = self.generate(*self.context())
        self.assertEqual(reply[0], 200, reply)
        self.assertEqual(len(self.model.requests), 2)
        self.assertTrue(all(r[2]['messages'][-1]['content'] == self.masked() for r in self.model.requests))

    def test_opaque_content_and_sensitive_structural_fields_are_refused(self):
        self.begin_pii()
        context, _ = self.context()
        for body in [
            {'model': 'local', 'messages': [{'role': 'user', 'content': [{'type': 'image_url', 'image_url': {'url': 'https://example.invalid'}}]}]},
            {'model': 'local', 'messages': [{'role': 'user', 'content': 'safe'}], 'metadata': {'email': 'alice@example.com'}},
        ]:
            self.assert_model_denied(self.call(self.gateway.model_port, '/v1/chat/completions', body, context))

    def test_request_wide_finding_limit_applies_across_messages(self):
        self.pii.update(maxFindings=1, policy={'entities': {'EMAIL_ADDRESS': {'action': 'replace', 'value': '[EMAIL_ADDRESS]'}}})
        self.begin_pii()
        context, _ = self.context()
        body = {'model': 'local', 'messages': [{'role': 'user', 'content': 'alice@example.com'}, {'role': 'user', 'content': 'bob@example.com'}]}
        self.assert_model_denied(self.call(self.gateway.model_port, '/v1/chat/completions', body, context))

    def test_shadow_detector_failure_is_observable_and_preserves_actual_payload(self):
        server = self.sidecar()
        self.pii['mode'] = 'shadow'
        self.begin_pii()
        server.mode = 'status'
        self.assertEqual(self.generate(*self.context())[0], 200)
        self.assertEqual(self.model.requests[-1][2]['messages'][-1]['content'], SENSITIVE)
        audit = ''.join(p.read_text() for p in self.audit.glob('segment-*.jsonl'))
        self.assertIn('UpstreamStatus', audit)

    def test_legacy_rag_configuration_is_rejected_instead_of_ignored(self):
        self.system['rag']['pii'] = self.pii.copy()
        self.system['security'].pop('pii')
        with self.assertRaises(RuntimeError):
            self.start()

    def test_concurrent_calls_do_not_share_mutable_request_content(self):
        self.begin_pii()
        context, result = self.context()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            replies = list(pool.map(lambda _: self.generate(context, result), range(4)))
        self.assertTrue(all(reply[0] == 200 for reply in replies), replies)
        self.assertEqual(len(self.model.requests), 4)
        self.assertTrue(all(req[2]['messages'][-1]['content'] == self.masked() for req in self.model.requests))


class SamplingPii(sampling_profile.Sampling):
    def test_pii_sampling_uses_the_same_model_egress(self):
        self.config['aiSystems'][0]['security']['pii'] = {'backend': 'native'}
        self.server.sampling_changes = {'messages': [{'role': 'user', 'content': {'type': 'text', 'text': SENSITIVE}}]}
        self.start()
        reply = self.result(self.task())
        self.assertEqual(reply[0], 200, reply)
        self.assertEqual(self.server.calls['chat'], 1)
        self.assertEqual(self.server.model_requests[0]['messages'][0]['content'], '张三联系[EMAIL_ADDRESS]，电话[PHONE_NUMBER]，地址[IP_ADDRESS]')

    def test_pii_sampling_block_produces_no_model_or_reply_side_effect(self):
        self.config['aiSystems'][0]['security']['pii'] = {'backend': 'native', 'policy': {'entities': {'EMAIL_ADDRESS': {'action': 'block'}}}}
        self.server.sampling_changes = {'messages': [{'role': 'user', 'content': {'type': 'text', 'text': SENSITIVE}}]}
        self.start()
        self.assert_denied(self.result(self.task()))
        self.assertEqual(self.server.calls['chat'], 0)
        self.assertEqual(self.server.answers, [])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    # The base fixture reads this module's binary location.
    import rag_profile
    rag_profile.BINARY = args.binary
    sampling_profile.BINARY = args.binary
    if args.report:
        gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Pii)
    suite.addTests(SamplingPii(name) for name in ('test_pii_sampling_uses_the_same_model_egress', 'test_pii_sampling_block_produces_no_model_or_reply_side_effect'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if args.report:
        args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
            'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors],
            'skipped': [str(t) for t, _ in result.skipped], 'evidence': Pii.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
