#!/usr/bin/env python3
"""Review regressions: real configuration admission and guarded HTTP delivery, no runtime hooks."""
import argparse
import copy
import http.client
import http.server
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

import gateway_faults

SECRET = 'REVIEW_SECRET'
BINARY = None


class Model(gateway_faults.Upstream):
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.requests.append((self.path, request))
        mode = self.server.mode
        text = 'safe answer' if mode == 'safe' else SECRET
        if self.path.endswith('/images/generations'):
            return self.reply(200, {'model': 'local', 'data': [{'url': 'https://example.test/result'}]})
        if request.get('stream'):
            events = []
            parts = (text[:7], text[7:])
            tool = mode in ('tool', 'tool-safe')
            if tool:
                arguments = self.arguments()
                split = arguments.index(SECRET) + 7 if SECRET in arguments else len(arguments) // 2
                parts = (arguments[:split], arguments[split:])
            for index, part in enumerate(parts):
                delta = {'content': part}
                if tool:
                    function = {'arguments': part}
                    if index == 0:
                        function['name'] = 'echo'
                    delta = {'tool_calls': [{'index': 0, 'function': function}]}
                    if index == 0:
                        delta['tool_calls'][0].update(id='call', type='function')
                events.append({'id': 'review', 'object': 'chat.completion.chunk', 'created': 1, 'model': 'local',
                               'choices': [{'index': 0, 'finish_reason': None, 'delta': delta}]})
            wire = ''.join('data: ' + json.dumps(event) + '\n\n' for event in events) + 'data: [DONE]\n\n'
            data = wire.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.endswith('/responses'):
            item = {'type': 'message', 'id': 'msg', 'role': 'assistant', 'status': 'completed',
                    'content': [{'type': 'output_text', 'text': text, 'annotations': []}]}
            if mode in ('tool', 'encoded', 'numeric'):
                item = {'type': 'function_call', 'id': 'fc', 'call_id': 'call', 'name': 'echo',
                        'arguments': self.arguments(), 'status': 'completed'}
            return self.reply(200, {'id': 'resp', 'status': 'completed', 'model': 'local', 'output': [item]})
        message = {'role': 'assistant', 'content': text}
        if mode in ('tool', 'encoded', 'numeric'):
            message = {'role': 'assistant', 'content': None, 'tool_calls': [
                {'id': 'call', 'type': 'function', 'function': {'name': 'echo', 'arguments': self.arguments()}}]}
        if mode == 'audio':
            message = {'role': 'assistant', 'content': None, 'audio': {'data': SECRET, 'id': 'audio'}}
        choices = [{'index': 0, 'finish_reason': 'tool_calls' if 'tool_calls' in message else 'stop', 'message': message}]
        if mode == 'multi':
            choices.insert(0, {'index': 1, 'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': 'safe answer'}})
        self.reply(200, {'id': 'review', 'object': 'chat.completion', 'created': 1, 'model': 'local', 'choices': choices})

    def arguments(self):
        if self.server.mode == 'tool-safe':
            return json.dumps({'value': 'safe tool result'})
        if self.server.mode == 'encoded':
            return r'{"value":"REVIEW_\u0053ECRET"}'
        if self.server.mode == 'numeric':
            return '{"value":7}'
        return json.dumps({'value': SECRET})


class SecurityContent(unittest.TestCase):
    evidence = {}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='security-content-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Model)
        self.server.daemon_threads = True
        self.server.requests = []
        self.server.mode = 'safe'
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        def close():
            self.server.shutdown()
            self.server.server_close()
            thread.join(5)
        self.addCleanup(close)
        self.gateways = []
        self.gateway, self.config = self.new_gateway()

    def new_gateway(self):
        directory = self.directory / str(len(self.gateways))
        directory.mkdir()
        gateway = gateway_faults.Gateway(BINARY, directory, self.server.server_port, llm_only=True)
        self.gateways.append(gateway)
        self.addCleanup(gateway.signer.close)
        self.addCleanup(gateway.stop)
        return gateway, json.loads(gateway.config.read_text())

    @staticmethod
    def wire(config, yaml=False):
        return '---\n' + '\n'.join(key + ': ' + json.dumps(value) for key, value in config.items()) if yaml else json.dumps(config)

    def start(self, yaml=False):
        self.gateway.config.write_text(self.wire(self.config, yaml))
        self.gateway.start()

    def guard(self, phase='response', streaming=None, action='reject', pattern=SECRET):
        guard = {phase: [{'regex': {'action': action, 'rules': [{'pattern': pattern}]}}]}
        if streaming is not None:
            guard['streaming'] = streaming
        self.config['aiSystems'][0]['llm']['models'][0]['guardrails'] = guard

    def call(self, path='/v1/chat/completions', *, stream=False, tenant='tenant-a'):
        body = {'model': 'local', 'stream': stream, 'messages': [{'role': 'user', 'content': 'question'}]}
        if path == '/v1/responses':
            body = {'model': 'local', 'input': 'question', 'stream': stream}
        elif path == '/v1/messages':
            body['max_tokens'] = 100
        elif '/images/' in path:
            body = {'model': 'local', 'prompt': SECRET}
        connection = http.client.HTTPConnection('127.0.0.1', self.gateway.model_port, timeout=8)
        try:
            connection.request('POST', path, json.dumps(body), {'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + self.gateway.token(tenant=tenant)})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def assert_blocked(self, response, before, *, request=False):
        status, body = response
        self.assertNotIn(SECRET.encode(), body)
        self.assertNotEqual(status, 200, body)
        self.assertEqual(len(self.server.requests), before + (0 if request else 1))
        self.assertIsNone(self.gateway.process.poll())

    def invalid_configs(self, yaml):
        for key in ('Mode', 'tenantID', 'agentID', 'resourceID', 'expiresAT'):
            with self.subTest(key=key):
                gateway, config = self.new_gateway()
                security = config['aiSystems'][0]['security']
                if key == 'Mode':
                    security[key] = security.pop('mode')
                elif key == 'expiresAT':
                    security['dynamicAuthorization'] = {'policyVersion': 'v1', 'policies': [
                        {'id': 'p', 'enabled': True, 'effect': 'allow', key: '2099-01-01T00:00:00Z'}]}
                else:
                    security['policies'][0][key] = security['policies'][0].pop('tenantId') if key == 'tenantID' else 'wrong'
                gateway.config.write_text(self.wire(config, yaml))
                with self.assertRaises(RuntimeError) as error:
                    gateway.start()
                self.assertIn(key, str(error.exception))
                self.assertEqual(len(self.server.requests), 0)

    def reload(self, config, *, yaml=False, successful=False):
        log = self.gateway.directory / 'gateway.log'
        offset = log.stat().st_size
        candidate = self.gateway.config.with_suffix('.next')
        candidate.write_text(self.wire(config, yaml))
        candidate.replace(self.gateway.config)
        expected = 'Config reloaded successfully' if successful else 'Failed to reload config:'
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            if expected in log.read_text()[offset:]:
                return
            self.assertIsNone(self.gateway.process.poll())
            time.sleep(.025)
        self.fail(log.read_text()[-5000:])

    def test_valid_enforce_and_explicit_audit_modes_keep_their_contract(self):
        self.start()
        self.assertEqual(self.call()[0], 200)
        self.assert_blocked(self.call(tenant='tenant-b'), 1, request=True)
        audit = copy.deepcopy(self.config)
        audit['aiSystems'][0]['security']['mode'] = 'audit'
        self.reload(audit, successful=True)
        self.assertEqual(self.call(tenant='tenant-b')[0], 200)

    def test_unknown_security_fields_reject_json_startup(self):
        self.invalid_configs(False)

    def test_unknown_security_fields_reject_yaml_startup(self):
        self.invalid_configs(True)

    def failed_update(self, yaml):
        self.start()
        self.assertEqual(self.call()[0], 200)
        bad = copy.deepcopy(self.config)
        bad['aiSystems'][0]['security']['policies'][0]['tenantID'] = bad['aiSystems'][0]['security']['policies'][0].pop('tenantId')
        self.reload(bad, yaml=yaml)
        self.assert_blocked(self.call(tenant='tenant-b'), 1, request=True)
        self.assertEqual(self.call()[0], 200)
        self.evidence[self.id()] = {'failedCandidatePreservedEnforce': True, 'unauthorizedUpstreamCalls': 0}

    def test_invalid_json_hot_update_preserves_previous_enforce_policy(self):
        self.failed_update(False)

    def test_invalid_yaml_hot_update_preserves_previous_enforce_policy(self):
        self.failed_update(True)

    def test_valid_hot_update_replaces_policy_and_denies_before_upstream(self):
        self.start()
        self.assertEqual(self.call()[0], 200)
        self.config['aiSystems'][0]['security']['policies'][0]['effect'] = 'deny'
        self.reload(self.config, successful=True)
        self.assert_blocked(self.call(), 1, request=True)

    def detect_denial(self, phase):
        self.guard(phase)
        self.start()
        for path in ('/v1/images/generations', '/v1/images/edits', '/v1/images/variations', '/v1/responses/compact'):
            self.assert_blocked(self.call(path), 0, request=True)
        self.assertNotIn('panicked at', (self.gateway.directory / 'gateway.log').read_text())
        self.evidence[self.id()] = {'upstreamCalls': 0, 'panic': False}

    def test_detect_request_guards_fail_before_upstream(self):
        self.detect_denial('request')

    def test_detect_response_guards_fail_before_upstream_without_panic(self):
        self.detect_denial('response')

    def test_unadapted_count_embedding_rerank_controls_fail_before_upstream(self):
        self.guard()
        self.start()
        for path in ('/v1/embeddings', '/v1/rerank', '/v1/messages/count_tokens'):
            self.assert_blocked(self.call(path), 0, request=True)

    def test_unguarded_detect_remains_an_explicit_compatible_path(self):
        self.start()
        self.assertEqual(self.call('/v1/images/generations')[0], 200)
        self.assertEqual(len(self.server.requests), 1)

    def blocked_stream(self, mode, output='text'):
        self.guard(streaming=mode)
        self.server.mode = output
        self.start()
        status, body = self.call(stream=True)
        self.assertEqual(status, 200, body)
        self.assertNotIn(SECRET.encode(), body)
        self.assertIn(b'guardrail_blocked', body)
        disclosed = ''
        for line in body.decode().splitlines():
            if not line.startswith('data:'):
                continue
            frame = json.loads(line[5:])
            for choice in frame.get('choices', []):
                delta = choice.get('delta', {})
                disclosed += delta.get('content', '')
                for tool in delta.get('tool_calls', []):
                    disclosed += tool.get('function', {}).get('arguments', '')
        self.assertNotIn(SECRET, disclosed)
        self.assertNotIn(b'[DONE]', body)
        self.assertEqual(len(self.server.requests), 1)

    def test_default_response_guard_blocks_streaming_disclosure(self):
        self.blocked_stream(None)

    def test_explicit_enabled_response_guard_blocks_streaming_disclosure(self):
        self.blocked_stream('Enabled')

    def test_default_response_guard_blocks_streamed_tool_arguments(self):
        self.blocked_stream(None, 'tool')

    def test_explicit_enabled_response_guard_blocks_streamed_tool_arguments(self):
        self.blocked_stream('Enabled', 'tool')

    def test_guarded_valid_tool_stream_is_delivered(self):
        self.guard()
        self.server.mode = 'tool-safe'
        self.start()
        status, body = self.call(stream=True)
        self.assertEqual(status, 200, body)
        arguments = ''.join(tool.get('function', {}).get('arguments', '')
            for line in body.decode().splitlines() if line.startswith('data:') and '[DONE]' not in line
            for choice in json.loads(line[5:]).get('choices', [])
            for tool in choice.get('delta', {}).get('tool_calls', []))
        self.assertEqual(json.loads(arguments), {'value': 'safe tool result'})
        self.assertIn(b'[DONE]', body)
        self.assertNotIn(b'guardrail_blocked', body)

    def test_explicit_disabled_response_guard_refuses_stream_before_upstream(self):
        self.guard(streaming='Disabled')
        self.start()
        self.assert_blocked(self.call(stream=True), 0, request=True)

    def test_guarded_valid_stream_is_delivered(self):
        self.guard()
        self.start()
        status, body = self.call(stream=True)
        self.assertEqual(status, 200, body)
        fragments = [json.loads(line[5:])['choices'][0]['delta'].get('content', '') for line in body.decode().splitlines() if line.startswith('data:') and '[DONE]' not in line]
        self.assertEqual(''.join(fragments), 'safe answer')
        self.assertIn(b'[DONE]', body)
        self.assertNotIn(b'guardrail_blocked', body)
        self.assertEqual(len(self.server.requests), 1)

    def tool_cases(self, action, mode='tool', pattern=SECRET):
        self.guard(action=action, pattern=pattern)
        self.server.mode = mode
        self.start()
        for path in ('/v1/chat/completions', '/v1/responses', '/v1/messages'):
            before = len(self.server.requests)
            response = self.call(path)
            if action == 'reject':
                self.assert_blocked(response, before)
            else:
                status, body = response
                self.assertEqual(status, 200, body)
                self.assertNotIn(SECRET.encode(), body)
                value = json.loads(body)
                if path.endswith('completions'):
                    arguments = json.loads(value['choices'][0]['message']['tool_calls'][0]['function']['arguments'])
                elif path.endswith('responses'):
                    arguments = json.loads(value['output'][0]['arguments'])
                else:
                    arguments = next(c['input'] for c in value['content'] if c['type'] == 'tool_use')
                self.assertEqual(arguments['value'], '<masked>')
                self.assertEqual(len(self.server.requests), before + 1)

    def test_nonstream_tool_arguments_are_checked_across_output_formats(self):
        self.tool_cases('reject')

    def test_mask_rewrites_real_tool_arguments_without_corrupting_structure(self):
        self.tool_cases('mask')

    def test_escaped_json_arguments_cannot_hide_from_nonstream_guards(self):
        self.tool_cases('reject', 'encoded')

    def test_mask_that_would_corrupt_json_is_rejected(self):
        self.guard(action='mask', pattern='7')
        self.server.mode = 'numeric'
        self.start()
        self.assert_blocked(self.call(), 0)

    def test_uninspectable_audio_output_is_not_delivered_under_text_guard(self):
        self.guard()
        self.server.mode = 'audio'
        self.start()
        self.assert_blocked(self.call(), 0)

    def test_all_completion_choices_are_checked(self):
        self.guard()
        self.server.mode = 'multi'
        self.start()
        self.assert_blocked(self.call(), 0)

    def test_request_guard_still_rejects_before_model_dispatch(self):
        self.guard('request', pattern='question')
        self.start()
        self.assert_blocked(self.call(), 0, request=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    BINARY = args.binary
    if args.report:
        gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SecurityContent))
    if args.report:
        args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
            'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors],
            'skipped': [str(t) for t, _ in result.skipped], 'evidence': SecurityContent.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
