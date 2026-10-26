#!/usr/bin/env python3
"""A2A Task/Artifact, streaming and durable inbox acceptance against production binaries."""
import argparse
import collections
import concurrent.futures
import http.client
import http.server
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from urllib.parse import urlsplit
import gateway_faults
from gateway_faults import Gateway, b64
from sampling_profile import tls_identity

BINARY = None

class A2AGateway(Gateway):
    def token(self, user='alice', tenant='tenant-a', expires=None):
        header = b64(json.dumps({'alg': 'EdDSA', 'kid': 'local'}).encode())
        claims = b64(json.dumps({'sub': user, 'tenant_id': tenant, 'client_id': 'client-a',
            'iss': 'https://issuer.example', 'aud': 'a2a', 'exp': int(time.time()) + 600 if expires is None else expires}).encode())
        message = f'{header}.{claims}'.encode()
        return f'{header}.{claims}.{b64(self.signer.sign(message))}'

def task_snapshot(server, task):
    return {'kind': 'task', 'id': task, 'contextId': f'context-{task}',
        'status': {'state': server.tasks[task]}, 'artifacts': [
            {'artifactId': name, 'parts': [{'kind': 'text', 'text': name + '-content'}]}
            for name in ('visible', 'hidden')]}

class Agent(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_): pass
    def reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        self.reply(200, {'protocolVersion': '0.3.0', 'url': 'https://upstream.example/agent',
            'capabilities': {'streaming': True, 'pushNotifications': True, 'extensions': [{}], 'stateTransitionHistory': True}})
    def snapshot(self, task):
        return task_snapshot(self.server, task)
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method = request['method']
        with self.server.lock:
            self.server.calls[method] += 1
            if method.startswith('message/'):
                task = request['params']['message'].get('taskId')
                if not task:
                    self.server.next_task += 1; task = f'task-{self.server.next_task}'
                    self.server.tasks[task] = 'working'
            else:
                task = request['params'].get('id') or request['params'].get('taskId')
            mode = self.server.mode
            if mode == 'lost':
                self.close_connection = True; self.connection.shutdown(socket.SHUT_RDWR); return
            if method.startswith('tasks/pushNotificationConfig/'):
                if method.endswith('/set'):
                    config = request['params']['pushNotificationConfig']
                    self.server.registration = (task, config)
                    result = {'taskId': task, 'pushNotificationConfig': dict(config)}
                    if mode == 'wrong-push': result['pushNotificationConfig']['url'] = 'https://foreign.example/'
                else: result = {}
            else:
                if method == 'tasks/cancel': self.server.tasks[task] = 'canceled'
                result = self.snapshot(task)
        if mode == 'error':
            self.reply(500, {'jsonrpc': '2.0', 'id': request['id'], 'error': {'code': -1, 'message': 'denied', 'data': {'secret': 'hidden-provider-data'}}}); return
        if mode == 'wrong-context': result['contextId'] = 'foreign-context'
        if method in ('message/stream', 'tasks/resubscribe'):
            self.send_response(200); self.send_header('Content-Type', 'text/event-stream'); self.send_header('Connection', 'close'); self.end_headers()
            def send(value):
                payload = {'jsonrpc': '2.0', 'id': request['id'], 'result': value}
                self.wfile.write(('data: ' + json.dumps(payload) + '\n\n').encode()); self.wfile.flush()
            try:
                send(result); self.server.stream_started.set()
                if mode in ('hold', 'foreign-event'): self.server.release.wait(10)
                send({'kind': 'artifact-update', 'taskId': 'foreign' if mode == 'foreign-event' else task,
                    'contextId': f'context-{task}', 'artifact': {'artifactId': 'visible', 'parts': [{'kind': 'text', 'text': 'AFTER-REVOKE-MARKER'}]}})
                send({'kind': 'status-update', 'taskId': task, 'contextId': f'context-{task}', 'status': {'state': 'completed'}, 'final': True})
                send({'kind': 'artifact-update', 'taskId': task, 'contextId': f'context-{task}', 'artifact': {'artifactId': 'visible', 'parts': [{'kind': 'text', 'text': 'AFTER-FINAL-MARKER'}]}})
            except (BrokenPipeError, ConnectionResetError): pass
            finally: self.close_connection = True
            return
        self.reply(200, {'jsonrpc': '2.0', 'id': request['id'] + 1 if mode == 'wrong-id' else request['id'], 'result': result})

class Pdp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length'])); self.server.calls += 1
        self.send_response(503); self.send_header('Content-Length', '0'); self.end_headers()

class A2A(unittest.TestCase):
    evidence = {}
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aisp-a2a-')
        self.directory = Path(self.temp.name)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Agent)
        self.server.daemon_threads = True; self.server.lock = threading.Lock(); self.server.calls = collections.Counter()
        self.server.next_task = 0; self.server.tasks = {}; self.server.mode = ''; self.server.registration = None
        self.server.release = threading.Event(); self.server.stream_started = threading.Event()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.gateway = A2AGateway(BINARY, self.directory, self.server.server_port, llm_only=True)
        self.gateway.scenario = self.id()
        self.config = json.loads(self.gateway.config.read_text())
        system = self.config['aiSystems'][0]; llm = system.pop('llm'); auth = llm['policies']['jwtAuth']; auth['audiences'] = ['a2a']
        self.port = self.gateway.port; self.gateway.listener_ports = (self.port,)
        system['a2a'] = {'port': self.port, 'backend': {'host': f'127.0.0.1:{self.server.server_port}'}}
        self.config['policies'] = [{'name': {'name': 'a2a-jwt', 'namespace': 'internal'},
            'target': {'route': {'name': 'ai-system:fault-acceptance:a2a:request', 'namespace': 'internal'}},
            'policy': {'jwtAuth': auth}}]
        policies = [{'id': kind, 'actionType': kind, 'effect': 'allow', 'enabled': True, 'tenantId': 'tenant-a'}
                    for kind in ('agentInvoke', 'agentTaskOperation')]
        resource = json.dumps([f'127.0.0.1:{self.server.server_port}', '/agent', 'task-1', 'visible'], separators=(',', ':'))
        policies.append({'id': 'visible', 'actionType': 'agentArtifactRead', 'resourceId': resource, 'effect': 'allow', 'enabled': True, 'tenantId': 'tenant-a'})
        system['security'] = {'mode': 'enforce', 'requiredIdentity': {'user': True, 'tenant': True, 'agent': False},
            'a2aObjects': {'streamIdleSeconds': 3, 'reauthorizeSeconds': 1, 'maxStreamSeconds': 15}, 'policies': policies}
    def tearDown(self):
        self.server.release.set()
        try:
            if hasattr(self, 'gateway'):
                if self.gateway.process and self.gateway.process.poll() is not None: self.gateway.snapshot('unexpected-exit')
                self.gateway.stop(); self.gateway.signer.close()
        finally:
            self.server.shutdown(); self.server.server_close(); self.thread.join(5); self.temp.cleanup()
    @property
    def security(self): return self.config['aiSystems'][0]['security']
    def start(self):
        self.gateway.config.write_text(json.dumps(self.config)); self.gateway.start()
    def rpc(self, method, params, token=True, stream=False, path='/agent'):
        headers = {'Content-Type': 'application/json', 'Accept': 'text/event-stream' if stream else 'application/json'}
        if token is not None: headers['Authorization'] = 'Bearer ' + (self.gateway.token() if token is True else token)
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=8)
        connection.request('POST', path, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}), headers)
        response = connection.getresponse()
        if stream: return connection, response
        try:
            self.last_cursor = response.getheader('x-aisp-event-cursor')
            return response.status, response.read()
        finally: connection.close()
    def create(self):
        status, body = self.rpc('message/send', {'message': self.message()}); self.assertEqual(status, 200, body)
        return json.loads(body)['result']
    @staticmethod
    def message(): return {'kind': 'message', 'role': 'user', 'messageId': 'message', 'parts': [{'kind': 'text', 'text': 'hello'}]}
    def denied(self, reply): self.assertIn(reply[0], (400, 401, 403), reply)
    @staticmethod
    def read_stream(response):
        try: return response.read()
        except http.client.IncompleteRead as error: return error.partial
    def test_concurrent_tasks_artifact_projection_and_authenticated_card(self):
        self.start()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: results = list(pool.map(lambda _: self.create(), range(8)))
        self.assertEqual(len({r['id'] for r in results}), 8)
        for result in results: self.assertEqual([a['artifactId'] for a in result['artifacts']], ['visible'] if result['id'] == 'task-1' else [])
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=8)
        connection.request('GET', '/.well-known/agent-card.json', headers={'Authorization': 'Bearer ' + self.gateway.token()})
        response = connection.getresponse(); card = json.loads(response.read()); connection.close()
        self.assertEqual(response.status, 200); self.assertFalse(card['capabilities']['pushNotifications']); self.assertNotIn('extensions', card['capabilities'])
        self.evidence[self.id()] = {'created': 8, 'visibleArtifactOnly': True}
    def test_identity_and_foreign_owner_denials_never_reach_agent(self):
        self.start(); task = self.create()['id']; before = sum(self.server.calls.values())
        for token in (None, self.gateway.token()[:-4] + 'xxxx', self.gateway.token(tenant='tenant-b'), self.gateway.token(expires=int(time.time()) - 1), self.gateway.token(user='bob')):
            self.denied(self.rpc('tasks/get', {'id': task}, token))
        self.assertEqual(sum(self.server.calls.values()), before)
    def test_invalid_references_and_methods_are_denied_without_dispatch(self):
        self.start(); before = sum(self.server.calls.values())
        for extra in ({'contextId': 'foreign'}, {'referenceTaskIds': ['foreign']}, {'parts': [{'kind': 'file', 'file': {'uri': 'https://untrusted.example/file'}}]}):
            self.denied(self.rpc('message/send', {'message': dict(self.message(), **extra)}))
        self.denied(self.rpc('custom/execute', {})); self.denied(self.rpc('tasks/get', {'id': 'foreign'}))
        self.assertEqual(sum(self.server.calls.values()), before)
    def test_deny_override_blocks_cancel_before_dispatch(self):
        self.security['policies'].append({'id': 'cancel-deny', 'actionType': 'agentInvoke', 'actionName': 'tasks/cancel', 'effect': 'deny', 'enabled': True})
        self.start(); task = self.create()['id']; self.denied(self.rpc('tasks/cancel', {'id': task})); self.assertEqual(self.server.calls['tasks/cancel'], 0)
    def test_correlated_response_and_context_binding_are_enforced(self):
        self.start(); self.server.mode = 'wrong-id'; self.denied(self.rpc('message/send', {'message': self.message()})); self.denied(self.rpc('tasks/get', {'id': 'task-1'}))
        self.server.mode = ''; task = self.create()['id']; self.server.mode = 'wrong-context'; self.denied(self.rpc('tasks/get', {'id': task}))
    def test_rpc_error_data_is_removed(self):
        self.start(); task = self.create()['id']; self.server.mode = 'error'; status, body = self.rpc('tasks/get', {'id': task}); self.assertEqual(status, 500)
        self.assertNotIn('data', json.loads(body)['error']); self.assertNotIn(b'hidden-provider-data', body)
    def test_terminal_cancel_blocks_later_continuation(self):
        self.start(); task = self.create()['id']; status, body = self.rpc('tasks/cancel', {'id': task}); self.assertEqual(status, 200, body)
        self.denied(self.rpc('message/send', {'message': dict(self.message(), taskId=task)})); self.denied(self.rpc('tasks/cancel', {'id': task})); self.assertEqual(self.server.calls['tasks/cancel'], 1)
    def test_uncertain_upstream_response_is_not_automatically_replayed(self):
        self.start(); self.server.mode = 'lost'; status, _ = self.rpc('message/send', {'message': self.message()}); self.assertGreaterEqual(status, 500)
        self.assertEqual(self.server.calls['message/send'], 1); self.denied(self.rpc('tasks/get', {'id': 'task-1'}))
    def test_stream_commits_binding_and_stops_at_terminal_event(self):
        self.start(); connection, response = self.rpc('message/stream', {'message': self.message()}, stream=True)
        body = self.read_stream(response); connection.close(); self.assertEqual(response.status, 200)
        self.assertIn(b'completed', body); self.assertIn(b'AFTER-REVOKE-MARKER', body); self.assertNotIn(b'AFTER-FINAL-MARKER', body); self.assertNotIn(b'hidden-content', body)
    def test_foreign_stream_event_is_not_disclosed(self):
        self.start(); self.server.mode = 'foreign-event'; connection, response = self.rpc('message/stream', {'message': self.message()}, stream=True)
        self.assertEqual(response.status, 200); first = response.readline(); self.assertIn(b'task-1', first); self.server.release.set(); body = first + self.read_stream(response); connection.close(); self.assertNotIn(b'AFTER-REVOKE-MARKER', body); self.assertNotIn(b'completed', body)
    def test_configuration_revocation_stops_pending_stream(self):
        self.start(); self.server.mode = 'hold'; connection, response = self.rpc('message/stream', {'message': self.message()}, stream=True)
        self.assertEqual(response.status, 200); self.assertTrue(self.server.stream_started.wait(3))
        first = response.readline(); self.assertIn(b'task-1', first)
        log = self.directory / 'gateway.log'; offset = log.stat().st_size
        self.security['policies'].append({'id': 'revoke', 'actionType': 'agentInvoke', 'effect': 'deny', 'enabled': True})
        next_file = self.gateway.config.with_suffix('.next'); next_file.write_text(json.dumps(self.config)); next_file.replace(self.gateway.config)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if b'Config reloaded successfully' in log.read_bytes()[offset:]: break
            time.sleep(.025)
        else: self.fail('configuration was not committed')
        self.server.release.set(); remainder = self.read_stream(response); connection.close(); self.assertNotIn(b'AFTER-REVOKE-MARKER', remainder)
    def test_required_audit_failure_and_pdp_failure_are_fail_closed(self):
        audit = self.directory / 'audit'; audit.mkdir(mode=0o700); self.config['config']['securityAudit'] = {'directory': str(audit)}
        self.security['requiredAudit'] = {'actionTypes': ['agentInvoke']}; self.start(); self.create()
        segments = list(audit.glob('segment-*.jsonl')); self.assertTrue(segments)
        for segment in segments: segment.rename(segment.with_suffix('.unavailable'))
        before = sum(self.server.calls.values()); self.denied(self.rpc('message/send', {'message': self.message()})); self.assertEqual(sum(self.server.calls.values()), before)
        # Independent deny path: a real TLS PDP returning 503 must never dispatch.
        self.gateway.stop(); certificate, key = tls_identity(self.directory)
        pdp = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Pdp); pdp.daemon_threads = True; pdp.calls = 0
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate, key); pdp.socket = tls.wrap_socket(pdp.socket, server_side=True)
        thread = threading.Thread(target=pdp.serve_forever, daemon=True); thread.start()
        self.addCleanup(thread.join, 5); self.addCleanup(pdp.server_close); self.addCleanup(pdp.shutdown)
        del self.security['requiredAudit']; del self.config['config']['securityAudit']
        self.security['dynamicAuthorization'] = {'policyVersion': 'a2a-v1', 'cacheTtlSeconds': 0}
        self.security['remotePdp'] = {'endpoint': f'https://127.0.0.1:{pdp.server_port}/pdp', 'rootCaPemFile': str(certificate), 'timeoutMillis': 500}
        self.start(); self.denied(self.rpc('message/send', {'message': self.message()})); self.assertGreater(pdp.calls, 0); self.assertEqual(sum(self.server.calls.values()), before)

class Durable(A2A):
    # Only the durable-specific cases below are selected by the dedicated profile.
    def setUp(self):
        super().setUp(); private = self.directory / 'private'; private.mkdir(mode=0o700)
        self.security['a2aObjects'].update({'storage': {'type': 'sqlite', 'path': str(private / 'tasks.db'), 'namespace': 'fault-acceptance', 'busyTimeoutMillis': 100},
            'eventRecovery': {'namespace': 'fault-acceptance', 'storage': {'path': str(private / 'events.jsonl'), 'maxBytes': 16777216}},
            'push': {'callbackBaseUrl': 'https://gateway.example/v1/a2a/push/', 'maxChannelSeconds': 300}})
        self.security['policies'].extend({'id': kind, 'actionType': kind, 'effect': 'allow', 'enabled': True, 'tenantId': 'tenant-a'} for kind in ('agentEventRecover', 'agentPushOperation'))
    def register(self, task):
        status, body = self.rpc('tasks/pushNotificationConfig/set', {'taskId': task, 'pushNotificationConfig': {'url': 'https://gateway.example/v1/a2a/push/'}})
        self.assertEqual(status, 200, body); self.assertNotIn(b'credentials', body)
        return json.loads(body)['result']['pushNotificationConfig'], self.server.registration[1]
    def callback(self, config, task, secret=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=8)
        connection.request('POST', urlsplit(config['url']).path, json.dumps(task), {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (secret or config['authentication']['credentials'])})
        response = connection.getresponse(); body = response.read(); connection.close(); return response.status, body
    def recover(self, task, cursor): return self.rpc('aisp.events/read', {'id': task, 'after': cursor, 'limit': 16})
    def push_task(self, task):
        with self.server.lock: value = task_snapshot(self.server, task)
        value['status']['timestamp'] = datetime.now(timezone.utc).isoformat(); return value
    def durable_ownership_survives_sigkill(self):
        self.start(); task = self.create()['id']; self.gateway.stop(); self.start()
        self.denied(self.rpc('tasks/get', {'id': task}, self.gateway.token(user='bob'))); status, body = self.rpc('tasks/get', {'id': task}); self.assertEqual(status, 200, body)
    def durable_recovery_keeps_cursor_owner_and_artifact_projection(self):
        self.start(); task = self.create()['id']; public, config = self.register(task); cursor = self.last_cursor; self.assertIsNotNone(cursor)
        # The registration checkpoint precedes newly committed inbox events.
        self.assertEqual(self.callback(config, self.push_task(task))[0], 202)
        status, body = self.recover(task, cursor); self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)['result']['scope'], 'gateway-observed'); self.assertGreaterEqual(len(json.loads(body)['result']['events']), 1); self.assertNotIn(b'hidden-content', body); self.assertNotIn(b'"sequence"', body)
        before = sum(self.server.calls.values()); self.denied(self.rpc('aisp.events/read', {'id': task, 'after': cursor}, self.gateway.token(user='bob'))); self.assertEqual(sum(self.server.calls.values()), before)
    def durable_event_storage_failure_prevents_stream_disclosure(self):
        self.start(); path = Path(self.security['a2aObjects']['eventRecovery']['storage']['path']); self.assertTrue(path.exists()); path.rename(path.with_suffix('.unavailable'))
        connection, response = self.rpc('message/stream', {'message': self.message()}, stream=True); body = self.read_stream(response); connection.close(); self.assertEqual(self.server.calls['message/stream'], 1); self.assertNotIn(b'"result"', body); self.assertIsNone(self.gateway.process.poll())
    def durable_push_secret_and_duplicate_handling(self):
        self.start(); task = self.create()['id']; _, config = self.register(task); value = self.push_task(task)
        self.denied(self.callback(config, value, '0' * 64)); self.assertEqual(self.callback(config, value)[0], 202); self.assertEqual(self.callback(config, value)[0], 202)
        status, body = self.rpc('tasks/pushNotificationConfig/get', {'id': task, 'pushNotificationConfigId': config['id']}); self.assertEqual(status, 200, body); self.assertNotIn(b'credentials', body)
    def durable_push_registration_mismatch_is_closed(self):
        self.start(); task = self.create()['id']; self.server.mode = 'wrong-push'; self.denied(self.rpc('tasks/pushNotificationConfig/set', {'taskId': task, 'pushNotificationConfig': {'url': 'https://gateway.example/v1/a2a/push/'}}))
        config = self.server.registration[1]; self.denied(self.callback(config, self.push_task(task)))
    def durable_deleted_channel_rejects_late_callback(self):
        self.start(); task = self.create()['id']; _, config = self.register(task)
        status, body = self.rpc('tasks/pushNotificationConfig/delete', {'id': task, 'pushNotificationConfigId': config['id']}); self.assertEqual(status, 200, body)
        self.denied(self.callback(config, self.push_task(task)))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve())); parser.add_argument('--report', type=Path); parser.add_argument('--durable', action='store_true'); args = parser.parse_args(); BINARY = args.binary
    if args.report: gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    if args.durable:
        suite = unittest.TestSuite(Durable(name) for name in sorted(vars(Durable)) if name.startswith('durable_'))
    else: suite = unittest.defaultTestLoader.loadTestsFromTestCase(A2A)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if args.report: args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun, 'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors], 'skipped': [str(t) for t, _ in result.skipped], 'evidence': A2A.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
