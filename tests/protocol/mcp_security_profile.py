#!/usr/bin/env python3
"""MCP compatibility declarations remain independent constraints on the real gateway."""
import argparse
import concurrent.futures
import collections
import copy
import http.client
import http.server
import io
import json
import os
import socket
from pathlib import Path
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone

import gateway_faults as fixture
import mcp_wire_profile as wire
from mcp_remote_security import RemoteSecurity


def policy(effect='allow', **fields):
    return dict(id='same-id', effect=effect, enabled=True, tenantId='tenant-a', **fields)


class Security(unittest.TestCase):
    evidence = {}
    setUpClass = classmethod(wire.Wire.setUpClass.__func__)
    tearDownClass = classmethod(wire.Wire.tearDownClass.__func__)
    setUp = wire.Wire.setUp
    tearDown = wire.Wire.tearDown
    request = wire.Wire.request
    deny = wire.Wire.deny
    count = wire.Wire.count

    def install(self, common, legacy, *, valid=True, stateful=False, target_legacy=None):
        if not hasattr(self, 'base_config'):
            # Each test derives its first candidate from the preceding valid configuration;
            # only the two declarations change below, never JWT or network destinations.
            self.base_config = json.loads(self.gateway.config.read_text())
        config = copy.deepcopy(self.base_config)
        system = config['aiSystems'][0]
        system['mcp']['statefulMode'] = 'stateful' if stateful else 'stateless'
        if common is None:
            system.pop('security', None)
        else:
            system['security'] = copy.deepcopy(common)
        if legacy is None:
            system['mcp']['policies'].pop('securityPipeline', None)
        else:
            system['mcp']['policies']['securityPipeline'] = copy.deepcopy(legacy)
        if target_legacy is not None:
            system['mcp']['targets'][0].setdefault('policies', {})['securityPipeline'] = copy.deepcopy(target_legacy)
        offset = (self.gateway.directory / 'gateway.log').stat().st_size
        candidate = self.gateway.config.with_suffix('.next')
        candidate.write_text(json.dumps(config))
        candidate.replace(self.gateway.config)
        marker = b'Config reloaded successfully' if valid else b'unknown field'
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with (self.gateway.directory / 'gateway.log').open('rb') as log:
                log.seek(offset)
                if marker in log.read():
                    return
            self.assertIsNone(self.gateway.process.poll(), 'Gateway exited during reload')
            time.sleep(.05)
        self.fail(f'configuration watcher did not report {marker!r}')

    def accepted(self, response):
        self.assertEqual(response[0], 200, response)
        self.assertTrue(any('result' in value for value in response[2]), response)

    def test_legacy_only_keeps_default_deny_and_verified_tenant(self):
        self.install(None, {'policies': [policy(actionType='toolInvoke', resourceId='echo')]})
        before = self.count()
        self.accepted(self.request())
        self.deny(self.request(wire.message(name='forbidden')))
        self.deny(self.request(tenant='tenant-b'))
        self.deny(self.request(auth=False))
        self.assertEqual(self.count(), before + 1)
        self.install(None, {})
        self.deny(self.request())
        self.assertEqual(self.count(), before + 1)

    def test_enforce_declarations_are_intersected_and_policy_ids_are_not_merged(self):
        for common_effect, legacy_effect in [('allow', 'deny'), ('deny', 'allow'), ('allow', 'allow')]:
            with self.subTest(common=common_effect, legacy=legacy_effect):
                self.install({'mode': 'enforce', 'policies': [policy(common_effect)]},
                             {'policies': [policy(legacy_effect)]})
                before = self.count()
                response = self.request()
                if common_effect == legacy_effect == 'allow':
                    self.accepted(response)
                    self.assertEqual(self.count(), before + 1)
                else:
                    self.deny(response)
                    self.assertEqual(self.count(), before)

    def test_observe_modes_never_downgrade_the_legacy_constraint(self):
        for mode in ['audit', 'shadow']:
            for legacy_effect in ['deny', 'allow']:
                with self.subTest(mode=mode, legacy=legacy_effect):
                    self.install({'mode': mode, 'policies': [policy('deny')]},
                                 {'policies': [policy(legacy_effect)]})
                    before = self.count()
                    response = self.request()
                    if legacy_effect == 'allow':
                        self.accepted(response)
                        self.assertEqual(self.count(), before + 1)
                    else:
                        self.deny(response)
                        self.assertEqual(self.count(), before)

    def test_both_argument_requirements_and_legacy_approval_remain_mandatory(self):
        common = {'mode': 'enforce', 'policies': [policy()], 'requiredToolArguments': [
            {'toolName': 'echo', 'requiredFields': ['query']}]}
        legacy = {'policies': [policy()], 'requiredToolArguments': [
            {'toolName': 'echo', 'requiredFields': ['recordId']}]}
        self.install(common, legacy)
        before = self.count()
        self.deny(self.request(wire.message(arguments={'query': 'safe'})))
        self.deny(self.request(wire.message(arguments={'recordId': 42})))
        args = {'query': 'safe', 'recordId': 42}
        self.accepted(self.request(wire.message(arguments=args)))
        self.assertEqual(self.count(), before + 1)
        legacy['requiredToolApprovals'] = [{'toolName': 'echo'}]
        self.install(common, legacy)
        self.deny(self.request(wire.message(arguments=args)))
        self.assertEqual(self.count(), before + 1)

    def test_legacy_hot_update_replaces_rules_and_failed_candidate_preserves_denial(self):
        common = {'mode': 'enforce', 'policies': [policy()]}
        self.install(common, {'policies': [policy()]})
        self.accepted(self.request())
        before = self.count()
        self.install(common, {})
        self.deny(self.request())
        self.install(common, {'policies': [policy()], 'unexpectedSecurityField': True}, valid=False)
        self.deny(self.request())
        self.assertEqual(self.count(), before)
        self.install(common, {'policies': [policy()]})
        self.accepted(self.request())
        self.assertEqual(self.count(), before + 1)

    def test_resource_and_prompt_visibility_and_execution_keep_both_constraints(self):
        common = {'mode': 'enforce', 'policies': [policy(), policy('deny', resourceType='mcpPrompt',
            resourceId=json.dumps(['local', 'blocked_prompt'], separators=(',', ':')))]}
        legacy = {'policies': [policy(), policy('deny', resourceType='mcpResource',
            resourceId=json.dumps(['local', 'file:///secret'], separators=(',', ':')))]}
        self.install(common, legacy)
        for method, field, key, expected in [
                ('resources/list', 'resources', 'uri', {'file:///guide'}),
                ('prompts/list', 'prompts', 'name', {'guide_prompt'})]:
            response = self.request(wire.message(method))
            self.accepted(response)
            result = next(value['result'] for value in response[2] if 'result' in value)
            self.assertEqual({item[key] for item in result[field]}, expected)
        for method, params in [('resources/read', {'uri': 'file:///secret'}),
                               ('prompts/get', {'name': 'blocked_prompt'})]:
            before = self.server.calls[method]
            self.deny(self.request(wire.message(method, **params)))
            self.assertEqual(self.server.calls[method], before)
        self.accepted(self.request(wire.message('resources/read', uri='file:///guide')))
        self.accepted(self.request(wire.message('prompts/get', name='guide_prompt')))

    def test_concurrent_arguments_and_tenants_do_not_share_decisions(self):
        self.install({'mode': 'enforce', 'policies': [policy()]}, {'policies': [policy()],
                     'requiredToolArguments': [{'toolName': 'echo', 'requiredFields': ['query']}]})
        inputs = [('tenant-a', {'query': 'safe'}, True), ('tenant-a', {}, False),
                  ('tenant-b', {'query': 'safe'}, False)] * 3
        before = self.count()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda item: self.request(wire.message(arguments=item[1]), tenant=item[0]), inputs))
        for (_, _, allowed), result in zip(inputs, results):
            self.accepted(result) if allowed else self.deny(result)
        self.assertEqual(self.count(), before + 3)

    def test_legacy_session_deny_prevents_initialization_even_when_common_allows(self):
        common = {'mode': 'enforce', 'mcpSessions': {}, 'policies': [policy()]}
        legacy = {'policies': [policy(), policy('deny', actionType='mcpSessionOperation')]}
        self.install(common, legacy, stateful=True)
        before = self.server.calls.copy()
        rpc = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'legacy-deny', 'version': '1'}}}
        self.deny(self.gateway.request(rpc))
        self.assertEqual(self.server.calls, before)

    def test_metadata_http_never_bypasses_common_or_legacy_security(self):
        def get():
            connection = http.client.HTTPConnection('127.0.0.1', self.gateway.port, timeout=8)
            try:
                connection.request('GET', '/.well-known/oauth-protected-resource', headers={
                    'Authorization': 'Bearer ' + self.gateway.token()})
                response = connection.getresponse()
                body = response.read()
                return response.status, body
            finally:
                connection.close()
        self.install(None, None)
        before = self.server.calls['metadata-http']
        self.assertEqual(get()[0], 200)
        self.assertEqual(self.server.calls['metadata-http'], before + 1)
        deny = {'policies': [policy('deny')]}
        for name, common, legacy, target in [
                ('common', {'mode': 'enforce', **deny}, None, None),
                ('legacy', None, deny, None), ('target-legacy', None, None, deny)]:
            with self.subTest(declaration=name):
                self.install(common, legacy, target_legacy=target)
                self.assertGreaterEqual(get()[0], 400)
                self.assertEqual(self.server.calls['metadata-http'], before + 1)

    def test_legacy_task_deny_blocks_creation_before_the_upstream_tool(self):
        common = {'mode': 'enforce', 'mcpSessions': {'tasks': {'tools': ['echo']}}, 'policies': [policy()]}
        legacy = {'policies': [policy(), policy('deny', actionType='mcpTaskOperation')]}
        self.install(common, legacy, stateful=True)
        session = self.gateway.initialize()
        try:
            self.accepted(self.gateway.request(fixture.rpc('tools/list'), session))
            before = self.server.calls['tools/call']
            self.deny(self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={},
                                                      task={'ttl': 60000}), session))
            self.assertEqual(self.server.calls['tools/call'], before)
        finally:
            self.gateway.request(session=session, method='DELETE')


class IdleUpstream(fixture.Upstream):
    def do_POST(self):
        payload = self.rfile.read(int(self.headers['Content-Length']))
        rpc = json.loads(payload)
        mode = rpc.get('params', {}).get('arguments', {}).get('idleTest')
        if rpc.get('method') != 'tools/call' or mode is None:
            original = self.rfile
            self.rfile = io.BytesIO(payload)
            try:
                return super().do_POST()
            finally:
                self.rfile = original
        with self.server.lock:
            self.server.calls['tools/call'] += 1
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()

        def send(message):
            data = ('data: ' + json.dumps(message) + '\n\n').encode()
            self.wfile.write(f'{len(data):x}\r\n'.encode() + data + b'\r\n')
            self.wfile.flush()
        start = time.monotonic()
        duration = 32 if mode == 'progress' else 6
        try:
            while time.monotonic() - start < duration:
                if mode == 'progress':
                    send({'jsonrpc': '2.0', 'method': 'notifications/progress', 'params': {
                        'progressToken': rpc['params']['_meta']['progressToken'], 'progress': 1}})
                else:
                    send({'jsonrpc': '2.0', 'method': 'notifications/message', 'params': {
                        'level': 'info', 'data': 'unrelated'}})
                time.sleep(.4)
            send({'jsonrpc': '2.0', 'id': rpc['id'], 'result': {'content': [{'type': 'text', 'text': 'complete'}]}})
            self.wfile.write(b'0\r\n\r\n')
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


class IdleSessions(unittest.TestCase):
    evidence = {}
    diagnostics = []

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aisp-mcp-idle-')
        self.addCleanup(self.temp.cleanup)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), IdleUpstream)
        self.server.daemon_threads = True
        self.server.lock = threading.Lock()
        self.server.calls = collections.Counter()
        self.server.effects = collections.Counter()
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.gateway = fixture.Gateway(fixture.BINARY, Path(self.temp.name), self.server.server_port, mcp_only=True)
        self.addCleanup(self.gateway.signer.close)
        self.addCleanup(self.gateway.stop)
        self.gateway.scenario = self.id()

    def start(self, max_age=60):
        config = json.loads(self.gateway.config.read_text())
        config['config']['mcp'] = {'sessionTtl': '3s'}
        limits = config['aiSystems'][0]['security']['mcpSessions']
        limits.pop('tasks', None)
        limits.update(maxSessionSeconds=max_age, reauthorizeSeconds=1, streamIdleSeconds=8, maxStreamSeconds=60)
        self.gateway.config.write_text(json.dumps(config))
        self.gateway.start()
        return self.gateway.initialize()

    def tearDown(self):
        self.diagnostics.extend(self.gateway.diagnostics)

    def test_valid_progress_keeps_session_alive_across_background_reaper(self):
        session = self.start()
        start = time.monotonic()
        response = self.gateway.request(fixture.rpc('tools/call', name='echo',
            arguments={'idleTest': 'progress'}, _meta={'progressToken': 'active'}), session)
        self.assertEqual(response[0], 200, response)
        self.assertTrue(any(v.get('result', {}).get('content') for v in response[2]), response)
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 30)
        self.assertEqual(self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), session)[0], 200)
        self.evidence[self.id()] = {'activeSeconds': elapsed, 'idleTtlSeconds': 3, 'reaperIntervalSeconds': 30}

    def test_reauthorization_and_unrelated_messages_do_not_prevent_idle_expiry(self):
        session = self.start()
        with self.assertRaises(http.client.IncompleteRead) as ended:
            self.gateway.request(fixture.rpc('tools/call', name='echo',
                arguments={'idleTest': 'unrelated'}), session)
        self.assertNotIn(b'complete', ended.exception.partial)
        self.assertNotIn(b'unrelated', ended.exception.partial)
        self.assertEqual(self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), session)[0], 403)

    def test_denied_traffic_cannot_keep_session_alive_and_activity_cannot_extend_max_age(self):
        session = self.start(max_age=4)
        # Wrong owners, foreign tenants and rejected tools must not renew the original session.
        for _ in range(4):
            time.sleep(.6)
            self.assertEqual(self.gateway.request(fixture.rpc('tools/call', name='forbidden', arguments={}), session)[0], 403)
            self.assertEqual(self.gateway.request(fixture.rpc('tools/list'), session, user='other')[0], 403)
            self.assertEqual(self.gateway.request(fixture.rpc('tools/list'), session, tenant='other')[0], 403)
        time.sleep(.8)
        self.assertEqual(self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), session)[0], 403)
        active = self.gateway.initialize()
        start = time.monotonic()
        while time.monotonic() - start < 3:
            self.assertEqual(self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), active)[0], 200)
            time.sleep(.5)
        time.sleep(1.2)
        self.assertEqual(self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), active)[0], 403)


class TaskUpstream(fixture.Upstream):
    def do_POST(self):
        payload = self.rfile.read(int(self.headers['Content-Length']))
        rpc = json.loads(payload)
        method = rpc.get('method')
        if method == 'tools/call' and 'task' in rpc['params']:
            mode = rpc['params'].get('arguments', {}).get('failure', 'ok')
            with self.server.lock:
                self.server.calls['task-create:' + mode] += 1
            if mode == 'http':
                return self.reply(503)
            if mode == 'rpc':
                return self.reply(200, {'jsonrpc': '2.0', 'id': rpc['id'],
                                        'error': {'code': -32603, 'message': 'create failed'}})
            if mode == 'malformed':
                return self.reply(200, {'jsonrpc': '2.0', 'id': rpc['id'], 'result': {'content': []}})
            if mode == 'empty-stream':
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            if mode == 'disconnect':
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            now = datetime.now(timezone.utc).isoformat()
            task = {'taskId': 'accepted-upstream-task', 'status': 'working',
                    'ttl': rpc['params']['task']['ttl'], 'createdAt': now, 'lastUpdatedAt': now}
            with self.server.lock:
                self.server.task = task
            return self.reply(200, {'jsonrpc': '2.0', 'id': rpc['id'], 'result': {'task': task}})
        if method == 'tasks/get':
            with self.server.lock:
                task = self.server.task.copy()
                self.server.calls['tasks/get'] += 1
            assert rpc['params']['taskId'] == task['taskId'], rpc
            return self.reply(200, {'jsonrpc': '2.0', 'id': rpc['id'], 'result': {'task': task}})
        if method == 'tasks/result':
            with self.server.lock:
                self.server.calls['tasks/result'] += 1
                attempt = self.server.calls['tasks/result']
            ids = ('root-1', 'root-2') if attempt == 1 else ('root-2',)
            body = ''.join('data: ' + json.dumps({'jsonrpc': '2.0', 'id': request_id,
                'method': 'roots/list', 'params': {'_meta': {
                    'io.modelcontextprotocol/related-task': {'taskId': rpc['params']['taskId']}}}})
                + '\n\n' for request_id in ids).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        original = self.rfile
        self.rfile = io.BytesIO(payload)
        try:
            super().do_POST()
        finally:
            self.rfile = original


class TaskAdmissions(unittest.TestCase):
    evidence = {}
    diagnostics = []

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aisp-mcp-admission-')
        self.addCleanup(self.temp.cleanup)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), TaskUpstream)
        self.server.daemon_threads = True
        self.server.lock = threading.Lock()
        self.server.calls = collections.Counter()
        self.server.effects = collections.Counter()
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.gateway = fixture.Gateway(fixture.BINARY, Path(self.temp.name), self.server.server_port, mcp_only=True)
        self.addCleanup(self.gateway.signer.close)
        self.addCleanup(self.gateway.stop)
        self.gateway.scenario = self.id()
        config = json.loads(self.gateway.config.read_text())
        config['aiSystems'][0]['security']['mcpSessions']['tasks']['maxTasks'] = 1
        self.gateway.config.write_text(json.dumps(config))
        self.gateway.start()
        self.session = self.gateway.initialize()
        self.assertEqual(self.gateway.request(fixture.rpc('tools/list'), self.session)[0], 200)

    def tearDown(self):
        self.diagnostics.extend(self.gateway.diagnostics)
        with self.server.lock:
            self.evidence[self.id()] = {'upstreamCalls': dict(self.server.calls)}

    def create(self, failure='ok'):
        return self.gateway.request(fixture.rpc('tools/call', name='echo',
            arguments={'failure': failure}, task={'ttl': 60000}), self.session)

    def accepted(self):
        response = self.create()
        self.assertEqual(response[0], 200, response)
        tasks = [item['result']['task'] for item in response[2] if 'task' in item.get('result', {})]
        self.assertEqual(len(tasks), 1, response)
        return tasks[0]['taskId']

    def failed(self, mode):
        try:
            response = self.create(mode)
        except http.client.IncompleteRead:
            return  # A rejected body after headers must terminate the stream.
        self.assertFalse(any('task' in item.get('result', {}) for item in response[2]), response)

    def test_failed_creates_release_capacity_without_waiting_for_ttl(self):
        for mode in ('http', 'rpc', 'malformed', 'empty-stream', 'disconnect'):
            with self.subTest(failure=mode):
                self.failed(mode)
                with self.server.lock:
                    self.assertEqual(self.server.calls['task-create:' + mode], 1)
        self.accepted()

    def test_accepted_task_keeps_its_slot_and_rejects_foreign_owners(self):
        task = self.accepted()
        rpc = fixture.rpc('tasks/get', taskId=task)
        self.assertEqual(self.gateway.request(rpc, self.session, user='other')[0], 403)
        self.assertEqual(self.gateway.request(rpc, self.session, tenant='other')[0], 403)
        self.assertEqual(self.gateway.request(rpc, self.session)[0], 200)
        response = self.create()
        self.assertFalse(any('task' in item.get('result', {}) for item in response[2]), response)
        with self.server.lock:
            self.assertEqual(self.server.calls['task-create:ok'], 1)
        self.assertEqual(self.gateway.request(rpc, self.session)[0], 200)

    def test_concurrent_failed_creates_do_not_exhaust_capacity(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(self.failed, ['rpc'] * 8))
        with self.server.lock:
            self.assertGreater(self.server.calls['task-create:rpc'], 0)
        self.accepted()

    def test_reverse_capacity_rejection_allows_retry_but_not_replay(self):
        self.gateway.stop()
        config = json.loads(self.gateway.config.read_text())
        limits = config['aiSystems'][0]['security']['mcpSessions']
        limits['tasks']['roots'] = True
        limits['reverse'] = {'roots': ['file:///workspace'], 'maxPending': 1}
        self.gateway.config.write_text(json.dumps(config))
        self.gateway.start()
        response = self.gateway.request(fixture.rpc('initialize', protocolVersion='2025-11-25',
            capabilities={'roots': {}}, clientInfo={'name': 'reverse-client', 'version': '1'}))
        self.assertEqual(response[0], 200, response)
        self.session = next(v for k, v in response[1].items() if k.lower() == 'mcp-session-id')
        self.gateway.request({'jsonrpc': '2.0', 'method': 'notifications/initialized'}, self.session)
        self.assertEqual(self.gateway.request(fixture.rpc('tools/list'), self.session)[0], 200)
        task = self.accepted()

        def result():
            try:
                response = self.gateway.request(fixture.rpc('tasks/result', taskId=task), self.session)
                self.assertIn(response[0], (200, 403), response)
                messages = response[2]
            except http.client.IncompleteRead as ended:
                messages = [json.loads(line[5:]) for line in ended.partial.decode().splitlines()
                            if line.startswith('data:')]
            return [message for message in messages if message.get('method') == 'roots/list']

        # Two questions compete for one pending slot. Closing the stream releases the slot,
        # while the rejected root-2 ID must remain available on the next tasks/result POST.
        self.assertLessEqual(len(result()), 1)
        retry = result()
        self.assertEqual(len(retry), 1, retry)
        self.assertEqual(retry[0].get('method'), 'roots/list', retry)
        self.assertEqual(retry[0]['params']['_meta']['io.modelcontextprotocol/related-task']['taskId'], task)
        self.assertNotIn(retry[0]['id'], ('root-1', 'root-2'))
        self.assertEqual(result(), [])  # An admitted ID remains single-use across result streams.
        self.assertEqual(self.server.calls['tasks/result'], 3)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fixture.BINARY = wire.BINARY = args.binary
    fixture.ARTIFACTS = Path(tempfile.mkdtemp(prefix='run-', dir=args.report.parent))
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case) for case in (Security, RemoteSecurity, IdleSessions, TaskAdmissions))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    gateway = getattr(Security, 'gateway', None)
    args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
        'errors': [str(t) for t, _ in result.errors], 'failures': [str(t) for t, _ in result.failures],
        'skipped': [str(t) for t, _ in result.skipped], 'evidence': {**Security.evidence, **RemoteSecurity.evidence, **IdleSessions.evidence, **TaskAdmissions.evidence},
        'diagnostics': getattr(gateway, 'diagnostics', []) + IdleSessions.diagnostics + TaskAdmissions.diagnostics, 'artifacts': str(fixture.ARTIFACTS)}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
