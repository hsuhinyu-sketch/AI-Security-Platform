#!/usr/bin/env python3
"""Real binary routing acceptance; no production test endpoints or external services."""
import argparse
import collections
import concurrent.futures
import contextlib
import http.client
import http.server
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import uuid
import gateway_faults
from gateway_faults import Gateway, Upstream


class Models(Upstream):
    def chat(self, request):
        with self.server.lock:
            self.server.calls[request['model']] += 1
        if request.get('stream'):
            return super().chat(request)
        if request['model'] == 'flaky':
            return self.reply(503, {'error': {'message': 'temporary failure', 'type': 'server_error'}})
        self.reply(200, {'id': 'routing', 'object': 'chat.completion', 'created': 1,
                        'model': request['model'], 'choices': [{'index': 0, 'finish_reason': 'stop',
                        'message': {'role': 'assistant', 'content': request['model']}}]})


class Routing(unittest.TestCase):
    evidence = {}

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='aisp-routing-')
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Models)
        cls.server.daemon_threads = True
        cls.server.lock = threading.Lock()
        cls.server.calls = collections.Counter()
        cls.server.model_release = threading.Event()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.gateway = Gateway(BINARY, Path(cls.temp.name), cls.server.server_port, llm_only=True)
        config = json.loads(cls.gateway.config.read_text())
        system = config['aiSystems'][0]
        system['security']['executionBudget'] = {'namespace': str(uuid.uuid4()), 'maxModelCalls': 1,
            'maxToolCalls': 0, 'maxAttempts': 1, 'maxConcurrent': 1, 'maxContextsPerOwner': 512}
        system['security']['policies'].append({'id': 'execution', 'enabled': True, 'effect': 'allow',
            'tenantId': 'tenant-a', 'actionType': 'executionOperation'})
        llm = system['llm']
        base = f'http://127.0.0.1:{cls.server.server_port}/v1'
        llm['models'] = [dict(name=name, provider='openAI', params={'baseUrl': base}, **extra)
            for name, extra in [('local', {}), ('hidden', {'visibility': 'internal'}),
                                ('denied', {'authorization': {'rules': ['false']}}), ('flaky', {})]]
        config['policies'] = [{'name': {'name': 'routing-retry', 'namespace': 'internal'},
            'target': {'route': {'name': 'ai-system:fault-acceptance:llm:request', 'namespace': 'internal'}},
            'policy': {'retry': {'attempts': 5, 'codes': [503]}}}]
        llm['virtualModels'] = [
            {'name': 'weighted', 'routing': {'weighted': {'targets': [{'model': 'denied', 'weight': 0}, {'model': 'hidden', 'weight': 1}]}}},
            {'name': 'conditional', 'routing': {'conditional': {'targets': [
                {'model': 'hidden', 'when': "request.headers['x-route'] == 'internal'"}, {'model': 'local'}]}}},
            {'name': 'blocked', 'routing': {'weighted': {'targets': [{'model': 'denied'}]}}},
            {'name': 'pool', 'routing': {'failover': {'targets': [{'model': 'local', 'priority': 0}, {'model': 'hidden', 'priority': 1}]}}},
            {'name': 'blocked-pool', 'routing': {'failover': {'targets': [{'model': 'denied', 'priority': 0}, {'model': 'local', 'priority': 1}]}}},
            {'name': 'retry', 'routing': {'weighted': {'targets': [{'model': 'flaky'}]}}},
        ]
        cls.gateway.config.write_text(json.dumps(config))
        try:
            cls.gateway.start()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.server.model_release.set()
        cls.gateway.stop()
        cls.gateway.signer.close()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temp.cleanup()

    def setUp(self):
        with self.server.lock:
            self.before = self.server.calls.copy()
        self.observations = {}

    def tearDown(self):
        with self.server.lock:
            calls = dict(self.server.calls - self.before)
        self.gateway.snapshot('routing-case-complete')
        self.evidence[self.id()] = {'upstreamCalls': calls, **self.observations}

    def execution(self):
        with contextlib.closing(http.client.HTTPConnection('127.0.0.1', self.gateway.model_port, timeout=5)) as client:
            client.request('POST', '/v1/executions', '{}',
                {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.gateway.token()})
            response = client.getresponse()
            body = response.read()
            self.assertEqual(response.status, 201, body)
            return json.loads(body)['executionId']

    def call(self, model='weighted', *, token=None, headers=None, method='POST'):
        supplied = {'Content-Type': 'application/json', 'x-aisp-execution-id': self.execution(), 'Authorization': 'Bearer ' + (token or self.gateway.token())}
        supplied.update(headers or {})
        with contextlib.closing(http.client.HTTPConnection('127.0.0.1', self.gateway.model_port, timeout=5)) as client:
            client.request(method, '/v1/models' if method == 'GET' else '/v1/chat/completions',
                           None if method == 'GET' else json.dumps({'model': model, 'messages': [{'role': 'user', 'content': 'hello'}]}), supplied)
            response = client.getresponse()
            body = response.read()
            try:
                value = json.loads(body) if body else {}
            except json.JSONDecodeError:
                value = {'error': body.decode(errors='replace')}
            return response.status, value

    def count(self, name=None):
        with self.server.lock:
            return self.server.calls[name] if name else sum(self.server.calls.values())

    def test_selection_visibility_and_public_alias_listing(self):
        for alias, headers, target in [('weighted', {}, 'hidden'), ('conditional', {'x-route': 'internal'}, 'hidden'),
                                       ('conditional', {}, 'local'), ('pool', {}, 'local')]:
            log = self.gateway.directory / 'gateway.log'
            loads_before = log.read_bytes().count(b'loaded config from')
            status, body = self.call(alias, headers=headers)
            loads_after = log.read_bytes().count(b'loaded config from')
            self.observations.setdefault('selections', []).append(dict(alias=alias, status=status,
                configLoadsBefore=loads_before, configLoadsAfter=loads_after))
            self.assertEqual(status, 200, body)
            self.assertEqual(body['choices'][0]['message']['content'], target)
        before = self.count()
        self.assertEqual(self.call('hidden')[0], 404)
        self.assertEqual(self.count(), before)
        status, body = self.call(method='GET')
        self.assertEqual(status, 200, body)
        names = [m['id'] for m in body['data']]
        self.assertNotIn('hidden', names)
        self.assertNotIn('denied', names)
        self.assertIn('blocked', names)  # Public alias declaration is not target authorization.
        self.assertIn('weighted', names)

    def test_target_authorization_is_required_for_weighted_and_failover(self):
        before = self.count()
        for name in ['denied', 'blocked', 'blocked-pool']:
            status, body = self.call(name)
            self.assertEqual(status, 403, body)
        self.assertEqual(self.count(), before, 'denied target reached an upstream or fallback')
        self.observations['deniedUpstreamCalls'] = 0

    def test_identity_denial_and_concurrent_alias_dispatch(self):
        before = self.count()
        for options in [dict(headers={'Authorization': ''}), dict(token=self.gateway.token()[:-4] + 'xxxx'),
                        dict(token=self.gateway.token(tenant='tenant-b'))]:
            self.assertIn(self.call(**options)[0], (401, 403))
        self.assertEqual(self.count(), before)
        before = self.count('hidden')
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.call(), range(8)))
        for status, body in results:
            self.assertEqual(status, 200, body)
            self.assertEqual(body['choices'][0]['message']['content'], 'hidden')
        self.assertEqual(self.count('hidden') - before, 8)

    def test_execution_budget_bounds_route_retries(self):
        before = self.count('flaky')
        status, body = self.call('retry')
        self.assertGreaterEqual(status, 400, body)
        self.assertEqual(self.count('flaky') - before, 1, 'retry exceeded maxAttempts=1')
        self.observations['outboundAttempts'] = 1

    def replace(self, contents):
        temporary = self.gateway.config.with_suffix('.next')
        temporary.write_text(contents)
        temporary.replace(self.gateway.config)

    def restore(self, original):
        # HTTP 200 can still come from the previous valid snapshot. Publish a unique
        # alias and observe it through the real model-list API before the next case.
        restored = json.loads(original)
        marker = 'reload-ready-' + uuid.uuid4().hex
        restored['aiSystems'][0]['llm']['virtualModels'].append({
            'name': marker, 'routing': {'weighted': {'targets': [{'model': 'local'}]}}})
        self.replace(json.dumps(restored))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status, body = self.call(method='GET')
            if status == 200 and marker in [entry['id'] for entry in body.get('data', [])]:
                self.assertEqual(self.call()[0], 200)
                return
            time.sleep(.05)
        self.fail('restored routing snapshot was not published')

    def wait_status(self, expected):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.call()[0] == expected:
                return
            time.sleep(.05)
        self.fail(f'updated alias did not reach HTTP {expected}')

    def test_invalid_reload_keeps_last_valid_router(self):
        original = self.gateway.config.read_text()
        changed = json.loads(original)
        changed['aiSystems'][0]['llm']['virtualModels'][0]['routing']['weighted']['targets'][1]['model'] = 'missing'
        log_path = self.gateway.directory / 'gateway.log'
        offset = log_path.stat().st_size
        try:
            self.replace(json.dumps(changed))
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with log_path.open('rb') as log:
                    log.seek(offset)
                    if b'does not match any llm.models entry' in log.read():
                        break
                time.sleep(.05)
            else:
                self.fail('watcher did not reject invalid virtual target')
            status, body = self.call()
            self.assertEqual(status, 200, body)
            self.assertEqual(body['choices'][0]['message']['content'], 'hidden')
        finally:
            self.restore(original)

    def test_alias_stream_is_revoked_when_routing_snapshot_changes(self):
        original = self.gateway.config.read_text()
        connection = http.client.HTTPConnection('127.0.0.1', self.gateway.model_port, timeout=12)
        self.server.model_release.clear()
        try:
            connection.request('POST', '/v1/chat/completions', json.dumps({'model': 'weighted', 'stream': True,
                'messages': [{'role': 'user', 'content': 'hello'}]}),
                {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.gateway.token(),
                 'x-aisp-execution-id': self.execution()})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            initial = response.read1(4096)
            self.assertIn(b'BEFORE_REVOCATION', initial)
            changed = json.loads(original)
            changed['aiSystems'][0]['llm']['virtualModels'][0]['routing']['weighted']['targets'] = [{'model': 'denied'}]
            self.replace(json.dumps(changed))
            self.wait_status(403)
            self.server.model_release.set()
            remaining = bytearray()
            while True:
                try:
                    data = response.read1(4096)
                except http.client.IncompleteRead as error:
                    remaining.extend(error.partial)
                    break
                except ConnectionResetError:
                    break
                if not data:
                    break
                remaining.extend(data)
            self.assertNotIn(b'AFTER_REVOCATION', initial + remaining)
            self.observations['postRevocationMarkerSeen'] = False
        finally:
            self.server.model_release.set()
            connection.close()
            self.restore(original)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    BINARY = args.binary
    if args.report:
        gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Routing))
    if args.report:
        args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
            'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors],
            'skipped': [str(t) for t, _ in result.skipped], 'evidence': Routing.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
