#!/usr/bin/env python3
"""MCP wire and dual-era baseline on a production binary, with real JWT and TCP."""
import argparse
import base64
import collections
import contextlib
import gzip
import http.client
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
import gateway_faults as fixture

MODERN = '2026-07-28'
VERSION_KEY = 'io.modelcontextprotocol/protocolVersion'


def message(method='tools/call', **params):
    if method == 'tools/call':
        params = {'name': 'echo', 'arguments': {}, **params}
    params['_meta'] = {VERSION_KEY: MODERN, 'io.modelcontextprotocol/clientInfo': {'name': 'wire-client', 'version': '1'},
                       'io.modelcontextprotocol/clientCapabilities': {}}
    return {'jsonrpc': '2.0', 'id': 31, 'method': method, 'params': params}


class WireUpstream(fixture.Upstream):
    def do_GET(self):
        if not self.path.startswith('/api/'):
            return super().do_GET()
        with self.server.lock:
            self.server.calls['openapi-http'] += 1
        self.reply(200, {'path': self.path, 'protected': self.headers.get('x-test')})

    def reply_raw(self, status, payload, content_type=None, encoding=None):
        self.send_response(status)
        if content_type is not None:
            self.send_header('Content-Type', content_type)
        if encoding is not None:
            self.send_header('Content-Encoding', encoding)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def reply(self, status, value=None):
        if self.headers.get('MCP-Protocol-Version') == MODERN and value and 'result' in value:
            value['result']['resultType'] = 'complete'
        super().reply(status, value)

    def do_POST(self):
        payload = self.rfile.read(int(self.headers['Content-Length']))
        rpc = json.loads(payload)
        method = rpc.get('method')
        if method == 'initialize' and rpc['params']['protocolVersion'] == MODERN:
            with self.server.lock:
                self.server.calls['invalid-modern-initialize'] += 1
            self.reply(400, {'jsonrpc': '2.0', 'id': rpc['id'],
                             'error': {'code': -32601, 'message': 'modern MCP does not initialize'}})
            return
        if method == 'server/discover':
            with self.server.lock:
                self.server.calls[method] += 1
            self.reply(200, {'jsonrpc': '2.0', 'id': rpc['id'], 'result': {'resultType': 'complete',
                'supportedVersions': [MODERN, '2025-11-25', '2099-01-01'], 'capabilities': {
                    'tools': {'listChanged': True}, 'resources': {'subscribe': True, 'listChanged': True},
                    'logging': {}, 'completions': {}, 'extensions': {'unsafe-extension': {}},
                    'tasks': {'requests': {'tools': {'call': {}}}}},
                'serverInfo': {'name': 'wire-upstream', 'version': '1'}, 'ttlMs': 0, 'cacheScope': 'private'}})
            return
        if method == 'subscriptions/listen':
            with self.server.lock:
                self.server.calls[method] += 1
                self.server.routing.append({'method': method, 'params': rpc['params']})
            self.reply(200, {'jsonrpc': '2.0', 'id': rpc['id'],
                            'result': {'_meta': {'io.modelcontextprotocol/subscriptionId': rpc['id']}}})
            return
        objects = {
            'resources/list': {'resources': [{'uri': 'file:///guide', 'name': 'guide'}]},
            'resources/templates/list': {'resourceTemplates': [{'uriTemplate': 'file:///guide/{page}', 'name': 'pages'}]},
            'prompts/list': {'prompts': [{'name': 'guide_prompt', 'description': 'guide'}]},
            'resources/read': {'contents': [{'uri': rpc.get('params', {}).get('uri'), 'text': 'guide'}]},
            'resources/subscribe': {},
            'resources/unsubscribe': {},
            'prompts/get': {'messages': [{'role': 'user', 'content': {'type': 'text', 'text': 'guide'}}]},
        }
        if method in objects:
            with self.server.lock:
                self.server.calls[method] += 1
                self.server.routing.append({'method': method, 'params': rpc.get('params', {})})
            self.reply(200, {'jsonrpc': '2.0', 'id': rpc['id'], 'result': objects[method]})
            return
        if method == 'tools/call':
            with self.server.lock:
                self.server.calls['model-era:' + self.headers.get('MCP-Protocol-Version', 'absent')] += 1
                self.server.routing.append({'method': self.headers.get('Mcp-Method'),
                                            'name': self.headers.get('Mcp-Name'), 'bodyName': rpc['params']['name']})
            case = rpc['params'].get('arguments', {}).get('transportCase')
            if case is not None:
                with self.server.lock:
                    self.server.calls[method] += 1
                    self.server.effects[rpc['params']['name']] += 1
                reply = {'jsonrpc': '2.0', 'id': rpc['id'], 'result': {'resultType': 'complete',
                    'content': [{'type': 'text', 'text': 'transport-ok'}]}}
                encoded = json.dumps(reply).encode()
                if case == 'sse':
                    self.reply_raw(200, b': keepalive\n\ndata: ' + encoded + b'\n\n', 'text/event-stream; charset=utf-8')
                elif case == 'json':
                    self.reply_raw(200, encoded, 'application/json; charset=utf-8')
                elif case == 'gzip':
                    self.reply_raw(200, gzip.compress(encoded), 'application/json', 'gzip')
                elif case == 'bad-json':
                    self.reply_raw(200, b'{', 'application/json')
                elif case == 'bad-sse':
                    self.reply_raw(200, b'data: {\n\n', 'text/event-stream')
                elif case == 'large-json':
                    reply['result']['content'][0]['text'] = 'x' * (128 * 1024)
                    self.reply_raw(200, json.dumps(reply).encode(), 'application/json')
                elif case == 'large-sse':
                    reply['result']['content'][0]['text'] = 'x' * (128 * 1024)
                    self.reply_raw(200, b'data: ' + json.dumps(reply).encode() + b'\n\n', 'text/event-stream')
                elif case == 'wrong-type':
                    self.reply_raw(200, encoded, 'text/plain')
                elif case == 'missing-type':
                    self.reply_raw(200, encoded)
                elif case == 'null':
                    self.reply_raw(200, b'null', 'application/json')
                elif case in ['202', '204']:
                    self.reply_raw(int(case), b'')
                elif case in ['403', '503']:
                    self.reply_raw(int(case), b'{"error":"upstream denied"}', 'application/json')
                else:
                    raise AssertionError('unknown test transport case')
                return
        original = self.rfile
        self.rfile = io.BytesIO(payload)
        try:
            super().do_POST()
        finally:
            self.rfile = original


class Wire(unittest.TestCase):
    evidence = {}

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='aisp-mcp-wire-')
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), WireUpstream)
        cls.server.daemon_threads = True
        cls.server.lock = threading.Lock()
        cls.server.calls = collections.Counter()
        cls.server.effects = collections.Counter()
        cls.server.routing = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.gateway = fixture.Gateway(BINARY, Path(cls.temp.name), cls.server.server_port, mcp_only=True)
        config = json.loads(cls.gateway.config.read_text())
        del config['aiSystems'][0]['security']['mcpSessions']['tasks']
        config['aiSystems'][0]['security']['mcpSessions']['maxMessageBytes'] = 4096
        cls.gateway.config.write_text(json.dumps(config))
        try:
            cls.gateway.start()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.gateway.stop()
        cls.gateway.signer.close()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(5)
        cls.temp.cleanup()

    def setUp(self):
        self.gateway.scenario = self.id()
        with self.server.lock:
            self.before = self.server.calls.copy()
            self.effects = self.server.effects.copy()

    def tearDown(self):
        with self.server.lock:
            self.evidence[self.id()] = {'upstreamCalls': dict(self.server.calls - self.before),
                                       'toolEffects': dict(self.server.effects - self.effects)}
        self.gateway.snapshot('wire-case-complete')

    def request(self, rpc=None, *, overrides=None, extra=(), auth=True, tenant='tenant-a'):
        rpc = message() if rpc is None else rpc
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
                   'MCP-Protocol-Version': MODERN, 'Mcp-Method': rpc.get('method', '')}
        if rpc.get('method') == 'tools/call':
            headers['Mcp-Name'] = rpc['params']['name']
        elif rpc.get('method') == 'resources/read':
            headers['Mcp-Name'] = rpc['params']['uri']
        elif rpc.get('method') == 'prompts/get':
            headers['Mcp-Name'] = rpc['params']['name']
        if auth:
            headers['Authorization'] = 'Bearer ' + self.gateway.token(tenant=tenant)
        headers.update(overrides or {})
        payload = json.dumps(rpc).encode()
        with contextlib.closing(http.client.HTTPConnection('127.0.0.1', self.gateway.port, timeout=8)) as client:
            client.putrequest('POST', '/mcp')
            for key, value in headers.items():
                if value is not None:
                    client.putheader(key, value)
            for key, value in extra:
                client.putheader(key, value)
            client.putheader('Content-Length', str(len(payload)))
            client.endheaders(payload)
            response = client.getresponse()
            body = response.read()
            if 'text/event-stream' in response.getheader('Content-Type', ''):
                values = [json.loads(line[5:]) for line in body.splitlines() if line.startswith(b'data:')]
            else:
                try:
                    values = [json.loads(body)] if body else []
                except json.JSONDecodeError:
                    values = []
            return response.status, dict(response.getheaders()), values

    def count(self):
        with self.server.lock:
            return self.server.calls['tools/call']

    def deny(self, response):
        status, _, values = response
        self.assertTrue(status >= 400 or any('error' in v for v in values), response)
        self.assertFalse(any('result' in v for v in values), response)

    def test_modern_tool_without_initialize_and_legacy_session(self):
        before = self.count()
        initializations = self.server.calls['initialize']
        status, headers, values = self.request()
        self.assertEqual(status, 200, values)
        self.assertTrue(any(v.get('result', {}).get('content') for v in values), values)
        self.assertFalse(any(k.lower() == 'mcp-session-id' for k in headers), headers)
        self.assertEqual(self.count(), before + 1)
        self.assertEqual(self.server.calls['initialize'], initializations)
        self.assertEqual(self.server.routing[-1]['method'], 'tools/call')
        self.assertEqual(self.server.routing[-1]['name'], self.server.routing[-1]['bodyName'])
        session = self.gateway.initialize()
        try:
            status, _, values = self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), session)
            self.assertEqual(status, 200, values)
            self.assertTrue(any('result' in v for v in values), values)
        finally:
            self.gateway.request(session=session, method='DELETE')

    def test_transport_decoding_retains_limits_fail_closed_and_no_replay(self):
        for case in ['json', 'sse', 'gzip', 'bad-json', 'bad-sse', 'large-json', 'large-sse',
                     'wrong-type', 'missing-type', 'null', '202', '204', '403', '503']:
            with self.subTest(case=case):
                before = self.count()
                effects = self.server.effects['echo']
                response = self.request(message(arguments={'transportCase': case}))
                if case in ['json', 'sse']:
                    self.assertEqual(response[0], 200, response)
                    self.assertTrue(any(v.get('result', {}).get('content') ==
                        [{'type': 'text', 'text': 'transport-ok'}] for v in response[2]), response)
                else:
                    self.deny(response)
                self.assertEqual(self.count(), before + 1)
                self.assertEqual(self.server.effects['echo'], effects + 1)

    def test_subscription_batches_preserve_transparent_routing_without_partial_dispatch(self):
        original = self.gateway
        with tempfile.TemporaryDirectory(prefix='aisp-mcp-batch-route-') as directory:
            gateway = fixture.Gateway(BINARY, Path(directory), self.server.server_port, mcp_only=True)
            if gateway.artifacts is not None:
                gateway.artifacts /= 'batch-route'
            self.gateway = gateway
            session = None
            try:
                config = json.loads(gateway.config.read_text())
                system = config['aiSystems'][0]
                # Exercise the existing transparent compatibility path. Protected
                # sessions continue rejecting the unadapted subscriptions/listen method.
                del system['security']
                system['mcp']['targets'].append({'name': 'other',
                    'mcp': {'host': f'http://127.0.0.1:{self.server.server_port}/mcp'}})
                system['mcp']['policies']['mcpAuthorization'] = {'rules': [
                    'true', {'deny': "has(mcp.resource) && mcp.resource.name == 'file:///denied'"}]}
                gateway.config.write_text(json.dumps(config))
                gateway.start()
                session = gateway.initialize()
                for filters, expected_calls in [
                    ({'resourceSubscriptions': ['local+file:///a', 'local+file:///b']}, 1),
                    ({'resourceSubscriptions': []}, 2), ({}, 2),
                ]:
                    before = self.server.calls['subscriptions/listen']
                    status, _, values = gateway.request(fixture.rpc('subscriptions/listen', notifications=filters), session)
                    self.assertEqual(status, 200, values)
                    result = next(v['result'] for v in values if 'result' in v)
                    self.assertEqual(result['_meta']['io.modelcontextprotocol/subscriptionId'], 2)
                    self.assertEqual(self.server.calls['subscriptions/listen'], before + expected_calls)
                    actual = self.server.routing[-1]['params']['notifications']
                    if filters.get('resourceSubscriptions'):
                        self.assertEqual(actual['resourceSubscriptions'], ['file:///a', 'file:///b'])
                    else:
                        self.assertEqual(actual, filters)
                for resources in [
                    ['local+file:///a', 'other+file:///b'], ['local+file:///a', 'file:///b'],
                    ['unknown+file:///a'], ['local+file:///a', 'local+file:///denied'],
                ]:
                    before = self.server.calls['subscriptions/listen']
                    self.deny(gateway.request(fixture.rpc('subscriptions/listen',
                        notifications={'resourceSubscriptions': resources}), session))
                    self.assertEqual(self.server.calls['subscriptions/listen'], before)
                status, _, values = gateway.request(fixture.rpc('tools/call', name='local_echo',
                    arguments={'transportCase': 'gzip'}), session)
                self.assertEqual(status, 200, values)
                self.assertTrue(any(v.get('result', {}).get('content') ==
                    [{'type': 'text', 'text': 'transport-ok'}] for v in values), values)
            finally:
                if session is not None:
                    gateway.request(session=session, method='DELETE')
                gateway.stop()
                gateway.signer.close()
                self.gateway = original
        before = self.server.calls['subscriptions/listen']
        self.deny(self.request(message('subscriptions/listen', notifications={})))
        self.assertEqual(self.server.calls['subscriptions/listen'], before)

    def test_modern_discovery_and_list(self):
        for method in ['server/discover', 'tools/list']:
            status, _, values = self.request(message(method))
            self.assertEqual(status, 200, values)
            self.assertTrue(any('result' in v for v in values), values)
            if method == 'server/discover':
                discovery = next(v['result'] for v in values if 'result' in v)
                self.assertIn(MODERN, discovery['supportedVersions'])
                self.assertNotIn('2099-01-01', discovery['supportedVersions'])
                capabilities = discovery['capabilities']
                for field in ['tasks', 'extensions', 'logging', 'completions']:
                    self.assertNotIn(field, capabilities)
                self.assertFalse(capabilities.get('tools', {}).get('listChanged'))
                self.assertFalse(capabilities.get('resources', {}).get('subscribe'))
                self.assertEqual(discovery['ttlMs'], 0)
                self.assertEqual(discovery['cacheScope'], 'private')

    def test_modern_stateless_configuration_does_not_initialize(self):
        original = self.gateway
        before = self.server.calls['invalid-modern-initialize']
        with tempfile.TemporaryDirectory(prefix='aisp-mcp-stateless-') as directory:
            gateway = fixture.Gateway(BINARY, Path(directory), self.server.server_port, mcp_only=True)
            if gateway.artifacts is not None:
                gateway.artifacts /= 'stateless'
            self.gateway = gateway
            try:
                config = json.loads(gateway.config.read_text())
                del config['aiSystems'][0]['security']['mcpSessions']['tasks']
                config['aiSystems'][0]['mcp']['statefulMode'] = 'stateless'
                gateway.config.write_text(json.dumps(config))
                gateway.start()
                status, _, values = self.request()
                self.assertEqual(status, 200, values)
                self.assertTrue(any('result' in v for v in values), values)
                self.assertEqual(self.server.calls['invalid-modern-initialize'], before)
            finally:
                gateway.stop()
                gateway.signer.close()
                self.gateway = original

    def test_discovery_fanout_uses_each_selected_server_policy(self):
        original = self.gateway
        discoveries = self.server.calls['server/discover']
        with tempfile.TemporaryDirectory(prefix='aisp-mcp-discovery-mux-') as directory:
            gateway = fixture.Gateway(BINARY, Path(directory), self.server.server_port, mcp_only=True)
            if gateway.artifacts is not None:
                gateway.artifacts /= 'discovery-mux'
            self.gateway = gateway
            try:
                config = json.loads(gateway.config.read_text())
                system = config['aiSystems'][0]
                del system['security']['mcpSessions']['tasks']
                system['mcp']['targets'].append({'name': 'denied-source',
                    'mcp': {'host': f'http://127.0.0.1:{self.server.server_port}/mcp'}})
                gateway.config.write_text(json.dumps(config))
                gateway.start()
                status, _, values = self.request(message('server/discover'))
                self.assertEqual(status, 200, values)
                self.assertTrue(any('result' in v for v in values), values)
                self.assertEqual(self.server.calls['server/discover'], discoveries + 1)
            finally:
                gateway.stop()
                gateway.signer.close()
                self.gateway = original

    def test_duplicate_routing_headers_rejected_before_dispatch(self):
        before = self.count()
        for name, value in [('Mcp-Method', 'tools/call'), ('Mcp-Name', 'echo'), ('MCP-Protocol-Version', MODERN)]:
            with self.subTest(header=name):
                self.deny(self.request(extra=[(name, value)]))
        self.deny(self.request(extra=[('Mcp-Param-Region', 'one'), ('Mcp-Param-Region', 'two')]))
        self.assertEqual(self.count(), before)

    def test_multiplexed_names_and_uris_keep_routing_and_authorization(self):
        original = self.gateway
        with tempfile.TemporaryDirectory(prefix='aisp-mcp-routing-mux-') as directory:
            gateway = fixture.Gateway(BINARY, Path(directory), self.server.server_port, mcp_only=True)
            if gateway.artifacts is not None:
                gateway.artifacts /= 'routing-mux'
            self.gateway = gateway
            session = None
            try:
                config = json.loads(gateway.config.read_text())
                system = config['aiSystems'][0]
                del system['security']['mcpSessions']['tasks']
                system['mcp']['targets'].append({'name': 'other',
                    'mcp': {'host': f'http://127.0.0.1:{self.server.server_port}/mcp'}})
                system['mcp']['policies']['mcpAuthorization'] = {'rules': [
                    'true', {'deny': "has(mcp.tool) && mcp.tool.name == 'commit'"}]}
                system['security']['policies'] += [
                    {'id': 'other-source', 'actionType': 'mcpOperation', 'effect': 'allow',
                     'enabled': True, 'tenantId': 'tenant-a', 'resourceType': 'mcpServer', 'resourceId': 'other'},
                    {'id': 'prompts', 'actionType': 'mcpOperation', 'effect': 'allow',
                     'enabled': True, 'tenantId': 'tenant-a', 'resourceType': 'mcpPrompt'},
                ]
                for target in ['local', 'other']:
                    for resource_type, resource in [('mcpPrompt', 'blocked_prompt'),
                                                     ('mcpResource', 'file:///secret')]:
                        system['security']['policies'].append({
                            'id': f'deny-{target}-{resource_type}', 'actionType': 'mcpOperation',
                            'effect': 'deny', 'enabled': True, 'tenantId': 'tenant-a',
                            'resourceType': resource_type,
                            'resourceId': json.dumps([target, resource], separators=(',', ':'))})
                gateway.config.write_text(json.dumps(config))
                gateway.start()
                session = gateway.initialize()
                for legacy in [False, True]:
                    def call(method, **params):
                        if legacy:
                            return gateway.request(fixture.rpc(method, **params), session)
                        return self.request(message(method, **params))

                    if not legacy:
                        status, _, values = call('server/discover')
                        self.assertEqual(status, 200, values)
                        discovery = next(v['result'] for v in values if 'result' in v)
                        self.assertEqual(set(discovery['supportedVersions']), {MODERN, '2025-11-25'})
                        self.assertEqual(discovery['ttlMs'], 0)
                        self.assertEqual(discovery['cacheScope'], 'private')
                        self.assertNotIn('tasks', discovery['capabilities'])
                    for method, field, key, expected in [
                        ('tools/list', 'tools', 'name', {'local_echo', 'other_echo'}),
                        ('resources/list', 'resources', 'uri', {'local+file:///guide', 'other+file:///guide'}),
                        ('resources/templates/list', 'resourceTemplates', 'uriTemplate',
                         {'local+file:///guide/{page}', 'other+file:///guide/{page}'}),
                        ('prompts/list', 'prompts', 'name', {'local_guide_prompt', 'other_guide_prompt'}),
                    ]:
                        status, _, values = call(method)
                        self.assertEqual(status, 200, values)
                        result = next(v['result'] for v in values if 'result' in v)
                        self.assertEqual({item[key] for item in result[field]}, expected)
                    for target in ['local', 'other']:
                        status, _, values = call('tools/call', name=target + '_echo', arguments={})
                        self.assertEqual(status, 200, values)
                        self.assertTrue(any('result' in v for v in values), values)
                        self.assertEqual(self.server.routing[-1]['bodyName'], 'echo')
                        if not legacy:
                            self.assertEqual(self.server.routing[-1]['name'], 'echo')
                        status, _, values = call('resources/read', uri=target + '+file:///guide')
                        self.assertEqual(status, 200, values)
                        self.assertTrue(any('result' in v for v in values), values)
                        self.assertEqual(self.server.routing[-1]['params']['uri'], 'file:///guide')
                        status, _, values = call('prompts/get', name=target + '_guide_prompt')
                        self.assertEqual(status, 200, values)
                        self.assertTrue(any('result' in v for v in values), values)
                        self.assertEqual(self.server.routing[-1]['params']['name'], 'guide_prompt')
                        if legacy:
                            for method in ['resources/subscribe', 'resources/unsubscribe']:
                                status, _, values = call(method, uri=target + '+file:///guide')
                                self.assertEqual(status, 200, values)
                                self.assertTrue(any('result' in v for v in values), values)
                                self.assertEqual(self.server.routing[-1]['params']['uri'], 'file:///guide')
                    before = self.server.calls.copy()
                    for method, params in [
                        ('tools/call', {'name': 'local_forbidden', 'arguments': {}}),
                        ('tools/call', {'name': 'local_commit', 'arguments': {}}),
                        ('tools/call', {'name': 'unknown_echo', 'arguments': {}}),
                        ('resources/read', {'uri': 'unknown+file:///guide'}),
                        ('resources/read', {'uri': 'file:///guide'}),
                        ('prompts/get', {'name': 'unknown_guide_prompt'}),
                        ('prompts/get', {'name': 'local_blocked_prompt'}),
                        ('prompts/get', {'name': 'other_blocked_prompt'}),
                        ('resources/read', {'uri': 'local+file:///secret'}),
                        ('resources/read', {'uri': 'other+file:///secret'}),
                        # Completion has routing support but remains unsupported
                        # by the existing Enforce security normalization. Moving
                        # dispatch must preserve that refusal, not grant access.
                        ('completion/complete', {'ref': {'type': 'ref/prompt', 'name': 'local_guide_prompt'},
                                                 'argument': {'name': 'topic', 'value': 'a'}}),
                        ('completion/complete', {'ref': {'type': 'ref/resource', 'uri': 'other+file:///guide'},
                                                 'argument': {'name': 'topic', 'value': 'a'}}),
                    ]:
                        self.deny(call(method, **params))
                    self.assertEqual(self.server.calls, before)
                before = self.server.calls.copy()
                self.deny(self.request(message('tools/call', name='local_echo'), tenant='tenant-b'))
                self.deny(self.request(message('resources/list'), tenant='tenant-b'))
                self.deny(self.request(message('prompts/list'), tenant='tenant-b'))
                self.deny(self.request(message('prompts/get', name='local_guide_prompt'), tenant='tenant-b'))
                self.deny(self.request(message('resources/read', uri='local+file:///guide'), tenant='tenant-b'))
                self.assertEqual(self.server.calls, before)
            finally:
                if session is not None:
                    gateway.request(session=session, method='DELETE')
                gateway.stop()
                gateway.signer.close()
                self.gateway = original

    def test_openapi_bridge_keeps_bound_execution_and_header_priority(self):
        original = self.gateway
        with tempfile.TemporaryDirectory(prefix='aisp-openapi-component-') as directory:
            gateway = fixture.Gateway(BINARY, Path(directory), self.server.server_port, mcp_only=True)
            if gateway.artifacts is not None:
                gateway.artifacts /= 'openapi-component'
            self.gateway = gateway
            try:
                config = json.loads(gateway.config.read_text())
                system = config['aiSystems'][0]
                del system['security']['mcpSessions']['tasks']
                schema = {'openapi': '3.0.3', 'info': {'title': 'local', 'version': '1'},
                          'servers': [{'url': 'http://unused.example/api'}],
                          'paths': {'/items/{id}': {'get': {'operationId': 'lookup',
                              'parameters': [
                                  {'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}},
                                  {'name': 'x-test', 'in': 'header', 'schema': {'type': 'string'}}],
                              'responses': {'200': {'description': 'ok'}}}}}}
                system['mcp']['targets'] = [{'name': 'local', 'openapi': {
                    'host': f'http://127.0.0.1:{self.server.server_port}', 'schema': json.dumps(schema)}}]
                system['security']['policies'].append({
                    'id': 'lookup', 'actionType': 'toolInvoke', 'effect': 'allow',
                    'enabled': True, 'tenantId': 'tenant-a', 'resourceId': 'lookup'})
                gateway.config.write_text(json.dumps(config))
                gateway.start()
                # Protected MCP sessions currently support Streamable HTTP only.
                # Preserve the fail-closed refusal instead of broadening the
                # production contract to make OpenAPI pass this test.
                before = self.server.calls['openapi-http']
                self.deny(self.request(message('tools/list')))
                self.assertEqual(self.server.calls['openapi-http'], before)
                gateway.stop()
                # Exercise the supported OpenAPI combination: verified JWT and
                # Enforce business authorization, without unsupported sessions.
                del system['security']['mcpSessions']
                gateway.config.write_text(json.dumps(config))
                gateway.start()
                status, _, values = self.request(message('tools/list'))
                self.assertEqual(status, 200, values)
                result = next(value['result'] for value in values if 'result' in value)
                self.assertEqual([tool['name'] for tool in result['tools']], ['lookup'])
                rpc = message('tools/call', name='lookup', arguments={
                    'path': {'id': 'item/one'}, 'header': {'x-test': 'untrusted'}})
                before = self.server.calls['openapi-http']
                status, _, values = self.request(rpc, overrides={'X-Test': 'trusted-context'})
                self.assertEqual(status, 200, values)
                result = next(value['result'] for value in values if 'result' in value)
                self.assertEqual(result['structuredContent'], {
                    'path': '/api/items/item%2Fone', 'protected': 'trusted-context'})
                self.assertEqual(self.server.calls['openapi-http'], before + 1)
                before = self.server.calls['openapi-http']
                self.deny(self.request(rpc, tenant='tenant-b'))
                self.deny(self.request(rpc, auth=False))
                self.deny(self.request(message('tools/call', name='forbidden', arguments={})))
                self.assertEqual(self.server.calls['openapi-http'], before)
            finally:
                gateway.stop()
                gateway.signer.close()
                self.gateway = original

    def test_reverse_responses_and_cancellation_require_a_live_parent(self):
        original = self.gateway
        with tempfile.TemporaryDirectory(prefix='aisp-mcp-reverse-boundary-') as directory:
            gateway = fixture.Gateway(BINARY, Path(directory), self.server.server_port, mcp_only=True)
            if gateway.artifacts is not None:
                gateway.artifacts /= 'reverse-boundary'
            self.gateway = gateway
            session = None
            try:
                config = json.loads(gateway.config.read_text())
                config['aiSystems'][0]['security']['mcpSessions']['reverse'] = {'roots': ['file:///workspace']}
                gateway.config.write_text(json.dumps(config))
                gateway.start()
                session = gateway.initialize()
                before = self.server.calls.copy()
                for rpc in [
                    {'jsonrpc': '2.0', 'id': 'unknown-reverse', 'result': {'roots': [{'uri': 'file:///workspace'}]}},
                    {'jsonrpc': '2.0', 'id': 'unknown-reverse', 'error': {'code': -32603, 'message': 'failed'}},
                    {'jsonrpc': '2.0', 'method': 'notifications/cancelled',
                     'params': {'requestId': 'unknown-parent', 'reason': 'private-reason'}},
                ]:
                    self.deny(gateway.request(rpc, session))
                    self.deny(gateway.request(rpc, session, tenant='tenant-b'))
                self.assertEqual(self.server.calls, before)
            finally:
                if session is not None:
                    gateway.request(session=session, method='DELETE')
                gateway.stop()
                gateway.signer.close()
                self.gateway = original

    def test_mismatched_method_name_and_version_never_dispatch(self):
        before = self.count()
        for overrides in [{'Mcp-Name': 'forbidden'}, {'Mcp-Method': 'tools/list'}, {'MCP-Protocol-Version': '2025-11-25'}]:
            self.deny(self.request(overrides=overrides))
        self.assertEqual(self.count(), before)

    def test_unknown_versions_report_supported_versions(self):
        before = self.count()
        for version in ['2099-01-01', '2026-07-08']:
            rpc = message()
            rpc['params']['_meta'][VERSION_KEY] = version
            status, _, values = self.request(rpc, overrides={'MCP-Protocol-Version': version})
            self.assertEqual(status, 400, values)
            error = next(v['error'] for v in values if 'error' in v)
            self.assertEqual(error['code'], -32022)
            self.assertIn(MODERN, error['data']['supported'])
            self.assertNotIn(version, error['data']['supported'])
        self.assertEqual(self.count(), before)

    def test_missing_and_malformed_metadata_never_dispatch(self):
        before = self.count()
        self.deny(self.request(overrides={'MCP-Protocol-Version': None}))
        for value in [None, 7, '2099-01-01']:
            rpc = message()
            rpc['params']['_meta'][VERSION_KEY] = value
            self.deny(self.request(rpc))
        self.deny(self.request(overrides={'Mcp-Name': None}))
        self.deny(self.request(overrides={'Mcp-Method': None}))
        self.assertEqual(self.count(), before)

    def test_base64_name_and_invalid_encoding(self):
        before = self.count()
        encoded = '=?base64?' + base64.b64encode(b'echo').decode() + '?='
        status, _, values = self.request(overrides={'Mcp-Name': encoded})
        self.assertEqual(status, 200, values)
        self.assertTrue(any('result' in v for v in values), values)
        self.deny(self.request(overrides={'Mcp-Name': '=?base64?%%%?='}))
        self.assertEqual(self.count(), before + 1)

    def test_each_request_requires_verified_identity(self):
        before = self.count()
        discoveries = self.server.calls['server/discover']
        for rpc in [message(), message('server/discover')]:
            self.deny(self.request(rpc, auth=False))
            self.deny(self.request(rpc, overrides={'Authorization': 'Bearer invalid'}))
            self.deny(self.request(rpc, tenant='tenant-b'))
        rpc = message()
        rpc['params']['_meta']['tenant_id'] = 'tenant-a'
        self.deny(self.request(rpc, tenant='tenant-b'))
        self.assertEqual(self.count(), before)
        self.assertEqual(self.server.calls['server/discover'], discoveries)

    def test_modern_initialize_is_rejected(self):
        before = self.count()
        rpc = message('initialize', protocolVersion=MODERN, capabilities={}, clientInfo={'name': 'wire-client', 'version': '1'})
        self.deny(self.request(rpc))
        self.assertEqual(self.count(), before)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    BINARY = args.binary
    fixture.ARTIFACTS = args.report.with_suffix('.gateway')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Wire))
    args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
        'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors],
        'skipped': [str(t) for t, _ in result.skipped], 'evidence': Wire.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
