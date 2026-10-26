#!/usr/bin/env python3
"""RAG -> MCP Tool -> model -> A2A Task/Artifact through the existing Gateway APIs."""
import argparse
import collections
import copy
import http.server
import io
import json
from pathlib import Path
import socket
import threading
import unittest

import a2a_profile
import gateway_faults
import rag_profile
from rag_llm_profile import RagLlmFixture


class Tool(gateway_faults.Upstream):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers['Content-Length']))
        request = json.loads(raw)
        with self.server.lock:
            self.server.requests.append((dict(self.headers), copy.deepcopy(request)))
        if request.get('method') == 'tools/call':
            name = request['params']['name']
            with self.server.lock:
                self.server.effects[name] += 1
            self.reply(200, {'jsonrpc': '2.0', 'id': request['id'], 'result': {
                'content': [{'type': 'text', 'text': 'Tool evidence: ' + request['params']['arguments']['evidence']}]}})
        else:
            original = self.rfile
            self.rfile = io.BytesIO(raw)
            try:
                super().do_POST()
            finally:
                self.rfile = original


class Agent(a2a_profile.Agent):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers['Content-Length']))
        self.server.requests.append(json.loads(raw))
        original = self.rfile
        self.rfile = io.BytesIO(raw)
        try:
            super().do_POST()
        finally:
            self.rfile = original

    def snapshot(self, task):
        if task not in self.server.inputs:
            message = next(r for r in reversed(self.server.requests) if r['method'].startswith('message/'))
            self.server.inputs[task] = message['params']['message']['parts'][0]['text']
        self.server.tasks[task] = 'completed'
        result = super().snapshot(task)
        result['artifacts'][0]['parts'][0]['text'] = 'Agent artifact: ' + self.server.inputs[task]
        return result


class Workflow(RagLlmFixture):
    evidence = {}

    def serve(self, handler):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        server.daemon_threads = True
        server.lock = threading.Lock()
        server.requests = []
        server.calls = collections.Counter()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def close():
            server.shutdown()
            server.server_close()
            thread.join(5)
        self.addCleanup(close)
        return server

    def reserve(self):
        reservation = self.gateway.role_ports.reservations.enter_context(socket.socket())
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]

    def setUp(self):
        super().setUp()
        self.tool = self.serve(Tool)
        self.tool.effects = collections.Counter()
        self.agent = self.serve(Agent)
        self.agent.next_task = 0
        self.agent.tasks = {}
        self.agent.inputs = {}
        self.agent.mode = ''
        self.mcp_port, self.agent_port = self.reserve(), self.reserve()
        self.gateway.role_ports.ports.update(tool=self.mcp_port, agent=self.agent_port)
        self.gateway.listener_ports += (self.mcp_port, self.agent_port)
        security = self.system['security']
        security['mcpSessions'] = {'maxSessions': 4}
        security['a2aObjects'] = {'streamIdleSeconds': 3, 'reauthorizeSeconds': 1, 'maxStreamSeconds': 15}
        security['policies'] += [self.allow(kind) for kind in ('mcpSessionOperation', 'toolList', 'agentInvoke', 'agentTaskOperation')]
        security['policies'] += [dict(self.allow('toolInvoke'), resourceId='echo'),
                                  dict(self.allow('mcpOperation'), resourceType='mcpServer', resourceId='local')]
        self.agent_target = f'127.0.0.1:{self.agent.server_port}'
        artifact = json.dumps([self.agent_target, '/agent', 'task-1', 'visible'], separators=(',', ':'))
        security['policies'].append(dict(self.allow('agentArtifactRead'), resourceId=artifact))
        for policy in security['crossComponent']['destinations']:
            policy.update(toolDestinations=['local/echo'], mcpDestinations=['local'], agentDestinations=[self.agent_target])
        auth = self.system['rag']['authentication']
        self.system['mcp'] = {'port': self.mcp_port, 'statefulMode': 'stateful',
                              'policies': {'jwtAuth': copy.deepcopy(auth)},
                              'targets': [{'name': 'local', 'mcp': {'host': f'http://127.0.0.1:{self.tool.server_port}/mcp'}}]}
        self.system['a2a'] = {'port': self.agent_port, 'backend': {'host': self.agent_target}}
        self.config['policies'] = [{'name': {'name': 'business-a2a-jwt', 'namespace': 'internal'},
            'target': {'route': {'name': 'ai-system:knowledge-poc:a2a:request', 'namespace': 'internal'}},
            'policy': {'jwtAuth': copy.deepcopy(auth)}}]

    def mcp(self, method, params, context, session=None, token=True):
        headers = {'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25'}
        if session:
            headers['Mcp-Session-Id'] = session
        rpc = {'jsonrpc': '2.0', 'method': method, 'params': params}
        if not method.startswith('notifications/'):
            rpc['id'] = 1
        status, response_headers, wire = self.call(self.mcp_port, '/mcp', rpc, context, token, headers)
        response_headers = {k.lower(): v for k, v in response_headers.items()}
        if 'text/event-stream' in response_headers.get('content-type', ''):
            values = [json.loads(line[5:]) for line in wire.decode().splitlines() if line.startswith('data:')]
        else:
            values = [json.loads(wire)] if wire.lstrip().startswith(b'{') else []
        return status, {k.lower(): v for k, v in response_headers.items()}, values

    def initialize(self, context):
        status, headers, values = self.mcp('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'business-poc', 'version': '1'}}, context)
        self.assertEqual(status, 200, values)
        self.assertTrue(any('result' in v for v in values), values)
        session = headers['mcp-session-id']
        self.assertIn(self.mcp('notifications/initialized', {}, context, session)[0], (200, 202, 204))
        return session

    def agent_rpc(self, method, params, context, token=True):
        return self.call(self.agent_port, '/agent', {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params},
                         context, token)

    def create(self, context, answer='business evidence'):
        message = {'kind': 'message', 'role': 'user', 'messageId': 'business', 'parts': [{'kind': 'text', 'text': answer}]}
        status, _, wire = self.agent_rpc('message/send', {'message': message}, context)
        self.assertEqual(status, 200, wire)
        return json.loads(wire)['result']

    def assert_mcp_denied(self, response, effects):
        status, _, values = response
        self.assertTrue(status in (400, 401, 403) or any('error' in value for value in values), response)
        self.assertEqual(self.tool.effects, effects)

    def test_retrieval_tool_model_agent_artifact_business_chain(self):
        context, retrieved = self.begin()
        session = self.initialize(context)
        status, _, values = self.mcp('tools/list', {}, context, session)
        self.assertEqual(status, 200, values)
        names = [t['name'] for v in values if 'result' in v for t in v['result']['tools']]
        self.assertIn('echo', names)
        self.assertNotIn('forbidden', names)
        text = '\n'.join(c['content'] for c in retrieved['chunks'])
        status, _, values = self.mcp('tools/call', {'name': 'echo', 'arguments': {'evidence': text}}, context, session)
        self.assertEqual(status, 200, values)
        result = next(v['result'] for v in values if 'result' in v)
        tool_text = result['content'][0]['text']
        self.assertEqual(tool_text, 'Tool evidence: ' + text)
        model_input = {'chunks': [{'content': tool_text}]}
        status, _, wire = self.generate(context, model_input)
        self.assertEqual(status, 200, wire)
        answer = json.loads(wire)['choices'][0]['message']['content']
        self.assertEqual(self.model.requests[0][2]['messages'][-1]['content'], tool_text)
        task = self.create(context, answer)
        self.assertEqual(task['status']['state'], 'completed')
        self.assertEqual([a['artifactId'] for a in task['artifacts']], ['visible'])
        self.assertEqual(task['artifacts'][0]['parts'][0]['text'], 'Agent artifact: ' + answer)
        status, _, wire = self.agent_rpc('tasks/get', {'id': task['id']}, context)
        self.assertEqual(status, 200, wire)
        self.assertIn(answer, json.loads(wire)['result']['artifacts'][0]['parts'][0]['text'])
        self.evidence[self.id()] = {'toolEffects': dict(self.tool.effects), 'modelCalls': len(self.model.requests),
            'agentCalls': dict(self.agent.calls), 'allProtocolListenersUsed': True, 'visibleArtifactOnly': True}

    def test_foreign_context_owner_cannot_use_tool_session_or_agent_task(self):
        context, _ = self.begin()
        session = self.initialize(context)
        task = self.create(context)
        effects, calls = self.tool.effects.copy(), self.agent.calls.copy()
        for token in (self.gateway.token(user='bob'), self.gateway.token(tenant='tenant-b')):
            self.assert_mcp_denied(self.mcp('tools/call', {'name': 'echo', 'arguments': {'evidence': 'secret'}}, context, session, token), effects)
            self.assertIn(self.agent_rpc('tasks/get', {'id': task['id']}, context, token)[0], (400, 401, 403))
        self.assertEqual(self.agent.calls, calls)

    def test_document_revocation_blocks_tool_model_and_agent_continuations(self):
        context, retrieved = self.begin()
        session = self.initialize(context)
        task = self.create(context)
        effects, calls = self.tool.effects.copy(), self.agent.calls.copy()
        self.document({'type': 'revoke'}, self.document()['revision'])
        self.assert_mcp_denied(self.mcp('tools/call', {'name': 'echo', 'arguments': {'evidence': 'secret'}}, context, session), effects)
        self.assert_blocked(self.generate(context, retrieved), 0)
        self.assertIn(self.agent_rpc('tasks/get', {'id': task['id']}, context)[0], (400, 403))
        self.assertEqual(self.agent.calls, calls)

    def test_fresh_context_cannot_replace_task_or_session_lineage(self):
        context, _ = self.begin()
        session = self.initialize(context)
        task = self.create(context)
        self.document({'type': 'revoke'}, self.document()['revision'])
        fresh, empty = self.context()
        self.assertNotEqual(fresh, context)
        self.assertEqual(empty['chunks'], [])
        effects, calls = self.tool.effects.copy(), self.agent.calls.copy()
        self.assert_mcp_denied(self.mcp('tools/call', {'name': 'echo', 'arguments': {'evidence': 'secret'}}, fresh, session), effects)
        self.assertIn(self.agent_rpc('tasks/get', {'id': task['id']}, fresh)[0], (400, 403))
        self.assertEqual(self.agent.calls, calls)

    def test_forbidden_tool_never_has_side_effects(self):
        context, _ = self.begin()
        session = self.initialize(context)
        self.assert_mcp_denied(self.mcp('tools/call', {'name': 'forbidden', 'arguments': {'evidence': 'secret'}}, context, session), collections.Counter())

    def test_agent_actual_exit_is_separate_from_model_exit(self):
        self.system['security']['crossComponent']['destinations'][-1]['agentDestinations'] = []
        context, retrieved = self.begin()
        self.assertEqual(self.generate(context, retrieved)[0], 200)
        message = {'kind': 'message', 'role': 'user', 'messageId': 'business', 'parts': [{'kind': 'text', 'text': 'secret'}]}
        self.assertIn(self.agent_rpc('message/send', {'message': message}, context)[0], (400, 403))
        self.assertFalse(self.agent.calls)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    rag_profile.BINARY = args.binary
    if args.report:
        gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Workflow))
    if args.report:
        args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
            'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors],
            'skipped': [str(t) for t, _ in result.skipped], 'evidence': Workflow.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
