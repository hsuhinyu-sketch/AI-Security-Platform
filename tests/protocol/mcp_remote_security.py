"""Remote MCP authorization/approval/issuance on real gateway HTTP APIs and disposable TLS peers."""
import base64
import collections
import contextlib
import copy
import hashlib
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid
from datetime import datetime, timedelta, timezone

import gateway_faults as fixture
import mcp_wire_profile as wire
from sampling_profile import tls_identity


class Authority(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        value = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        request = value['request']
        tool = request['action']['actionType'] == 'toolInvoke'
        with self.server.lock:
            self.server.calls.append((self.path, value))
        if tool and self.path == self.server.hold:
            self.server.entered.set()
            if not self.server.release.wait(12):
                raise TimeoutError('remote fixture decision was not released')
        expires = (datetime.now(timezone.utc) + timedelta(seconds=self.server.approval_ttl)).isoformat()
        if self.path == '/pdp':
            effect = 'allow' if request['subject'].get('tenantId') == 'tenant-a' else 'deny'
            response = dict(requestId=request['requestId'], policyVersion='remote-v1',
                            effect=effect, policyId='remote', expiresAt=expires)
        elif self.path == '/approval':
            response = dict(requestId=request['requestId'], argumentsHash=value['argumentsHash'],
                            approvalId='trusted-approval', approved=self.server.approved, expiresAt=expires)
        else:
            token = uuid.uuid4().hex
            response = dict(requestId=request['requestId'], argumentsHash=value['argumentsHash'],
                            token=token, expiresAt=expires)
            approval = request.get('authorizationContext', {}).get('approval')
            if approval:
                response['expiresAt'] = min(expires, approval['expiresAt'])
                response['approvalId'] = approval['approvalId']
            if self.server.approval_binding == 'extend':
                response['expiresAt'] = (datetime.now(timezone.utc) + timedelta(seconds=10)).isoformat()
            elif self.server.approval_binding == 'wrong':
                response['approvalId'] = 'wrong-approval'
            elif self.server.approval_binding == 'missing':
                response.pop('approvalId', None)
            if self.server.bad_binding:
                response['requestId'] = 'wrong-request'
            with self.server.lock:
                self.server.grants[token] = copy.deepcopy(value)
        status = 503 if self.path == '/issue' and self.server.issue_error else 200
        data = json.dumps(response).encode()
        try:
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        finally:
            if tool and self.path == self.server.hold:
                self.server.finished.set()


class ProtectedTool(wire.WireUpstream):
    def do_POST(self):
        payload = self.rfile.read(int(self.headers['Content-Length']))
        rpc = json.loads(payload)
        if rpc.get('method') == 'tools/call' and self.server.require_capability:
            token = self.headers.get('x-ai-security-capability')
            encoded = self.headers.get('x-ai-security-capability-context', '')
            try:
                context = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
            except (ValueError, TypeError):
                context = None
            arguments = rpc['params'].get('arguments', {})
            digest = hashlib.sha256(json.dumps(arguments, sort_keys=True, separators=(',', ':'),
                                                ensure_ascii=False).encode()).hexdigest()
            with self.server.authority.lock:
                grant = self.server.authority.grants.get(token)
                if (not grant or grant['request'] != context or grant['argumentsHash'] != digest
                        or (context.get('authorizationContext', {}).get('approval') and
                            datetime.fromisoformat(context['authorizationContext']['approval']['expiresAt'].replace('Z', '+00:00')) <= datetime.now(timezone.utc))):
                    return self.reply(403, {'error': 'capability rejected'})
                del self.server.authority.grants[token]
                self.server.consumed.append((token, encoded, rpc))
        self.rfile = io.BytesIO(payload)
        super().do_POST()


class RemoteSecurity(unittest.TestCase):
    evidence = {}
    request = wire.Wire.request
    deny = wire.Wire.deny
    count = wire.Wire.count

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mcp-remote-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.authority = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Authority)
        self.authority.daemon_threads = True
        self.authority.lock, self.authority.calls, self.authority.grants = threading.Lock(), [], {}
        self.authority.approved, self.authority.issue_error, self.authority.bad_binding = True, False, False
        self.authority.hold = None
        self.authority.approval_ttl, self.authority.approval_binding = 10, 'respect'
        self.authority.entered, self.authority.release, self.authority.finished = (threading.Event() for _ in range(3))
        self.addCleanup(self.authority.release.set)
        certificate, key = tls_identity(self.directory)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certificate, key)
        self.authority.socket = tls.wrap_socket(self.authority.socket, server_side=True)
        self.serve(self.authority)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), ProtectedTool)
        self.server.daemon_threads = True
        self.server.lock, self.server.calls, self.server.effects = threading.Lock(), collections.Counter(), collections.Counter()
        self.server.routing, self.server.consumed, self.server.require_capability = [], [], False
        self.server.authority = self.authority
        self.serve(self.server)
        self.gateway = fixture.Gateway(wire.BINARY, self.directory, self.server.server_port, mcp_only=True)
        self.gateway.scenario = self.id()
        if self.gateway.artifacts is not None:
            self.gateway.artifacts /= self.id().rsplit('.', 1)[-1]
        self.addCleanup(self.gateway.signer.close)
        self.addCleanup(self.gateway.stop)
        self.config = json.loads(self.gateway.config.read_text())
        self.system = self.config['aiSystems'][0]
        self.system['mcp']['statefulMode'] = 'stateless'
        self.system['security']['mcpSessions'].pop('tasks', None)
        self.security = self.system['security']
        self.security['policies'] = [{'id': 'allow', 'enabled': True, 'effect': 'allow', 'tenantId': 'tenant-a'}]
        self.security['dynamicAuthorization'] = {'policyVersion': 'remote-v1', 'cacheTtlSeconds': 0}
        remote = {'rootCaPemFile': str(certificate), 'timeoutMillis': 10000}
        base = f'https://127.0.0.1:{self.authority.server_port}'
        self.security['remotePdp'] = dict(remote, endpoint=base + '/pdp')
        self.approval = dict(remote, endpoint=base + '/approval')
        self.broker = dict(remote, issueEndpoint=base + '/issue')

    def tearDown(self):
        self.evidence[self.id()] = {'toolDispatches': self.count(), 'issued': self.calls('/issue'),
                                   'approvals': self.calls('/approval'), 'consumed': len(self.server.consumed)}
        self.gateway.snapshot('remote-security-case-complete')

    def serve(self, server):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

    def start(self, *, per_core=False):
        self.gateway.config.write_text(json.dumps(self.config))
        if per_core:
            affinity = os.sched_getaffinity(0)
            try:
                os.sched_setaffinity(0, {min(affinity)})
                with mock.patch.dict(os.environ, {'THREADING_MODE': 'thread_per_core'}):
                    self.gateway.start()
            finally:
                os.sched_setaffinity(0, affinity)
        else:
            self.gateway.start()

    def high_risk(self):
        self.server.require_capability = True
        self.security['requiredToolApprovals'] = [{'toolName': 'echo'}]
        self.security['approval'], self.security['capabilityBroker'] = self.approval, self.broker

    def accepted(self, response):
        self.assertEqual(response[0], 200, response)
        self.assertTrue(any('result' in value for value in response[2]), response)

    def calls(self, path):
        with self.authority.lock:
            return sum(endpoint == path for endpoint, _ in self.authority.calls)

    def pending(self, path, **kwargs):
        self.authority.hold = path
        self.authority.entered.clear()
        self.authority.release.clear()
        self.authority.finished.clear()
        values, errors = [], []
        def invoke():
            try:
                values.append(self.request(wire.message(arguments={'record': 42}), **kwargs))
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=invoke)
        thread.start()
        self.addCleanup(thread.join, 12)
        self.addCleanup(self.authority.release.set)
        self.assertTrue(self.authority.entered.wait(6), 'remote stage was not reached')
        return thread, values, errors

    def reload(self, config):
        offset = (self.directory / 'gateway.log').stat().st_size
        candidate = self.gateway.config.with_suffix('.next')
        candidate.write_text(json.dumps(config))
        candidate.replace(self.gateway.config)
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            with (self.directory / 'gateway.log').open('rb') as log:
                log.seek(offset)
                if b'Config reloaded successfully' in log.read():
                    return
            time.sleep(.02)
        self.fail('configuration was not published')

    def test_slow_tool_pdp_keeps_single_listener_schedulable(self):
        self.start(per_core=True)
        thread, result, errors = self.pending('/pdp')
        try:
            self.deny(self.request(tenant='tenant-b'))
            self.assertTrue(thread.is_alive())
        finally:
            self.authority.release.set()
            thread.join(10)
        self.assertEqual(errors, [])
        self.accepted(result[0])
        self.assertEqual(self.count(), 1)

    def test_approved_capability_is_bound_single_use_and_caller_headers_are_replaced(self):
        self.high_risk()
        self.start()
        for _ in range(2):
            self.accepted(self.request(wire.message(arguments={'record': 42}), overrides={
                'x-ai-security-capability': 'caller-forgery', 'x-ai-security-capability-context': 'caller-forgery'}))
        self.assertEqual(self.calls('/issue'), 2)
        self.assertEqual(self.count(), 2)
        self.assertEqual(len({token for token, _, _ in self.server.consumed}), 2)
        token, context, rpc = self.server.consumed[0]
        with contextlib.closing(http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)) as client:
            client.request('POST', '/mcp', json.dumps(rpc), {'Content-Type': 'application/json',
                'x-ai-security-capability': token, 'x-ai-security-capability-context': context})
            response = client.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
        self.assertEqual(self.count(), 2)

    def test_bound_progress_and_unrelated_notifications_keep_terminal_result(self):
        self.start()
        rpc = wire.message(arguments={'transportCase': 'notifications'})
        rpc['params']['_meta']['progressToken'] = 'mine'
        status, _, values = self.request(rpc)
        self.assertEqual(status, 200, values)
        self.assertTrue(any(value.get('result', {}).get('content') for value in values), values)
        notifications = [v for v in values if 'method' in v]
        self.assertEqual(len(notifications), 1, values)
        self.assertEqual(notifications[0]['params']['progressToken'], 'mine')
        self.assertFalse(any('error' in value for value in values), values)

    def test_short_approval_is_preserved_in_issued_and_consumed_context(self):
        self.high_risk()
        self.authority.approval_ttl = 2
        self.start()
        self.accepted(self.request())
        with self.authority.lock:
            issued = [value for path, value in self.authority.calls if path == '/issue']
        self.assertEqual(len(issued), 1)
        approval = issued[0]['request']['authorizationContext'].get('approval')
        self.assertIsNotNone(approval)
        self.assertEqual(approval['approvalId'], 'trusted-approval')
        self.assertEqual(len(self.server.consumed), 1)
        context = json.loads(base64.urlsafe_b64decode(self.server.consumed[0][1] + '==='))
        self.assertEqual(context['authorizationContext']['approval'], approval)

    def test_broker_cannot_extend_or_change_approval(self):
        self.high_risk()
        self.authority.approval_ttl = 2
        self.start()
        for binding in ['extend', 'wrong', 'missing']:
            with self.subTest(binding=binding):
                self.authority.approval_binding = binding
                self.deny(self.request())
                self.assertEqual(self.count(), 0)

    def test_approval_expiring_while_issuance_waits_never_reaches_tool(self):
        self.high_risk()
        self.authority.approval_ttl = 1
        self.start()
        thread, result, errors = self.pending('/issue')
        time.sleep(1.1)
        self.authority.release.set()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.deny(result[0])
        self.assertEqual(self.count(), 0)

    def test_denied_approval_cannot_issue_or_dispatch(self):
        self.high_risk()
        self.authority.approved = False
        self.start()
        self.deny(self.request())
        self.assertGreater(self.calls('/approval'), 0)
        self.assertEqual(self.calls('/issue'), 0)
        self.assertEqual(self.count(), 0)

    def test_legacy_deny_never_publishes_a_common_capability(self):
        self.high_risk()
        self.system['mcp']['policies']['securityPipeline'] = {'policies': [
            # Reach the Tool authorization/issuance phase; Session now also defaults to deny.
            {'id': 'legacy-session', 'enabled': True, 'effect': 'allow', 'actionType': 'mcpSessionOperation'},
            {'id': 'legacy-deny', 'enabled': True, 'effect': 'deny', 'actionType': 'toolInvoke'}]}
        self.start()
        self.deny(self.request())
        self.assertEqual(self.calls('/issue'), 1)
        self.assertEqual(self.count(), 0)

    def test_configuration_revokes_waiting_approval_and_issuance(self):
        self.high_risk()
        self.start()
        original = copy.deepcopy(self.config)
        for path in ['/approval', '/issue']:
            with self.subTest(path=path):
                thread, result, errors = self.pending(path)
                try:
                    changed = copy.deepcopy(original)
                    changed['aiSystems'][0]['security']['policies'][0]['effect'] = 'deny'
                    self.reload(changed)
                    thread.join(3)
                    self.assertFalse(thread.is_alive(), 'revocation must stop waiting before peer release')
                    self.assertEqual(errors, [])
                    self.deny(result[0])
                    self.assertEqual(self.count(), 0)
                finally:
                    self.authority.release.set()
                    thread.join(10)
                self.assertTrue(self.authority.finished.wait(3))
                self.authority.hold = None
                self.reload(original)

    def control(self, path, execution=None):
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.gateway.token()}
        if execution:
            headers['x-aisp-execution-id'] = execution
        with contextlib.closing(http.client.HTTPConnection('127.0.0.1', self.gateway.port, timeout=6)) as client:
            client.request('POST', path, '{}', headers)
            response = client.getresponse()
            body = response.read()
            self.assertIn(response.status, (200, 201), body)
            return json.loads(body)

    def test_execution_cancel_discards_pending_tool_decision(self):
        self.security['executionBudget'] = {'namespace': uuid.uuid4().hex, 'maxDurationSeconds': 30,
            'maxModelCalls': 1, 'maxToolCalls': 4, 'maxAttempts': 8, 'maxConcurrent': 4}
        self.start()
        execution = self.control('/v1/executions')['executionId']
        thread, result, errors = self.pending('/pdp', overrides={'x-aisp-execution-id': execution})
        try:
            self.control('/v1/executions/cancel', execution)
            thread.join(3)
            self.assertFalse(thread.is_alive(), 'execution cancel must stop waiting before PDP release')
            self.assertEqual(errors, [])
            self.deny(result[0])
        finally:
            self.authority.release.set()
            thread.join(10)
        self.assertEqual(self.count(), 0)

    def test_broker_failure_and_mismatched_binding_are_fail_closed(self):
        self.high_risk()
        self.start()
        for bad_binding, issue_error in [(False, True), (True, False)]:
            self.authority.bad_binding, self.authority.issue_error = bad_binding, issue_error
            self.deny(self.request())
        self.assertEqual(self.count(), 0)

    def test_required_audit_failure_prevents_issuance_and_tool_side_effect(self):
        self.high_risk()
        audit = self.directory / 'audit'
        audit.mkdir(mode=0o700)
        self.config['config']['securityAudit'] = {'directory': str(audit)}
        self.security['requiredAudit'] = {'actionTypes': ['toolInvoke']}
        self.start()
        self.accepted(self.request())
        self.assertEqual(self.calls('/issue'), 1)
        segments = list(audit.glob('segment-*.jsonl'))
        self.assertTrue(segments)
        for segment in segments:
            segment.rename(segment.with_suffix('.unavailable'))
        self.deny(self.request())
        self.assertEqual(self.calls('/issue'), 1)
        self.assertEqual(self.count(), 1)
