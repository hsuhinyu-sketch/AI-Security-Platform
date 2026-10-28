#!/usr/bin/env python3
"""2025 MCP Task Sampling compatibility against the production binary and real TCP."""
import argparse
import collections
import concurrent.futures
import contextlib
import copy
import ctypes
import http.client
import http.server
import json
import ssl
import socket
from pathlib import Path
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
import gateway_faults
from gateway_faults import Gateway, Signer, Upstream, rpc

RELATED = 'io.modelcontextprotocol/related-task'


def tls_identity(directory):
    """Disposable localhost certificate via the fixture's existing system libcrypto."""
    signer = Signer()
    library = signer.crypto
    pointer = ctypes.c_void_p
    signatures = {
        'X509_new': (pointer, []), 'X509_free': (None, [pointer]),
        'X509_set_version': (ctypes.c_int, [pointer, ctypes.c_long]),
        'X509_get_serialNumber': (pointer, [pointer]),
        'ASN1_INTEGER_set': (ctypes.c_int, [pointer, ctypes.c_long]),
        'X509_getm_notBefore': (pointer, [pointer]), 'X509_getm_notAfter': (pointer, [pointer]),
        'X509_gmtime_adj': (pointer, [pointer, ctypes.c_long]),
        'X509_set_pubkey': (ctypes.c_int, [pointer, pointer]),
        'X509_get_subject_name': (pointer, [pointer]),
        'X509_NAME_add_entry_by_txt': (ctypes.c_int, [pointer, ctypes.c_char_p, ctypes.c_int,
                                                   ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]),
        'X509_set_issuer_name': (ctypes.c_int, [pointer, pointer]),
        'X509V3_EXT_conf': (pointer, [pointer, pointer, ctypes.c_char_p, ctypes.c_char_p]),
        'X509_add_ext': (ctypes.c_int, [pointer, pointer, ctypes.c_int]),
        'X509_EXTENSION_free': (None, [pointer]),
        'X509_sign': (ctypes.c_int, [pointer, pointer, pointer]),
        'BIO_s_mem': (pointer, []), 'BIO_new': (pointer, [pointer]), 'BIO_free': (ctypes.c_int, [pointer]),
        'BIO_ctrl_pending': (ctypes.c_size_t, [pointer]),
        'BIO_read': (ctypes.c_int, [pointer, pointer, ctypes.c_int]),
        'PEM_write_bio_X509': (ctypes.c_int, [pointer, pointer]),
        'PEM_write_bio_PrivateKey': (ctypes.c_int, [pointer, pointer, pointer, pointer, ctypes.c_int, pointer, pointer]),
    }
    for name, (result, arguments) in signatures.items():
        function = getattr(library, name)
        function.restype, function.argtypes = result, arguments
    certificate = library.X509_new()
    if not certificate:
        signer.close()
        raise RuntimeError('cannot allocate test certificate')
    try:
        Signer.check(library.X509_set_version(certificate, 2))
        Signer.check(library.ASN1_INTEGER_set(library.X509_get_serialNumber(certificate), 1))
        for field, offset in [(library.X509_getm_notBefore, -60), (library.X509_getm_notAfter, 3600)]:
            if not library.X509_gmtime_adj(field(certificate), offset):
                raise RuntimeError('cannot set test certificate validity')
        Signer.check(library.X509_set_pubkey(certificate, signer.key))
        subject = library.X509_get_subject_name(certificate)
        Signer.check(library.X509_NAME_add_entry_by_txt(subject, b'CN', 0x1001, b'localhost', -1, -1, 0))
        Signer.check(library.X509_set_issuer_name(certificate, subject))
        extension = library.X509V3_EXT_conf(None, None, b'subjectAltName', b'IP:127.0.0.1')
        if not extension:
            raise RuntimeError('cannot construct localhost SAN')
        try:
            Signer.check(library.X509_add_ext(certificate, extension, -1))
        finally:
            library.X509_EXTENSION_free(extension)
        if library.X509_sign(certificate, signer.key, None) <= 0:
            raise RuntimeError('cannot sign test certificate')
        paths = []
        for name, writer in [('pdp.pem', lambda bio: library.PEM_write_bio_X509(bio, certificate)),
                             ('pdp-key.pem', lambda bio: library.PEM_write_bio_PrivateKey(bio, signer.key, None, None, 0, None, None))]:
            bio = library.BIO_new(library.BIO_s_mem())
            if not bio:
                raise RuntimeError('cannot allocate PEM buffer')
            try:
                Signer.check(writer(bio))
                length = library.BIO_ctrl_pending(bio)
                buffer = ctypes.create_string_buffer(length)
                if library.BIO_read(bio, buffer, length) != length:
                    raise RuntimeError('incomplete PEM encoding')
                path = directory / name
                path.write_bytes(buffer.raw)
                path.chmod(0o600)
                paths.append(path)
            finally:
                library.BIO_free(bio)
        return paths
    finally:
        library.X509_free(certificate)
        signer.close()


class Pdp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        query = json.loads(self.rfile.read(int(self.headers['Content-Length'])))['request']
        failed = query['action']['actionType'] == 'modelInvoke'
        if failed:
            self.server.model_failures += 1
        body = json.dumps({'requestId': query['requestId'], 'effect': 'allow', 'policyId': 'test-pdp',
            'policyVersion': 'sampling-v1', 'expiresAt': (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()}).encode()
        self.send_response(503 if failed else 200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SamplingUpstream(Upstream):
    def do_POST(self):
        payload = self.rfile.read(int(self.headers['Content-Length']))
        message = json.loads(payload)
        if self.path.endswith('/chat/completions'):
            self.chat(message)
            return
        if 'method' not in message:
            with self.server.lock:
                self.server.answers.append(message)
            self.reply(202)
            self.server.answered.set()
            return
        if message['method'] == 'tasks/result':
            with self.server.lock:
                self.server.calls['tasks/result'] += 1
            params = {'messages': [{'role': 'user', 'content': {'type': 'text', 'text': 'hello'}}],
                      'modelPreferences': {'hints': [{'name': 'local'}]}, 'maxTokens': 8,
                      '_meta': {RELATED: {'taskId': message['params']['taskId']}}}
            params.update(self.server.sampling_changes)
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            def emit(value):
                data = ('data: ' + json.dumps(value) + '\n\n').encode()
                self.wfile.write(f'{len(data):x}\r\n'.encode() + data + b'\r\n')
                self.wfile.flush()

            try:
                emit({'jsonrpc': '2.0', 'id': 'sample-1', 'method': 'sampling/createMessage', 'params': params})
                if self.server.answered.wait(4):
                    emit({'jsonrpc': '2.0', 'id': message['id'], 'result': {
                        'content': [{'type': 'text', 'text': 'sampled'}],
                        '_meta': {RELATED: {'taskId': message['params']['taskId']}}}})
                self.wfile.write(b'0\r\n\r\n')
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        # Reuse the ordinary MCP fixture without changing production interfaces.
        import io
        original = self.rfile
        self.rfile = io.BytesIO(payload)
        try:
            super().do_POST()
        finally:
            self.rfile = original

    def chat(self, request):
        with self.server.lock:
            self.server.calls['chat'] += 1
            self.server.model_requests.append(request)
        self.server.model_started.set()
        if not self.server.model_release.wait(8):
            raise TimeoutError('test did not release model response')
        if self.server.model_status == 0:
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        if self.server.model_status != 200:
            self.reply(self.server.model_status, {'error': {'message': 'unavailable'}})
            return
        try:
            self.reply(200, {'id': 'sample', 'object': 'chat.completion', 'created': 1,
                'model': 'local', 'choices': [{'index': 0, 'finish_reason': 'stop',
                'message': {'role': 'assistant', 'content': 'generated'}}],
                'usage': {'prompt_tokens': 2, 'completion_tokens': 1, 'total_tokens': 3}})
        except (BrokenPipeError, ConnectionResetError):
            pass


class Sampling(unittest.TestCase):
    evidence = {}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aisp-sampling-')
        self.addCleanup(self.temp.cleanup)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), SamplingUpstream)
        self.server.daemon_threads = True
        self.server.lock = threading.Lock()
        self.server.calls = collections.Counter()
        self.server.effects = collections.Counter()
        self.server.answers = []
        self.server.model_requests = []
        self.server.sampling_changes = {}
        self.server.answered = threading.Event()
        self.server.model_started = threading.Event()
        self.server.model_release = threading.Event()
        self.server.model_release.set()
        self.server.model_status = 200
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.gateway = Gateway(BINARY, Path(self.temp.name), self.server.server_port)
        if self.gateway.artifacts is not None:
            self.gateway.artifacts /= self.id().rsplit('.', 1)[-1]
        self.addCleanup(self.gateway.signer.close)
        self.addCleanup(self.gateway.stop)
        self.addCleanup(self.server.model_release.set)
        config = json.loads(self.gateway.config.read_text())
        security = config['aiSystems'][0]['security']
        security['executionBudget'] = {'namespace': str(uuid.uuid4()), 'maxModelCalls': 1,
            'maxToolCalls': 1, 'maxAttempts': 32, 'maxConcurrent': 4}
        security['mcpSessions'].update({'reauthorizeSeconds': 1, 'reverse': {
            'samplingModels': ['local'], 'timeoutSeconds': 3}, 'tasks': {'tools': ['echo'],
            'sampling': {'authority': f'127.0.0.1:{self.gateway.model_port}',
                         'path': '/v1/chat/completions', 'model': 'local'}}})
        security['policies'].append({'id': 'execution', 'actionType': 'executionOperation',
            'effect': 'allow', 'enabled': True, 'tenantId': 'tenant-a'})
        self.config = config
        self.addCleanup(self.record)

    def record(self):
        self.gateway.snapshot('sampling-case-complete')
        with self.server.lock:
            self.evidence[self.id()] = {'upstreamCalls': dict(self.server.calls),
                'samplingAnswers': len(self.server.answers), 'modelRequests': len(self.server.model_requests)}

    def start(self):
        self.gateway.config.write_text(json.dumps(self.config))
        self.gateway.start()

    def http(self, path, body, *, execution=None):
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.gateway.token()}
        if execution:
            headers['x-aisp-execution-id'] = execution
        with contextlib.closing(http.client.HTTPConnection('127.0.0.1', self.gateway.model_port, timeout=8)) as client:
            client.request('POST', path, json.dumps(body), headers)
            response = client.getresponse()
            value = response.read()
            self.assertIn(response.status, (200, 201), value)
            return json.loads(value)

    def request(self, message, *, session=None, execution=None, invocation=None, tenant='tenant-a'):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': '2025-11-25', 'Authorization': 'Bearer ' + self.gateway.token(tenant=tenant)}
        if session:
            headers['Mcp-Session-Id'] = session
        if execution:
            headers['x-aisp-execution-id'] = execution
        if invocation:
            headers['x-aisp-invocation-id'] = invocation
        with contextlib.closing(http.client.HTTPConnection('127.0.0.1', self.gateway.port, timeout=8)) as client:
            client.request('POST', '/mcp', json.dumps(message), headers)
            response = client.getresponse()
            try:
                body = response.read()
            except http.client.IncompleteRead as error:
                body = error.partial
            values = []
            if 'text/event-stream' in response.getheader('Content-Type', ''):
                values = [json.loads(line[5:]) for line in body.splitlines() if line.startswith(b'data:')]
            elif body:
                try:
                    values = [json.loads(body)]
                except json.JSONDecodeError:
                    pass
            return response.status, dict(response.getheaders()), values

    def task(self, *, capabilities=None):
        execution = self.http('/v1/executions', {})['executionId']
        invocation = self.http('/v1/executions/invocations', {'server': 'local', 'tool': 'echo',
            'arguments': {}}, execution=execution)['invocationId']
        status, headers, values = self.request(rpc('initialize', protocolVersion='2025-11-25',
            capabilities={'sampling': {}} if capabilities is None else capabilities,
            clientInfo={'name': 'sampling-client', 'version': '1'}), execution=execution)
        self.assertEqual(status, 200, values)
        session = next(v for k, v in headers.items() if k.lower() == 'mcp-session-id')
        self.request({'jsonrpc': '2.0', 'method': 'notifications/initialized'}, session=session, execution=execution)
        self.request(rpc('tools/list'), session=session, execution=execution)
        status, _, values = self.request(rpc('tools/call', name='echo', arguments={}, task={'ttl': 60000}),
            session=session, execution=execution, invocation=invocation)
        self.assertEqual(status, 200, values)
        task = next(v['result']['task']['taskId'] for v in values if 'result' in v)
        return session, execution, task

    def result(self, task, **extra):
        session, execution, task_id = task
        return self.request(rpc('tasks/result', taskId=task_id), session=session, execution=execution, **extra)

    def test_managed_sampling_round_trip_once(self):
        self.start()
        # The administrator enables gateway-managed Sampling; the downstream client
        # does not need to implement inference or advertise its own Sampling handler.
        task = self.task(capabilities={})
        status, _, values = self.result(task)
        self.assertEqual(status, 200, values)
        self.assertTrue(any(v.get('result', {}).get('content', [{}])[0].get('text') == 'sampled' for v in values), values)
        self.assertEqual(self.server.calls['chat'], 1)
        self.assertEqual(len(self.server.answers), 1)
        self.assertEqual(self.server.answers[0]['result']['content']['text'], 'generated')
        self.assertEqual(self.server.model_requests[0]['max_tokens'], 8)
        with contextlib.closing(http.client.HTTPConnection('127.0.0.1', self.gateway.model_port, timeout=5)) as client:
            client.request('POST', '/v1/chat/completions', json.dumps({'model': 'local',
                'messages': [{'role': 'user', 'content': 'second call'}]}),
                {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.gateway.token(),
                 'x-aisp-execution-id': task[1]})
            response = client.getresponse()
            self.assertEqual(response.status, 429, response.read())
        self.assertEqual(self.server.calls['chat'], 1)  # The nested call debited this workflow.

    def assert_denied(self, response):
        status, _, values = response
        self.assertTrue(status >= 400 or any('error' in v for v in values), response)
        self.assertFalse(any('result' in v for v in values), response)

    def test_foreign_model_never_calls_model(self):
        self.start()
        self.server.sampling_changes['modelPreferences'] = {'hints': [{'name': 'foreign'}]}
        self.assert_denied(self.result(self.task()))
        self.assertEqual(self.server.calls['chat'], 0)
        self.assertEqual(len(self.server.answers), 0)

    def test_excessive_tokens_never_call_model(self):
        self.start()
        self.server.sampling_changes['maxTokens'] = 257
        self.assert_denied(self.result(self.task()))
        self.assertEqual(self.server.calls['chat'], 0)

    def test_disabled_sampling_and_cross_tenant_never_dispatch(self):
        limits = self.config['aiSystems'][0]['security']['mcpSessions']
        del limits['tasks']['sampling']
        limits['reverse']['samplingModels'] = []
        self.start()
        task = self.task(capabilities={})
        self.assert_denied(self.result(task, tenant='tenant-b'))
        self.assertEqual(self.server.calls['tasks/result'], 0)
        self.assert_denied(self.result(task))
        self.assertEqual(self.server.calls['chat'], 0)

    def assert_closed_without_result(self, response):
        # Cancellation after HTTP headers were committed can end the protected
        # SSE body without an RPC error frame. It must disclose no result/request.
        status, headers, values = response
        self.assertTrue(status >= 400 or 'text/event-stream' in headers.get('content-type', ''))
        self.assertTrue(all('error' in v and 'result' not in v and 'method' not in v for v in values), values)

    def test_model_policy_denial_never_calls_model(self):
        self.config['aiSystems'][0]['security']['policies'].append({
            'id': 'deny-model', 'actionType': 'modelInvoke', 'effect': 'deny', 'enabled': True})
        self.start()
        self.assert_denied(self.result(self.task()))
        self.assertEqual(self.server.calls['chat'], 0)
        self.assertEqual(len(self.server.answers), 0)

    def separate_model_system(self):
        parent = self.config['aiSystems'][0]
        listeners = [self.gateway.role_ports.reservations.enter_context(socket.socket()) for _ in range(2)]
        for listener in listeners:
            listener.bind(('127.0.0.1', 0))
        parent['security']['mcpSessions']['tasks']['sampling']['authority'] = f'127.0.0.1:{listeners[1].getsockname()[1]}'
        # The common security declaration includes MCP session controls, so the second
        # system also provides MCP. Original controls keep creating the parent's budget.
        model = copy.deepcopy(parent)
        model['name'] += '-model'
        model['mcp']['port'] = listeners[0].getsockname()[1]
        model['llm']['port'] = listeners[1].getsockname()[1]
        self.config['aiSystems'].append(model)
        return model

    def test_equal_configuration_in_distinct_protocol_systems_allows_sampling(self):
        self.separate_model_system()
        self.start()
        reply = self.result(self.task())
        self.assertEqual(reply[0], 200, reply)
        self.assertEqual(self.server.calls['chat'], 1)
        self.assertEqual(len(self.server.answers), 1)

    def test_different_allowing_model_configuration_never_dispatches_sampling(self):
        model = self.separate_model_system()
        # Both configurations authorize the model; differing declared constraints still cannot
        # satisfy the originating protocol's exact model-route contract.
        model['security']['policies'].append({
            'id': 'another-allow-model', 'actionType': 'modelInvoke', 'effect': 'allow',
            'enabled': True, 'tenantId': 'tenant-a'})
        self.start()
        self.assert_denied(self.result(self.task()))
        self.assertEqual(self.server.calls['chat'], 0)
        self.assertEqual(self.server.answers, [])

    def test_unregistered_local_port_never_becomes_a_network_destination(self):
        self.config['aiSystems'][0]['security']['mcpSessions']['tasks']['sampling']['authority'] = f'127.0.0.1:{self.server.server_port}'
        self.start()
        self.assert_denied(self.result(self.task()))
        self.assertEqual(self.server.calls['chat'], 0)
        self.assertEqual(len(self.server.answers), 0)

    def test_failed_and_lost_model_responses_never_retry_or_replay(self):
        self.config['policies'] = [{'name': {'name': 'sampling-retry', 'namespace': 'internal'},
            'target': {'route': {'name': 'ai-system:fault-acceptance:llm:request', 'namespace': 'internal'}},
            'policy': {'retry': {'attempts': 5, 'codes': [503]}}}]
        self.start()
        for expected, status in enumerate((503, 0), start=1):
            self.server.model_status = status
            task = self.task()
            self.assert_denied(self.result(task))
            self.assertEqual(self.server.calls['chat'], expected)
            self.assert_denied(self.result(task))  # Same interaction ID is single-use.
            self.assertEqual(self.server.calls['chat'], expected)
            self.assertEqual(len(self.server.answers), 0)

    def test_cancelled_execution_stops_pending_model_and_parallel_result(self):
        self.server.model_release.clear()
        self.start()
        task = self.task()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.result, task)
            self.assertTrue(self.server.model_started.wait(3))
            self.assert_denied(self.result(task))  # Cannot hold a second Task result lease.
            self.assertFalse(pending.done())
            self.http('/v1/executions/cancel', {}, execution=task[1])
            self.assert_closed_without_result(pending.result(timeout=4))
            self.assertEqual(self.server.calls['chat'], 1)
            self.assertEqual(len(self.server.answers), 0)

    def test_configuration_revocation_stops_pending_model(self):
        self.server.model_release.clear()
        self.start()
        task = self.task()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.result, task)
            self.assertTrue(self.server.model_started.wait(3))
            self.assertFalse(pending.done())
            self.config['aiSystems'][0]['security']['policies'].append({
                'id': 'revoke-model', 'actionType': 'modelInvoke', 'effect': 'deny', 'enabled': True})
            replacement = self.gateway.config.with_suffix('.next')
            replacement.write_text(json.dumps(self.config))
            replacement.replace(self.gateway.config)
            self.assert_closed_without_result(pending.result(timeout=5))
            self.assertEqual(self.server.calls['chat'], 1)
            self.assertEqual(len(self.server.answers), 0)

    def test_timeout_drops_model_without_reply(self):
        self.server.model_release.clear()
        self.start()
        task = self.task()
        started = time.monotonic()
        self.assert_denied(self.result(task))
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(self.server.calls['chat'], 1)
        self.assertEqual(len(self.server.answers), 0)

    def test_required_audit_quarantine_denies_model_dispatch(self):
        audit = Path(self.temp.name) / 'audit'
        audit.mkdir(mode=0o700)
        self.config['config']['securityAudit'] = {'directory': str(audit)}
        self.config['aiSystems'][0]['security']['requiredAudit'] = {'actionTypes': ['modelInvoke']}
        self.start()
        task = self.task()
        segments = list(audit.glob('segment-*.jsonl'))
        self.assertTrue(segments)
        # Real persistence fault: remove the journal pathname after admission.
        # The still-open FD must not let required auditing silently succeed.
        for segment in segments:
            segment.rename(segment.with_suffix('.unavailable'))
        self.assert_denied(self.result(task))
        self.assertEqual(self.server.calls['chat'], 0)
        self.assertEqual(len(self.server.answers), 0)
        self.assertIn('required-audit-unavailable', (self.gateway.directory / 'gateway.log').read_text())

    def test_remote_pdp_failure_is_fail_closed_for_model_dispatch(self):
        certificate, key = tls_identity(Path(self.temp.name))
        pdp = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Pdp)
        pdp.daemon_threads = True
        pdp.model_failures = 0
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certificate, key)
        pdp.socket = tls.wrap_socket(pdp.socket, server_side=True)
        thread = threading.Thread(target=pdp.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(pdp.server_close)
        self.addCleanup(pdp.shutdown)
        security = self.config['aiSystems'][0]['security']
        security['dynamicAuthorization'] = {'policyVersion': 'sampling-v1', 'cacheTtlSeconds': 0}
        security['remotePdp'] = {'endpoint': f'https://127.0.0.1:{pdp.server_port}/pdp',
            'rootCaPemFile': str(certificate), 'timeoutMillis': 500}
        self.start()
        self.assert_denied(self.result(self.task()))
        self.assertGreater(pdp.model_failures, 0)
        self.assertEqual(self.server.calls['chat'], 0)
        self.assertEqual(len(self.server.answers), 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    BINARY = args.binary
    if args.report:
        gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Sampling))
    if args.report:
        args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
            'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors],
            'skipped': [str(t) for t, _ in result.skipped], 'evidence': Sampling.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
