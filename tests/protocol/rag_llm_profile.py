#!/usr/bin/env python3
"""Business PoC: actual RAG issuance, version-bound context and protected model execution."""
import argparse
import collections
import concurrent.futures
import copy
from datetime import datetime, timedelta, timezone
import http.client
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time
import unittest
import uuid

import gateway_faults
import rag_profile
import rag_llm_client
from rag_profile import RagFixture
from sampling_profile import tls_identity


class Model(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        with self.server.condition:
            self.server.requests.append((self.path, dict(self.headers), body))
            self.server.condition.notify_all()
        def value(text, stream=False):
            return {'id': 'business', 'object': 'chat.completion.chunk' if stream else 'chat.completion',
                    'created': 1, 'model': 'local', 'choices': [{'index': 0, 'finish_reason': None if stream else 'stop',
                    'delta' if stream else 'message': {'role': 'assistant', 'content': text}}]}
        if not body.get('stream'):
            text = 'Answer from retrieved evidence: ' + body['messages'][-1]['content']
            encoded = json.dumps(value(text)).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        def send(text):
            data = ('data: ' + json.dumps(value(text, True)) + '\n\n').encode()
            self.wfile.write(f'{len(data):x}\r\n'.encode() + data + b'\r\n')
            self.wfile.flush()
        try:
            send('BEFORE_BUSINESS_REVOKE')
            self.server.started.set()
            if not self.server.release.wait(8):
                raise TimeoutError('business fixture did not release model stream')
            send('AFTER_BUSINESS_REVOKE')
            self.wfile.write(b'0\r\n\r\n')
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


class Pdp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))['request']
        action = request['action']['actionType']
        self.server.calls[action] += 1
        failed = self.server.fail_model and action == 'modelInvoke'
        payload = {'requestId': request['requestId'], 'effect': 'allow', 'policyId': 'business-allow',
                   'policyVersion': 'business-v1', 'expiresAt': (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()}
        encoded = json.dumps(payload).encode() if not failed else b''
        self.send_response(503 if failed else 200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class RagLlmFixture(RagFixture):
    evidence = {}

    def setUp(self):
        super().setUp()
        self.addCleanup(super().tearDown)
        self.model = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Model)
        self.model.daemon_threads = True
        self.model.condition = threading.Condition()
        self.model.requests = []
        self.model.release = threading.Event()
        self.model.started = threading.Event()
        self.model_thread = threading.Thread(target=self.model.serve_forever, daemon=True)
        self.model_thread.start()
        def close_model():
            self.model.release.set()
            self.model.shutdown()
            self.model.server_close()
            self.model_thread.join(5)
        self.addCleanup(close_model)
        self.integrity_env = 'AISP_POC_VECTOR_' + uuid.uuid4().hex.upper()
        os.environ[self.integrity_env] = os.urandom(32).hex()
        self.addCleanup(lambda: os.environ.pop(self.integrity_env, None))
        original = json.loads(self.gateway.config.read_text())['aiSystems'][0]
        bindings = {
            'RAG_PORT': self.port, 'LLM_PORT': self.gateway.model_port,
            'VECTOR_URL': f'http://127.0.0.1:{self.backend.server_port}',
            'EMBEDDING_URL': f'http://127.0.0.1:{self.backend.server_port}/embeddings',
            'MODEL_BASE_URL': f'http://127.0.0.1:{self.model.server_port}/v1',
            'MODEL_TARGET': f'127.0.0.1:{self.model.server_port}', 'INTEGRITY_ENV': self.integrity_env,
            'CONTEXT_JOURNAL': str(self.directory / 'contexts.jsonl'),
            'DOCUMENT_JOURNAL': str(self.directory / 'documents.jsonl'),
            'JWKS_JSON': original['llm']['policies']['jwtAuth']['jwks'],
        }
        def expand(value):
            if isinstance(value, dict):
                return {k: expand(v) for k, v in value.items()}
            if isinstance(value, list):
                return [expand(v) for v in value]
            if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
                return bindings[value[2:-1]]
            return value
        example = (Path(__file__).resolve().parents[2] / 'docs/examples/rag-llm-poc.md').read_text()
        template = json.loads(example.split('```json\n', 1)[1].split('\n```', 1)[0])
        self.config['aiSystems'] = expand(template)['aiSystems']
        self.gateway.listener_ports = (self.port, self.gateway.model_port)

    def tearDown(self):
        # Both fixture generations are registered as cleanups, including setup failures.
        pass

    def call(self, port, path, body, context=None, token=True, extra=None, stream=False):
        headers = {'Content-Type': 'application/json'}
        if token is not None:
            headers['Authorization'] = 'Bearer ' + (self.gateway.token() if token is True else token)
        if context is not None:
            headers['x-aisp-context-id'] = context
        headers.update(extra or {})
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=6)
        connection.request('POST', path, json.dumps(body), headers)
        response = connection.getresponse()
        if stream:
            return connection, response
        try:
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def context(self, parent=None, token=True):
        status, headers, body = self.call(self.port, '/v1/rag/query',
                                         {'corpusId': 'docs', 'query': 'question', 'limit': 4}, parent, token)
        self.assertEqual(status, 200, body)
        self.assertIn('x-aisp-context-id', headers)
        return headers['x-aisp-context-id'], json.loads(body)

    def generate(self, context, result=None, token=True, extra=None, stream=False):
        text = '\n'.join(c['content'] for c in result['chunks']) if result is not None else 'question'
        return self.call(self.gateway.model_port, '/v1/chat/completions',
                         {'model': 'local', 'messages': [{'role': 'user', 'content': text}], 'stream': stream},
                         context, token, extra, stream)

    def begin(self):
        self.start()
        self.seed()
        return self.context()

    def assert_blocked(self, reply, before):
        self.assertIn(reply[0], (400, 401, 403), reply)
        self.assertEqual(len(self.model.requests), before, 'denial reached the model')

    def document(self, mutation=None, revision=None):
        body = {'corpusId': 'docs', 'documentId': 'document'}
        if mutation is not None:
            body.update(mutation=mutation, expectedRevision=revision)
        status, _, wire = self.call(self.port, '/v1/rag/documents/lifecycle', body)
        self.assertEqual(status, 200, wire)
        return json.loads(wire)

    def revoke(self, context, token=True):
        return self.call(self.port, '/v1/rag/contexts/revoke', {'contextId': context}, token=token)

class RagLlm(RagLlmFixture):
    evidence = {}

    def test_query_context_generation_uses_actual_guarded_chunks(self):
        context, result = self.begin()
        status, _, answer = self.generate(context, result)
        self.assertEqual(status, 200, answer)
        self.assertIn(b'visible knowledge', answer)
        self.assertTrue(result['chunks'])
        self.assertTrue(all(c['sourceOrigin']['kind'] == 'lifecycle' for c in result['chunks']))
        path, headers, body = self.model.requests[-1]
        self.assertEqual(path, '/v1/chat/completions')
        self.assertEqual(body['messages'][-1]['content'], '\n'.join(c['content'] for c in result['chunks']))
        self.assertNotIn('x-aisp-context-id', {k.lower(): v for k, v in headers.items()})
        self.evidence[self.id()] = {'actualModelCalls': len(self.model.requests), 'guardedChunks': len(result['chunks']),
                                    'documentVersionPinned': True, 'internalContextHeaderRemoved': True}

    def test_business_cli_uses_the_query_and_authorized_evidence(self):
        self.start()
        self.seed()
        query = 'What evidence is available?'
        env = dict(os.environ, AISP_POC_TOKEN=self.gateway.token())
        process = subprocess.run([sys.executable, str(Path(__file__).with_name('rag_llm_client.py')),
            '--rag-url', f'http://127.0.0.1:{self.port}', '--llm-url', f'http://127.0.0.1:{self.gateway.model_port}',
            '--corpus', 'docs', '--query', query], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result['documents'], ['document'])
        self.assertIn('visible knowledge', result['answer'])
        supplied = json.loads(self.model.requests[0][2]['messages'][-1]['content'])
        self.assertEqual(supplied['question'], query)
        self.assertEqual(supplied['context'][0]['content'], 'visible knowledge')
        self.assertNotIn(env['AISP_POC_TOKEN'], process.stdout + process.stderr)

    def test_business_client_retrieval_denial_does_not_invoke_model(self):
        self.deny('knowledgeRetrieve')
        self.start()
        self.seed()
        with self.assertRaisesRegex(rag_llm_client.PocError, 'RAG: request rejected'):
            rag_llm_client.answer(f'http://127.0.0.1:{self.port}', f'http://127.0.0.1:{self.gateway.model_port}',
                                  self.gateway.token(), 'docs', 'question')
        self.assertEqual(len(self.model.requests), 0)

    def test_business_client_empty_evidence_does_not_invoke_model(self):
        self.start()
        with self.assertRaisesRegex(rag_llm_client.PocError, 'no authorized evidence'):
            rag_llm_client.answer(f'http://127.0.0.1:{self.port}', f'http://127.0.0.1:{self.gateway.model_port}',
                                  self.gateway.token(), 'docs', 'question')
        self.assertEqual(len(self.model.requests), 0)

    def test_missing_forged_and_foreign_contexts_do_not_dispatch(self):
        context, _ = self.begin()
        for value, token in [(None, True), ('not-a-context', True), (str(uuid.uuid4()), True),
                             (context, self.gateway.token(user='bob')), (context, self.gateway.token(tenant='tenant-b')),
                             (context, None), (context, self.gateway.token()[:-4] + 'xxxx')]:
            with self.subTest(context=value, tokenProvided=token is not None):
                self.assert_blocked(self.generate(value, token=token), 0)

    def test_expired_context_does_not_dispatch(self):
        self.system['security']['crossComponent']['ttlSeconds'] = 1
        context, _ = self.begin()
        time.sleep(1.1)
        self.assert_blocked(self.generate(context), 0)

    def test_classification_cannot_be_downgraded_by_request_headers(self):
        self.system['security']['crossComponent']['destinations'][-1]['modelDestinations'] = []
        context, _ = self.begin()
        self.assert_blocked(self.generate(context, extra={'x-classification': 'public'}), 0)

    def test_owner_bound_revocation_does_not_allow_foreign_revoke(self):
        context, result = self.begin()
        self.assertIn(self.revoke(context, self.gateway.token(user='bob'))[0], (400, 403))
        self.assertEqual(self.generate(context, result)[0], 200)
        self.assertEqual(self.revoke(context)[0], 200)
        self.assert_blocked(self.generate(context, result), 1)
        self.assert_blocked(self.call(self.port, '/v1/rag/query', {'corpusId': 'docs', 'query': 'q', 'limit': 4}, context), 1)

    def test_document_update_invalidates_old_context_and_new_context_uses_new_content(self):
        context, result = self.begin()
        before = self.document()['revision']
        status, wire = self.ingest('updated evidence')
        self.assertEqual(status, 201, wire)
        self.assertGreater(self.document()['revision'], before)
        self.assert_blocked(self.generate(context, result), 0)
        fresh, updated = self.context()
        self.assertTrue(updated['chunks'])
        self.assertTrue(all('updated evidence' in c['content'] for c in updated['chunks']))
        self.assertEqual(self.generate(fresh, updated)[0], 200)

    def test_acl_revision_rejects_old_context_and_filters_current_retrieval(self):
        context, result = self.begin()
        revision = self.document()['revision']
        self.document({'type': 'acl', 'access': {'allowedUsers': ['bob'], 'allowTenantAuthenticated': False}}, revision)
        self.assert_blocked(self.generate(context, result), 0)
        _, filtered = self.context()
        self.assertEqual(filtered['chunks'], [])
        bob = self.gateway.token(user='bob')
        fresh, visible = self.context(token=bob)
        self.assertTrue(visible['chunks'])
        self.assertEqual(self.generate(fresh, visible, token=bob)[0], 200)

    def stop_stream(self, mutation):
        context, result = self.begin()
        connection, response = self.generate(context, result, stream=True)
        self.addCleanup(connection.close)
        self.assertEqual(response.status, 200)
        first = b''
        while b'BEFORE_BUSINESS_REVOKE' not in first:
            line = response.readline()
            self.assertTrue(line, first)
            first += line
        mutation(context)
        self.model.release.set()
        try:
            tail = response.read()
        except http.client.IncompleteRead as error:
            tail = error.partial
        self.assertNotIn(b'AFTER_BUSINESS_REVOKE', tail)
        self.assertEqual(len(self.model.requests), 1)

    def test_model_stream_stops_after_document_revocation(self):
        def mutation(_):
            self.document({'type': 'revoke'}, self.document()['revision'])
        self.stop_stream(mutation)

    def test_model_stream_stops_after_context_revocation(self):
        def mutation(context):
            self.assertEqual(self.revoke(context)[0], 200)
        self.stop_stream(mutation)

    def test_failed_candidate_preserves_context_but_live_policy_change_reauthorizes(self):
        context, result = self.begin()
        original = copy.deepcopy(self.system['rag'])
        self.system['rag']['retrieval'] = {'maxChunks': 0, 'maxContextTokens': 10}
        self.reload(successful=False)
        self.assertEqual(self.generate(context, result)[0], 200)
        self.system['rag'] = original
        self.deny('modelInvoke')
        self.reload()
        self.assert_blocked(self.generate(context, result), 1)
        fresh, updated = self.context()
        self.assert_blocked(self.generate(fresh, updated), 1)

    def test_context_journal_failure_is_closed_before_model(self):
        context, result = self.begin()
        (self.directory / 'contexts.jsonl').write_bytes(b'')
        self.assert_blocked(self.generate(context, result), 0)

    def test_document_authority_failure_is_closed_before_model(self):
        context, result = self.begin()
        (self.directory / 'documents.jsonl').write_bytes(b'')
        self.assert_blocked(self.generate(context, result), 0)

    def test_required_model_audit_failure_does_not_dispatch(self):
        audit = self.directory / 'audit'
        audit.mkdir(mode=0o700)
        self.config['config']['securityAudit'] = {'directory': str(audit)}
        self.system['security']['requiredAudit'] = {'actionTypes': ['modelInvoke']}
        context, result = self.begin()
        self.assertEqual(self.generate(context, result)[0], 200)
        self.assertTrue(list(audit.glob('segment-*.jsonl')))
        audit.rename(audit.with_suffix('.unavailable'))
        self.assert_blocked(self.generate(context, result), 1)

    def test_live_pdp_failure_does_not_dispatch_model_with_valid_context(self):
        certificate, key = tls_identity(self.directory)
        pdp = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Pdp)
        pdp.calls = collections.Counter()
        pdp.fail_model = False
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certificate, key)
        pdp.socket = tls.wrap_socket(pdp.socket, server_side=True)
        thread = threading.Thread(target=pdp.serve_forever, daemon=True)
        thread.start()
        def close_pdp():
            pdp.shutdown()
            pdp.server_close()
            thread.join(5)
        self.addCleanup(close_pdp)
        self.system['security']['dynamicAuthorization'] = {'policyVersion': 'business-v1', 'cacheTtlSeconds': 0}
        self.system['security']['remotePdp'] = {'endpoint': f'https://127.0.0.1:{pdp.server_port}/pdp',
                                              'rootCaPemFile': str(certificate), 'timeoutMillis': 500}
        context, result = self.begin()
        self.assertEqual(self.generate(context, result)[0], 200)
        before = pdp.calls['modelInvoke']
        pdp.fail_model = True
        self.assert_blocked(self.generate(context, result), 1)
        self.assertGreater(pdp.calls['modelInvoke'], before)

    def test_concurrent_context_use_and_acknowledged_revocation(self):
        context, result = self.begin()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            replies = list(pool.map(lambda _: self.generate(context, result), range(4)))
        self.assertTrue(all(reply[0] == 200 for reply in replies), replies)
        self.assertEqual(len(self.model.requests), 4)
        self.assertEqual(self.revoke(context)[0], 200)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            replies = list(pool.map(lambda _: self.generate(context, result), range(4)))
        for reply in replies:
            self.assert_blocked(reply, 4)

    def test_vector_payload_tampering_never_reaches_context_or_model(self):
        self.start()
        self.seed()
        candidate = copy.deepcopy(self.backend.points[0])
        candidate['payload']['content'] = 'FORGED_VECTOR_SECRET'
        self.backend.override = [candidate]
        status, _, body = self.call(self.port, '/v1/rag/query', {'corpusId': 'docs', 'query': 'q', 'limit': 4})
        self.assertEqual(status, 502, body)
        self.assertNotIn(b'FORGED_VECTOR_SECRET', body)
        self.assertEqual(len(self.model.requests), 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    rag_profile.BINARY = args.binary
    if args.report:
        gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RagLlm))
    if args.report:
        args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
            'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors],
            'skipped': [str(t) for t, _ in result.skipped], 'evidence': RagLlm.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
