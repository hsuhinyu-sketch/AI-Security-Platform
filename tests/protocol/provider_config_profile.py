#!/usr/bin/env python3
"""Remote security configuration preflight, CLI and reload on the production gateway."""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

import gateway_faults as fixture
from sampling_profile import tls_identity

FIELDS = ('remotePdp', 'approval', 'capabilityBroker', 'delegationRevocation', 'remoteAgentIdentity')


def provider_security(original, field, provider, mode='enforce'):
    security = copy.deepcopy(original)
    security['mode'] = mode
    if mode != 'enforce':
        security.pop('mcpSessions', None)  # Protected sessions require Enforce independently of providers.
    if field == 'remotePdp':
        security['dynamicAuthorization'] = {'policyVersion': 'preflight-v1'}
    if field in ('approval', 'capabilityBroker'):
        security['requiredToolApprovals'] = [{'toolName': 'echo'}]
    if field == 'capabilityBroker':
        security.setdefault('approval', {'endpoint': 'https://127.0.0.1:9/approve'})
    security[field] = provider
    return security


class Preflight(unittest.TestCase):
    mcp_only = True
    setUpClass = classmethod(fixture.Acceptance.setUpClass.__func__)
    tearDownClass = classmethod(fixture.Acceptance.tearDownClass.__func__)
    setUp = fixture.Acceptance.setUp
    tearDown = fixture.Acceptance.tearDown
    record_evidence = fixture.Acceptance.record_evidence
    session = fixture.Acceptance.session
    count = fixture.Acceptance.count
    denied = fixture.Acceptance.denied

    def validate(self, config):
        path = self.gateway.directory / 'validate-candidate.json'
        path.write_text(json.dumps(config))
        return subprocess.run([fixture.BINARY, '--file', str(path), '--validate-only'],
                              capture_output=True, text=True, timeout=15)

    def reload(self, config, successful):
        log = self.gateway.directory / 'gateway.log'
        offset = log.stat().st_size
        candidate = self.gateway.config.with_suffix('.next')
        candidate.write_text(json.dumps(config))
        candidate.replace(self.gateway.config)
        marker = 'Config reloaded successfully' if successful else 'Failed to reload config:'
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            tail = log.read_text()[offset:]
            if marker in tail:
                if not successful:
                    self.assertIn('endpoint', tail)
                return
            self.assertIsNone(self.gateway.process.poll())
            time.sleep(.025)
        self.fail(log.read_text()[-5000:])

    def test_validate_only_rejects_invalid_provider_configuration(self):
        original = json.loads(self.gateway.config.read_text())
        invalid = self.gateway.directory / 'invalid.pem'
        invalid.write_text('not a PEM')
        non_certificate = self.gateway.directory / 'invalid-der.pem'
        non_certificate.write_text('-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n')
        checked = 0
        for field in FIELDS:
            key = 'issueEndpoint' if field == 'capabilityBroker' else 'endpoint'
            for mode in ('enforce', 'audit', 'shadow'):
                if field == 'capabilityBroker' and mode != 'enforce':
                    continue
                for value, reason in (({key: 'http://127.0.0.1:9/unused'}, 'endpoint'),
                                      ({key: 'https://127.0.0.1:9', 'timeoutMillis': 0}, 'timeoutMillis')):
                    with self.subTest(field=field, mode=mode, reason=reason):
                        config = copy.deepcopy(original)
                        config['aiSystems'][0]['security'] = provider_security(
                            original['aiSystems'][0]['security'], field, value, mode)
                        result = self.validate(config)
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn(reason, result.stdout + result.stderr)
                        self.assertNotIn('panicked', result.stderr)
                        checked += 1
            for material, path in (('rootCaPemFile', invalid), ('rootCaPemFile', non_certificate),
                                   ('identityPemFile', invalid)):
                with self.subTest(field=field, material=material, file=path.name):
                    config = copy.deepcopy(original)
                    config['aiSystems'][0]['security'] = provider_security(
                        original['aiSystems'][0]['security'], field,
                        {key: 'https://127.0.0.1:9', material: str(path)})
                    result = self.validate(config)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('panicked', result.stderr)
                    checked += 1
        self.observations['invalidCliCandidatesRejected'] = checked

    def test_valid_tls_preflight_does_not_contact_provider(self):
        original = json.loads(self.gateway.config.read_text())
        directory = self.gateway.directory / 'preflight-tls'
        directory.mkdir()
        certificate, key = tls_identity(directory)
        identity = directory / 'identity.pem'
        identity.write_bytes(certificate.read_bytes() + key.read_bytes())
        with socket.socket() as peer:
            peer.bind(('127.0.0.1', 0))
            peer.listen(1)
            peer.setblocking(False)
            endpoint = f'https://127.0.0.1:{peer.getsockname()[1]}/unused'
            config = copy.deepcopy(original)
            security = config['aiSystems'][0]['security']
            # All five providers have valid local material, but the peer cannot speak TLS.
            for field in FIELDS:
                name = 'issueEndpoint' if field == 'capabilityBroker' else 'endpoint'
                security = provider_security(security, field, {name: endpoint,
                    'rootCaPemFile': str(certificate), 'identityPemFile': str(identity)})
            config['aiSystems'][0]['security'] = security
            result = self.validate(config)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            with self.assertRaises(BlockingIOError):
                peer.accept()
        self.observations.update(validTlsAccepted=True, providerConnections=0)

    def test_invalid_provider_reload_keeps_enforcement_and_recovers(self):
        original = json.loads(self.gateway.config.read_text())
        session = self.session()
        echo = fixture.rpc('tools/call', name='echo', arguments={})
        try:
            for field in FIELDS:
                with self.subTest(field=field):
                    key = 'issueEndpoint' if field == 'capabilityBroker' else 'endpoint'
                    config = copy.deepcopy(original)
                    security = provider_security(original['aiSystems'][0]['security'], field,
                                                 {key: 'http://127.0.0.1:9/unused'})
                    security['policies'].append({'id': 'unpublished-allow', 'effect': 'allow',
                        'enabled': True, 'actionType': 'toolInvoke', 'resourceId': 'forbidden'})
                    config['aiSystems'][0]['security'] = security
                    self.reload(config, False)
                    self.assertEqual(self.gateway.request(echo, session)[0], 200)
                    before = self.count('forbidden', effects=True)
                    self.denied(self.gateway.request(fixture.rpc('tools/call', name='forbidden', arguments={}), session))
                    self.assertEqual(self.count('forbidden', effects=True), before)
            corrected = copy.deepcopy(original)
            corrected['aiSystems'][0]['security']['policies'].append({'id': 'deny-echo',
                'effect': 'deny', 'enabled': True, 'actionType': 'toolInvoke', 'resourceId': 'echo'})
            self.reload(corrected, True)
            self.denied(self.gateway.request(echo, session))
            self.denied(self.gateway.request(echo, self.session()))
            self.reload(original, True)
            self.assertEqual(self.gateway.request(echo, self.session())[0], 200)
            self.observations.update(invalidProviderKeptSession=True, correctedPolicyApplied=True)
        finally:
            self.reload(original, True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda value: str(Path(value).resolve()))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fixture.BINARY = args.binary
    fixture.ARTIFACTS = Path(tempfile.mkdtemp(prefix='run-', dir=args.report.parent))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Preflight))
    args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
        'errors': [str(test) for test, _ in result.errors], 'failures': [str(test) for test, _ in result.failures],
        'skipped': [str(test) for test, _ in result.skipped], 'evidence': getattr(Preflight, 'evidence', {}),
        'diagnostics': getattr(getattr(Preflight, 'gateway', None), 'diagnostics', []),
        'artifacts': str(fixture.ARTIFACTS)}, indent=2) + '\n')
    raise SystemExit(not result.wasSuccessful())
