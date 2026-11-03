#!/usr/bin/env python3
"""Listener removal, re-addition and readiness on real TCP in both Host modes."""
import argparse
import copy
import http.client
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest

import gateway_faults as fixture
from config_reload_profile import Reload


class ListenerLifecycle:
    mcp_only = True
    tearDownClass = classmethod(fixture.Acceptance.tearDownClass.__func__)
    setUp = fixture.Acceptance.setUp
    tearDown = fixture.Acceptance.tearDown
    record_evidence = fixture.Acceptance.record_evidence
    session = fixture.Acceptance.session
    count = fixture.Acceptance.count
    denied = fixture.Acceptance.denied
    reload = Reload.reload

    @classmethod
    def setUpClass(cls):
        # Keep per-core acceptance small and deterministic. The gateway inherits
        # the fixture's allowed CPUs; no production-only test switch is needed.
        affinity = os.sched_getaffinity(0)
        previous = os.environ.get('THREADING_MODE')
        try:
            os.sched_setaffinity(0, sorted(affinity)[:2])
            os.environ['THREADING_MODE'] = cls.threading_mode
            fixture.Acceptance.setUpClass.__func__(cls)
        finally:
            os.sched_setaffinity(0, affinity)
            if previous is None:
                os.environ.pop('THREADING_MODE', None)
            else:
                os.environ['THREADING_MODE'] = previous

    def ready_status(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.gateway.role_ports.ports['readiness'], timeout=2)
        try:
            conn.request('GET', '/healthz/ready')
            response = conn.getresponse()
            return response.status, response.read().decode()
        finally:
            conn.close()

    def wait_ready(self, expected):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            status, body = self.ready_status()
            if status == expected:
                return body
            self.assertIsNone(self.gateway.process.poll())
            time.sleep(.025)
        self.fail(f'readiness stayed {status}: {body}')

    def test_remove_and_readd_listener_keeps_security(self):
        original = self.gateway.config.read_text()
        try:
            for cycle in range(2):
                with self.subTest(cycle=cycle):
                    session = self.session()
                    self.assertEqual(self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), session)[0], 200)
                    self.gateway.request(None, session, method='DELETE')
                    changed = json.loads(original)
                    changed['aiSystems'] = []
                    self.reload(json.dumps(changed), True)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        with socket.socket() as probe:
                            probe.settimeout(.2)
                            if probe.connect_ex(('127.0.0.1', self.gateway.port)) == 111:
                                break
                        time.sleep(.025)
                    else:
                        self.fail('removed listener still accepts connections')
                    self.reload(original, True)
                    self.wait_ready(200)
                    session = self.session()
                    self.assertEqual(self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), session)[0], 200)
                    before = self.count('forbidden', effects=True)
                    self.denied(self.gateway.request(fixture.rpc('tools/call', name='forbidden', arguments={}), session))
                    self.gateway.request(None, session, method='DELETE')
                    self.assertEqual(self.count('forbidden', effects=True), before)
            self.observations.update(removalCycles=2, samePortReadded=True, deniedEffects=0)
        finally:
            self.reload(original, True)

    def test_socket_creation_failure_blocks_readiness_until_removed(self):
        original = self.gateway.config.read_text()
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            candidate = json.loads(original)
            extra = copy.deepcopy(candidate['aiSystems'][0])
            extra['name'] = 'occupied-listener'
            extra['mcp']['port'] = occupied.getsockname()[1]
            candidate['aiSystems'].append(extra)
            try:
                self.reload(json.dumps(candidate), True)
                body = self.wait_ready(500)
                self.assertIn('bind ', body)
                self.assertEqual(self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), self.session())[0], 200)
                self.observations.update(failedListenerReported=True, existingListenerStillWorks=True)
            finally:
                self.reload(original, True)
                self.wait_ready(200)


class Single(ListenerLifecycle, unittest.TestCase):
    threading_mode = 'multithreaded'


class PerCore(ListenerLifecycle, unittest.TestCase):
    threading_mode = 'thread_per_core'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda value: str(Path(value).resolve()))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fixture.BINARY = args.binary
    fixture.ARTIFACTS = Path(tempfile.mkdtemp(prefix='run-', dir=args.report.parent))
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in (Single, PerCore))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
        'errors': [str(test) for test, _ in result.errors], 'failures': [str(test) for test, _ in result.failures],
        'skipped': [str(test) for test, _ in result.skipped],
        'evidence': {cls.__name__: getattr(cls, 'evidence', {}) for cls in (Single, PerCore)},
        'diagnostics': [snapshot for cls in (Single, PerCore)
                        for snapshot in getattr(getattr(cls, 'gateway', None), 'diagnostics', [])],
        'artifacts': str(fixture.ARTIFACTS)}, indent=2) + '\n')
    raise SystemExit(not result.wasSuccessful())
