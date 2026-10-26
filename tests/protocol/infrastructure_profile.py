#!/usr/bin/env python3
"""Disabled SQL/OTLP updates must preserve the last admitted gateway and session."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest

import gateway_faults as fixture
from mcp_profile import MCPProfile


class InfrastructureProfile(unittest.TestCase):
    mcp_only = True
    setUpClass = classmethod(fixture.Acceptance.setUpClass.__func__)
    tearDownClass = classmethod(fixture.Acceptance.tearDownClass.__func__)
    setUp = fixture.Acceptance.setUp
    tearDown = fixture.Acceptance.tearDown
    record_evidence = fixture.Acceptance.record_evidence
    session = fixture.Acceptance.session
    count = fixture.Acceptance.count
    replace_config = MCPProfile.replace_config
    wait_log = MCPProfile.wait_log

    def test_uncompiled_output_updates_preserve_the_active_session(self):
        session = self.session()
        original = self.gateway.config.read_text()
        self.addCleanup(self.replace_config, original)
        updates = [
            ({'database': {'url': 'sqlite::memory:'}}, None, b'database is not compiled'),
            ({'logging': {'database': {'url': 'sqlite::memory:'}}}, None, b'database is not compiled'),
            ({'tracing': {'otlpEndpoint': 'http://127.0.0.1:4318'}}, None, b'OTLP telemetry is not compiled'),
            ({}, {'accessLog': {'otlp': {'host': '127.0.0.1:4318'}}}, b'OTLP telemetry is not compiled'),
            ({}, {'accessLog': {'database': {}}}, b'database is not compiled'),
        ]
        for settings, frontend, marker in updates:
            with self.subTest(settings=settings, frontend=frontend):
                candidate = json.loads(original)
                candidate['config'].update(settings)
                if frontend is not None:
                    candidate['frontendPolicies'] = frontend
                offset = (self.gateway.directory / 'gateway.log').stat().st_size
                before = self.count('echo', effects=True)
                self.replace_config(json.dumps(candidate))
                self.wait_log(marker, offset)
                status, _, values = self.gateway.request(
                    fixture.rpc('tools/call', name='echo', arguments={}), session)
                self.assertEqual(status, 200, values)
                self.assertTrue(any('result' in value for value in values), values)
                self.assertEqual(self.count('echo', effects=True), before + 1)
        self.observations.update(rejectedOutputUpdates=5, sameSessionSurvived=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fixture.BINARY = args.binary
    fixture.ARTIFACTS = Path(tempfile.mkdtemp(prefix='run-', dir=args.report.parent))
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(InfrastructureProfile))
    gateway = getattr(InfrastructureProfile, 'gateway', None)
    args.report.write_text(json.dumps({
        'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
        'errors': [str(test) for test, _ in result.errors],
        'failures': [str(test) for test, _ in result.failures],
        'skipped': [str(test) for test, _ in result.skipped],
        'scenarios': getattr(InfrastructureProfile, 'evidence', {}),
        'diagnostics': getattr(gateway, 'diagnostics', []),
        'artifacts': str(fixture.ARTIFACTS),
    }, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
