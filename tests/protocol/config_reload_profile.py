#!/usr/bin/env python3
"""Startup-only Host configuration and dynamic security publication on real TCP."""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest

import gateway_faults as fixture


class Reload(unittest.TestCase):
    mcp_only = True
    setUpClass = classmethod(fixture.Acceptance.setUpClass.__func__)
    tearDownClass = classmethod(fixture.Acceptance.tearDownClass.__func__)
    setUp = fixture.Acceptance.setUp
    tearDown = fixture.Acceptance.tearDown
    record_evidence = fixture.Acceptance.record_evidence
    session = fixture.Acceptance.session
    count = fixture.Acceptance.count
    denied = fixture.Acceptance.denied

    def reload(self, contents, successful):
        log = self.gateway.directory / 'gateway.log'
        offset = log.stat().st_size
        candidate = self.gateway.config.with_suffix('.next')
        candidate.write_text(contents)
        candidate.replace(self.gateway.config)
        marker = 'Config reloaded successfully' if successful else 'Failed to reload config:'
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            tail = log.read_text()[offset:]
            if marker in tail:
                if not successful:
                    self.assertIn('config: is startup-only; restart required', tail)
                return
            self.assertIsNone(self.gateway.process.poll())
            time.sleep(.025)
        self.fail(log.read_text()[-5000:])

    def call(self, session, name='echo'):
        return self.gateway.request(fixture.rpc('tools/call', name=name, arguments={}), session)

    def test_changed_startup_section_keeps_session_policy_and_listeners(self):
        original = self.gateway.config.read_text()
        session = self.session()
        changed = json.loads(original)
        changed['config']['mcp'] = {'sessionTtl': '1s'}
        changed['aiSystems'][0]['security']['mode'] = 'audit'
        system = copy.deepcopy(changed['aiSystems'][0])
        system['name'] = 'rejected-listener'
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        system['mcp']['port'] = port
        changed['aiSystems'].append(system)
        try:
            self.reload(json.dumps(changed), False)
            self.assertEqual(self.call(session)[0], 200)
            before = self.count('forbidden', effects=True)
            self.denied(self.call(session, 'forbidden'))
            self.assertEqual(self.count('forbidden', effects=True), before)
            with self.assertRaises(ConnectionRefusedError):
                socket.create_connection(('127.0.0.1', port), timeout=.5)
            self.observations.update(rejectedStartupKeptSession=True, rejectedPolicyNotPublished=True,
                                     ghostListeners=0)
        finally:
            self.reload(original, True)

    def test_removed_empty_and_invalid_startup_sections_are_rejected(self):
        original = self.gateway.config.read_text()
        session = self.session()
        try:
            for section in ('absent', None, {}, 'private-candidate'):
                with self.subTest(section=section):
                    candidate = json.loads(original)
                    if section == 'absent':
                        candidate.pop('config')
                    else:
                        candidate['config'] = section
                    self.reload(json.dumps(candidate), False)
                    self.assertEqual(self.call(session)[0], 200)
        finally:
            self.reload(original, True)

    def test_formatting_and_security_updates_still_publish_and_recover(self):
        original = self.gateway.config.read_text()
        session = self.session()
        changed = json.loads(original)
        changed['aiSystems'][0]['security']['policies'].append({
            'id': 'deny-echo', 'enabled': True, 'effect': 'deny', 'actionType': 'toolInvoke',
            'resourceId': 'echo'})
        try:
            self.reload('# yaml-language-server: $schema=ignored\n'
                        + json.dumps(changed, sort_keys=True, indent=2), True)
            self.denied(self.call(session))  # Successful publication revokes the old generation.
            self.denied(self.call(self.session()))
            self.reload(original, True)
            self.assertEqual(self.call(self.session())[0], 200)
            self.observations.update(dynamicDenyApplied=True, correctedUpdateRecovered=True)
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
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Reload))
    args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
        'errors': [str(test) for test, _ in result.errors], 'failures': [str(test) for test, _ in result.failures],
        'skipped': [str(test) for test, _ in result.skipped], 'evidence': getattr(Reload, 'evidence', {}),
        'diagnostics': getattr(getattr(Reload, 'gateway', None), 'diagnostics', []),
        'artifacts': str(fixture.ARTIFACTS)}, indent=2) + '\n')
    raise SystemExit(not result.wasSuccessful())
