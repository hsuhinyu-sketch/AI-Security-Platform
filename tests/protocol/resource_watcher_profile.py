#!/usr/bin/env python3
"""JWKS dependency watch recovery and retirement through the real security chain."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

import gateway_faults as fixture
from config_reload_profile import Reload
from config_watcher_profile import Watcher


class Resources(unittest.TestCase):
    mcp_only = True
    setUpClass = classmethod(fixture.Acceptance.setUpClass.__func__)
    tearDownClass = classmethod(fixture.Acceptance.tearDownClass.__func__)
    tearDown = fixture.Acceptance.tearDown
    record_evidence = fixture.Acceptance.record_evidence
    session = fixture.Acceptance.session
    count = fixture.Acceptance.count
    denied = fixture.Acceptance.denied
    reload = Reload.reload
    metrics = Watcher.metrics

    def setUp(self):
        fixture.Acceptance.setUp(self)
        self.original = self.gateway.config.read_text()
        self.directory = tempfile.TemporaryDirectory(prefix='resource-', dir=self.gateway.directory)
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(self.reload, self.original, True)
        self.live = Path(self.directory.name) / 'live'
        self.parked = Path(self.directory.name) / 'parked'
        self.live.mkdir()
        self.keys = self.live / 'jwks.json'
        candidate = json.loads(self.original)
        auth = candidate['aiSystems'][0]['mcp']['policies']['jwtAuth']
        self.valid_keys = auth['jwks']
        self.keys.write_text(self.valid_keys)
        auth['jwks'] = {'file': str(self.keys)}
        self.reload(json.dumps(candidate), True)

    def wait_log(self, marker, offset):
        log = self.gateway.directory / 'gateway.log'
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if marker in log.read_text()[offset:]:
                return
            self.assertIsNone(self.gateway.process.poll())
            time.sleep(.025)
        self.fail(f'missing {marker!r}\n' + log.read_text()[-7000:])

    def offset(self):
        return (self.gateway.directory / 'gateway.log').stat().st_size

    def call(self, session, name='echo', **kwargs):
        return self.gateway.request(fixture.rpc('tools/call', name=name, arguments={}), session, **kwargs)

    def write_keys(self, contents, successful=True):
        offset = self.offset()
        staged = self.keys.with_suffix('.next')
        staged.write_text(contents)
        staged.replace(self.keys)
        self.wait_log('Config reloaded successfully' if successful else 'Failed to reload config:', offset)

    def lose_parent(self):
        offset = self.offset()
        self.live.rename(self.parked)
        (self.parked / 'jwks.json').unlink()
        self.wait_log('failed to re-watch resource file', offset)

    def restore_parent(self, contents):
        (self.parked / 'jwks.json').write_text(contents)
        self.parked.rename(self.live)

    def assert_key_rejected_without_upstream(self, session):
        before = self.count('tools/call')
        self.assertEqual(self.call(session)[0], 401)
        self.assertEqual(self.count('tools/call'), before)

    def test_parent_recovery_loads_gap_keys_and_reauthorizes_without_config_write(self):
        config_before = self.gateway.config.read_text()
        session = self.session()
        self.lose_parent()
        self.assertEqual(self.call(session)[0], 200)
        before = self.count('forbidden', effects=True)
        self.denied(self.call(session, 'forbidden'))
        self.assertEqual(self.count('forbidden', effects=True), before)
        offset = self.offset()
        # Publish the entire directory in one rename: the new keys exist before
        # any new inode watch can be registered on the original path.
        self.restore_parent(json.dumps({'keys': []}))
        self.wait_log('Config reloaded successfully', offset)
        self.assert_key_rejected_without_upstream(session)
        self.write_keys(self.valid_keys)
        restored = self.session()
        self.assertEqual(self.call(restored)[0], 200)
        before = self.count('echo', effects=True)
        self.denied(self.call(restored, tenant='tenant-b'))
        self.assertEqual(self.count('echo', effects=True), before)
        self.assertEqual(self.gateway.config.read_text(), config_before)
        self.observations.update(gapKeysLoaded=True, invalidKeyDispatches=0,
                                 crossTenantEffects=0, mainConfigurationUnchanged=True)

    def test_retired_retrying_dependency_does_not_reload_or_revoke_new_sessions(self):
        self.lose_parent()
        self.reload(self.original, True)
        # Allow notifications already queued before retirement to settle.
        time.sleep(1.2)
        session = self.session()
        success = 'agentgateway_config_reloads_total{result="success"}'
        before = self.metrics()[success]
        self.restore_parent(json.dumps({'keys': []}))
        time.sleep(1.2)
        self.assertEqual(self.metrics()[success], before)
        self.assertEqual(self.call(session)[0], 200)
        self.observations.update(retiredDependencyPublications=0, currentSessionKept=True)

    def test_invalid_keys_keep_old_policy_and_atomic_rotations_continue(self):
        session = self.session()
        self.write_keys('{invalid', successful=False)
        self.assertEqual(self.call(session)[0], 200)
        self.write_keys(json.dumps({'keys': []}))
        self.assert_key_rejected_without_upstream(session)
        self.write_keys(self.valid_keys)
        self.denied(self.call(session))  # Valid publications revoke the old generation.
        restored = self.session()
        self.assertEqual(self.call(restored)[0], 200)
        before = self.count('forbidden', effects=True)
        self.denied(self.call(restored, 'forbidden'))
        self.assertEqual(self.count('forbidden', effects=True), before)
        self.observations.update(invalidCandidateKeptPolicy=True, oldGenerationRevoked=True,
                                 laterKeyRotationsWork=True, deniedEffects=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda value: str(Path(value).resolve()))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fixture.BINARY = args.binary
    fixture.ARTIFACTS = Path(tempfile.mkdtemp(prefix='run-', dir=args.report.parent))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Resources))
    args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
        'errors': [str(test) for test, _ in result.errors], 'failures': [str(test) for test, _ in result.failures],
        'skipped': [str(test) for test, _ in result.skipped], 'evidence': getattr(Resources, 'evidence', {}),
        'diagnostics': getattr(getattr(Resources, 'gateway', None), 'diagnostics', []),
        'artifacts': str(fixture.ARTIFACTS)}, indent=2) + '\n')
    raise SystemExit(not result.wasSuccessful())
