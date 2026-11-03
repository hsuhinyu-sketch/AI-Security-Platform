#!/usr/bin/env python3
"""Configuration watch recovery, publication and diagnostics over real TCP."""
import argparse
import http.client
import json
import os
import signal
from pathlib import Path
import tempfile
import time
import unittest

import gateway_faults as fixture


class Watcher(unittest.TestCase):
    mcp_only = True
    setUpClass = classmethod(fixture.Acceptance.setUpClass.__func__)
    tearDownClass = classmethod(fixture.Acceptance.tearDownClass.__func__)
    setUp = fixture.Acceptance.setUp
    tearDown = fixture.Acceptance.tearDown
    record_evidence = fixture.Acceptance.record_evidence
    session = fixture.Acceptance.session
    count = fixture.Acceptance.count
    denied = fixture.Acceptance.denied

    def call(self, session, name='echo'):
        return self.gateway.request(fixture.rpc('tools/call', name=name, arguments={}), session)

    def metrics(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.gateway.role_ports.ports['stats'], timeout=2)
        try:
            conn.request('GET', '/metrics')
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            samples = {}
            for line in response.read().decode().splitlines():
                if line and not line.startswith('#'):
                    key, value = line.split()[:2]
                    samples[key] = float(value)
            return samples
        finally:
            conn.close()

    def wait(self, predicate, description):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if predicate():
                return
            self.assertIsNone(self.gateway.process.poll())
            time.sleep(.025)
        self.fail(description + '\n' + (self.gateway.directory / 'gateway.log').read_text()[-7000:])

    def load(self, contents, successful=True, atomic=True):
        log = self.gateway.directory / 'gateway.log'
        offset = log.stat().st_size
        if atomic:
            candidate = self.gateway.config.with_suffix('.next')
            candidate.write_text(contents)
            candidate.replace(self.gateway.config)
        else:
            self.gateway.config.write_text(contents)
        marker = 'Config reloaded successfully' if successful else 'Failed to reload config:'
        self.wait(lambda: marker in log.read_text()[offset:], marker)

    def deny_echo(self, original):
        candidate = json.loads(original)
        candidate['aiSystems'][0]['security']['policies'].append({
            'id': 'watch-deny-echo', 'enabled': True, 'effect': 'deny',
            'actionType': 'toolInvoke', 'resourceId': 'echo'})
        return json.dumps(candidate)

    def test_a_metrics_report_rejected_and_corrected_candidates(self):
        success = 'agentgateway_config_reloads_total{result="success"}'
        failure = 'agentgateway_config_reloads_total{result="failure"}'
        original = self.gateway.config.read_text()
        before = self.metrics()
        self.assertGreaterEqual(before.get(success, 0), 1)
        self.assertEqual(before['agentgateway_config_watch_active'], 1)
        session = self.session()
        try:
            self.load('aiSystems: [', successful=False)
            rejected = self.metrics()
            self.assertGreater(rejected[failure], before.get(failure, 0))
            self.assertEqual(rejected['agentgateway_config_reload_last_successful'], 0)
            self.assertEqual(self.call(session)[0], 200)
            effects = self.count('forbidden', effects=True)
            self.denied(self.call(session, 'forbidden'))
            self.assertEqual(self.count('forbidden', effects=True), effects)
            self.assertIn('CONFIG_RELOAD_FAILED', (self.gateway.directory / 'gateway.log').read_text())
            self.load(original)
            corrected = self.metrics()
            self.assertGreater(corrected[success], before[success])
            self.assertEqual(corrected['agentgateway_config_reload_last_successful'], 1)
            self.observations.update(rejectedCandidateKeptSession=True, failedResultVisible=True,
                                     correctedResultVisible=True, deniedEffects=0)
        finally:
            self.load(original)

    def test_b_atomic_replacement_keeps_later_updates_working(self):
        original = self.gateway.config.read_text()
        old = self.session()
        try:
            self.load(self.deny_echo(original))
            self.denied(self.call(old))
            session = self.session()
            self.denied(self.call(session))
            self.load(original, atomic=False)
            self.assertEqual(self.call(self.session())[0], 200)
            self.observations.update(oldGenerationRevoked=True, replacementFollowedByWrite=True)
        finally:
            self.load(original)

    def test_c_missing_parent_retries_and_reads_the_recovery_gap(self):
        original = self.gateway.config.read_text()
        live = self.gateway.directory
        parked = live.with_name(live.name + '-parked')
        offset = (live / 'gateway.log').stat().st_size
        session = self.session()
        try:
            live.rename(parked)
            self.gateway.directory = parked
            # Invalidate the inode watch after its parent has disappeared.
            (parked / self.gateway.config.name).unlink()
            log = parked / 'gateway.log'
            self.wait(lambda: 'failed to re-watch config file' in log.read_text()[offset:],
                      'a failed re-watch must be reported')
            self.assertEqual(self.call(session)[0], 200)
            effects = self.count('forbidden', effects=True)
            self.denied(self.call(session, 'forbidden'))
            self.assertEqual(self.count('forbidden', effects=True), effects)
            degraded = self.metrics()
            if 'agentgateway_config_watch_active' in degraded:
                self.assertEqual(degraded['agentgateway_config_watch_active'], 0)
                self.assertGreater(degraded['agentgateway_config_watch_failures_total'], 0)
                self.assertIn('CONFIG_WATCH_RETRY_FAILED', log.read_text()[offset:])
            # Written while no watch exists. A successful re-registration must
            # explicitly load this candidate rather than wait for another write.
            gap_offset = log.stat().st_size
            live.mkdir()
            self.gateway.config.write_text('aiSystems: [')
            self.wait(lambda: 'Failed to reload config:' in log.read_text()[gap_offset:],
                      'recovered watch must read the invalid candidate from the gap')
            self.assertEqual(self.call(session)[0], 200)
            self.load(self.deny_echo(original))
            self.denied(self.call(session))
            self.denied(self.call(self.session()))
            self.load(original)
            self.assertEqual(self.call(self.session())[0], 200)
            self.assertEqual(self.metrics()['agentgateway_config_watch_active'], 1)
            self.observations.update(rewatchRecovered=True, gapCandidateRead=True,
                                     oldSessionRetainedUntilValidUpdate=True, denyPublished=True)
        finally:
            # The gateway's log fd remains in the parked directory until stop.
            # Put the fixture back before its ordinary evidence/cleanup routines.
            if parked.exists():
                if live.exists():
                    for file in live.iterdir():
                        file.unlink()
                    live.rmdir()
                parked.rename(live)
            self.gateway.directory = live
            self.load(original)

    def test_d_shutdown_finishes_while_watch_registration_is_failing(self):
        original = self.gateway.config.read_text()
        live = self.gateway.directory
        parked = live.with_name(live.name + '-shutdown')
        try:
            live.rename(parked)
            self.gateway.directory = parked
            (parked / self.gateway.config.name).unlink()
            self.wait(lambda: 'failed to re-watch config file' in (parked / 'gateway.log').read_text(),
                      'watch registration failure before shutdown')
            self.gateway.process.send_signal(signal.SIGTERM)
            self.assertEqual(self.gateway.process.wait(timeout=15), 0)
            self.observations.update(gracefulShutdownWhileRetrying=True)
        finally:
            if parked.exists():
                parked.rename(live)
            self.gateway.directory = live
            self.gateway.config.write_text(original)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda value: str(Path(value).resolve()))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fixture.BINARY = args.binary
    fixture.ARTIFACTS = Path(tempfile.mkdtemp(prefix='run-', dir=args.report.parent))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Watcher))
    args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
        'errors': [str(test) for test, _ in result.errors], 'failures': [str(test) for test, _ in result.failures],
        'skipped': [str(test) for test, _ in result.skipped], 'evidence': getattr(Watcher, 'evidence', {}),
        'diagnostics': getattr(getattr(Watcher, 'gateway', None), 'diagnostics', []),
        'artifacts': str(fixture.ARTIFACTS)}, indent=2) + '\n')
    raise SystemExit(not result.wasSuccessful())
