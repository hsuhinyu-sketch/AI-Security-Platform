#!/usr/bin/env python3
"""Acceptance infrastructure regressions; the Gateway remains an unmodified binary."""
import errno
import concurrent.futures
import os
import json
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import gateway_faults as fixture
import run_full_tcp as runner


class GateTests(unittest.TestCase):
    def test_profile_cannot_pass_using_another_profiles_case_count(self):
        clock = {"wallNs":100,"monotonicNs":100}
        for profile, (_, expected) in runner.PROFILES.items():
            report = {"successful":True,"testsRun":expected,"errors":[],"failures":[],"skipped":[]}
            self.assertEqual(runner.check_round(report,0,clock,clock,expected), [], profile)
            report['testsRun'] -= 1
            self.assertTrue(runner.check_round(report,0,clock,clock,expected), profile)

    def test_failure_missing_cases_skip_or_incomplete_report_cannot_pass(self):
        clock = {"wallNs": 100, "monotonicNs": 100}
        good = {"successful": True, "testsRun": 10, "errors": [], "failures": [], "skipped": []}
        self.assertEqual(runner.check_round(good, 0, clock, clock), [])
        for report, code in [({}, 0), (dict(good, testsRun=0), 0), (good, 1),
                             (dict(good, successful=False), 0), (dict(good, errors=['DELETE']), 0),
                             (dict(good, failures=['revocation']), 0), (dict(good, skipped=['JWT']), 0),
                             ({"successful": True, "testsRun": 10}, 0)]:
            with self.subTest(report=report, code=code):
                self.assertTrue(runner.check_round(report, code, clock, clock))

    def test_wall_clock_jump_is_not_misreported_as_a_valid_passing_round(self):
        before = {"wallNs": 100_000_000_000, "monotonicNs": 100_000_000_000}
        for jump in (-3600_000_000_000, 3600_000_000_000):
            after = {"wallNs": before['wallNs'] + jump, "monotonicNs": before['monotonicNs'] + 1_000_000_000}
            report = {"successful": True, "testsRun": 10, "errors": [], "failures": [], "skipped": []}
            errors = runner.check_round(report, 0, before, after)
            self.assertEqual(errors[0]['type'], 'ClockDiscontinuity')
        self.assertIsNone(runner.clock_error(before, {k: v + 100_000_000_000 for k, v in before.items()}))

    def test_refusal_with_owned_listener_and_child_exit_are_distinct_failures(self):
        clock = {"wallNs": 100, "monotonicNs": 100}
        report = {"successful": False, "testsRun": 10, "errors": ['DELETE'], "failures": [], "skipped": [],
                  "diagnostics": [{"phase":"request-error", "exitCode":None, "errorChain":[{"errno":111}],
                                   "ports":{"mcp":12345}, "sockets":[{"local":"00000000:3039","state":"0A","ownedFds":["16"]}]}]}
        errors = runner.check_round(report, 1, clock, clock)
        self.assertIn('ConnectionRefusedWithLiveListener', [e['type'] for e in errors])
        report['diagnostics'][0]['exitCode'] = -6
        errors = runner.check_round(report, 1, clock, clock)
        self.assertIn({"type":"GatewayExitedDuringRequest", "exitCode":-6}, errors)
        self.assertNotIn('ConnectionRefusedWithLiveListener', [e['type'] for e in errors])

    def test_isolation_verifies_namespace_and_interfaces(self):
        runner.validate_isolation({"namespace": "net:[2]", "interfaces": ['lo']}, "net:[1]")
        for state in [dict(namespace="net:[1]", interfaces=['lo']),
                      dict(namespace="net:[2]", interfaces=['lo', 'loopback0'])]:
            with self.assertRaisesRegex(RuntimeError, 'new network namespace'):
                runner.validate_isolation(state, "net:[1]")

    def test_isolation_failure_is_reported_without_host_network_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'report.json'
            with patch.object(sys, 'argv', ['run_full_tcp.py', '--binary', '/bin/false', '--report', str(report)]), \
                    patch.object(runner.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'namespace denied')) as launch:
                self.assertEqual(runner.main(), 1)
                self.assertEqual(launch.call_count, 1)
            data = json.loads(report.read_text())
            self.assertFalse(data['successful'])
            self.assertEqual(data['error']['type'], 'NetworkIsolationFailed')
            self.assertEqual(data['rounds'], [])
            self.assertIn('namespace denied', report.with_suffix('.launcher.log').read_text())

    def test_privileged_launcher_drops_uid_and_gid_before_repository_python(self):
        child = ['/usr/bin/python3', '/path with spaces/runner.py', '--binary', '$(must-stay-literal)']
        command = runner.namespace_command('sudo', '/usr/bin/unshare', child)
        self.assertEqual(command[:4], ['sudo', '-n', '/usr/bin/unshare', '--net'])
        self.assertIn('setpriv', command[6])
        self.assertIn('--clear-groups', command[6])
        self.assertEqual(command[-len(child):], child)

    def test_real_failed_binary_stays_failed_and_preserves_exit_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'report.json'
            completed = subprocess.run([sys.executable, str(Path(runner.__file__)), '--binary', '/bin/false',
                                        '--report', str(report), '--rounds', '1', '--launcher', os.environ.get('AISP_TEST_NETNS_LAUNCHER', 'user')], capture_output=True, text=True, timeout=20)
            self.assertEqual(completed.returncode, 1, completed.stderr)
            data = json.loads(report.read_text())
            self.assertFalse(data['successful'])
            self.assertNotEqual(data['network']['namespace'], data['parentNamespace'])
            self.assertEqual(data['network']['interfaces'], ['lo'])
            result = data['rounds'][0]['acceptance']
            self.assertEqual(result['testsRun'], 0)
            self.assertEqual(len(result['errors']), 1)
            self.assertEqual(result['diagnostics'][0]['exitCode'], 1)
            self.assertTrue((Path(result['artifacts']) / 'gateway.log').is_file())


class FailureEvidenceTests(unittest.TestCase):
    def test_exited_child_and_errno_chain_remain_after_handles_are_cleared(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway = fixture.Gateway('/bin/false', Path(directory), 9)
            gateway.artifacts = Path(directory) / 'evidence'
            (Path(directory) / 'gateway.log').write_text('retained startup failure\n')
            gateway.process = subprocess.Popen(['/bin/false'])
            gateway.process.wait(timeout=5)
            try:
                snapshot = gateway.snapshot('request-error', ConnectionRefusedError(errno.ECONNREFUSED, 'refused'))
                self.assertEqual(snapshot['exitCode'], 1)
                self.assertEqual(snapshot['errorChain'][0]['errno'], errno.ECONNREFUSED)
            finally:
                gateway.stop()
                gateway.signer.close()
            self.assertIsNone(gateway.process)
            self.assertEqual(gateway.diagnostics[0]['exitCode'], 1)
            self.assertEqual((gateway.artifacts / 'gateway.log').read_text(), 'retained startup failure\n')
            self.assertEqual(json.loads((gateway.artifacts / 'diagnostics.json').read_text())[0]['exitCode'], 1)

    def test_concurrent_error_snapshots_preserve_valid_complete_local_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway = fixture.Gateway('/bin/false', Path(directory), 9)
            gateway.artifacts = Path(directory) / 'evidence'
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    list(pool.map(lambda n: gateway.snapshot(str(n), ConnectionRefusedError(errno.ECONNREFUSED, 'observer')), range(8)))
                snapshots = json.loads((gateway.artifacts / 'diagnostics.json').read_text())
                self.assertEqual({e['phase'] for e in snapshots}, {str(n) for n in range(8)})
                self.assertEqual(len(snapshots), 8)
            finally:
                gateway.stop()
                gateway.signer.close()

    def test_snapshot_records_actual_listener_inode_owned_by_child(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway = fixture.Gateway('/bin/false', Path(directory), 9)
            gateway.role_ports.close()
            code = "import socket,sys,time;s=socket.socket();s.bind(('127.0.0.1',int(sys.argv[1])));s.listen();print('ready',flush=True);time.sleep(30)"
            gateway.process = subprocess.Popen([sys.executable, '-c', code, str(gateway.port)], stdout=subprocess.PIPE, text=True)
            try:
                self.assertTrue(select.select([gateway.process.stdout], [], [], 5)[0])
                self.assertEqual(gateway.process.stdout.readline().strip(), 'ready')
                snapshot = gateway.snapshot('request-error', ConnectionRefusedError(errno.ECONNREFUSED, 'synthetic observer input'))
                listeners = [row for row in snapshot['sockets'] if row['state'] == '0A' and row['ownedFds']]
                self.assertTrue(listeners)
                self.assertIn(gateway.port, [int(row['local'].rsplit(':', 1)[1], 16) for row in listeners])
                self.assertTrue(all(int(row['inode']) > 0 for row in listeners))
                self.assertIsNone(snapshot['exitCode'])
            finally:
                output = gateway.process.stdout
                gateway.stop()
                output.close()
                gateway.signer.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
