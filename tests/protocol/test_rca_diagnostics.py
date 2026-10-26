#!/usr/bin/env python3
"""Fixture reservations and observer contract tests; never inject Gateway hooks."""

import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import socket_evidence

spec = importlib.util.spec_from_file_location('fixture_under_test', Path(__file__).with_name('gateway_faults.py'))
fixture = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixture
spec.loader.exec_module(fixture)


class FixtureTests(unittest.TestCase):
    def test_roles_are_distinct_and_reserved_until_release(self):
        for _ in range(20):
            allocation = fixture.RolePorts()
            try:
                self.assertEqual(set(allocation.ports), set(fixture.RolePorts.roles))
                self.assertEqual(len(set(allocation.ports.values())), 5)
                for port in allocation.ports.values():
                    with socket.socket() as competitor:
                        with self.assertRaises(OSError) as failed:
                            competitor.bind(('127.0.0.1', port))
                        self.assertEqual(failed.exception.errno, errno.EADDRINUSE)
            finally:
                allocation.close()

    def test_partial_allocation_failure_closes_every_reservation(self):
        failure = OSError(errno.EADDRINUSE, 'injected bind failure')

        class Reservation:
            closed = False

            def __init__(self, fail=False):
                self.fail = fail

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.closed = True

            def bind(self, address):
                if self.fail:
                    raise failure

            def getsockname(self):
                return '127.0.0.1', 12345

        first, second = Reservation(), Reservation(True)
        with patch.object(fixture.socket, 'socket', side_effect=[first, second]) as factory:
            with self.assertRaises(OSError) as caught:
                fixture.RolePorts()
        self.assertIs(caught.exception, failure)
        self.assertEqual(factory.call_count, 2)
        self.assertTrue(first.closed and second.closed)

    def test_gateway_configuration_uses_five_unique_roles(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway = fixture.Gateway('/bin/false', Path(directory), 9)
            try:
                config = json.loads(gateway.config.read_text())
                ports = [config['aiSystems'][0][name]['port'] for name in ('mcp', 'llm')]
                ports += [int(config['config'][name].rsplit(':', 1)[1])
                          for name in ('adminAddr', 'statsAddr', 'readinessAddr')]
                self.assertEqual(set(ports), set(gateway.role_ports.ports.values()))
                self.assertEqual(len(set(ports)), 5)
            finally:
                gateway.stop()
                gateway.signer.close()

    def test_spawn_failure_propagates_once_and_releases_fds(self):
        with tempfile.TemporaryDirectory() as directory:
            before = len(list(Path('/proc/self/fd').iterdir()))
            gateway = fixture.Gateway('/bin/false', Path(directory), 9)
            failure = FileNotFoundError(errno.ENOENT, 'injected spawn failure')
            try:
                with patch.object(fixture.subprocess, 'Popen', side_effect=failure) as spawn:
                    with self.assertRaises(FileNotFoundError) as caught:
                        gateway.start()
                    self.assertIs(caught.exception, failure)
                    self.assertEqual(spawn.call_count, 1)
            finally:
                gateway.stop()
                gateway.signer.close()
            self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)

    def test_child_start_failure_is_not_reported_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway = fixture.Gateway('/bin/false', Path(directory), 9)
            try:
                with self.assertRaises(RuntimeError):
                    gateway.start()
                self.assertEqual(gateway.process.returncode, 1)
            finally:
                gateway.stop()
                gateway.signer.close()


class EvidenceTests(unittest.TestCase):
    @staticmethod
    def event(op, inode, ns=1, ret=-1, error=0, peer='127.0.0.1:9'):
        return dict(ns=ns, pid=1, tid=2, op=op, fd=6, inode=inode, local='127.0.0.1:12345',
                    peer=peer, ret=ret, errno=error)

    def test_fd_reuse_cannot_mix_socket_error_or_destination(self):
        events = [self.event('connect', 100, error=115),
                  self.event('SO_ERROR', 100, 2, 111, peer='family:0'),
                  self.event('connect', 101, 3, error=115, peer='127.0.0.1:80'),
                  self.event('SO_ERROR', 101, 4, 0), self.event('recv', 101, 5, error=104, peer='family:0')]
        found = socket_evidence.failures(events)
        self.assertEqual([(x['inode'], x['errno'], x['peer']) for x in found],
                         [(100, 111, '127.0.0.1:9'), (101, 104, '127.0.0.1:80')])
        self.assertEqual([e['inode'] for e in found[1]['timeline']], [101, 101, 101])
        self.assertEqual(socket_evidence.failures(list(reversed(events))), found)

    def test_eof_eagain_and_inprogress_are_not_reset_or_refusal(self):
        events = [self.event('connect', 100, error=115), self.event('recv', 100, 2, error=11),
                  self.event('recv', 100, 3, ret=0)]
        self.assertEqual(socket_evidence.failures(events), [])

    def test_missing_identity_is_an_error_not_a_silent_empty_result(self):
        with self.assertRaisesRegex(ValueError, 'incomplete socket event'):
            socket_evidence.connections([{'fd': 6}])

    def test_report_preserves_failures_and_errno_chains(self):
        report = dict(round=1, successful=False, testsRun=1, errors=['DELETE'], failures=[],
                      events=[dict(kind='request-error', monotonic=1, utc=2,
                                   errorChain=[dict(type='ConnectionResetError', errno=104)])],
                      binarySha256='f' * 64)
        self.assertIs(socket_evidence.validate_round_report(report), report)
        with self.assertRaisesRegex(ValueError, 'hides failure'):
            socket_evidence.validate_round_report(dict(report, successful=True))
        report['events'][0]['errorChain'][0].pop('errno')
        with self.assertRaisesRegex(ValueError, 'errno chain'):
            socket_evidence.validate_round_report(report)

    def test_cli_failure_exits_nonzero_without_creating_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'must-not-exist'
            for script in ('gateway_lifecycle_diagnostics.py', 'gateway_transport_diagnostics.py'):
                flag = '--rounds' if 'lifecycle' in script else '--requests'
                completed = subprocess.run([sys.executable, str(Path(__file__).with_name(script)),
                                            '--binary', '/bin/false', '--output', str(output), flag, '0'],
                                           capture_output=True, text=True)
                self.assertEqual(completed.returncode, 2)
                self.assertFalse(output.exists())


class TraceIntegrationTests(unittest.TestCase):
    def test_compiled_observer_records_real_errno_inode_listener_and_shutdown(self):
        library = os.environ.get('AISP_TEST_TRACE_LIBRARY')
        if not library:
            self.skipTest('set AISP_TEST_TRACE_LIBRARY to the freshly compiled observer')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'trace.jsonl'
            # These deliberate failures validate the observer only, not Gateway RCA.
            code = '''
import errno,socket,struct,select
with socket.socket() as reserved:
 reserved.bind(('127.0.0.1',0))
 with socket.socket() as refused:
  try:refused.connect(reserved.getsockname())
  except OSError as e:assert e.errno==errno.ECONNREFUSED
  else:raise AssertionError('unlistened socket accepted connection')
 with socket.socket() as refused:
  refused.setblocking(False)
  assert refused.connect_ex(reserved.getsockname()) in (errno.EINPROGRESS,errno.ECONNREFUSED)
  assert select.select([], [refused], [], 2)[1]
  assert refused.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)==errno.ECONNREFUSED
with socket.socket() as server:
 server.bind(('127.0.0.1',0));server.listen(1)
 with socket.create_connection(server.getsockname()) as client:
  accepted,_=server.accept()
  accepted.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
  accepted.close()
  try:client.recv(1)
  except OSError as e:assert e.errno==errno.ECONNRESET
  else:raise AssertionError('expected deliberate RST')
with socket.socket() as server:
 server.bind(('127.0.0.1',0));server.listen(1)
 with socket.create_connection(server.getsockname()) as client:
  with server.accept()[0] as accepted:
   accepted.shutdown(socket.SHUT_WR)
   assert client.recv(1)==b''
'''
            completed = subprocess.run([sys.executable, '-c', code],
                                       env=dict(os.environ, LD_PRELOAD=library, AISP_SOCKET_TRACE=str(output)),
                                       capture_output=True, text=True, timeout=10)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            events = socket_evidence.load(output)
            errors = socket_evidence.failures(events)
            self.assertEqual({e['errno'] for e in errors}, {104, 111})
            self.assertTrue(any(e['op'] == 'SO_ERROR' and e['ret'] == 111 and e['errno'] == 0 for e in events))
            for failed in errors:
                self.assertGreater(failed['inode'], 0)
                self.assertGreater(failed['tid'], 0)
                self.assertEqual(len({e['fd'] for e in failed['timeline']}), 1)
            accepted = [e for e in events if e['op'] in ('accept', 'accept4') and e['ret'] >= 0]
            self.assertEqual(len(accepted), 2)
            listeners = {(e['pid'], e['inode'], e['fd']) for e in events if e['op'] == 'listen'}
            self.assertTrue(all((e['pid'], e['parentInode'], e['arg']) in listeners for e in accepted))
            self.assertTrue(any(e['op'] == 'shutdown' and e['arg'] == socket.SHUT_WR for e in events))


if __name__ == '__main__':
    unittest.main(verbosity=2)
