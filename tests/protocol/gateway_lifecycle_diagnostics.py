#!/usr/bin/env python3
"""Observe the unchanged TCP acceptance suite; never retry requests or change assertions.

Linux /proc snapshots are best effort. All output contains disposable local test data.
"""
import argparse
import ctypes
import errno
import socket
import subprocess
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import sys
import threading
import time
import unittest

from socket_evidence import validate_round_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--rounds', type=int, default=10)
    parser.add_argument('--scenario', choices=['full', 'first-llm', 'session', 'commit-followup', 'restart', 'address-family'], default='full')
    parser.add_argument('--capture', action='store_true', help='explicit sudo -n tcpdump metadata on fixture ports')
    parser.add_argument('--log-level', default='info,ai_security_platform_runtime::proxy::gateway=debug,platform_core::drain=debug')
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error('--rounds must be positive')
    args.output.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location('gateway_faults_observed', Path(__file__).with_name('gateway_faults.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.BINARY = str(binary)
    original_request, original_start, original_stop = module.Gateway.request, module.Gateway.start, module.Gateway.stop
    original_popen = module.subprocess.Popen
    lock = threading.Lock()
    events, current_test, round_dir, gateway = [], None, None, None
    previous_test = None
    previous_outcome = None
    captures = {}

    def stop_captures():
        for process, stdout, stderr in captures.values():
            try:
                if process.poll() is None:
                    subprocess.run(['sudo', '-n', 'kill', '-INT', '--', f'-{process.pid}'], check=True)
                process.wait(timeout=5)
            finally:
                stdout.close()
                stderr.close()
        captures.clear()

    def record(kind, g=None, **details):
        nonlocal gateway
        with lock:
            event = dict(kind=kind, test=current_test, monotonic=time.monotonic(), utc=time.time(), **details)
            if g is not None:
                gateway = g
                event.update(observerNetns=os.readlink('/proc/self/ns/net'),
                             pid=g.process.pid if g.process else None,
                             processStatus=g.process.poll() if g.process else None,
                             mcpPort=g.port, modelPort=g.model_port)
                if g.config.exists():
                    event['configSha256'] = hashlib.sha256(g.config.read_bytes()).hexdigest()
                if hasattr(g, 'role_ports'):
                    event['rolePorts'] = g.role_ports.ports
            events.append(event)
            return len(events) - 1

    def snapshot(kind, g):
        index = record(kind, g)
        evidence = {}
        if g.process:
            process = Path('/proc') / str(g.process.pid)
            owners = {}
            try:
                evidence['gatewayNetns'] = os.readlink(process / 'ns/net')
            except OSError as error:
                evidence['gatewayNetnsError'] = type(error).__name__
            try:
                for fd in (process / 'fd').iterdir():
                    try:
                        target = os.readlink(fd)
                        if target.startswith('socket:['):
                            owners.setdefault(target[8:-1], []).append(fd.name)
                    except OSError:
                        pass  # An fd can close between directory enumeration and readlink.
                ports = {f'{g.port:04X}', f'{g.model_port:04X}'}
                for table in ('tcp', 'tcp6'):
                    rows = []
                    for line in (process / 'net' / table).read_text().splitlines()[1:]:
                        fields = line.split()
                        if fields[1].split(':')[-1] in ports:
                            rows.append(dict(raw=line, state=fields[3], ownedFds=owners.get(fields[9], [])))
                    evidence[table] = rows
                listener_fds = {int(fd) for rows in (evidence.get('tcp', []), evidence.get('tcp6', []))
                                for row in rows if row['state'] == '0A' for fd in row['ownedFds']}
                evidence['listenerOptions'] = []
                for listener_fd in sorted(listener_fds):
                    item = {'fd': listener_fd}
                    pidfd = duplicate = None
                    try:
                        pidfd = os.pidfd_open(g.process.pid)
                        libc = ctypes.CDLL(None, use_errno=True)
                        # pidfd_getfd is syscall 438 on the supported Linux x86_64 diagnostic host.
                        if os.uname().machine != 'x86_64':
                            raise OSError(errno.ENOSYS, 'pidfd_getfd number not reviewed for this architecture')
                        duplicate = libc.syscall(438, pidfd, listener_fd, 0)
                        if duplicate < 0:
                            raise OSError(ctypes.get_errno(), 'pidfd_getfd')
                        with socket.socket(fileno=duplicate) as listener_socket:
                            duplicate = None
                            item.update(address=listener_socket.getsockname(), family=int(listener_socket.family),
                                        reuseAddr=listener_socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR),
                                        reusePort=listener_socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT),
                                        accepting=listener_socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))
                            if listener_socket.family == socket.AF_INET6:
                                item['ipv6Only'] = listener_socket.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY)
                    except OSError as error:
                        item['error'] = {'type': type(error).__name__, 'errno': error.errno}
                    finally:
                        if duplicate is not None and duplicate >= 0:
                            os.close(duplicate)
                        if pidfd is not None:
                            os.close(pidfd)
                    evidence['listenerOptions'].append(item)
                status = subprocess.run(['ss', '-ltnpeH', f'( sport = :{g.port} or sport = :{g.model_port} )'],
                                        capture_output=True, text=True)
                evidence['ss'] = {'exitCode': status.returncode, 'output': status.stdout, 'error': status.stderr}
            except OSError as error:
                evidence['procSnapshotError'] = type(error).__name__
        log = g.directory / 'gateway.log'
        if log.exists():
            target = round_dir / f'gateway-{index:04}.log'
            target.write_bytes(log.read_bytes())
            evidence['fullLog'] = str(target)
        with lock:
            events[index].update(evidence)

    def observed_popen(command, *a, **kw):
        if command and command[0] == str(binary):
            env = dict(kw['env'])
            env['RUST_LOG'] = args.log_level
            kw['env'] = env
            record('process-spawn', readyFd=env.get('READY_FD'))
        return original_popen(command, *a, **kw)

    def start(g):
        record('start-enter', g)
        key = (g.port, g.model_port)
        if args.capture and key not in captures:
            stdout = (round_dir / f'tcp-{g.port}-{g.model_port}.txt').open('w')
            stderr_path = round_dir / f'tcp-{g.port}-{g.model_port}.stderr'
            stderr = stderr_path.open('w')
            command = ['sudo', '-n', 'tcpdump', '-Z', pwd.getpwuid(os.getuid()).pw_name,
                       '-i', 'any', '-nn', '-tt', '-S', '--time-stamp-precision=nano', '-l', '-s', '96',
                       f'tcp and (port {g.port} or port {g.model_port})']
            capture = original_popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            captures[key] = (capture, stdout, stderr)
            deadline = time.monotonic() + 5
            while 'listening on' not in stderr_path.read_text():
                if capture.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f'packet observer unavailable: {stderr_path.read_text()}')
                time.sleep(.02)
        try:
            result = original_start(g)
        except BaseException:
            snapshot('start-error', g)
            raise
        snapshot('ready-fd-eof-and-listener-probes-complete', g)
        return result

    def stop(g):
        snapshot('stop-enter', g)
        result = original_stop(g)
        record('stop-return', g, exitCode=result)
        return result

    def request(g, *a, **kw):
        rpc = kw.get('rpc', a[0] if a else None)
        request_id = record('request-enter', g, rpcMethod=rpc.get('method') if isinstance(rpc, dict) else None,
                            httpMethod=kw.get('method', 'POST'), hasSession=bool(kw.get('session', a[1] if len(a) > 1 else None)))
        try:
            response = original_request(g, *a, **kw)
        except BaseException as error:
            chain = []
            while error is not None:
                chain.append({'type': type(error).__name__, 'errno': getattr(error, 'errno', None)})
                error = error.__cause__
            record('request-error', g, requestEvent=request_id, errorChain=chain)
            snapshot('request-error-snapshot', g)
            raise
        record('request-return', g, requestEvent=request_id, httpStatus=response[0])
        return response

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            nonlocal current_test, previous_outcome
            current_test = test.id()
            record('test-start', previousTest=previous_test, previousOutcome=previous_outcome)
            previous_outcome = 'passed'
            super().startTest(test)

        def addError(self, test, error):
            nonlocal previous_outcome
            previous_outcome = 'error'
            if gateway is not None:
                snapshot('test-error-snapshot', gateway)
            super().addError(test, error)

        def addFailure(self, test, error):
            nonlocal previous_outcome
            previous_outcome = 'failure'
            if gateway is not None:
                snapshot('test-failure-snapshot', gateway)
            super().addFailure(test, error)

        def stopTest(self, test):
            nonlocal previous_test
            record('test-stop', outcome=previous_outcome)
            previous_test = test.id()
            super().stopTest(test)

    class Minimal(module.Acceptance):
        def test_rca_session_lifecycle(self):
            session = self.session()
            status, _, _ = self.gateway.request(module.rpc('tools/list'), session)
            self.assertEqual(status, 200)
            status, _, _ = self.gateway.request(session=session, method='DELETE')
            self.assertIn(status, (200, 202, 204))
            self.sessions.remove(session)

        def test_rca_address_family(self):
            # Explicitly separate active TCP-only probes from normal acceptance.
            for address in ('127.0.0.1', '::1'):
                for port in (self.gateway.port, self.gateway.model_port):
                    family = socket.AF_INET6 if ':' in address else socket.AF_INET
                    with socket.socket(family, socket.SOCK_STREAM) as probe:
                        probe.settimeout(2)
                        try:
                            probe.connect((address, port))
                            record('active-family-probe', self.gateway, address=address, port=port,
                                   local=probe.getsockname(), peer=probe.getpeername(), errno=0)
                        except OSError as error:
                            record('active-family-probe', self.gateway, address=address, port=port,
                                   local=probe.getsockname(), errno=error.errno)
                            raise

    def selected_suite():
        if args.scenario == 'full':
            return unittest.defaultTestLoader.loadTestsFromTestCase(module.Acceptance)
        names = {
            'first-llm': ['test_authenticated_model_call_and_missing_identity_denial'],
            'session': ['test_rca_session_lifecycle'],
            'commit-followup': ['test_committed_side_effect_with_lost_response_is_not_replayed', 'test_rca_session_lifecycle'],
            'restart': ['test_graceful_shutdown_drains_and_restart_rejects_old_session', 'test_sigkill_restart_rejects_old_session'],
            'address-family': ['test_rca_address_family'],
        }[args.scenario]
        return unittest.TestSuite(Minimal(name) for name in names)

    module.Gateway.request, module.Gateway.start, module.Gateway.stop = request, start, stop
    module.subprocess.Popen = observed_popen
    summaries = []
    try:
        for number in range(1, args.rounds + 1):
            round_dir = args.output / f'round-{number:02}'
            round_dir.mkdir()
            events, current_test, gateway = [], None, None
            previous_test, previous_outcome = None, None
            started = time.monotonic()
            try:
                with (round_dir / 'unittest.log').open('w') as stream:
                    suite = selected_suite()
                    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
            finally:
                stop_captures()
            report = dict(round=number, successful=result.wasSuccessful(), testsRun=result.testsRun,
                          failures=[str(t) for t, _ in result.failures], errors=[str(t) for t, _ in result.errors],
                          seconds=time.monotonic() - started, events=events, scenario=args.scenario,
                          activeProbes=args.scenario == 'address-family',
                          packetCapture=args.capture,
                          scenarios=getattr(module.Acceptance if args.scenario == 'full' else Minimal, 'evidence', {}), binarySha256=digest)
            path = round_dir / 'report.json'
            validate_round_report(report)
            path.write_text(json.dumps(report, indent=2) + '\n')
            summaries.append(dict(round=number, successful=report['successful'], testsRun=result.testsRun,
                                  errors=report['errors'], failures=report['failures'], report=str(path)))
            (args.output / 'summary.json').write_text(json.dumps(summaries, indent=2) + '\n')
            print(json.dumps(summaries[-1]), flush=True)
    finally:
        stop_captures()
        module.subprocess.Popen = original_popen
        module.Gateway.request, module.Gateway.start, module.Gateway.stop = original_request, original_start, original_stop
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise RuntimeError('binary changed during fixed diagnostic rounds')
    return 0 if all(row['successful'] for row in summaries) else 1


if __name__ == '__main__':
    raise SystemExit(main())
