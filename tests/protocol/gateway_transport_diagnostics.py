#!/usr/bin/env python3
"""Independent denied-HTTP transport experiment, never a Tool or acceptance retry.

Reuses the disposable gateway fixture. Sends no credential, records no payload,
and requires zero upstream calls. Packet capture is explicit and headers only.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--requests', type=int, default=100)
    parser.add_argument('--log-level', default='info')
    parser.add_argument('--capture', action='store_true', help='explicit sudo -n tcpdump on fixture ports, interface any')
    args = parser.parse_args()
    if args.requests < 1:
        parser.error('--requests must be positive')
    args.output.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location('transport_fixture', Path(__file__).with_name('gateway_faults.py'))
    fixture = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fixture
    spec.loader.exec_module(fixture)
    fixture.BINARY = str(binary)
    original_popen = fixture.subprocess.Popen

    def observed_popen(command, *a, **kw):
        if command and command[0] == str(binary):
            kw['env'] = dict(kw['env'], RUST_LOG=args.log_level)
        return original_popen(command, *a, **kw)

    fixture.subprocess.Popen = observed_popen
    try:
        report = {'binarySha256': digest, 'uid': os.getuid(), 'netns': os.readlink('/proc/self/ns/net'),
                  'activeExperiment': True, 'capture': args.capture, 'rows': [], 'groups': []}
        report['logLevel'] = args.log_level
        for address in ('127.0.0.1', '::1'):
            route = subprocess.run(['ip', 'route', 'get', address], capture_output=True, text=True)
            report.setdefault('routes', {})[address] = {'exitCode': route.returncode, 'stdout': route.stdout, 'stderr': route.stderr}
        report_path = args.output / 'report.json'

        def persist():
            report_path.write_text(json.dumps(report, indent=2) + '\n')

        for mode, delay in [('atomic', 0), ('split', .001), ('split', .01)]:
            name = f'{mode}-{delay}'
            capture = out = err = None
            original_start = fixture.Gateway.start

            def start(gateway):
                nonlocal capture, out, err
                if args.capture:
                    out = (args.output / f'{name}.packets.txt').open('w')
                    err_path = args.output / f'{name}.tcpdump.log'
                    err = err_path.open('w')
                    command = ['sudo', '-n', 'tcpdump', '-Z', pwd.getpwuid(os.getuid()).pw_name, '-i', 'any', '-nn', '-tt', '-S',
                               '--time-stamp-precision=nano', '-l', '-s', '96',
                               f'tcp and (port {gateway.port} or port {gateway.model_port})']
                    capture = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True)
                    deadline = time.monotonic() + 5
                    while 'listening on' not in err_path.read_text():
                        if capture.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError(f'packet observer unavailable: {err_path.read_text()}')
                        time.sleep(.02)
                return original_start(gateway)

            fixture.Gateway.start = start
            setup = False
            try:
                fixture.Acceptance.setUpClass()
                setup = True
                gateway = fixture.Acceptance.gateway
                for number in range(args.requests):
                    body = b'{"model":"local","messages":[{"role":"user","content":"hello"}]}'
                    header = (f'POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{gateway.model_port}\r\n'
                              f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n').encode()
                    row = {'group': name, 'request': number, 'pid': gateway.process.pid, 'port': gateway.model_port,
                           'startNs': time.monotonic_ns(), 'utcNs': time.time_ns(), 'phase': 'connect'}
                    try:
                        with socket.create_connection(('127.0.0.1', gateway.model_port), timeout=2) as connection:
                            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            row.update(local=connection.getsockname(), peer=connection.getpeername(), phase='send')
                            if mode == 'atomic':
                                connection.sendall(header + body)
                            else:
                                connection.sendall(header)
                                time.sleep(delay)
                                connection.sendall(body)
                            row['phase'] = 'recv'
                            response = connection.recv(1024)
                            row.update(status=response.split(b'\r\n', 1)[0].decode(errors='replace'), responseBytes=len(response))
                            row['passed'] = row['status'] == 'HTTP/1.1 401 Unauthorized'
                    except OSError as error:
                        row.update(error=type(error).__name__, errno=error.errno, passed=False)
                    row['endNs'] = time.monotonic_ns()
                    report['rows'].append(row)
                with fixture.Acceptance.server.lock:
                    calls = dict(fixture.Acceptance.server.calls)
                    effects = dict(fixture.Acceptance.server.effects)
                report['groups'].append({'name': name, 'upstreamCalls': calls, 'upstreamEffects': effects})
                if calls or effects:
                    raise AssertionError('denied transport experiment reached upstream')
            finally:
                fixture.Gateway.start = original_start
                if setup:
                    (args.output / f'{name}.gateway.log').write_bytes((gateway.directory / 'gateway.log').read_bytes())
                    fixture.Acceptance.tearDownClass()
                if capture is not None and capture.poll() is None:
                    subprocess.run(['sudo', '-n', 'kill', '-INT', '--', f'-{capture.pid}'], check=True)
                    capture.wait(timeout=5)
                if out:
                    out.close()
                if err:
                    err.close()
                persist()
            selected = [row for row in report['rows'] if row['group'] == name]
            print(json.dumps({'group': name, 'requests': len(selected), 'failed': sum(not row['passed'] for row in selected)}), flush=True)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise RuntimeError('binary changed during transport experiment')
        return 0 if all(row['passed'] for row in report['rows']) else 1
    finally:
        fixture.subprocess.Popen = original_popen


if __name__ == '__main__':
    raise SystemExit(main())
