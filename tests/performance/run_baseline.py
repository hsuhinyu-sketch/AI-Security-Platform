#!/usr/bin/env python3
"""Finite, isolated-loopback PoC baseline, with no production hooks or external services."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import signal
import socket
import subprocess
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'tests' / 'protocol'))
from gateway_faults import Gateway  # noqa: E402
from http_workload import Client, encode, messages, valid  # noqa: E402
from resources import Sampler, host, window  # noqa: E402
from build_release import digest, inputs  # noqa: E402

CASES = [('direct-llm-c1', None, 'llm', 1), ('direct-llm-c8', None, 'llm', 8),
         ('llm-c1', 'llm', 'llm', 1), ('llm-c8', 'llm', 'llm', 8),
         ('full-c1', 'full', 'llm', 1), ('full-c8', 'full', 'llm', 8),
         ('direct-mcp-c8', None, 'mcp', 8), ('mcp-c8', 'mcp', 'mcp', 8)]


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(5)
    else:
        process.wait()


def spawn(command, cpus, log, env=None, pass_fds=()):
    prefix = ['taskset', '-c', ','.join(map(str, cpus))]
    return subprocess.Popen(prefix + command, stdout=log, stderr=subprocess.STDOUT,
                            env=env, pass_fds=pass_fds, start_new_session=True)


def wait_file(path, process, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f'process exited {process.returncode}, awaiting {path}')
        if path.exists():
            return json.loads(path.read_text())
        time.sleep(.02)
    raise TimeoutError(str(path))


def start_gateway(gateway, cpus, log):
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ')}
    env['RUST_LOG'] = 'warn'
    env['PPROF_ALLOC_ALLOCATOR'] = 'system'
    read_fd, write_fd = os.pipe()
    env['READY_FD'] = str(write_fd)
    gateway.role_ports.close()
    start = time.monotonic_ns()
    try:
        gateway.process = spawn([gateway.binary, '--file', str(gateway.config)], cpus, log,
                                env=env, pass_fds=(write_fd,))
    finally:
        os.close(write_fd)
    return start, read_fd


def await_ready(gateway, fd):
    try:
        if not select.select([fd], [], [], 30)[0] or os.read(fd, 1) != b'':
            raise TimeoutError('gateway READY_FD')
    finally:
        os.close(fd)
    if gateway.process.poll() is not None:
        raise RuntimeError('gateway exited at readiness')
    # Includes readiness notification and listener verification, not config parsing alone.
    for port in gateway.listener_ports:
        with socket.create_connection(('127.0.0.1', port), timeout=2):
            pass
    return time.monotonic_ns()


async def preflight(gateway, kind):
    port = gateway.model_port if kind == 'llm' else gateway.port
    path = '/v1/chat/completions' if kind == 'llm' else '/mcp'
    data = encode({'model': 'local', 'messages': [{'role': 'user', 'content': 'benchmark question'}]}
                  if kind == 'llm' else {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                      'protocolVersion': '2025-11-25', 'capabilities': {},
                      'clientInfo': {'name': 'benchmark', 'version': '1'}}})
    base = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': '2025-11-25'}
    client = Client(port)
    probes = []
    try:
        for auth in (None, gateway.token()[:-4] + 'xxxx', gateway.token(tenant='tenant-b')):
            headers = dict(base)
            if auth:
                headers['Authorization'] = 'Bearer ' + auth
            status, response_headers, wire = await client.request(path, data, headers)
            rpc = messages(response_headers, wire) if kind == 'mcp' and status == 200 else []
            rpc_denied = bool(rpc) and all('error' in message and 'result' not in message for message in rpc)
            probes.append({'status': status, 'rpcDenied': rpc_denied})
            if status not in (401, 403) and not rpc_denied:
                raise RuntimeError(f'identity denial failed: {status}')
    finally:
        await client.close()
    base['Authorization'] = 'Bearer ' + gateway.token()
    if kind == 'mcp':
        session = gateway.initialize()
        base['Mcp-Session-Id'] = session
        data = encode({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'echo', 'arguments': {}}})
    client = Client(port)
    try:
        status, headers, wire = await client.request(path, data, base)
        if status != 200 or not valid(kind, headers, wire):
            raise RuntimeError(f'normal call failed: {status}: {wire[:1000]!r}')
    finally:
        await client.close()
    return port, path, base, data, {'denialStatuses': probes, 'normalCall': True}


def run_case(args, case, round_number, enabled=True, calibration=False):
    name, product, kind, concurrency = case
    directory = args.out / f'{name}-r{round_number}'
    directory.mkdir(mode=0o700)
    record = {'name': name, 'product': product, 'kind': kind, 'concurrency': concurrency,
              'round': round_number, 'calibration': calibration, 'samplerEnabled': enabled,
              'directory': str(directory), 'startedWallNs': time.time_ns(), 'hostBefore': host(),
              'successful': False}
    upstream = driver = gateway = None
    handles = []
    sampler = Sampler(directory / 'resources.jsonl', enabled=enabled)
    sampler.start()
    start_cpu = time.process_time()
    try:
        def log(filename):
            handle = (directory / filename).open('xb')
            handles.append(handle)
            return handle

        upstream = spawn([sys.executable, str(HERE / 'http_workload.py'), 'serve',
                          '--ready', str(directory / 'upstream.ready.json'),
                          '--counters', str(directory / 'upstream.counters.json'),
                          '--delay-ms', '5'], args.cpus['upstream'], log('upstream.log'))
        sampler.attach('upstream', upstream)
        info = wait_file(directory / 'upstream.ready.json', upstream)
        upstream_port = info['port']
        if product:
            binary = args.build['products'][product]['path']
            gateway = Gateway(binary, directory, upstream_port,
                              llm_only=kind == 'llm', mcp_only=kind == 'mcp')
            config = json.loads(gateway.config.read_text())
            config['config']['workerThreads'] = 2
            config['aiSystems'][0]['name'] = 'benchmark'
            # Same active configuration for LLM-only and Full. Dormant protocols stay unconfigured.
            gateway.config.write_text(json.dumps(config, indent=2))
            record['configSha256'] = digest(gateway.config)
            record['config'] = config
            record['gatewayEnvironment'] = {'RUST_LOG': 'warn', 'PPROF_ALLOC_ALLOCATOR': 'system',
                                             'READY_FD': 'per-process readiness pipe',
                                             'otherVariablesPassed': ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ']}
            record['securityProfile'] = {'jwt': 'strict Ed25519', 'mode': 'enforce',
                                         'requiredAudit': False, 'workflowBudget': False,
                                         'contentGuard': False, 'mcpSessions': kind == 'mcp'}
            started, fd = start_gateway(gateway, args.cpus['gateway'], log('gateway.log'))
            sampler.attach('gateway', gateway.process)
            ready = await_ready(gateway, fd)
            record.update(startupMs=(ready - started) / 1e6, processStartedNs=started, readyNs=ready)
            record['effectiveGatewayAffinity'] = sorted(os.sched_getaffinity(gateway.process.pid))
            idle_start = time.monotonic_ns()
            time.sleep(args.idle)
            record['idleWindowNs'] = [idle_start, time.monotonic_ns()]
            time.sleep(.15)
            # No valid model/tool calls have been dispatched yet.
            port, path, headers, payload, record['preflight'] = asyncio.run(preflight(gateway, kind))
        else:
            port, path = upstream_port, '/v1/chat/completions' if kind == 'llm' else '/mcp'
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
            payload = encode({'model': 'local', 'messages': [{'role': 'user', 'content': 'benchmark question'}]}
                             if kind == 'llm' else {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                             'params': {'name': 'echo', 'arguments': {}}})
        (directory / 'headers.json').write_text(json.dumps(headers))
        (directory / 'payload.json').write_bytes(payload)
        time.sleep(.15)
        before = json.loads((directory / 'upstream.counters.json').read_text())
        record['upstreamBeforeLoad'] = before
        if gateway:
            operation = 'model' if kind == 'llm' else 'tools/call'
            if before.get(operation, 0) != 1 or (kind == 'mcp' and before.get('initialize', 0) != 1):
                raise RuntimeError('preflight identity denials reached upstream')
            record['preflight']['deniedUpstreamCalls'] = 0
        command = [sys.executable, str(HERE / 'http_workload.py'), 'load', '--port', str(port),
                   '--kind', kind, '--path', path, '--payload', str(directory / 'payload.json'),
                   '--headers', str(directory / 'headers.json'), '--samples', str(directory / 'requests.csv'),
                   '--report', str(directory / 'load.json'), '--concurrency', str(concurrency),
                   '--warmup', str(args.warmup), '--seconds', str(10 if calibration else args.seconds)]
        record['driverCommand'] = command
        driver = spawn(command, args.cpus['driver'], log('load.log'))
        sampler.attach('driver', driver)
        exit_code = driver.wait(timeout=args.warmup + (10 if calibration else args.seconds) + 15)
        record['driverExitCode'] = exit_code
        load_report = json.loads((directory / 'load.json').read_text())
        record['load'] = load_report
        if exit_code or not load_report['successful']:
            raise RuntimeError('workload failed; see load.json/log')
        time.sleep(.2)
        after = json.loads((directory / 'upstream.counters.json').read_text())
        record['upstreamAfterLoad'] = after
        operation = 'model' if kind == 'llm' else 'tools/call'
        expected = load_report['completed'] + load_report['warmupCompleted']
        actual = after.get(operation, 0) - before.get(operation, 0)
        if actual != expected or after.get('serverError', 0) or after.get('incompleteRequest', 0):
            raise RuntimeError(f'upstream execution mismatch/errors: expected {expected}, actual {actual}, counters {after}')
        if gateway:
            if gateway.process.poll() is not None:
                raise RuntimeError('gateway exited during load')
            cooldown = time.monotonic_ns()
            time.sleep(args.cooldown)
            record['cooldownWindowNs'] = [cooldown, time.monotonic_ns()]
        record['successful'] = True
    except BaseException as error:
        record['error'] = repr(error)
        record['traceback'] = traceback.format_exc()
    finally:
        sampler.stop()
        record['sampler'] = {'cpuSeconds': sampler.cpu_seconds, 'errors': sampler.errors,
                             'exitedDuringRead': sampler.exited_during_read,
                             'intervalSeconds': .2, 'pssIntervalSeconds': 1}
        record['coordinatorCpuSeconds'] = time.process_time() - start_cpu
        if sampler.errors:
            record['successful'] = False
        if 'load' in record:
            start, end = record['load']['measuredStartNs'], record['load']['measuredEndNs']
            record['measurement'] = {role: window(sampler.rows, role, start, end)
                                     for role in ('gateway', 'upstream', 'driver')}
            metric = record['measurement']['gateway']
            if metric:
                metric['cpuMsPerCompletedRequest'] = metric['cpuSeconds'] * 1000 / record['load']['completed'] if record['load']['completed'] else None
                if metric['samples'] < 3 or metric['pssBytes'] is None or max(metric['boundaryGapMs']) > 500:
                    record['successful'] = False
                    record['measurementError'] = 'insufficient process samples or boundary coverage'
        for phase in ('idle', 'cooldown'):
            if phase + 'WindowNs' in record:
                record[phase] = window(sampler.rows, 'gateway', *record[phase + 'WindowNs'])
        if 'readyNs' in record:
            record['startup'] = window(sampler.rows, 'gateway', record['processStartedNs'], record['readyNs'])
        stop(driver)
        if gateway:
            stop(gateway.process)
            record['gatewayStopExitCode'] = gateway.process.returncode if gateway.process else None
            gateway.role_ports.close()
            gateway.signer.close()
        stop(upstream)
        for handle in handles:
            handle.close()
        record.update(finishedWallNs=time.time_ns(), hostAfter=host())
        save(directory / 'result.json', record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--warmup', type=float, default=10)
    parser.add_argument('--seconds', type=float, default=30)
    parser.add_argument('--idle', type=float, default=5)
    parser.add_argument('--cooldown', type=float, default=20)
    parser.add_argument('--only', help='comma-separated declared case names')
    parser.add_argument('--calibrate', action='store_true', help='append three paired sampler on/off direct controls')
    parser.add_argument('--parent-netns', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 3 or not 0 <= args.warmup <= 60 or not 1 <= args.seconds <= 120 or not 0 <= args.idle <= 30 or not 0 <= args.cooldown <= 60:
        parser.error('parameter exceeds finite baseline bounds')
    args.out = args.out.resolve()
    args.build = args.build.resolve()
    if not args.parent_netns:
        namespace = os.readlink('/proc/self/ns/net')
        command = ['unshare', '--user', '--map-root-user', '--net', 'sh', '-c',
                   'ip link set dev lo up && exec "$@"', 'poc-benchmark', sys.executable,
                   str(Path(__file__).resolve()), *sys.argv[1:], '--parent-netns', namespace]
        return subprocess.run(command).returncode
    if os.readlink('/proc/self/ns/net') == args.parent_netns or sorted(n for _, n in socket.if_nameindex()) != ['lo']:
        raise RuntimeError('benchmark requires a new network namespace with only lo')
    os.umask(0o077)
    available = sorted(os.sched_getaffinity(0))
    if len(available) < 8:
        raise RuntimeError('this controlled baseline requires eight available CPUs for disjoint affinity')
    args.cpus = {'gateway': available[:2], 'upstream': available[2:4],
                 'driver': available[4:6], 'coordinator': available[6:8]}
    os.sched_setaffinity(0, args.cpus['coordinator'])
    args.out.mkdir(parents=True, exist_ok=False)
    args.build = json.loads(args.build.read_text())
    if not args.build.get('successful') or inputs() != args.build['sourceSha256']:
        raise RuntimeError('release manifest not successful or production source drift')
    for product in args.build['products'].values():
        if digest(Path(product['path'])) != product['sha256']:
            raise RuntimeError('binary digest differs')
    report = {'successful': False, 'profile': 'release', 'build': args.build,
              'parameters': {k: v for k, v in vars(args).items() if k not in ('build',)},
              'environment': {'platform': platform.platform(), 'machine': platform.machine(),
                              'cpuinfo': Path('/proc/cpuinfo').read_text(), 'host': host(),
                              'netns': os.readlink('/proc/self/ns/net'),
                              'cgroup': Path('/proc/self/cgroup').read_text(),
                              'cgroupDelegated': os.access('/sys/fs/cgroup/cgroup.subtree_control', os.W_OK),
                              'cpuPercentBasis': 'one logical CPU = 100%',
                              'clockTicks': os.sysconf('SC_CLK_TCK')},
              'harnessSha256': {str(p.relative_to(ROOT)): digest(p) for p in HERE.glob('*.py')},
              'startedWallNs': time.time_ns(), 'cases': []}
    report['parameters']['out'] = str(args.out)
    def checkpoint():
        save(args.out / 'baseline.json', report)
    checkpoint()
    selected = [case for case in CASES if not args.only or case[0] in args.only.split(',')]
    if not selected or (args.only and set(args.only.split(',')) - {c[0] for c in CASES}):
        parser.error('unknown/empty case selection')
    for round_number in range(1, args.rounds + 1):
        # Reverse order each alternate round to expose warm-cache/order effects.
        for case in selected if round_number % 2 else reversed(selected):
            print(f'round {round_number}/{args.rounds}: {case[0]}', flush=True)
            result = run_case(args, case, round_number)
            report['cases'].append(result)
            checkpoint()
            if not result['successful']:
                print('stopping baseline after failure; all evidence retained', flush=True)
                return 1
    if args.calibrate:
        for round_number in range(1, 4):
            for enabled in ([False, True] if round_number % 2 else [True, False]):
                name = f'calibration-{"on" if enabled else "off"}'
                print(f'round {round_number}/3: {name}', flush=True)
                result = run_case(args, (name, None, 'llm', 8), round_number, enabled, True)
                report['cases'].append(result)
                checkpoint()
                if not result['successful']:
                    return 1
    report.update(successful=True, finishedWallNs=time.time_ns())
    checkpoint()
    print('baseline complete', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
