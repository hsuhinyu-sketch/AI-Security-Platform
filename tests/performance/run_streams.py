#!/usr/bin/env python3
"""Basic streaming/payload measurements; reuse release binary, Host and PID sampler."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import platform
import socket
import sys
import time
import traceback

from build_release import digest, inputs
from http_workload import Client, encode, valid
from resources import Sampler, host, window
from run_baseline import Gateway, HERE, ROOT, await_ready, preflight, save, spawn, start_gateway, stop, wait_file
from stream_workload import CHUNK_BYTES, GAP_SECONDS, INITIAL_SECONDS

# One variable at a time: response growth at C8, concurrency at 8 KiB, JSON/SSE at 8 KiB.
CASES = [('direct-json-8k-c8', False, False, 8192, 8),
         ('llm-json-8k-c8', True, False, 8192, 8),
         ('direct-sse-8k-c8', False, True, 8192, 8),
         ('llm-sse-8k-c1', True, True, 8192, 1),
         ('llm-sse-8k-c8', True, True, 8192, 8),
         ('llm-sse-8k-c32', True, True, 8192, 32),
         ('direct-sse-128k-c8', False, True, 131072, 8),
         ('llm-sse-128k-c8', True, True, 131072, 8),
         ('direct-sse-1m-c8', False, True, 1048576, 8),
         ('llm-sse-1m-c8', True, True, 1048576, 8)]


def clock_quality(rows):
    """Wall vs monotonic discrepancy detects suspend/resume or clock discontinuity."""
    threshold = 5_000_000_000
    differences = [(b['wallNs'] - a['wallNs']) - (b['monotonicNs'] - a['monotonicNs'])
                   for a, b in zip(rows, rows[1:])]
    maximum = max(map(abs, differences), default=0)
    total = sum(differences)
    return {'valid': maximum <= threshold and abs(total) <= threshold,
            'thresholdNs': threshold, 'maxDiscontinuityNs': maximum, 'totalDriftNs': total,
            'samples': len(rows)}


async def prime(gateway, count):
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + gateway.token()}
    data = encode({'model': 'local', 'messages': [{'role': 'user', 'content': 'benchmark question'}]})
    async def worker(index):
        client = Client(gateway.model_port)
        try:
            for _ in range(index, count, 8):
                status, response_headers, raw = await client.request('/v1/chat/completions', data, headers)
                if status != 200 or not valid('llm', response_headers, raw):
                    raise RuntimeError('cache priming failed')
        finally:
            await client.close()
    begin = time.monotonic_ns()
    await asyncio.gather(*(worker(i) for i in range(8)))
    return {'requests': count, 'concurrency': 8, 'elapsedSeconds': (time.monotonic_ns() - begin) / 1e9}


def run_case(args, case, round_number):
    name, protected, stream, size, concurrency = case
    directory = args.out / f'{name}-r{round_number}'
    directory.mkdir(mode=0o700)
    result = {'name': name, 'protected': protected, 'stream': stream, 'outputBytes': size,
              'concurrency': concurrency, 'round': round_number, 'directory': str(directory),
              'successful': False, 'startedWallNs': time.time_ns(), 'hostBefore': host()}
    children, handles = [], []
    gateway = None
    sampler = Sampler(directory / 'resources.jsonl')
    sampler.start()
    def log(name):
        value = (directory / name).open('xb')
        handles.append(value)
        return value
    try:
        server = spawn([sys.executable, str(HERE / 'stream_workload.py'), 'serve',
                        '--output-bytes', str(size), '--ready', str(directory / 'ready.json'),
                        '--counters', str(directory / 'counters.json')], args.cpus['upstream'], log('upstream.log'))
        children.append(server)
        sampler.attach('upstream', server)
        port = wait_file(directory / 'ready.json', server)['port']
        if protected:
            gateway = Gateway(args.build['products']['llm']['path'], directory, port, llm_only=True)
            config = json.loads(gateway.config.read_text())
            config['config']['workerThreads'] = 2
            config['aiSystems'][0]['name'] = 'benchmark-stream'
            gateway.config.write_text(json.dumps(config, indent=2))
            result['config'] = config
            started, fd = start_gateway(gateway, args.cpus['gateway'], log('gateway.log'))
            children.append(gateway.process)
            sampler.attach('gateway', gateway.process)
            ready = await_ready(gateway, fd)
            result.update(startupMs=(ready - started) / 1e6, processStartedNs=started, readyNs=ready)
            result['idleWindowNs'] = [time.monotonic_ns()]
            time.sleep(args.idle)
            result['idleWindowNs'].append(time.monotonic_ns())
            port, _, headers, _, result['preflight'] = asyncio.run(preflight(gateway, 'llm'))
            time.sleep(.15)
            assert json.loads((directory / 'counters.json').read_text()).get('model') == 1, 'denied identities reached upstream'
            result['preflight']['deniedUpstreamCalls'] = 0
            async def bounded_prime():
                return await asyncio.wait_for(prime(gateway, args.prime), timeout=90)
            result['priming'] = asyncio.run(bounded_prime())
            result['primedWindowNs'] = [time.monotonic_ns()]
            time.sleep(args.idle)
            result['primedWindowNs'].append(time.monotonic_ns())
        else:
            headers = {'Content-Type': 'application/json'}
        (directory / 'headers.json').write_text(json.dumps(headers))
        time.sleep(.15)
        before = json.loads((directory / 'counters.json').read_text())
        if protected and before.get('model', 0) != 1 + args.prime:
            raise RuntimeError('priming upstream count mismatch')
        result['upstreamBefore'] = before
        command = [sys.executable, str(HERE / 'stream_workload.py'), 'load', '--port', str(port),
                   '--output-bytes', str(size), '--concurrency', str(concurrency),
                   '--headers', str(directory / 'headers.json'), '--samples', str(directory / 'requests.csv'),
                   '--report', str(directory / 'load.json'), '--warmup', str(args.warmup), '--seconds', str(args.seconds)]
        if stream:
            command.append('--stream')
        result['driverCommand'] = command
        driver = spawn(command, args.cpus['driver'], log('load.log'))
        children.append(driver)
        sampler.attach('driver', driver)
        result['driverExitCode'] = driver.wait(timeout=args.warmup + args.seconds + 20)
        result['load'] = json.loads((directory / 'load.json').read_text())
        if result['driverExitCode'] or not result['load']['successful']:
            raise RuntimeError('workload failed')
        time.sleep(.2)
        after = json.loads((directory / 'counters.json').read_text())
        result['upstreamAfter'] = after
        expected = result['load']['warmupCompleted'] + result['load']['completed']
        if (after.get('model', 0) - before.get('model', 0) != expected
                or after.get('completed', 0) - before.get('completed', 0) != expected
                or after.get('errors', 0) or after.get('incomplete', 0)):
            raise RuntimeError('upstream count mismatch or error')
        if gateway:
            if gateway.process.poll() is not None:
                raise RuntimeError('gateway exited')
            result['cooldownWindowNs'] = [time.monotonic_ns()]
            time.sleep(args.cooldown)
            result['cooldownWindowNs'].append(time.monotonic_ns())
        result['successful'] = True
    except BaseException as failure:
        result.update(error=repr(failure), traceback=traceback.format_exc())
    finally:
        sampler.stop()
        result['sampler'] = {'cpuSeconds': sampler.cpu_seconds, 'errors': sampler.errors,
                             'exitedDuringRead': sampler.exited_during_read}
        result['clockQuality'] = clock_quality(sampler.rows)
        if not result['clockQuality']['valid']:
            result.update(successful=False, clockError='wall/monotonic discontinuity')
        if sampler.errors:
            result['successful'] = False
        if 'load' in result:
            load = result['load']
            result['measurement'] = {role: window(sampler.rows, role, load['measuredStartNs'], load['measuredEndNs'])
                                     for role in ('gateway', 'upstream', 'driver')}
            for role in ('gateway', 'upstream', 'driver'):
                metric = result['measurement'][role]
                if role == 'gateway' and not protected:
                    continue
                if not metric or not metric['pssBytes'] or metric['samples'] < 3 or max(metric['boundaryGapMs']) > 500:
                    result.update(successful=False, measurementError=f'insufficient {role} sample coverage')
        for phase in ('idle', 'primed', 'cooldown'):
            if phase + 'WindowNs' in result:
                result[phase] = window(sampler.rows, 'gateway', *result[phase + 'WindowNs'])
        for child in reversed(children):
            stop(child)
        if gateway:
            gateway.role_ports.close()
            gateway.signer.close()
        for handle in handles:
            handle.close()
        result.update(finishedWallNs=time.time_ns(), hostAfter=host())
        save(directory / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--warmup', type=float, default=20)
    parser.add_argument('--seconds', type=float, default=20)
    parser.add_argument('--idle', type=float, default=2)
    parser.add_argument('--cooldown', type=float, default=10)
    parser.add_argument('--prime', type=int, choices=(0, 11000), default=11000)
    parser.add_argument('--only')
    parser.add_argument('--parent-netns', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 3 or not 0 <= args.warmup <= 60 or not 1 <= args.seconds <= 120 or not 1 <= args.idle <= 10 or not 0 <= args.cooldown <= 60:
        parser.error('parameters exceed finite bounds')
    selected = [c for c in CASES if not args.only or c[0] in args.only.split(',')]
    if not selected or (args.only and set(args.only.split(',')) - {c[0] for c in CASES}):
        parser.error('unknown case')
    if not args.parent_netns:
        import subprocess
        return subprocess.run(['unshare', '--user', '--map-root-user', '--net', 'sh', '-c',
            'ip link set dev lo up && exec "$@"', 'stream-benchmark', sys.executable, str(Path(__file__).resolve()),
            *sys.argv[1:], '--parent-netns', os.readlink('/proc/self/ns/net')]).returncode
    if os.readlink('/proc/self/ns/net') == args.parent_netns or sorted(n for _, n in socket.if_nameindex()) != ['lo']:
        raise RuntimeError('requires isolated lo')
    cpus = sorted(os.sched_getaffinity(0))
    if len(cpus) < 8:
        raise RuntimeError('requires eight CPUs for disjoint process affinity')
    args.cpus = dict(gateway=cpus[:2], upstream=cpus[2:4], driver=cpus[4:6], coordinator=cpus[6:8])
    os.sched_setaffinity(0, args.cpus['coordinator'])
    os.umask(0o077)
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    args.build = json.loads(args.build.read_text())
    if not args.build['successful'] or inputs() != args.build['sourceSha256']:
        raise RuntimeError('production source drift')
    product = args.build['products']['llm']
    if digest(Path(product['path'])) != product['sha256']:
        raise RuntimeError('binary drift')
    result = {'successful': False, 'build': args.build, 'startedWallNs': time.time_ns(), 'cases': [],
              'parameters': {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items() if k != 'build'},
              'environment': {'platform': platform.platform(), 'host': host(), 'netns': os.readlink('/proc/self/ns/net'),
                              'cpuinfo': Path('/proc/cpuinfo').read_text()},
              'wire': {'chunkBytes': CHUNK_BYTES, 'gapSeconds': GAP_SECONDS, 'initialSeconds': INITIAL_SECONDS,
                       'requestContentBytes': 8192},
              'harnessSha256': {str(p.relative_to(ROOT)): digest(p) for p in HERE.glob('*.py')}}
    save(args.out / 'streams.json', result)
    for r in range(1, args.rounds + 1):
        for case in selected if r % 2 else reversed(selected):
            print(f'round {r}/{args.rounds}: {case[0]}', flush=True)
            case_result = run_case(args, case, r)
            result['cases'].append(case_result)
            save(args.out / 'streams.json', result)
            if not case_result['successful']:
                print('stopped after failure; retained evidence', flush=True)
                return 1
    result.update(successful=True, finishedWallNs=time.time_ns())
    save(args.out / 'streams.json', result)
    print('stream measurements complete', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
