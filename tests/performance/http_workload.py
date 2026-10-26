#!/usr/bin/env python3
"""Bounded external HTTP/1.1 upstream and closed-loop load generator (stdlib only)."""
import argparse
import asyncio
import collections
import csv
import json
import os
from pathlib import Path
import time

MAX_BODY = 2 * 1024 * 1024
ANSWER = 'safe benchmark answer ' * 32
MODEL_RESPONSE = {'id': 'bench', 'object': 'chat.completion', 'created': 1,
                  'model': 'local', 'choices': [{'index': 0, 'finish_reason': 'stop',
                  'message': {'role': 'assistant', 'content': ANSWER}}],
                  'usage': {'prompt_tokens': 32, 'completion_tokens': 32, 'total_tokens': 64}}


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode()


async def head(reader):
    raw = await reader.readuntil(b'\r\n\r\n')
    if len(raw) > 16384:
        raise ValueError('oversized headers')
    lines = raw.decode('latin1').split('\r\n')
    headers = {}
    for line in lines[1:]:
        if line:
            key, value = line.split(':', 1)
            key = key.lower()
            if key in headers:
                raise ValueError('duplicate header: ' + key)
            headers[key] = value.strip()
    return lines[0], headers


async def body(reader, headers):
    if 'transfer-encoding' in headers:
        if headers['transfer-encoding'].lower() != 'chunked' or 'content-length' in headers:
            raise ValueError('unsupported/ambiguous body framing')
        chunks, size = [], 0
        while True:
            line = await reader.readline()
            length = int(line.split(b';')[0], 16)
            if length == 0:
                while await reader.readline() != b'\r\n':
                    if reader.at_eof():
                        raise ValueError('incomplete trailers')
                return b''.join(chunks)
            size += length
            if size > MAX_BODY:
                raise ValueError('oversized body')
            chunks.append(await reader.readexactly(length))
            if await reader.readexactly(2) != b'\r\n':
                raise ValueError('bad chunk framing')
    if 'content-length' not in headers:
        raise ValueError('unbounded body framing')
    size = int(headers['content-length'])
    if not 0 <= size <= MAX_BODY:
        raise ValueError('oversized body')
    return await reader.readexactly(size)


def rpc_result(request):
    method = request['method']
    if method == 'initialize':
        return {'protocolVersion': request['params']['protocolVersion'],
                'serverInfo': {'name': 'benchmark-tool', 'version': '1'}, 'capabilities': {'tools': {}}}
    if method == 'tools/list':
        return {'tools': [{'name': 'echo', 'description': 'deterministic echo',
                          'inputSchema': {'type': 'object', 'properties': {}}}]}
    if method == 'tools/call' and request['params']['name'] == 'echo':
        return {'content': [{'type': 'text', 'text': ANSWER}], 'isError': False}
    raise ValueError('unexpected RPC: ' + method)


async def serve(args):
    calls = collections.Counter()

    async def client(reader, writer):
        try:
            while True:
                line, headers = await head(reader)
                method, path, _ = line.split(' ')
                if method in ('GET', 'DELETE'):
                    calls[method] += 1
                    status = 405 if method == 'GET' else 200
                    writer.write(f'HTTP/1.1 {status} Response\r\nContent-Length: 0\r\n\r\n'.encode())
                    await writer.drain()
                    continue
                request = json.loads(await body(reader, headers))
                if method != 'POST':
                    raise ValueError('expected POST')
                operation = 'model' if path == '/v1/chat/completions' else request['method']
                calls[operation] += 1
                if operation == 'model':
                    if request.get('stream') or request['model'] != 'local':
                        raise ValueError('unexpected model request')
                    result, status = MODEL_RESPONSE, 200
                elif 'id' in request:
                    result = {'jsonrpc': '2.0', 'id': request['id'], 'result': rpc_result(request)}
                    status = 200
                else:
                    if request['method'] != 'notifications/initialized':
                        raise ValueError('unexpected notification')
                    result, status = None, 202
                await asyncio.sleep(args.delay_ms / 1000)
                data = encode(result) if result is not None else b''
                writer.write(f'HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n'.encode() + data)
                await writer.drain()
        except asyncio.IncompleteReadError as error:
            if error.partial:
                calls['incompleteRequest'] += 1
        except (ConnectionError, ValueError, KeyError, asyncio.LimitOverrunError) as error:
            calls['serverError'] += 1
            print(json.dumps({'error': repr(error)}), flush=True)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(client, '127.0.0.1', 0, limit=16384)
    port = server.sockets[0].getsockname()[1]
    args.ready.write_text(json.dumps({'pid': os.getpid(), 'port': port}))

    async def checkpoint():
        while True:
            candidate = args.counters.with_suffix('.next')
            candidate.write_text(json.dumps(dict(calls)))
            candidate.replace(args.counters)
            await asyncio.sleep(.1)

    async with server:
        await asyncio.gather(server.serve_forever(), checkpoint())


class Client:
    def __init__(self, port):
        self.port, self.reader, self.writer = port, None, None
        self.connections = 0

    async def request(self, path, data, headers):
        async def exchange():
            if self.writer is None:
                self.reader, self.writer = await asyncio.open_connection('127.0.0.1', self.port, limit=16384)
                self.connections += 1
            header = f'POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nContent-Length: {len(data)}\r\n'
            header += ''.join(f'{key}: {value}\r\n' for key, value in headers.items()) + '\r\n'
            self.writer.write(header.encode() + data)
            await self.writer.drain()
            line, response_headers = await head(self.reader)
            status = int(line.split(' ')[1])
            data_out = await body(self.reader, response_headers)
            if response_headers.get('connection', '').lower() == 'close':
                await self.close()
            return status, response_headers, data_out
        return await asyncio.wait_for(exchange(), timeout=5)

    async def close(self):
        if self.writer is not None:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except OSError:
                pass
            self.writer = None


def messages(headers, data):
    if 'text/event-stream' in headers.get('content-type', ''):
        return [json.loads(line[5:]) for line in data.decode().splitlines() if line.startswith('data:')]
    return [json.loads(data)] if data else []


def valid(kind, headers, data, expected_id=2):
    values = messages(headers, data)
    if kind == 'llm':
        return (len(values) == 1 and 'error' not in values[0]
                and values[0]['choices'][0]['message']['content'] == ANSWER)
    results = [v for v in values if v.get('id') == expected_id]
    return (len(results) == 1 and 'error' not in results[0]
            and not results[0]['result'].get('isError', False)
            and results[0]['result']['content'] == [{'type': 'text', 'text': ANSWER}])


def quantiles(values):
    values = sorted(values)
    if not values:
        return {'count': 0, 'p50': None, 'p95': None, 'p99': None, 'max': None}
    def percentile(fraction):
        index = (len(values) - 1) * fraction
        low = int(index)
        high = min(low + 1, len(values) - 1)
        return values[low] + (values[high] - values[low]) * (index - low)
    return {'count': len(values), 'p50': percentile(.5), 'p95': percentile(.95),
            'p99': percentile(.99), 'max': values[-1]}


async def load(args):
    headers = json.loads(args.headers.read_text())
    payload = args.payload.read_bytes()
    rpc_payload = json.loads(payload) if args.kind == 'mcp' else None
    stopped = asyncio.Event()
    clients = [Client(args.port) for _ in range(args.concurrency)]
    start = time.monotonic_ns()
    measured_start = start + int(args.warmup * 1e9)
    stop = measured_start + int(args.seconds * 1e9)
    report = {'kind': args.kind, 'concurrency': args.concurrency, 'warmupSeconds': args.warmup,
              'measurementSeconds': args.seconds, 'startNs': start,
              'measuredStartNs': measured_start, 'measuredEndNs': stop,
              'templatePayloadBytes': len(payload), 'errors': [], 'completed': 0, 'warmupCompleted': 0,
              'requestBytesMin': MAX_BODY, 'requestBytesMax': 0}
    durations, counts, byte_count = [], collections.Counter(), 0
    with args.samples.open('x', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(('startNs', 'durationNs', 'phase', 'worker', 'status', 'success', 'requestBytes', 'responseBytes', 'error'))

        async def worker(index):
            nonlocal byte_count
            client = clients[index]
            sequence = 0
            while not stopped.is_set() and time.monotonic_ns() < stop:
                begin = time.monotonic_ns()
                phase = 'measure' if begin >= measured_start else 'warmup'
                error, status, length, success = '', 0, 0, False
                sequence += 1
                request_id = f'load:{index}:{sequence}'
                request_body = encode(dict(rpc_payload, id=request_id)) if rpc_payload is not None else payload
                report['requestBytesMin'] = min(report['requestBytesMin'], len(request_body))
                report['requestBytesMax'] = max(report['requestBytesMax'], len(request_body))
                try:
                    status, response_headers, data = await client.request(args.path, request_body, headers)
                    length = len(data)
                    success = status == 200 and valid(args.kind, response_headers, data, request_id)
                    if not success:
                        error = f'invalid response: HTTP {status}: {data[:200]!r}'
                except (OSError, ValueError, KeyError, IndexError, TypeError, asyncio.TimeoutError,
                        asyncio.IncompleteReadError, asyncio.LimitOverrunError) as failure:
                    error = repr(failure)
                    await client.close()
                elapsed = time.monotonic_ns() - begin
                writer.writerow((begin, elapsed, phase, index, status, int(success), len(request_body), length, error))
                if phase == 'measure':
                    report['completed'] += 1
                    durations.append(elapsed / 1e6)
                    counts[str(status)] += 1
                    byte_count += length
                else:
                    report['warmupCompleted'] += 1
                if not success:
                    report['errors'].append({'phase': phase, 'worker': index, 'error': error})
                    stopped.set()  # retain first failure; do not replay or raise concurrency
                total = report['completed'] + report['warmupCompleted']
                if total >= 1_000_000 or (total % 1024 == 0 and stream.tell() > 256 * 1024 * 1024):
                    report['errors'].append({'error': 'sample bound reached'})
                    stopped.set()

        print(json.dumps({'event': 'load', **report}), flush=True)
        await asyncio.gather(*(worker(i) for i in range(args.concurrency)))
    await asyncio.gather(*(client.close() for client in clients))
    elapsed = (time.monotonic_ns() - measured_start) / 1e9
    report.update(successful=not report['errors'] and elapsed >= args.seconds,
                  finishedNs=time.monotonic_ns(), latencyMs=quantiles(durations),
                  completedPerSecond=report['completed'] / max(args.seconds, elapsed),
                  responseBytes=byte_count, statuses=dict(counts),
                  connections=sum(c.connections for c in clients))
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'event': 'complete', 'successful': report['successful'],
                      'completed': report['completed']}), flush=True)
    return 0 if report['successful'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    server = commands.add_parser('serve')
    server.add_argument('--ready', type=Path, required=True)
    server.add_argument('--counters', type=Path, required=True)
    server.add_argument('--delay-ms', type=float, default=5)
    load_parser = commands.add_parser('load')
    load_parser.add_argument('--port', type=int, required=True)
    load_parser.add_argument('--kind', choices=('llm', 'mcp'), required=True)
    load_parser.add_argument('--path', required=True)
    load_parser.add_argument('--payload', type=Path, required=True)
    load_parser.add_argument('--headers', type=Path, required=True)
    load_parser.add_argument('--samples', type=Path, required=True)
    load_parser.add_argument('--report', type=Path, required=True)
    load_parser.add_argument('--concurrency', type=int, required=True)
    load_parser.add_argument('--warmup', type=float, default=20)
    load_parser.add_argument('--seconds', type=float, default=60)
    args = parser.parse_args()
    if args.command == 'serve':
        if not 0 <= args.delay_ms <= 100:
            parser.error('delay must be 0..100 ms')
        asyncio.run(serve(args))
        return 0
    if not 1 <= args.concurrency <= 32 or not 0 <= args.warmup <= 60 or not 1 <= args.seconds <= 300:
        parser.error('bounded concurrency 1..32, warmup 0..60, seconds 1..300 required')
    return asyncio.run(load(args))


if __name__ == '__main__':
    raise SystemExit(main())
