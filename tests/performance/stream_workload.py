#!/usr/bin/env python3
"""External paced OpenAI upstream and incremental content-validated HTTP/SSE load."""
import argparse
import asyncio
import collections
import csv
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import time

from http_workload import Client, MAX_BODY, MODEL_RESPONSE, body, encode, head, quantiles

CHUNK_BYTES = 4096
GAP_SECONDS = .001
INITIAL_SECONDS = .005


def text(size, seed='safe benchmark answer '):
    return (seed * (size // len(seed) + 1))[:size]


@lru_cache(maxsize=3)
def expected_digest(size):
    return hashlib.sha256(text(size).encode()).hexdigest()


def event(delta, finish=None):
    return {'id': 'stream-bench', 'object': 'chat.completion.chunk', 'created': 1, 'model': 'local',
            'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish}]}


class Content:
    """Track only digest/length and one bounded SSE event, never cumulative response text."""
    def __init__(self, expected_bytes, begin_ns):
        self.expected_bytes = expected_bytes
        self.expected_hash = expected_digest(expected_bytes)
        self.begin_ns = begin_ns
        self.digest = hashlib.sha256()
        self.length = 0
        self.first_ns = None
        self.buffer = bytearray()
        self.data = []
        self.done = False
        self.finished = False

    def add_text(self, value, now):
        if not isinstance(value, str) or self.finished or self.done:
            raise ValueError('invalid/late content')
        raw = value.encode()
        if raw and self.first_ns is None:
            self.first_ns = now - self.begin_ns
        self.length += len(raw)
        if self.length > self.expected_bytes:
            raise ValueError('unexpected excess content')
        self.digest.update(raw)

    def frame(self, data, now):
        if data == b'[DONE]':
            if not self.finished or self.done:
                raise ValueError('invalid DONE ordering')
            self.done = True
            return
        value = json.loads(data)
        if self.done or 'error' in value or value.get('object') != 'chat.completion.chunk':
            raise ValueError('invalid/error SSE event')
        choices = value.get('choices', [])
        if not choices and 'usage' in value:
            return
        if len(choices) != 1 or choices[0]['index'] != 0:
            raise ValueError('unexpected choices')
        choice = choices[0]
        delta = choice['delta']
        if set(delta) - {'role', 'content'}:
            raise ValueError('unexpected output type')
        if delta.get('content') is not None:
            self.add_text(delta['content'], now)
        if choice.get('finish_reason') is not None:
            if self.finished or choice['finish_reason'] != 'stop':
                raise ValueError('unexpected terminal event')
            self.finished = True

    def feed(self, raw, now):
        self.buffer.extend(raw)
        while (end := self.buffer.find(b'\n')) >= 0:
            line = bytes(self.buffer[:end]).removesuffix(b'\r')
            del self.buffer[:end + 1]
            if not line:
                if self.data:
                    self.frame(b'\n'.join(self.data), now)
                    self.data.clear()
            elif line.startswith(b'data:'):
                self.data.append(line[5:].removeprefix(b' '))
            elif not line.startswith((b':', b'event:', b'id:', b'retry:')):
                raise ValueError('unexpected SSE field')
            if sum(map(len, self.data)) > 65536:
                raise ValueError('SSE event bound exceeded')
        if len(self.buffer) + sum(map(len, self.data)) > 65536:
            raise ValueError('SSE event bound exceeded')

    def complete(self):
        if (self.buffer or self.data or not self.done or not self.finished or self.first_ns is None
                or self.length != self.expected_bytes or self.digest.hexdigest() != self.expected_hash):
            raise ValueError('incomplete or incorrect content')


async def chunks(reader, headers):
    """Read actual arriving fragments; readexactly(whole chunk) would distort first-byte time."""
    total = 0
    chunked = headers.get('transfer-encoding', '').lower() == 'chunked'
    if 'transfer-encoding' in headers and not chunked:
        raise ValueError('unsupported transfer encoding')
    if chunked and 'content-length' in headers:
        raise ValueError('ambiguous body framing')
    if not chunked and 'content-length' not in headers:
        raise ValueError('unbounded response')
    while True:
        if chunked:
            length = int((await reader.readline()).split(b';')[0], 16)
            if length == 0:
                trailer_bytes = 0
                while (line := await reader.readline()) != b'\r\n':
                    trailer_bytes += len(line)
                    if not line or trailer_bytes > 16384:
                        raise ValueError('invalid trailers')
                return
        else:
            length = int(headers['content-length'])
        if length < 0 or total + length > MAX_BODY:
            raise ValueError('body bound exceeded')
        remaining = length
        while remaining:
            data = await reader.read(min(16384, remaining))
            if not data:
                raise ValueError('truncated body')
            remaining -= len(data)
            total += len(data)
            yield data
        if not chunked:
            return
        if await reader.readexactly(2) != b'\r\n':
            raise ValueError('invalid chunk delimiter')


class StreamClient(Client):
    async def call(self, payload, headers, stream, expected_bytes, begin):
        if self.writer is None:
            self.reader, self.writer = await asyncio.open_connection('127.0.0.1', self.port, limit=16384)
            self.connections += 1
        wire = f'POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nContent-Length: {len(payload)}\r\n'
        wire += ''.join(f'{k}: {v}\r\n' for k, v in headers.items()) + '\r\n'
        self.writer.write(wire.encode() + payload)
        await self.writer.drain()
        line, response_headers = await head(self.reader)
        status = int(line.split(' ')[1])
        if status != 200:
            raise ValueError('HTTP status ' + str(status))
        if stream and 'text/event-stream' not in response_headers.get('content-type', ''):
            raise ValueError('expected SSE')
        first_byte, count, raw = None, 0, bytearray()
        content = Content(expected_bytes, begin)
        async for fragment in chunks(self.reader, response_headers):
            now = time.monotonic_ns()
            if first_byte is None:
                first_byte = now - begin
            count += len(fragment)
            if stream:
                content.feed(fragment, now)
            else:
                raw.extend(fragment)
        if stream:
            content.complete()
        else:
            value = json.loads(raw)
            if 'error' in value or len(value['choices']) != 1 or value['choices'][0]['finish_reason'] != 'stop':
                raise ValueError('invalid JSON output')
            content.add_text(value['choices'][0]['message']['content'], time.monotonic_ns())
            content.finished = content.done = True
            content.complete()
        if response_headers.get('connection', '').lower() == 'close':
            await self.close()
        return first_byte, content.first_ns, count, content.length


async def serve(args):
    counts = collections.Counter()
    answer = text(args.output_bytes)
    json_response = dict(MODEL_RESPONSE, choices=[{'index': 0, 'finish_reason': 'stop',
                                                 'message': {'role': 'assistant', 'content': answer}}])
    json_wire = encode(json_response)
    frames = [encode(event({'role': 'assistant'}))]
    frames += [encode(event({'content': answer[i:i + CHUNK_BYTES]})) for i in range(0, len(answer), CHUNK_BYTES)]
    frames += [encode(event({}, 'stop')), b'[DONE]']
    frames = [b'data: ' + value + b'\n\n' for value in frames]

    async def client(reader, writer):
        try:
            while True:
                line, headers = await head(reader)
                if line.split(' ')[:2] != ['POST', '/v1/chat/completions']:
                    raise ValueError('unexpected route')
                request = json.loads(await body(reader, headers))
                if request['model'] != 'local':
                    raise ValueError('unexpected model')
                counts['model'] += 1
                await asyncio.sleep(INITIAL_SECONDS)
                # Reuse existing JWT/preflight fixture and prime the normal security-event cache.
                if request['messages'][-1]['content'] == 'benchmark question':
                    data = encode(MODEL_RESPONSE)
                    writer.write(f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n'.encode() + data)
                elif request.get('stream'):
                    writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n')
                    for index, frame in enumerate(frames):
                        if 1 <= index < len(frames) - 2:
                            await asyncio.sleep(GAP_SECONDS)
                        writer.write(f'{len(frame):x}\r\n'.encode() + frame + b'\r\n')
                        await writer.drain()
                    writer.write(b'0\r\n\r\n')
                else:
                    writer.write(f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(json_wire)}\r\n\r\n'.encode() + json_wire)
                await writer.drain()
                counts['completed'] += 1
        except asyncio.IncompleteReadError as error:
            if error.partial:
                counts['incomplete'] += 1
        except (ValueError, KeyError, ConnectionError, asyncio.LimitOverrunError) as error:
            counts['errors'] += 1
            print(repr(error), flush=True)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    server = await asyncio.start_server(client, '127.0.0.1', 0, limit=16384)
    args.ready.write_text(json.dumps({'pid': os.getpid(), 'port': server.sockets[0].getsockname()[1]}))
    async def checkpoint():
        while True:
            candidate = args.counters.with_suffix('.next')
            candidate.write_text(json.dumps(dict(counts)))
            candidate.replace(args.counters)
            await asyncio.sleep(.1)
    async with server:
        await asyncio.gather(server.serve_forever(), checkpoint())


async def load(args):
    headers = json.loads(args.headers.read_text())
    payload = encode({'model': 'local', 'stream': args.stream, 'messages': [
        {'role': 'user', 'content': text(8192, 'request data ')}]})
    clients = [StreamClient(args.port) for _ in range(args.concurrency)]
    expected_digest(args.output_bytes)
    start = time.monotonic_ns()
    measured = start + int(args.warmup * 1e9)
    end = measured + int(args.seconds * 1e9)
    report = {'successful': False, 'startNs': start, 'measuredStartNs': measured, 'measuredEndNs': end,
              'stream': args.stream, 'outputBytes': args.output_bytes, 'requestBytes': len(payload),
              'concurrency': args.concurrency, 'warmupCompleted': 0, 'completed': 0, 'errors': [],
              'responseBytes': 0, 'contentBytes': 0}
    durations, first_bytes, first_content = [], [], []
    stopped = asyncio.Event()
    with args.samples.open('x', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(('startNs', 'durationNs', 'firstByteNs', 'firstContentNs', 'phase', 'worker',
                         'success', 'requestBytes', 'responseBytes', 'contentBytes', 'error'))
        async def worker(index):
            client = clients[index]
            while not stopped.is_set() and time.monotonic_ns() < end:
                begin = time.monotonic_ns()
                phase = 'measure' if begin >= measured else 'warmup'
                first, content, count, size, error = None, None, 0, 0, ''
                try:
                    first, content, count, size = await asyncio.wait_for(
                        client.call(payload, headers, args.stream, args.output_bytes, begin), timeout=10)
                except (OSError, ValueError, KeyError, IndexError, TypeError, asyncio.TimeoutError,
                        asyncio.IncompleteReadError, asyncio.LimitOverrunError) as failure:
                    error = repr(failure)
                    await client.close()
                    report['errors'].append({'phase': phase, 'worker': index, 'error': error})
                    stopped.set()
                elapsed = time.monotonic_ns() - begin
                writer.writerow((begin, elapsed, first, content, phase, index, int(not error), len(payload), count, size, error))
                if phase == 'measure':
                    report['completed'] += 1
                    report['responseBytes'] += count
                    report['contentBytes'] += size
                    durations.append(elapsed / 1e6)
                    if first is not None:
                        first_bytes.append(first / 1e6)
                    if content is not None:
                        first_content.append(content / 1e6)
                else:
                    report['warmupCompleted'] += 1
                if report['completed'] + report['warmupCompleted'] >= 500000:
                    report['errors'].append({'error': 'request bound exceeded'})
                    stopped.set()
        await asyncio.gather(*(worker(i) for i in range(args.concurrency)))
    await asyncio.gather(*(client.close() for client in clients))
    finished = time.monotonic_ns()
    seconds = max(args.seconds, (finished - measured) / 1e9)
    report.update(successful=not report['errors'] and finished >= end, finishedNs=finished,
                  completedPerSecond=report['completed'] / seconds,
                  contentBytesPerSecond=report['contentBytes'] / seconds,
                  latencyMs=quantiles(durations), firstByteMs=quantiles(first_bytes),
                  firstContentMs=quantiles(first_content), connections=sum(c.connections for c in clients),
                  lowTailSampleCount=report['completed'] < 1000)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'successful': report['successful'], 'completed': report['completed']}), flush=True)
    return 0 if report['successful'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('serve', 'load'))
    parser.add_argument('--output-bytes', type=int, required=True)
    parser.add_argument('--ready', type=Path)
    parser.add_argument('--counters', type=Path)
    parser.add_argument('--port', type=int)
    parser.add_argument('--headers', type=Path)
    parser.add_argument('--samples', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--stream', action='store_true')
    parser.add_argument('--concurrency', type=int, default=8)
    parser.add_argument('--warmup', type=float, default=20)
    parser.add_argument('--seconds', type=float, default=20)
    args = parser.parse_args()
    if args.output_bytes not in (8192, 131072, 1048576) or not 1 <= args.concurrency <= 32 or not 0 <= args.warmup <= 60 or not 1 <= args.seconds <= 120:
        parser.error('parameters exceed bounded workload')
    if args.command == 'serve':
        if not args.ready or not args.counters:
            parser.error('serve requires ready and counters')
        asyncio.run(serve(args))
        return 0
    if not all((args.port, args.headers, args.samples, args.report)):
        parser.error('load requires port, headers, samples and report')
    return asyncio.run(load(args))


if __name__ == '__main__':
    raise SystemExit(main())
