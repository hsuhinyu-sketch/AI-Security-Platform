"""Verify content arrival timing and terminal/error semantics before interpreting throughput."""
import asyncio
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from http_workload import encode
from stream_workload import Content, chunks, event, text
from run_streams import clock_quality


def frame(delta, finish=None):
    return b'data: ' + encode(event(delta, finish)) + b'\n\n'


class StreamMeasurementTests(unittest.TestCase):
    def test_suspend_or_clock_jump_cannot_be_accepted_as_a_clean_sample(self):
        rows = [{'wallNs': i * 1_000_000_000, 'monotonicNs': i * 1_000_000_000} for i in range(3)]
        self.assertTrue(clock_quality(rows)['valid'])
        for jump in (10_000_000_000, -10_000_000_000):
            changed = [dict(row) for row in rows]
            changed[2]['wallNs'] += jump
            self.assertFalse(clock_quality(changed)['valid'])
        gradual = [{'wallNs': i * 3_000_000_000, 'monotonicNs': i * 1_000_000_000} for i in range(5)]
        self.assertFalse(clock_quality(gradual)['valid'])

    def collector(self):
        return Content(8192, 100)

    def test_first_valid_content_excludes_role_and_incomplete_event(self):
        value = self.collector()
        value.feed(frame({'role': 'assistant'}), 110)
        self.assertIsNone(value.first_ns)
        first = frame({'content': text(8192)[:4096]})
        value.feed(first[:-1], 120)
        self.assertIsNone(value.first_ns)
        value.feed(first[-1:], 130)
        self.assertEqual(value.first_ns, 30)
        value.feed(frame({'content': text(8192)[4096:]}), 140)
        value.feed(frame({}, 'stop') + b'data: [DONE]\n\n', 150)
        value.complete()
        self.assertEqual(value.length, 8192)

    def test_fragmented_utf8_or_json_cannot_count_before_full_frame(self):
        value = self.collector()
        wire = frame({'content': text(8192)}) + frame({}, 'stop') + b'data: [DONE]\n\n'
        for position in range(0, len(wire), 7):
            value.feed(wire[position:position + 7], 200 + position)
        value.complete()
        self.assertGreater(value.first_ns, 8192)

    def test_http_200_error_event_is_not_a_successful_stream(self):
        with self.assertRaises(ValueError):
            self.collector().feed(b'data: {"error":{"message":"blocked"}}\n\n', 200)

    def test_missing_done_or_finish_or_wrong_content_fails(self):
        for wire in (frame({'content': text(8192)}) + frame({}, 'stop'),
                     frame({'content': text(8192)}),
                     frame({'content': 'x' * 8192}) + frame({}, 'stop') + b'data: [DONE]\n\n'):
            with self.subTest(length=len(wire)), self.assertRaises(ValueError):
                value = self.collector()
                value.feed(wire, 200)
                value.complete()

    def test_done_before_finish_or_data_after_done_is_rejected(self):
        with self.assertRaises(ValueError):
            self.collector().feed(b'data: [DONE]\n\n', 200)
        value = self.collector()
        value.feed(frame({'content': text(8192)}) + frame({}, 'stop') + b'data: [DONE]\n\n', 200)
        with self.assertRaises(ValueError):
            value.feed(frame({'content': 'late'}), 300)

    def test_event_and_content_limits_are_enforced(self):
        with self.assertRaisesRegex(ValueError, 'bound'):
            self.collector().feed(b'data: ' + b'x' * 65537 + b'\n\n', 200)
        with self.assertRaisesRegex(ValueError, 'excess'):
            self.collector().feed(frame({'content': 'x' * 8193}), 200)

    def test_chunked_and_content_length_fragments_preserve_all_wire_bytes(self):
        async def run():
            for raw, headers in ((b'3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n', {'transfer-encoding': 'chunked'}),
                                 (b'abcde', {'content-length': '5'})):
                reader = asyncio.StreamReader()
                reader.feed_data(raw)
                reader.feed_eof()
                self.assertEqual(b''.join([v async for v in chunks(reader, headers)]), b'abcde')
        asyncio.run(run())

    def test_incomplete_or_ambiguous_http_body_is_rejected(self):
        async def run():
            for raw, headers in ((b'abc', {'content-length': '5'}),
                                 (b'', {'content-length': '1', 'transfer-encoding': 'chunked'}),
                                 (b'', {'content-length': '2097153'})):
                reader = asyncio.StreamReader()
                reader.feed_data(raw)
                reader.feed_eof()
                with self.assertRaises(ValueError):
                    [v async for v in chunks(reader, headers)]
        asyncio.run(run())


if __name__ == '__main__':
    unittest.main()
