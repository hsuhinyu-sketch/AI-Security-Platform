"""Verify wire/error accounting and process attribution before interpreting samples."""
import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from http_workload import ANSWER, MODEL_RESPONSE, body, encode, head, quantiles, valid
from resources import Sampler, proc_stat, window


class MeasurementTests(unittest.TestCase):
    def test_proc_permission_error_only_tolerated_for_confirmed_child_exit(self):
        sampler = Sampler(Path('unused'))
        child = Mock(pid=42)
        with patch('resources.process', side_effect=PermissionError(13, 'denied')):
            child.poll.return_value = None
            with self.assertRaises(PermissionError):
                sampler.read_child('driver', child, True, 123)
            self.assertEqual(sampler.exited_during_read, [])
            child.poll.return_value = 0
            self.assertIsNone(sampler.read_child('driver', child, True, 456))
            self.assertEqual(sampler.exited_during_read[0]['exitCode'], 0)
            self.assertEqual(sampler.exited_during_read[0]['monotonicNs'], 456)

    def test_linux_stat_comm_does_not_shift_cpu_fields(self):
        fields = ['S'] + ['0'] * 49
        fields[11], fields[12], fields[19] = '123', '45', '999'
        sample = proc_stat('42 (name with ) parentheses) ' + ' '.join(fields), 100)
        self.assertEqual(sample, {'userSeconds': 1.23, 'systemSeconds': .45, 'startTicks': 999})

    def test_cpu_window_is_pid_scoped_and_reports_one_core_basis(self):
        rows = [{'monotonicNs': t * 1_000_000_000, 'processes': {
            'gateway': {'startTicks': 1, 'userSeconds': t / 2, 'systemSeconds': 0,
                        'VmRSSBytes': 100 + t, 'pssBytes': 80 + t},
            'upstream': {'startTicks': 1, 'userSeconds': t * 1000, 'systemSeconds': 0}}} for t in range(4)]
        result = window(rows, 'gateway', 1_000_000_000, 3_000_000_000)
        self.assertEqual(result['cpuPercentOneCore'], 50)
        self.assertEqual(result['VmRSSBytes']['median'], 102)
        self.assertEqual(result['boundaryGapMs'], [0, 0])
        rows[-1]['processes']['gateway']['startTicks'] = 2
        with self.assertRaisesRegex(RuntimeError, 'PID reused'):
            window(rows, 'gateway', 1_000_000_000, 3_000_000_000)

    def test_http_200_rpc_or_output_errors_are_not_successes(self):
        headers = {'content-type': 'application/json'}
        self.assertTrue(valid('llm', headers, encode(MODEL_RESPONSE)))
        rpc = {'jsonrpc': '2.0', 'id': 2, 'result': {'content': [{'type': 'text', 'text': ANSWER}]}}
        self.assertTrue(valid('mcp', headers, encode(rpc)))
        rpc['id'] = 'load:1:42'
        self.assertTrue(valid('mcp', headers, encode(rpc), 'load:1:42'))
        self.assertFalse(valid('mcp', headers, encode(rpc), 'load:1:43'))
        rpc['id'] = 2
        rpc['result']['isError'] = True
        self.assertFalse(valid('mcp', headers, encode(rpc)))
        self.assertFalse(valid('mcp', headers, encode({'id': 2, 'error': {'code': -1}})))
        self.assertFalse(valid('mcp', headers, encode({'id': 3, 'result': {}})))
        model = json.loads(encode(MODEL_RESPONSE))
        model['choices'][0]['message']['content'] = 'wrong'
        self.assertFalse(valid('llm', headers, encode(model)))

    def test_sse_error_and_success_content_are_distinguished(self):
        headers = {'content-type': 'text/event-stream'}
        error = b'data: {"jsonrpc":"2.0","id":2,"error":{"code":-1}}\n\n'
        self.assertFalse(valid('mcp', headers, error))
        rpc = {'id': 2, 'result': {'content': [{'type': 'text', 'text': ANSWER}]}}
        self.assertTrue(valid('mcp', headers, b'data: ' + encode(rpc) + b'\n\n'))

    def test_chunked_wire_is_bounded_and_truncation_fails(self):
        async def check():
            reader = asyncio.StreamReader()
            reader.feed_data(b'3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n')
            reader.feed_eof()
            self.assertEqual(await body(reader, {'transfer-encoding': 'chunked'}), b'abcde')
            with self.assertRaises(ValueError):
                await body(reader, {'content-length': '2097153'})
            with self.assertRaises(ValueError):
                await body(reader, {'transfer-encoding': 'chunked', 'content-length': '5'})
            reader = asyncio.StreamReader()
            reader.feed_data(b'ab')
            reader.feed_eof()
            with self.assertRaises(asyncio.IncompleteReadError):
                await body(reader, {'content-length': '3'})
        asyncio.run(check())

    def test_duplicate_headers_rejected_instead_of_misframing(self):
        async def check():
            reader = asyncio.StreamReader()
            reader.feed_data(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n')
            with self.assertRaises(ValueError):
                await head(reader)
        asyncio.run(check())

    def test_quantiles_keep_sample_count_and_empty_samples(self):
        self.assertEqual(quantiles([])['count'], 0)
        values = quantiles([1, 2, 3, 100])
        self.assertEqual(values['count'], 4)
        self.assertEqual(values['p50'], 2.5)
        self.assertGreater(values['p99'], values['p95'])


if __name__ == '__main__':
    unittest.main()
