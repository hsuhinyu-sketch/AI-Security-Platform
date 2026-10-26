#!/usr/bin/env python3
"""Recompute counts, latency and resource windows from retained raw samples."""
import argparse
import csv
import gzip
import hashlib
import json
from pathlib import Path

from build_release import digest, inputs
from http_workload import quantiles
from resources import window


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.evidence.read_text())
    baseline = report['baseline']
    assert inputs() == baseline['build']['sourceSha256'], 'production input drift'
    for product in baseline['build']['products'].values():
        assert digest(Path(product['path'])) == product['sha256'], 'binary drift'
    # Verify each durable compressed sample against both its compressed and original digest.
    for name, record in report['archivedSamples'].items():
        path = args.evidence.parent / name
        assert digest(path) == record['sha256'], name
        with gzip.open(path, 'rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == record['originalSha256'], name
    completed = 0
    cases = baseline['cases'] + baseline.get('earlierCases', []) + report.get('fixtureCapacityControls', [])
    for case in cases:
        directory = Path(case['directory'])
        load = case['load']
        measured, warmup, output_bytes = [], 0, 0
        with (directory / 'requests.csv').open(newline='') as stream:
            for row in csv.DictReader(stream):
                assert row['success'] == '1' and row['status'] == '200' and not row['error'], directory
                start = int(row['startNs'])
                assert load['startNs'] <= start < load['measuredEndNs'], directory
                assert int(row['requestBytes']) <= load['requestBytesMax'], directory
                if start < load['measuredStartNs']:
                    assert row['phase'] == 'warmup', directory
                    warmup += 1
                else:
                    assert row['phase'] == 'measure', directory
                    measured.append(int(row['durationNs']) / 1e6)
                    output_bytes += int(row['responseBytes'])
        assert len(measured) == load['completed'] and warmup == load['warmupCompleted'], directory
        assert output_bytes == load['responseBytes'] and quantiles(measured) == load['latencyMs'], directory
        rows = [json.loads(line) for line in (directory / 'resources.jsonl').read_text().splitlines()]
        for role, actual in case['measurement'].items():
            recomputed = window(rows, role, load['measuredStartNs'], load['measuredEndNs'])
            if role == 'gateway' and recomputed:
                recomputed['cpuMsPerCompletedRequest'] = recomputed['cpuSeconds'] * 1000 / load['completed']
            assert recomputed == actual, (directory, role)
        for phase in ('idle', 'cooldown'):
            if phase in case:
                assert window(rows, 'gateway', *case[phase + 'WindowNs']) == case[phase], (directory, phase)
        completed += len(measured)
    assert len([c for c in baseline['cases'] if not c['calibration']]) == 24
    assert len([c for c in baseline['cases'] if c['calibration']]) == 6
    assert len(baseline.get('earlierCases', [])) == 3
    print(json.dumps({'successful': True, 'selectedConditions': 30, 'earlierConditions': 3,
                      'allRecomputedMeasurementRequests': completed,
                      'archivedSampleFiles': len(report['archivedSamples']),
                      'sourceInputs': len(baseline['build']['sourceSha256']), 'binaries': 3}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
