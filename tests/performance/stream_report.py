#!/usr/bin/env python3
"""Recompute raw streaming measurements, archive evidence and draw resource curves."""
import argparse
import csv
import gzip
import hashlib
import json
from pathlib import Path
import statistics
import tarfile

from build_release import digest, inputs
from http_workload import quantiles
from resources import window
from run_streams import CASES, clock_quality
from summarize import compressed_copy

MIB = 1024 ** 2


def sample_name(case, kind):
    return f"{Path(case['directory']).parent.name}-{case['name']}-r{case['round']}-{kind}.gz"


def verify_case(case, request_file, resource_file, require_clock=True):
    load = case['load']
    measured, byte_times, content_times = [], [], []
    warmup = response_bytes = content_bytes = 0
    with gzip.open(request_file, 'rt', newline='') as file:
        for row in csv.DictReader(file):
            assert row['success'] == '1' and not row['error'], case['name']
            start, elapsed, first, content = [int(row[k]) for k in ('startNs', 'durationNs', 'firstByteNs', 'firstContentNs')]
            assert load['startNs'] <= start < load['measuredEndNs']
            assert 0 <= first <= content <= elapsed
            assert int(row['requestBytes']) == load['requestBytes']
            assert int(row['contentBytes']) == case['outputBytes']
            if start < load['measuredStartNs']:
                assert row['phase'] == 'warmup'
                warmup += 1
            else:
                assert row['phase'] == 'measure'
                measured.append(elapsed / 1e6)
                byte_times.append(first / 1e6)
                content_times.append(content / 1e6)
                response_bytes += int(row['responseBytes'])
                content_bytes += int(row['contentBytes'])
    assert len(measured) == load['completed'] and warmup == load['warmupCompleted']
    assert quantiles(measured) == load['latencyMs']
    assert quantiles(byte_times) == load['firstByteMs']
    assert quantiles(content_times) == load['firstContentMs']
    assert response_bytes == load['responseBytes'] and content_bytes == load['contentBytes']
    with gzip.open(resource_file, 'rt') as file:
        rows = [json.loads(line) for line in file]
    quality = clock_quality(rows)
    if require_clock:
        assert quality['valid'], (case['name'], case['round'], 'clock discontinuity')
    for role, actual in case['measurement'].items():
        assert window(rows, role, load['measuredStartNs'], load['measuredEndNs']) == actual, (case['name'], role)
    for phase in ('idle', 'primed', 'cooldown'):
        if phase in case:
            assert window(rows, 'gateway', *case[phase + 'WindowNs']) == case[phase], (case['name'], phase)
    return len(measured), warmup, quality


def validate(evidence, directory):
    run = evidence['run']
    expected = {(case[0], r) for case in CASES for r in (1, 2, 3)}
    actual = [(case['name'], case['round']) for case in run['cases']]
    assert run['successful'] and len(actual) == 30 and set(actual) == expected
    assert inputs() == run['build']['sourceSha256'], 'production source drift'
    product = run['build']['products']['llm']
    assert digest(Path(product['path'])) == product['sha256'], 'binary drift'
    for name, spec in evidence['samples'].items():
        path = directory / name
        assert digest(path) == spec['sha256'], name
        with gzip.open(path, 'rb') as file:
            assert hashlib.file_digest(file, 'sha256').hexdigest() == spec['originalSha256'], name
    measured = warmup = earlier = invalid_earlier = 0
    for index, case in enumerate(run['cases'] + run.get('earlierCases', [])):
        assert case['successful'] and case['load']['successful']
        assert not case['load']['errors'] and not case['sampler']['errors']
        selected = index < len(run['cases'])
        count, warm, quality = verify_case(case, directory / sample_name(case, 'requests.csv'),
                                           directory / sample_name(case, 'resources.jsonl'), selected)
        if selected:
            measured += count
            warmup += warm
        else:
            earlier += count
            invalid_earlier += int(not quality['valid'])
    legacy_count = 0
    legacy = evidence.get('priorBaselineRepair')
    if legacy:
        assert legacy['run']['successful'] and legacy['run']['build'] == run['build']
        assert len(legacy['run']['cases']) == 3
        assert {(c['name'], c['round']) for c in legacy['run']['cases']} == {('full-c1', r) for r in (1, 2, 3)}
        assert digest(Path(run['build']['products']['full']['path'])) == run['build']['products']['full']['sha256']
        for case in legacy['run']['cases']:
            assert case['successful'] and not case['sampler']['errors']
            load = case['load']
            durations, warm, bytes_out = [], 0, 0
            with gzip.open(directory / sample_name(case, 'requests.csv'), 'rt', newline='') as file:
                for row in csv.DictReader(file):
                    assert row['success'] == '1' and row['status'] == '200' and not row['error']
                    if row['phase'] == 'measure':
                        durations.append(int(row['durationNs']) / 1e6)
                        bytes_out += int(row['responseBytes'])
                    else:
                        assert row['phase'] == 'warmup'
                        warm += 1
            assert len(durations) == load['completed'] and warm == load['warmupCompleted']
            assert quantiles(durations) == load['latencyMs'] and bytes_out == load['responseBytes']
            with gzip.open(directory / sample_name(case, 'resources.jsonl'), 'rt') as file:
                rows = [json.loads(line) for line in file]
            assert clock_quality(rows)['valid']
            for role, actual in case['measurement'].items():
                metric = window(rows, role, load['measuredStartNs'], load['measuredEndNs'])
                if role == 'gateway':
                    metric['cpuMsPerCompletedRequest'] = metric['cpuSeconds'] * 1000 / load['completed']
                assert metric == actual
            legacy_count += len(durations)
    return {'successful': True, 'conditions': 30, 'measurementRequests': measured, 'warmupRequests': warmup,
            'earlierConditions': len(run.get('earlierCases', [])), 'earlierRequests': earlier,
            'invalidEarlierClockSamples': invalid_earlier,
            'priorBaselineRecheckRequests': legacy_count,
            'compressedSamples': len(evidence['samples']), 'productionInputs': len(inputs())}


def aggregate(run):
    result = {}
    for name, protected, stream, size, concurrency in CASES:
        cases = [case for case in run['cases'] if case['name'] == name]
        row = {'protected': protected, 'stream': stream, 'outputBytes': size, 'concurrency': concurrency,
               'completed': sum(c['load']['completed'] for c in cases),
               'rounds': [{key: c['load'][key] for key in ('completedPerSecond', 'contentBytesPerSecond', 'completed',
                          'firstByteMs', 'firstContentMs', 'latencyMs', 'lowTailSampleCount')} for c in cases]}
        if protected:
            row['resources'] = [{**{phase: c[phase] for phase in ('idle', 'primed', 'cooldown')},
                                 'load': c['measurement']['gateway']} for c in cases]
        result[name] = row
    return result


def plots(evidence, directory):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    summary = evidence['summary']
    figure, axes = plt.subplots(1, 3, figsize=(15, 4.5), constrained_layout=True)
    groups = [('llm-sse-8k-c1', 'llm-sse-8k-c8', 'llm-sse-8k-c32'),
              ('llm-sse-8k-c8', 'llm-sse-128k-c8', 'llm-sse-1m-c8')]
    for ax, group, labels in zip(axes[:2], groups, (['1', '8', '32'], ['8 KiB', '128 KiB', '1 MiB'])):
        for i, name in enumerate(group):
            for phase, offset, color in (('primed', -.16, 'tab:green'), ('load', .16, 'tab:blue')):
                values = [v[phase]['VmRSSBytes']['median'] / MIB for v in summary[name]['resources']]
                ax.scatter([i + offset] * len(values), values, color=color, s=25,
                           label=phase if i == 0 else None)
        ax.set(xticks=range(3), xticklabels=labels, ylabel='Gateway RSS (MiB)')
        ax.legend()
    axes[0].set(title='8 KiB SSE: concurrency', xlabel='Concurrency')
    axes[1].set(title='C8 SSE: response size', xlabel='Response content bytes')
    names = [name for name, row in summary.items() if row['protected']]
    for i, name in enumerate(names):
        axes[2].scatter([i] * 3, [r['firstContentMs']['p50'] for r in summary[name]['rounds']], color='tab:orange')
    axes[2].set(xticks=range(len(names)), xticklabels=[n.removeprefix('llm-') for n in names],
                ylabel='First valid content p50 (ms)', title='Each dot = an independent round')
    axes[2].tick_params(axis='x', labelrotation=30)
    figure.savefig(directory / 'resources.png', dpi=150)
    figure.savefig(directory / 'resources.svg')
    plt.close(figure)
    figure, axes = plt.subplots(len(names), 1, figsize=(11, 2.2 * len(names)), constrained_layout=True, squeeze=False)
    for ax, name in zip(axes[:, 0], names):
        for c in [c for c in evidence['run']['cases'] if c['name'] == name]:
            with gzip.open(directory / sample_name(c, 'resources.jsonl'), 'rt') as file:
                rows = [json.loads(line) for line in file]
            rows = [r for r in rows if 'gateway' in r['processes']]
            ax.plot([(r['monotonicNs'] - c['processStartedNs']) / 1e9 for r in rows],
                    [r['processes']['gateway']['VmRSSBytes'] / MIB for r in rows],
                    label=f"Round {c['round']}", linewidth=1)
            ax.axvspan((c['load']['measuredStartNs'] - c['processStartedNs']) / 1e9,
                       (c['load']['measuredEndNs'] - c['processStartedNs']) / 1e9, color='grey', alpha=.04)
        ax.set(title=name, xlabel='Seconds after spawn (includes cache priming)', ylabel='RSS (MiB)')
        ax.legend(loc='lower right')
    figure.savefig(directory / 'memory-timeline.png', dpi=130)
    figure.savefig(directory / 'memory-timeline.svg')
    plt.close(figure)


def assemble(initial, repair, initial_path, repair_path):
    assert initial['successful'] and repair['successful']
    assert initial['build'] == repair['build'] and initial['wire'] == repair['wire']
    for key in ('rounds', 'warmup', 'seconds', 'idle', 'cooldown', 'prime', 'cpus'):
        assert initial['parameters'][key] == repair['parameters'][key], key
    for key in ('tests/performance/stream_workload.py', 'tests/performance/resources.py',
                'tests/performance/http_workload.py', 'tests/performance/run_baseline.py'):
        assert initial['harnessSha256'][key] == repair['harnessSha256'][key], key
    quality = []
    for case in initial['cases']:
        rows = [json.loads(line) for line in (Path(case['directory']) / 'resources.jsonl').read_text().splitlines()]
        quality.append({'name': case['name'], 'round': case['round'], **clock_quality(rows)})
    assert [(q['name'], q['round']) for q in quality if not q['valid']] == [('direct-sse-128k-c8', 3)]
    assert {(c['name'], c['round']) for c in repair['cases']} == {('direct-sse-128k-c8', r) for r in (1, 2, 3)}
    assert len(repair['cases']) == 3 and all(c['clockQuality']['valid'] for c in repair['cases'])
    result = dict(initial)
    result.update(cases=[c for c in initial['cases'] if c['name'] != 'direct-sse-128k-c8'] + repair['cases'],
                  earlierCases=[c for c in initial['cases'] if c['name'] == 'direct-sse-128k-c8'],
                  finishedWallNs=repair['finishedWallNs'],
                  assembly={'reason': 'One direct 128 KiB round crossed a wall/monotonic discontinuity. All three direct 128 KiB rounds replaced after adding clock-quality admission; original observations retained.',
                            'initialClockQuality': quality,
                            'initial': {'path': str(initial_path), 'sha256': digest(initial_path)},
                            'repair': {'path': str(repair_path), 'sha256': digest(repair_path)},
                            'repairHarnessSha256': repair['harnessSha256']})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--repair', type=Path, help='Retained three-round direct-128k clock repair')
    parser.add_argument('--initial-tools', type=Path, help='Exact initial harness snapshot if its sources changed')
    parser.add_argument('--repair-tools', type=Path)
    args = parser.parse_args()
    if args.verify:
        print(json.dumps(validate(json.loads(args.verify.read_text()), args.verify.parent)))
        return 0
    if not args.run or not args.out:
        parser.error('run/out or verify required')
    run = json.loads(args.run.read_text())
    if args.repair:
        run = assemble(run, json.loads(args.repair.read_text()), args.run, args.repair)
    if not run['successful']:
        raise RuntimeError('cannot accept an incomplete/failed run')
    args.out.mkdir(parents=True, exist_ok=False)
    evidence = {'run': run, 'summary': aggregate(run), 'samples': {},
                'postprocessorSha256': digest(Path(__file__)),
                'summaryConvention': 'Median of independent-round statistics; quantiles are not pooled.'}
    for case in run['cases'] + run.get('earlierCases', []):
        for name in ('requests.csv', 'resources.jsonl'):
            original = Path(case['directory']) / name
            target = args.out / sample_name(case, name)
            compressed_copy(original, target)
            evidence['samples'][target.name] = {'sha256': digest(target), 'originalSha256': digest(original), 'bytes': target.stat().st_size}
    for filename, source, hashes in [('measurement-tools.tar.gz', args.initial_tools, run['harnessSha256']),
                                    ('repair-tools.tar.gz', args.repair_tools, run.get('assembly', {}).get('repairHarnessSha256', {}))]:
        if not hashes:
            continue
        with tarfile.open(args.out / filename, 'w:gz') as tar:
            for name, sha in hashes.items():
                actual = source / Path(name).name if source else Path(name)
                assert digest(actual) == sha, name
                tar.add(actual, arcname=Path(name).name)
    evidence['rawVerification'] = validate(evidence, args.out)
    (args.out / 'validation.json').write_text(json.dumps(evidence, indent=2) + '\n')
    with (args.out / 'summary.csv').open('x', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(('case', 'completed', 'rpsMedian', 'contentMiBPerSecondMedian', 'firstBodyP50Ms',
                         'firstContentP50Ms', 'firstContentP95Ms', 'fullP50Ms', 'fullP95Ms', 'lowTailSamples',
                         'primedRssMiB', 'loadRssMiB', 'loadPssMiB', 'peakRssMiB', 'cooldownRssMiB', 'cpuPercentOneCore'))
        for name, row in evidence['summary'].items():
            rounds = row['rounds']
            values = [statistics.median([r[k] for r in rounds]) for k in ('completedPerSecond', 'contentBytesPerSecond')]
            values[1] /= MIB
            values += [statistics.median(r[k][q] for r in rounds) for k, q in (
                ('firstByteMs', 'p50'), ('firstContentMs', 'p50'), ('firstContentMs', 'p95'),
                ('latencyMs', 'p50'), ('latencyMs', 'p95'))]
            values += [any(r['lowTailSampleCount'] for r in rounds)]
            if row['protected']:
                values += [statistics.median(r[phase][field][stat] for r in row['resources']) / MIB
                           for phase, field, stat in (('primed', 'VmRSSBytes', 'median'), ('load', 'VmRSSBytes', 'median'),
                             ('load', 'pssBytes', 'median'), ('load', 'VmRSSBytes', 'max'), ('cooldown', 'VmRSSBytes', 'median'))]
                values += [statistics.median(r['load']['cpuPercentOneCore'] for r in row['resources'])]
            writer.writerow([name, row['completed'], *values])
    plots(evidence, args.out)
    print(json.dumps(evidence['rawVerification']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
