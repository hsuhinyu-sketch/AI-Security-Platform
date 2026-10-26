#!/usr/bin/env python3
"""Archive baseline samples and draw standalone resource figures (matplotlib)."""
import argparse
import csv
import gzip
import json
from pathlib import Path
import shutil
import statistics

from build_release import digest

MIB = 1024 ** 2


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def aggregate(cases):
    result = {}
    for name in dict.fromkeys(case['name'] for case in cases):
        rounds = [case for case in cases if case['name'] == name]
        first = rounds[0]
        row = {'rounds': len(rounds), 'product': first['product'], 'kind': first['kind'],
               'concurrency': first['concurrency'], 'calibration': first['calibration'],
               'successful': all(case['successful'] for case in rounds),
               'completed': sum(case['load']['completed'] for case in rounds),
               'errors': sum(len(case['load']['errors']) for case in rounds),
               'rps': [case['load']['completedPerSecond'] for case in rounds],
               'p50Ms': [case['load']['latencyMs']['p50'] for case in rounds],
               'p95Ms': [case['load']['latencyMs']['p95'] for case in rounds],
               'p99Ms': [case['load']['latencyMs']['p99'] for case in rounds]}
        if first['product']:
            for phase in ('idle', 'measurement', 'cooldown'):
                metrics = [case['measurement']['gateway'] if phase == 'measurement' else case[phase] for case in rounds]
                for metric in ('VmRSSBytes', 'pssBytes', 'threads', 'fds', 'socketFds'):
                    row[f'{phase}-{metric}'] = [m[metric]['median'] for m in metrics]
            row['peakRssBytes'] = [case['measurement']['gateway']['VmRSSBytes']['max'] for case in rounds]
            row['lifetimeHighWaterBytes'] = [case['cooldown']['VmHWMBytes']['max'] for case in rounds]
            row['cpuPercentOneCore'] = [case['measurement']['gateway']['cpuPercentOneCore'] for case in rounds]
            row['cpuMsPerRequest'] = [case['measurement']['gateway']['cpuMsPerCompletedRequest'] for case in rounds]
            row['startupMs'] = [case['startupMs'] for case in rounds]
        for role in ('driver', 'upstream'):
            row[role + 'CpuPercentOneCore'] = [case['measurement'][role]['cpuPercentOneCore'] for case in rounds
                                              if case['measurement'][role]]
        result[name] = row
    return result


def compressed_copy(source, target):
    with source.open('rb') as src, target.open('xb') as dst:
        with gzip.GzipFile(filename='', mode='wb', fileobj=dst, mtime=0) as compressed:
            shutil.copyfileobj(src, compressed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.run.read_text())
    if not report['successful'] or any(not case['successful'] for case in report['cases']):
        raise RuntimeError('do not present an incomplete/failed run as an accepted baseline')
    args.out.mkdir(parents=True, exist_ok=False)
    summary = aggregate(report['cases'])
    archived = {}
    for case in report['cases'] + report.get('earlierCases', []):
        original = Path(case['directory'])
        for name in ('requests.csv', 'resources.jsonl'):
            target = args.out / f'{original.parent.name}-{original.name}-{name}.gz'
            compressed_copy(original / name, target)
            archived[target.name] = {'sha256': digest(target), 'originalSha256': digest(original / name),
                                     'bytes': target.stat().st_size}
    # Configs contain public JWKS only; bearer tokens and private signing state are not archived.
    evidence = {'summary': summary, 'baseline': report, 'archivedSamples': archived,
                'summaryConvention': 'Lists retain independent rounds; table/figure shows median of round statistics, not pooled quantiles.'}
    (args.out / 'validation.json').write_text(json.dumps(evidence, indent=2) + '\n')
    with (args.out / 'summary.csv').open('x', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(('case', 'rounds', 'completed', 'errors', 'rpsMedian', 'p50MsMedian', 'p95MsMedian', 'p99MsMedian',
                         'idleRssMiB', 'loadRssMiB', 'loadPssMiB', 'cooldownRssMiB', 'cpuPercentOneCore', 'cpuMsPerRequest'))
        for name, row in summary.items():
            writer.writerow([name, row['rounds'], row['completed'], row['errors'],
                             *[median(row[key]) for key in ('rps', 'p50Ms', 'p95Ms', 'p99Ms')],
                             *[median(row[key]) / MIB if key in row else None for key in (
                                 'idle-VmRSSBytes', 'measurement-VmRSSBytes', 'measurement-pssBytes', 'cooldown-VmRSSBytes')],
                             median(row.get('cpuPercentOneCore', [])), median(row.get('cpuMsPerRequest', []))])
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    selected = [(name, row) for name, row in summary.items() if row['product']]
    figure, axes = plt.subplots(1, 2, figsize=(13, 4.6), constrained_layout=True)
    labels = [name for name, _ in selected]
    for i, (phase, label) in enumerate((('idle', 'Idle'), ('measurement', 'Load'), ('cooldown', 'Cooldown'))):
        axes[0].bar([x + (i - 1) * .25 for x in range(len(selected))],
                    [median(row[f'{phase}-VmRSSBytes']) / MIB for _, row in selected], width=.25, label=label)
    axes[0].set(xticks=range(len(labels)), xticklabels=labels, ylabel='Gateway RSS (MiB)', title='Median of per-round median RSS')
    axes[0].legend()
    for x, (name, row) in enumerate(selected):
        axes[1].scatter([x] * len(row['p95Ms']), row['p95Ms'], color='tab:blue', alpha=.7)
    axes[1].set(xticks=range(len(labels)), xticklabels=labels, ylabel='End-to-end p95 (ms)', title='Each dot = one independent round')
    figure.savefig(args.out / 'baseline.png', dpi=160)
    figure.savefig(args.out / 'baseline.svg')
    plt.close(figure)
    figure, axes = plt.subplots(len(selected), 1, figsize=(11, 2.3 * len(selected)), constrained_layout=True, squeeze=False)
    for ax, (name, _) in zip(axes[:, 0], selected):
        for case in [case for case in report['cases'] if case['name'] == name]:
            zero = case['processStartedNs']
            times, rss = [], []
            with (Path(case['directory']) / 'resources.jsonl').open() as stream:
                for line in stream:
                    sample = json.loads(line)
                    process = sample['processes'].get('gateway')
                    if process:
                        times.append((sample['monotonicNs'] - zero) / 1e9)
                        rss.append(process['VmRSSBytes'] / MIB)
            ax.plot(times, rss, label=f"Round {case['round']}", linewidth=1)
            # Workload window locations may vary slightly by start/preflight timing.
            ax.axvspan((case['load']['measuredStartNs'] - zero) / 1e9,
                       (case['load']['measuredEndNs'] - zero) / 1e9, alpha=.04, color='grey')
        ax.set(title=name, ylabel='RSS (MiB)', xlabel='Seconds after process spawn')
        ax.legend(loc='lower right')
    figure.savefig(args.out / 'memory-timeline.png', dpi=130)
    figure.savefig(args.out / 'memory-timeline.svg')
    plt.close(figure)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
