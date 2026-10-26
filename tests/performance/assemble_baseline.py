#!/usr/bin/env python3
"""Assemble the documented sampler-race repair without rewriting either execution."""
import argparse
import copy
import json
from pathlib import Path

from build_release import digest
from run_baseline import CASES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--initial', type=Path, required=True)
    parser.add_argument('--repair', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    initial, repair = [json.loads(path.read_text()) for path in (args.initial, args.repair)]
    if initial['successful'] or not repair['successful']:
        raise RuntimeError('expected the retained failed initial run and successful fixed three-round repair')
    if initial['build'] != repair['build']:
        raise RuntimeError('production build changed between runs')
    workload = 'tests/performance/http_workload.py'
    if initial['harnessSha256'][workload] != repair['harnessSha256'][workload]:
        raise RuntimeError('workload changed; these measurements cannot be combined')
    for key in ('warmup', 'seconds', 'idle', 'cooldown', 'rounds', 'cpus'):
        if initial['parameters'][key] != repair['parameters'][key]:
            raise RuntimeError('measurement controls differ: ' + key)
    failed = [case for case in initial['cases'] if not case['successful']]
    if len(failed) != 1 or failed[0]['name'] != 'mcp-c8' or failed[0]['round'] != 3:
        raise RuntimeError('unexpected original failure; needs independent review')
    failure = failed[0]
    errors = failure['sampler']['errors']
    if (not failure['load']['successful'] or failure.get('error') or failure.get('measurementError')
            or len(errors) != 1 or errors[0]['role'] != 'driver'
            or not errors[0]['error'].startswith('PermissionError(')):
        raise RuntimeError('original failure was not the documented collector permission error')
    cases = [case for case in initial['cases'] if case['name'] != 'mcp-c8'] + repair['cases']
    if not all(case['successful'] and case['load']['successful'] for case in cases):
        raise RuntimeError('selected case unsuccessful')
    expected = {(name, round_number) for name, *_ in CASES for round_number in (1, 2, 3)}
    actual = [(case['name'], case['round']) for case in cases if not case['calibration']]
    if len(actual) != len(expected) or set(actual) != expected:
        raise RuntimeError('missing or duplicate baseline conditions')
    calibrations = [(case['name'], case['round']) for case in cases if case['calibration']]
    if len(calibrations) != 6 or set(calibrations) != {(name, r) for name in ('calibration-on', 'calibration-off') for r in (1, 2, 3)}:
        raise RuntimeError('missing or duplicate calibration pairs')
    result = copy.deepcopy(initial)
    result.update(successful=True, cases=cases, finishedWallNs=repair['finishedWallNs'],
                  earlierCases=[c for c in initial['cases'] if c['name'] == 'mcp-c8'],
                  assembly={
                      'reason': 'Initial workload succeeded in all 24 conditions. A driver /proc PermissionError invalidated MCP round 3; all three MCP rounds were replaced after fixing confirmed-child-exit handling. Both original runs are retained unchanged.',
                      'initial': {'path': str(args.initial.resolve()), 'sha256': digest(args.initial), 'successful': False},
                      'repair': {'path': str(args.repair.resolve()), 'sha256': digest(args.repair), 'successful': True},
                      'repairHarnessSha256': repair['harnessSha256'],
                      'repairStartedWallNs': repair['startedWallNs'],
                      'repairFinishedWallNs': repair['finishedWallNs'],
                      'scriptSha256': digest(Path(__file__))})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print('assembled 24 independent conditions + 6 calibration conditions; earlier 3 MCP executions retained')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
