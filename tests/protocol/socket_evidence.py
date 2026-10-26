"""Read diagnostic metadata without confusing recycled fds or SO_ERROR values.

No request replay or automatic attribution across forwarded TCP segments.
"""

import json


def connections(events):
    result = {}
    required = {'ns', 'pid', 'tid', 'op', 'fd', 'inode', 'local', 'peer', 'ret', 'errno'}
    for event in events:
        missing = required - event.keys()
        if missing:
            raise ValueError(f'incomplete socket event: {sorted(missing)}')
        # fd numbers are recycled; inode alone can also repeat across processes.
        key = (event['pid'], event['inode'])
        result.setdefault(key, []).append(event)
    for timeline in result.values():
        timeline.sort(key=lambda event: event['ns'])
    return result


def failures(events):
    result = []
    for (pid, inode), timeline in connections(events).items():
        for event in timeline:
            if event['op'] == 'SO_ERROR':
                # The wrapper's ret is the SO_ERROR value, not getsockopt's rc.
                error = event['ret']
            elif event['ret'] < 0:
                error = event['errno']
            else:
                continue
            if error not in (104, 111):
                continue
            prior = [e for e in timeline if e['ns'] <= event['ns']]
            origin = next((e for e in reversed(prior) if e['op'] == 'connect'), event)
            result.append({'pid': pid, 'inode': inode, 'fd': event['fd'], 'tid': event['tid'],
                           'ns': event['ns'], 'op': event['op'], 'errno': error,
                           'local': origin['local'], 'peer': origin['peer'],
                           'timeline': prior})
    return sorted(result, key=lambda item: item['ns'])


def load(path):
    with open(path) as stream:
        return [json.loads(line) for line in stream if line.strip()]


def validate_round_report(report):
    required = {'round', 'successful', 'testsRun', 'errors', 'failures', 'events', 'binarySha256'}
    if required - report.keys():
        raise ValueError('incomplete diagnostic round report')
    if report['successful'] != (not report['errors'] and not report['failures']):
        raise ValueError('diagnostic result hides failure')
    for event in report['events']:
        if not {'kind', 'monotonic', 'utc'} <= event.keys():
            raise ValueError('incomplete diagnostic event')
        if event['kind'] == 'request-error':
            chain = event.get('errorChain', [])
            if not chain or any(not {'type', 'errno'} <= item.keys() for item in chain):
                raise ValueError('incomplete diagnostic errno chain')
    return report
