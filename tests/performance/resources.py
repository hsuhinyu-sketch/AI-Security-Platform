"""Linux per-PID measurements. Units are bytes, seconds and one-core percentages."""
import json
import os
from pathlib import Path
import statistics
import threading
import time


def proc_stat(text, ticks):
    # comm may contain spaces and parentheses; fields following the last ')' are fixed.
    fields = text[text.rindex(')') + 2:].split()
    return {'userSeconds': int(fields[11]) / ticks, 'systemSeconds': int(fields[12]) / ticks,
            'startTicks': int(fields[19])}


def process(pid, pss=False):
    root = Path('/proc') / str(pid)
    values = proc_stat((root / 'stat').read_text(), os.sysconf('SC_CLK_TCK'))
    status = {}
    for line in (root / 'status').read_text().splitlines():
        key, _, value = line.partition(':')
        status[key] = value.strip()
    for key in ('VmRSS', 'VmHWM', 'VmSwap'):
        values[key + 'Bytes'] = int(status.get(key, '0 kB').split()[0]) * 1024
    values['threads'] = int(status['Threads'])
    values['fds'] = 0
    values['socketFds'] = 0
    for fd in (root / 'fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue  # descriptor closed concurrently
        values['fds'] += 1
        values['socketFds'] += int(target.startswith('socket:['))
    if pss:
        for line in (root / 'smaps_rollup').read_text().splitlines():
            if line.startswith('Pss:'):
                values['pssBytes'] = int(line.split()[1]) * 1024
                break
        if 'pssBytes' not in values:
            raise RuntimeError('smaps_rollup did not expose PSS')
    return values


def host():
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'):
            memory[key + 'Bytes'] = int(value.split()[0]) * 1024
    vm = {line.split()[0]: int(line.split()[1]) for line in Path('/proc/vmstat').read_text().splitlines()
          if line.startswith(('pswpin ', 'pswpout '))}
    return {'loadAverage': list(os.getloadavg()), 'memory': memory, 'swapPages': vm}


class Sampler:
    def __init__(self, path, enabled=True):
        self.path, self.enabled = path, enabled
        self.pids = {}
        self.rows = []
        self.errors = []
        self.exited_during_read = []
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.cpu_seconds = 0
        self.thread = None

    def attach(self, role, child):
        with self.lock:
            self.pids[role] = child

    def read_child(self, role, child, pss, now):
        try:
            return {'pid': child.pid, **process(child.pid, pss)}
        except (FileNotFoundError, ProcessLookupError):
            return None  # exited generator or process not yet spawned
        except PermissionError as error:
            # A dying process can revoke /proc access before its entries disappear.
            # Only a confirmed exit of our own Popen child makes that race benign.
            # A live child's permission failure must still fail the measurement.
            code = child.poll()
            if code is None:
                raise
            self.exited_during_read.append({'role': role, 'pid': child.pid, 'monotonicNs': now,
                                           'exitCode': code, 'error': repr(error)})
            return None

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        begin = time.thread_time()
        try:
            with self.path.open('x') as stream:
                next_pss = 0
                while not self.stopped.is_set():
                    now = time.monotonic_ns()
                    if self.enabled:
                        pss = now >= next_pss
                        if pss:
                            next_pss = now + 1_000_000_000
                        row = {'monotonicNs': now, 'wallNs': time.time_ns(), 'processes': {}}
                        with self.lock:
                            roles = dict(self.pids)
                        for role, child in roles.items():
                            try:
                                value = self.read_child(role, child, pss, now)
                                if value is not None:
                                    row['processes'][role] = value
                            except (OSError, ValueError, RuntimeError) as error:
                                self.errors.append({'role': role, 'pid': child.pid,
                                                    'monotonicNs': now, 'error': repr(error)})
                        self.rows.append(row)
                        stream.write(json.dumps(row, separators=(',', ':')) + '\n')
                        stream.flush()
                    self.stopped.wait(.2)
        except Exception as error:
            self.errors.append({'samplerThread': repr(error)})
        finally:
            self.cpu_seconds = time.thread_time() - begin

    def stop(self):
        self.stopped.set()
        if self.thread:
            self.thread.join(5)
            if self.thread.is_alive():
                raise RuntimeError('sampler did not stop')


def distribution(values):
    return {'count': len(values), 'median': statistics.median(values), 'min': min(values), 'max': max(values)} if values else None


def window(rows, role, start, end):
    all_samples = [(r['monotonicNs'], r['processes'][role]) for r in rows if role in r['processes']]
    if not all_samples:
        return None
    selected = [v for t, v in all_samples if start <= t <= end]
    if not selected:
        return None
    first_t, first = min(all_samples, key=lambda row: abs(row[0] - start))
    last_t, last = min(all_samples, key=lambda row: abs(row[0] - end))
    if first['startTicks'] != last['startTicks']:
        raise RuntimeError('PID reused during measurement')
    seconds = (last_t - first_t) / 1e9
    cpu = sum(last[key] - first[key] for key in ('userSeconds', 'systemSeconds'))
    return {'samples': len(selected), 'sampledSeconds': seconds,
            'boundaryGapMs': [abs(first_t - start) / 1e6, abs(last_t - end) / 1e6],
            'cpuSeconds': cpu, 'cpuPercentOneCore': cpu / seconds * 100 if seconds > 0 else None,
            **{key: distribution([v[key] for v in selected if key in v]) for key in (
                'VmRSSBytes', 'VmHWMBytes', 'VmSwapBytes', 'pssBytes', 'threads', 'fds', 'socketFds')}}
