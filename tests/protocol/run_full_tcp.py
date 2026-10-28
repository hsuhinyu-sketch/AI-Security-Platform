#!/usr/bin/env python3
"""Run complete TCP acceptance on native, isolated Linux loopback.

No host-network fallback and no retry-until-green. Every declared round is kept.
Linux user/network namespaces and iproute2 are required; host networking is explicit.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

PROFILES = {
    'full': ('gateway_faults.py', 10),
    'mcp': ('mcp_profile.py', 12),
    'llm': ('llm_profile.py', 3),
    'routing': ('model_routing.py', 6),
    'sampling': ('sampling_profile.py', 14),
    'mcp-wire': ('mcp_wire_profile.py', 16),
    'mcp-security': ('mcp_security_profile.py', 7),
    'infrastructure': ('infrastructure_profile.py', 1),
    'a2a': ('a2a_profile.py', 12),
    'a2a-durable': ('a2a_durable_profile.py', 6),
    'rag': ('rag_profile.py', 15),
    'security-content': ('security_content_profile.py', 26),
    'pii': ('pii_profile.py', 30),
    'rag-llm': ('rag_llm_profile.py', 19),
    'workflow': ('workflow_profile.py', 6),
    'workflow-durable': ('workflow_durable_profile.py', 7),
}

def binary_digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def clock_sample():
    return {"wallNs": time.time_ns(), "monotonicNs": time.monotonic_ns()}


def clock_error(start, end):
    drift = (end["wallNs"] - start["wallNs"]) - (end["monotonicNs"] - start["monotonicNs"])
    return {"type": "ClockDiscontinuity", "driftNs": drift} if abs(drift) > 5_000_000_000 else None


def network_sample():
    return {"namespace": os.readlink('/proc/self/ns/net'),
            "interfaces": sorted(name for _, name in socket.if_nameindex()),
            "uid": os.getuid(), "gid": os.getgid()}


def loopback_up():
    return bool(subprocess.run(['ip', '-o', 'link', 'show', 'up', 'dev', 'lo'],
                               check=True, capture_output=True, text=True).stdout.strip())


def namespace_command(launcher, unshare, child):
    if launcher == 'user':
        return [unshare, '--user', '--map-root-user', '--net', 'sh', '-c',
                'ip link set dev lo up && exec "$@"', 'full-tcp-netns', *child]
    # The privileged bootstrap executes only system tools. Repository Python and
    # the Gateway run after dropping host uid/gid and supplementary groups.
    return ['sudo', '-n', unshare, '--net', 'sh', '-c',
            'ip link set dev lo up || exit; acceptance_uid=$1; acceptance_gid=$2; shift 2; '
            'exec setpriv --reuid="$acceptance_uid" --regid="$acceptance_gid" --clear-groups -- "$@"',
            'full-tcp-netns', str(os.getuid()), str(os.getgid()), *child]


def validate_isolation(network, parent_namespace):
    if network["namespace"] == parent_namespace or network["interfaces"] != ["lo"]:
        raise RuntimeError("isolated acceptance requires a new network namespace with only lo")


def check_round(report, exit_code, before, after, expected_tests=10):
    errors = []
    if exit_code != 0:
        errors.append({"type": "AcceptanceProcessFailed", "exitCode": exit_code})
    if (not {"successful", "testsRun", "errors", "failures", "skipped"} <= report.keys()
            or report.get("successful") is not True or report.get("testsRun") != expected_tests
            or any(report.get(key) != [] for key in ("errors", "failures", "skipped"))):
        errors.append({"type": "AcceptanceIncompleteOrFailed", "testsRun": report.get("testsRun")})
    for snapshot in report.get('diagnostics', []):
        if snapshot.get('phase') != 'request-error':
            continue
        if snapshot.get('exitCode') is not None:
            errors.append({"type": "GatewayExitedDuringRequest", "exitCode": snapshot['exitCode']})
        else:
            codes = {item.get('errno') for item in snapshot.get('errorChain', [])}
            if 111 in codes:
                port = snapshot.get('ports', {}).get('mcp')
                listening = any(row.get('state') == '0A' and row.get('ownedFds')
                                and int(row['local'].rsplit(':', 1)[1], 16) == port
                                for row in snapshot.get('sockets', []))
                errors.append({"type": "ConnectionRefusedWithLiveListener" if listening else "ConnectionRefused"})
            elif 104 in codes:
                errors.append({"type": "ConnectionReset"})
    if error := clock_error(before, after):
        errors.append(error)
    return errors


def run_round(command, log_path, timeout):
    # A failed/hung fixture must not leave a gateway and namespace alive.
    with log_path.open('w') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            # Kill any descendants even if the parent already stopped.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return 124


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--network', choices=('isolated', 'host'), default='isolated')
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--launcher', choices=('user', 'sudo'), default='user',
                        help='user namespaces, or explicit sudo bootstrap with uid/gid drop for CI')
    parser.add_argument('--profile', choices=PROFILES, default='full')
    parser.add_argument('--namespace-child', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.rounds < 1 or args.timeout < 1:
        parser.error('rounds and timeout must be positive')
    os.umask(0o077)  # Keep complete local failure evidence private to the runner user.
    binary, report = args.binary.resolve(), args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    if report.exists():
        parser.error('report exists; use a new path so previous evidence is preserved')
    evidence = {"successful": False, "networkMode": args.network, "roundsRequested": args.rounds,
                "rounds": [], "clockStart": clock_sample(), "launcher": args.launcher,
                "profile": args.profile}
    try:
        if sys.platform != 'linux':
            raise RuntimeError('Linux TCP acceptance requires Linux')
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError('binary must be an existing executable')
        evidence['binarySha256'] = binary_digest(binary)
        evidence['network'] = network_sample()
        if args.network == 'isolated' and not args.namespace_child:
            unshare = shutil.which('unshare')
            if not unshare or not shutil.which('ip'):
                raise RuntimeError('isolated acceptance requires unshare and iproute2')
            child = [sys.executable, str(Path(__file__).resolve()),
                     '--binary', str(binary), '--report', str(report), '--rounds', str(args.rounds),
                     '--timeout', str(args.timeout), '--launcher', args.launcher,
                     '--profile', args.profile,
                     '--namespace-child', evidence['network']['namespace']]
            command = namespace_command(args.launcher, unshare, child)
            completed = subprocess.run(command, capture_output=True, text=True)
            report.with_suffix('.launcher.log').write_text(completed.stdout + completed.stderr)
            if report.exists():
                result = json.loads(report.read_text())
                if completed.returncode == 0 and result.get('successful') is True:
                    return 0
                return 1
            evidence['error'] = {"type": "NetworkIsolationFailed", "exitCode": completed.returncode,
                                 "stderr": completed.stderr}
            report.write_text(json.dumps(evidence, indent=2) + '\n')
            return 1
        if args.namespace_child:
            if args.network != 'isolated':
                raise RuntimeError('namespace-child is only valid for isolated networking')
            validate_isolation(evidence['network'], args.namespace_child)
            if not loopback_up():
                raise RuntimeError('isolated loopback is not UP')
            evidence['network']['loopbackUp'] = True
            evidence['parentNamespace'] = args.namespace_child
        artifacts = report.with_suffix('.artifacts')
        artifacts.mkdir(exist_ok=False)
        worker, expected_tests = PROFILES[args.profile]
        for number in range(1, args.rounds + 1):
            directory = artifacts / f'round-{number:02}'
            directory.mkdir()
            result_path = directory / 'acceptance.json'
            before = clock_sample()
            exit_code = run_round([sys.executable, str(Path(__file__).with_name(worker)),
                                   '--binary', str(binary), '--report', str(result_path)],
                                  directory / 'acceptance.log', args.timeout)
            after = clock_sample()
            result = json.loads(result_path.read_text()) if result_path.exists() else {}
            errors = check_round(result, exit_code, before, after, expected_tests)
            evidence['rounds'].append({"round": number, "exitCode": exit_code, "successful": not errors,
                                       "errors": errors, "clockStart": before, "clockEnd": after,
                                       "report": str(result_path), "acceptance": result})
            report.write_text(json.dumps(evidence, indent=2) + '\n')
        evidence['clockEnd'] = clock_sample()
        evidence['successful'] = all(r['successful'] for r in evidence['rounds'])
        if changed := clock_error(evidence['clockStart'], evidence['clockEnd']):
            evidence['error'] = changed
            evidence['successful'] = False
        if binary_digest(binary) != evidence['binarySha256']:
            raise RuntimeError('binary changed during acceptance')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        evidence['error'] = {"type": type(error).__name__, "message": str(error)}
        evidence['successful'] = False
    report.write_text(json.dumps(evidence, indent=2) + '\n')
    return 0 if evidence['successful'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
