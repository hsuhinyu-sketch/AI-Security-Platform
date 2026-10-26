#!/usr/bin/env python3
"""Build comparable PoC products; keep logs, exact source inputs and every failure."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PRODUCTS = {
    'llm': ('ai-security-platform-llm', 'gateway-llm,security-s1,tls-aws-lc'),
    'mcp': ('ai-security-platform-mcp', 'gateway-mcp,security-s1,tls-aws-lc'),
    'full': ('ai-security-platform-full', 'gateway-full,tls-aws-lc'),
}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inputs():
    paths = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'rust-toolchain.toml']
    paths += list((ROOT / '.cargo').rglob('*.toml'))
    paths += [p for p in (ROOT / 'crates').rglob('*') if p.is_file()]
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(paths) if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 4:
        parser.error('jobs must be 1..4')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, CARGO_BUILD_JOBS=str(args.jobs), CARGO_INCREMENTAL='0')
    overrides = {k: v for k, v in env.items() if k.startswith((
        'CARGO_PROFILE_', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'CARGO_TARGET_DIR'))}
    if overrides:
        raise RuntimeError(f'unexpected build overrides: {sorted(overrides)}')
    report = {'profile': 'release', 'allocator': 'system', 'defaultFeatures': False,
              'jobs': args.jobs, 'sourceSha256': inputs(), 'products': {},
              'rustc': subprocess.check_output(['rustc', '-Vv'], text=True),
              'cargo': subprocess.check_output(['cargo', '-V'], text=True),
              'startedWallNs': time.time_ns(), 'successful': False}

    def save():
        (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')

    save()
    for name, (binary, features) in PRODUCTS.items():
        command = ['cargo', 'build', '--release', '--offline', '--locked',
                   '-p', 'ai-security-platform-app', '--no-default-features',
                   '--features', features, '--bin', binary]
        record = {'command': command, 'features': features.split(','), 'binary': binary,
                  'startedWallNs': time.time_ns()}
        report['products'][name] = record
        save()
        print(f'building {name}: {" ".join(command)}', flush=True)
        with (out / f'{name}.build.log').open('w') as log:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        record.update(exitCode=result.returncode, finishedWallNs=time.time_ns())
        save()
        if result.returncode:
            return result.returncode
        destination = out / binary
        shutil.copy2(ROOT / 'target' / 'release' / binary, destination)
        record.update(path=str(destination), sha256=digest(destination), bytes=destination.stat().st_size)
        tree_command = ['cargo', 'tree', '--offline', '--locked', '-p', 'ai-security-platform-app',
                        '--no-default-features', '--features', features, '-e', 'normal']
        with (out / f'{name}.tree.txt').open('w') as tree:
            subprocess.run(tree_command, cwd=ROOT, env=env, stdout=tree, check=True)
        save()
    if inputs() != report['sourceSha256']:
        raise RuntimeError('production inputs changed during build')
    report.update(successful=True, finishedWallNs=time.time_ns())
    save()
    print('three release products built', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
