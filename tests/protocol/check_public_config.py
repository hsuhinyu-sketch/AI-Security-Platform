#!/usr/bin/env python3
"""Compile the public LLM configuration boundary, including expected absent Rust variants."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def check_profile(directory, features, expected_available):
    # Path patches belong to the root invoking Cargo, including isolated consumer projects.
    patches = (ROOT / 'Cargo.toml').read_text().split('[workspace]', 1)[0]
    patches = re.sub(r'path\s*=\s*"([^"]+)"',
                     lambda m: 'path = ' + json.dumps(str((ROOT / m.group(1)).resolve())), patches)
    resolver = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['resolver']
    manifest = '\n'.join([
        '[workspace]', 'resolver = ' + json.dumps(resolver), '[package]', 'name = "public-config-consumer"',
        'version = "0.0.0"', 'edition = "2024"', '[dependencies]',
        'runtime = { package = "ai-security-platform-runtime", path = ' +
        json.dumps(str(ROOT / 'crates/gateway/runtime')) + ', default-features = false, features = ' +
        json.dumps(features) + ' }',
        'llm = { package = "gateway-llm", path = ' + json.dumps(str(ROOT / 'crates/gateway/llm')) +
        ', default-features = false, features = ' + json.dumps([]) + ' }', patches,
    ])
    (directory / 'Cargo.toml').write_text(manifest)
    command = ['cargo', 'check', '--offline', '--manifest-path', str(directory / 'Cargo.toml'),
               '--message-format=json']
    env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / 'target'))
    completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    diagnostics = []
    for line in completed.stdout.splitlines():
        record = json.loads(line)
        if record.get('reason') == 'compiler-message' and record['message']['level'] == 'error':
            diagnostics.append(record['message'])
    if expected_available:
        assert completed.returncode == 0, completed.stderr + completed.stdout[-10000:]
    else:
        assert completed.returncode != 0 and diagnostics, completed.stderr
        primary = [d for d in diagnostics if any(s['is_primary'] and s['file_name'].endswith('src/lib.rs')
                                                  for s in d['spans'])]
        assert len(primary) == len(diagnostics) == 11, diagnostics
        messages = '\n'.join(d['message'] for d in primary)
        for name in ('AI', 'LLMRouter', 'AIBackend', 'AIProvider', 'NamedAIProvider', 'model_router', 'CatalogService', 'CatalogReader', 'ModelCatalog',
                     'conversion', 'streaming', 'routing', 'GuardedSseBody', 'adapter'):
            assert re.search(r'`(?:llm::(?:provider::)?)?' + re.escape(name) + r'`', messages), (name, messages)
        assert all(d['code'] and d['code']['code'] in ('E0599', 'E0425', 'E0433', 'E0432') for d in primary), messages
        assert all('public-config-consumer' in str(s.get('file_name', '')) or
                   s['file_name'] == 'src/lib.rs'
                   for d in primary for s in d['spans'] if s['is_primary']), diagnostics
    return {'features': features, 'expectedAvailable': expected_available, 'command': command,
            'compilerExitCode': completed.returncode, 'successful': True,
            'diagnostics': [{'code': d['code'], 'message': d['message']} for d in diagnostics]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    assert not args.report.exists(), 'preserve earlier verification evidence'
    with tempfile.TemporaryDirectory(prefix='public-config-consumer-') as path:
        directory = Path(path)
        (directory / 'Cargo.lock').write_text((ROOT / 'Cargo.lock').read_text())
        (directory / 'src').mkdir()
        (directory / 'src/observation.rs').write_text('''
pub fn observation(_: runtime::cel::LLMContext, _: llm::LLMResponse,
                   _: llm::catalog::Catalog, _: llm::provider::PromptCachingConfig) {}
''')
        (directory / 'src/lib.rs').write_text('''
mod observation;
use runtime::types::agent::Backend;
pub fn inspect(value: &Backend) -> bool {
    matches!(value, Backend::AI(..) | Backend::LLMRouter(..))
}
pub fn provider(_: Option<runtime::llm::AIProvider>) {}
pub fn backend(_: Option<runtime::llm::AIBackend>) {}
pub fn named(_: Option<runtime::llm::NamedAIProvider>) {}
pub fn router(_: Option<runtime::llm::model_router::ModelRouter>) {}
pub fn catalog(_: Option<runtime::llm::cost::CatalogService>) {}
pub fn reader(_: Option<runtime::llm::cost::CatalogReader>) {}
pub fn live_catalog(_: Option<runtime::llm::cost::ModelCatalog>) {}
pub use llm::{conversion, streaming, routing, GuardedSseBody};
pub use llm::provider::adapter;

''')
        results = [check_profile(directory, ['gateway-rag', 'security-s1', 'tls-aws-lc'], False),
                   check_profile(directory, ['gateway-llm', 'security-s1', 'tls-aws-lc'], True)]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({'successful': True, 'profiles': results}, indent=2) + '\n')
    print('PASS: execution, codecs/streaming/routing and live Catalog absent without LLM; shared values remain; LLM profile compiles all')


if __name__ == '__main__':
    main()
