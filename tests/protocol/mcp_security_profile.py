#!/usr/bin/env python3
"""MCP compatibility declarations remain independent constraints on the real gateway."""
import argparse
import concurrent.futures
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

import gateway_faults as fixture
import mcp_wire_profile as wire


def policy(effect='allow', **fields):
    return dict(id='same-id', effect=effect, enabled=True, tenantId='tenant-a', **fields)


class Security(unittest.TestCase):
    evidence = {}
    setUpClass = classmethod(wire.Wire.setUpClass.__func__)
    tearDownClass = classmethod(wire.Wire.tearDownClass.__func__)
    setUp = wire.Wire.setUp
    tearDown = wire.Wire.tearDown
    request = wire.Wire.request
    deny = wire.Wire.deny
    count = wire.Wire.count

    def install(self, common, legacy, *, valid=True):
        if not hasattr(self, 'base_config'):
            # Each test derives its first candidate from the preceding valid configuration;
            # only the two declarations change below, never JWT or network destinations.
            self.base_config = json.loads(self.gateway.config.read_text())
        config = copy.deepcopy(self.base_config)
        system = config['aiSystems'][0]
        system['mcp']['statefulMode'] = 'stateless'
        if common is None:
            system.pop('security', None)
        else:
            system['security'] = copy.deepcopy(common)
        if legacy is None:
            system['mcp']['policies'].pop('securityPipeline', None)
        else:
            system['mcp']['policies']['securityPipeline'] = copy.deepcopy(legacy)
        offset = (self.gateway.directory / 'gateway.log').stat().st_size
        candidate = self.gateway.config.with_suffix('.next')
        candidate.write_text(json.dumps(config))
        candidate.replace(self.gateway.config)
        marker = b'Config reloaded successfully' if valid else b'unknown field'
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with (self.gateway.directory / 'gateway.log').open('rb') as log:
                log.seek(offset)
                if marker in log.read():
                    return
            self.assertIsNone(self.gateway.process.poll(), 'Gateway exited during reload')
            time.sleep(.05)
        self.fail(f'configuration watcher did not report {marker!r}')

    def accepted(self, response):
        self.assertEqual(response[0], 200, response)
        self.assertTrue(any('result' in value for value in response[2]), response)

    def test_legacy_only_keeps_default_deny_and_verified_tenant(self):
        self.install(None, {'policies': [policy(actionType='toolInvoke', resourceId='echo')]})
        before = self.count()
        self.accepted(self.request())
        self.deny(self.request(wire.message(name='forbidden')))
        self.deny(self.request(tenant='tenant-b'))
        self.deny(self.request(auth=False))
        self.assertEqual(self.count(), before + 1)
        self.install(None, {})
        self.deny(self.request())
        self.assertEqual(self.count(), before + 1)

    def test_enforce_declarations_are_intersected_and_policy_ids_are_not_merged(self):
        for common_effect, legacy_effect in [('allow', 'deny'), ('deny', 'allow'), ('allow', 'allow')]:
            with self.subTest(common=common_effect, legacy=legacy_effect):
                self.install({'mode': 'enforce', 'policies': [policy(common_effect)]},
                             {'policies': [policy(legacy_effect)]})
                before = self.count()
                response = self.request()
                if common_effect == legacy_effect == 'allow':
                    self.accepted(response)
                    self.assertEqual(self.count(), before + 1)
                else:
                    self.deny(response)
                    self.assertEqual(self.count(), before)

    def test_observe_modes_never_downgrade_the_legacy_constraint(self):
        for mode in ['audit', 'shadow']:
            for legacy_effect in ['deny', 'allow']:
                with self.subTest(mode=mode, legacy=legacy_effect):
                    self.install({'mode': mode, 'policies': [policy('deny')]},
                                 {'policies': [policy(legacy_effect)]})
                    before = self.count()
                    response = self.request()
                    if legacy_effect == 'allow':
                        self.accepted(response)
                        self.assertEqual(self.count(), before + 1)
                    else:
                        self.deny(response)
                        self.assertEqual(self.count(), before)

    def test_both_argument_requirements_and_legacy_approval_remain_mandatory(self):
        common = {'mode': 'enforce', 'policies': [policy()], 'requiredToolArguments': [
            {'toolName': 'echo', 'requiredFields': ['query']}]}
        legacy = {'policies': [policy()], 'requiredToolArguments': [
            {'toolName': 'echo', 'requiredFields': ['recordId']}]}
        self.install(common, legacy)
        before = self.count()
        self.deny(self.request(wire.message(arguments={'query': 'safe'})))
        self.deny(self.request(wire.message(arguments={'recordId': 42})))
        args = {'query': 'safe', 'recordId': 42}
        self.accepted(self.request(wire.message(arguments=args)))
        self.assertEqual(self.count(), before + 1)
        legacy['requiredToolApprovals'] = [{'toolName': 'echo'}]
        self.install(common, legacy)
        self.deny(self.request(wire.message(arguments=args)))
        self.assertEqual(self.count(), before + 1)

    def test_legacy_hot_update_replaces_rules_and_failed_candidate_preserves_denial(self):
        common = {'mode': 'enforce', 'policies': [policy()]}
        self.install(common, {'policies': [policy()]})
        self.accepted(self.request())
        before = self.count()
        self.install(common, {})
        self.deny(self.request())
        self.install(common, {'policies': [policy()], 'unexpectedSecurityField': True}, valid=False)
        self.deny(self.request())
        self.assertEqual(self.count(), before)
        self.install(common, {'policies': [policy()]})
        self.accepted(self.request())
        self.assertEqual(self.count(), before + 1)

    def test_resource_and_prompt_visibility_and_execution_keep_both_constraints(self):
        common = {'mode': 'enforce', 'policies': [policy(), policy('deny', resourceType='mcpPrompt',
            resourceId=json.dumps(['local', 'blocked_prompt'], separators=(',', ':')))]}
        legacy = {'policies': [policy(), policy('deny', resourceType='mcpResource',
            resourceId=json.dumps(['local', 'file:///secret'], separators=(',', ':')))]}
        self.install(common, legacy)
        for method, field, key, expected in [
                ('resources/list', 'resources', 'uri', {'file:///guide'}),
                ('prompts/list', 'prompts', 'name', {'guide_prompt'})]:
            response = self.request(wire.message(method))
            self.accepted(response)
            result = next(value['result'] for value in response[2] if 'result' in value)
            self.assertEqual({item[key] for item in result[field]}, expected)
        for method, params in [('resources/read', {'uri': 'file:///secret'}),
                               ('prompts/get', {'name': 'blocked_prompt'})]:
            before = self.server.calls[method]
            self.deny(self.request(wire.message(method, **params)))
            self.assertEqual(self.server.calls[method], before)
        self.accepted(self.request(wire.message('resources/read', uri='file:///guide')))
        self.accepted(self.request(wire.message('prompts/get', name='guide_prompt')))

    def test_concurrent_arguments_and_tenants_do_not_share_decisions(self):
        self.install({'mode': 'enforce', 'policies': [policy()]}, {'policies': [policy()],
                     'requiredToolArguments': [{'toolName': 'echo', 'requiredFields': ['query']}]})
        inputs = [('tenant-a', {'query': 'safe'}, True), ('tenant-a', {}, False),
                  ('tenant-b', {'query': 'safe'}, False)] * 3
        before = self.count()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda item: self.request(wire.message(arguments=item[1]), tenant=item[0]), inputs))
        for (_, _, allowed), result in zip(inputs, results):
            self.accepted(result) if allowed else self.deny(result)
        self.assertEqual(self.count(), before + 3)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fixture.BINARY = wire.BINARY = args.binary
    fixture.ARTIFACTS = Path(tempfile.mkdtemp(prefix='run-', dir=args.report.parent))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Security))
    gateway = getattr(Security, 'gateway', None)
    args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
        'errors': [str(t) for t, _ in result.errors], 'failures': [str(t) for t, _ in result.failures],
        'skipped': [str(t) for t, _ in result.skipped], 'evidence': getattr(Security, 'evidence', {}),
        'diagnostics': getattr(gateway, 'diagnostics', []), 'artifacts': str(fixture.ARTIFACTS)}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
