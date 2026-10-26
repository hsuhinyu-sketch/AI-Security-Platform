#!/usr/bin/env python3
"""MCP-only real-binary acceptance; existing Tool/Task lifecycle assertions are reused."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

import gateway_faults as fixture


class MCPProfile(unittest.TestCase):
    mcp_only = True
    setUpClass = classmethod(fixture.Acceptance.setUpClass.__func__)
    tearDownClass = classmethod(fixture.Acceptance.tearDownClass.__func__)
    setUp = fixture.Acceptance.setUp
    tearDown = fixture.Acceptance.tearDown
    record_evidence = fixture.Acceptance.record_evidence
    session = fixture.Acceptance.session
    count = fixture.Acceptance.count
    denied = fixture.Acceptance.denied

    test_authenticated_tool_dispatch_and_policy_denial = fixture.Acceptance.test_authenticated_tool_dispatch_and_policy_denial
    test_foreign_owner_and_missing_identity_never_dispatch = fixture.Acceptance.test_foreign_owner_and_missing_identity_never_dispatch
    test_committed_side_effect_with_lost_response_is_not_replayed = fixture.Acceptance.test_committed_side_effect_with_lost_response_is_not_replayed
    test_sigkill_restart_rejects_old_session = fixture.Acceptance.test_sigkill_restart_rejects_old_session
    test_graceful_shutdown_drains_and_restart_rejects_old_session = fixture.Acceptance.test_graceful_shutdown_drains_and_restart_rejects_old_session
    test_session_capacity_is_bounded_and_delete_releases_slot = fixture.Acceptance.test_session_capacity_is_bounded_and_delete_releases_slot
    test_cancel_response_lost_client_retry_does_not_repeat_upstream_cancel = fixture.Acceptance.test_cancel_response_lost_client_retry_does_not_repeat_upstream_cancel
    test_unsubscribe_before_ack_prevents_late_subscription_commit = fixture.Acceptance.test_unsubscribe_before_ack_prevents_late_subscription_commit

    def replace_config(self, contents):
        path = self.gateway.config.with_suffix('.next')
        path.write_text(contents)
        path.replace(self.gateway.config)

    def wait_log(self, marker, offset):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with (self.gateway.directory / 'gateway.log').open('rb') as log:
                log.seek(offset)
                if marker in log.read():
                    return
            self.assertIsNone(self.gateway.process.poll(), 'Gateway exited during reload')
            time.sleep(.05)
        self.fail(f'configuration watcher did not report {marker!r}')

    def test_cross_tenant_rejected_and_concurrent_tools_execute_once_each(self):
        session = self.session()
        self.gateway.request(fixture.rpc('tools/list'), session)
        before = self.count('tools/call')
        self.denied(self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), session, tenant='tenant-b'))
        self.assertEqual(self.count('tools/call'), before)
        before = self.count('echo', effects=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), session), range(8)))
        for status, _, messages in results:
            self.assertEqual(status, 200, messages)
            self.assertTrue(any('result' in message for message in messages), messages)
        self.assertEqual(self.count('echo', effects=True) - before, 8)
        self.observations.update(foreignTenantDispatches=0, concurrentToolEffects=8)

    def test_invalid_llm_reload_preserves_active_mcp_configuration(self):
        session = self.session()
        original = self.gateway.config.read_text()
        self.addCleanup(self.replace_config, original)
        changed = json.loads(original)
        changed['aiSystems'][0]['llm'] = {'models':[{'name':'local','provider':'openai'}]}
        offset = (self.gateway.directory / 'gateway.log').stat().st_size
        self.replace_config(json.dumps(changed))
        self.wait_log(b'LLM support is not compiled', offset)
        status, _, messages = self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), session)
        self.assertEqual(status, 200, messages)
        self.assertTrue(any('result' in message for message in messages), messages)
        self.observations['rejectedLlmReloadKeptSession'] = True

    def test_sampling_configuration_is_rejected_without_dispatching_a_model(self):
        session = self.session()
        original = self.gateway.config.read_text()
        self.addCleanup(self.replace_config, original)
        changed = json.loads(original)
        changed['aiSystems'][0]['security']['mcpSessions']['reverse'] = {'samplingModels':['local']}
        offset = (self.gateway.directory / 'gateway.log').stat().st_size
        before = self.count('chat')
        self.replace_config(json.dumps(changed))
        self.wait_log(b'MCP sampling requires LLM support', offset)
        status, _, messages = self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), session)
        self.assertEqual(status, 200, messages)
        self.assertTrue(any('result' in message for message in messages), messages)
        self.assertEqual(self.count('chat'), before)
        self.observations['modelDispatches'] = 0

    def test_valid_security_reload_revokes_existing_session(self):
        session = self.session()
        original = self.gateway.config.read_text()
        # Restore after assertions and independently from failures in tearDown.
        self.addCleanup(self.replace_config, original)
        changed = json.loads(original)
        changed['aiSystems'][0]['security']['policies'] = [p for p in changed['aiSystems'][0]['security']['policies'] if p['id'] != 'echo']
        before = self.count('echo', effects=True)
        offset = (self.gateway.directory / 'gateway.log').stat().st_size
        self.replace_config(json.dumps(changed))
        # This event is emitted after sync_local publishes the configuration.
        # A request racing that publication may be revoked before its HTTP
        # headers are sent; that tests in-flight revocation, not this assertion.
        self.wait_log(b'Config reloaded successfully', offset)
        self.denied(self.gateway.request(fixture.rpc('tools/list'), session))
        self.denied(self.gateway.request(fixture.rpc('tools/call', name='echo', arguments={}), session))
        self.assertEqual(self.count('echo', effects=True), before)
        self.sessions.remove(session)  # Already invalidated by the revision change.
        self.observations['postRevocationToolEffects'] = 0
        self.observations['configCommitObserved'] = True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fixture.BINARY = args.binary
    fixture.ARTIFACTS = Path(tempfile.mkdtemp(prefix='run-', dir=args.report.parent))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MCPProfile))
    gateway = getattr(MCPProfile, 'gateway', None)
    args.report.write_text(json.dumps({'successful':result.wasSuccessful(), 'testsRun':result.testsRun,
        'errors':[str(t) for t, _ in result.errors], 'failures':[str(t) for t, _ in result.failures],
        'skipped':[str(t) for t, _ in result.skipped], 'scenarios':getattr(MCPProfile, 'evidence', {}),
        'diagnostics':getattr(gateway, 'diagnostics', []), 'artifacts':str(fixture.ARTIFACTS)}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
