#!/usr/bin/env python3
"""The business workflow lineage, including SQLite Task restart and recovery."""
import argparse
import json
from pathlib import Path
import unittest

import gateway_faults
import rag_profile
from workflow_profile import Workflow


class DurableWorkflow(Workflow):
    evidence = {}

    def setUp(self):
        super().setUp()
        self.system['security']['a2aObjects']['storage'] = {
            'type': 'sqlite', 'path': str(self.directory / 'tasks.db'), 'namespace': self.system['name'],
            'busyTimeoutMillis': 100,
        }

    def test_same_context_survives_restart_but_fresh_context_cannot_take_over_task(self):
        context, _ = self.begin()
        task = self.create(context)
        self.gateway.stop()
        self.gateway.start()
        status, _, wire = self.agent_rpc('tasks/get', {'id': task['id']}, context)
        self.assertEqual(status, 200, wire)
        fresh, _ = self.context()
        calls = self.agent.calls.copy()
        self.assertIn(self.agent_rpc('tasks/get', {'id': task['id']}, fresh)[0], (400, 403))
        self.assertEqual(self.agent.calls, calls)
        self.evidence[self.id()] = {'sameContextAfterRestart': True, 'contextReplacementDenied': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    rag_profile.BINARY = args.binary
    if args.report:
        gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DurableWorkflow))
    if args.report:
        args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
            'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors],
            'skipped': [str(t) for t, _ in result.skipped], 'evidence': DurableWorkflow.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
