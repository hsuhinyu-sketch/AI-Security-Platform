#!/usr/bin/env python3
"""LLM-only production-binary acceptance over real TCP and signed JWTs."""
import argparse
import collections
import concurrent.futures
import contextlib
import http.client
import http.server
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from gateway_faults import Gateway, Upstream, Acceptance


class LLMProfile(unittest.TestCase):
    evidence = {}

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="aisp-llm-profile-")
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        cls.server.daemon_threads = True
        cls.server.lock = threading.Lock()
        cls.server.calls = collections.Counter()
        cls.server.model_release = threading.Event()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.gateway = Gateway(BINARY, Path(cls.temp.name), cls.server.server_port, llm_only=True)
        try:
            cls.gateway.start()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.gateway.stop()
        cls.gateway.signer.close()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temp.cleanup()

    def setUp(self):
        self.observations = {}

    def tearDown(self):
        self.evidence[self.id()] = {"gatewayExit": self.gateway.process.poll(), **self.observations}

    def model(self, token):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", self.gateway.model_port, timeout=5)) as client:
            try:
                client.request("POST", "/v1/chat/completions", json.dumps({"model":"local","messages":[{"role":"user","content":"hello"}]}), headers)
                response = client.getresponse()
                return response.status, response.read()
            except OSError as error:
                raise RuntimeError(f"gatewayExit={self.gateway.process.poll()}\n{(self.gateway.directory / 'gateway.log').read_text()[-10000:]}") from error

    def test_authenticated_concurrent_calls_and_identity_denials(self):
        with self.server.lock:
            before = self.server.calls["chat"]
        for token in [None, self.gateway.token()[:-4] + "xxxx", self.gateway.token(tenant="tenant-b")]:
            status, _ = self.model(token)
            self.assertIn(status, (401, 403))
        with self.server.lock:
            self.assertEqual(self.server.calls["chat"], before, "denied identities reached upstream")
        token = self.gateway.token()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            replies = list(pool.map(self.model, [token] * 8))
        for status, body in replies:
            self.assertEqual(status, 200, body)
            self.assertEqual(json.loads(body)["choices"][0]["message"]["content"], "ok")
        with self.server.lock:
            self.assertEqual(self.server.calls["chat"] - before, 8)
        self.observations.update(deniedUpstreamCalls=0, successfulConcurrentCalls=8)

    def test_invalid_protocol_reload_preserves_previous_configuration(self):
        original = self.gateway.config.read_text()
        changed = json.loads(original)
        changed["aiSystems"][0]["mcp"] = {"targets": []}
        log_path = self.gateway.directory / "gateway.log"
        offset = log_path.stat().st_size
        def replace(contents):
            path = self.gateway.config.with_suffix(".next")
            path.write_text(contents)
            path.replace(self.gateway.config)
        try:
            replace(json.dumps(changed))
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with log_path.open("rb") as log:
                    log.seek(offset)
                    if b"MCP support is not compiled" in log.read():
                        break
                if self.gateway.process.poll() is not None:
                    self.fail(f"gateway exited: {self.gateway.process.returncode}")
                time.sleep(.05)
            else:
                self.fail("file watcher did not reject unavailable MCP configuration")
            status, body = self.model(self.gateway.token())
            self.assertEqual(status, 200, body)
            self.observations["invalidReloadKeptPreviousLlm"] = True
        finally:
            replace(original)

    # Reuse the unchanged revocation assertions against the real Host file watcher.
    test_stream_stops_after_live_policy_revocation = Acceptance.test_stream_stops_after_live_policy_revocation


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    BINARY = args.binary
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LLMProfile)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if args.report:
        args.report.write_text(json.dumps({"successful": result.wasSuccessful(), "testsRun": result.testsRun,
            "failures": [str(t) for t, _ in result.failures], "errors": [str(t) for t, _ in result.errors],
            "skipped": [str(t) for t, _ in result.skipped],
            "evidence": LLMProfile.evidence}, indent=2) + "\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
