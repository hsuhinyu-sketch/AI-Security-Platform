#!/usr/bin/env python3
"""Black-box acceptance worker: real binary, JWT validation, TCP upstream, no runtime hooks.

Use run_full_tcp.py for the isolated development/CI gate. Direct execution uses the host network.

Requires Python 3 and system libcrypto. Pass an already built production gateway with --binary.
All keys/configuration/logs are disposable and private; no external services are contacted.
"""

import argparse
import base64
import collections
import contextlib
import ctypes
import ctypes.util
import concurrent.futures
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import select
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timezone


ARTIFACTS = None

def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class RolePorts:
    """Reserve all fixture roles together until immediately before child spawn.

    The gateway does not support inherited listeners. Closing reservations before
    spawn leaves an external bind race; startup failures must still propagate.
    """

    roles = ("mcp", "llm", "admin", "stats", "readiness")

    def __init__(self):
        self.reservations = contextlib.ExitStack()
        self.ports = {}
        try:
            for role in self.roles:
                reservation = self.reservations.enter_context(socket.socket())
                reservation.bind(("127.0.0.1", 0))
                self.ports[role] = reservation.getsockname()[1]
        except BaseException:
            self.close()
            raise

    def close(self):
        self.reservations.close()


class Signer:
    """Ephemeral Ed25519 identity via system OpenSSL; test process only."""

    def __init__(self):
        self.crypto = ctypes.CDLL(ctypes.util.find_library("crypto") or "libcrypto.so.3")
        pointer = ctypes.c_void_p
        size = ctypes.c_size_t
        signatures = {
            "EVP_PKEY_CTX_new_id": (pointer, [ctypes.c_int, pointer]),
            "EVP_PKEY_keygen_init": (ctypes.c_int, [pointer]),
            "EVP_PKEY_keygen": (ctypes.c_int, [pointer, ctypes.POINTER(pointer)]),
            "EVP_PKEY_CTX_free": (None, [pointer]),
            "EVP_PKEY_get_raw_public_key": (ctypes.c_int, [pointer, pointer, ctypes.POINTER(size)]),
            "EVP_MD_CTX_new": (pointer, []),
            "EVP_DigestSignInit": (ctypes.c_int, [pointer, pointer, pointer, pointer, pointer]),
            "EVP_DigestSign": (ctypes.c_int, [pointer, pointer, ctypes.POINTER(size), pointer, size]),
            "EVP_MD_CTX_free": (None, [pointer]),
            "EVP_PKEY_free": (None, [pointer]),
        }
        for name, (result, arguments) in signatures.items():
            function = getattr(self.crypto, name)
            function.restype, function.argtypes = result, arguments
        self.key = pointer()
        context = self.crypto.EVP_PKEY_CTX_new_id(1087, None)  # EVP_PKEY_ED25519
        if not context:
            raise RuntimeError("libcrypto cannot create Ed25519 context")
        try:
            self.check(self.crypto.EVP_PKEY_keygen_init(context))
            self.check(self.crypto.EVP_PKEY_keygen(context, ctypes.byref(self.key)))
            public, length = ctypes.create_string_buffer(32), size(32)
            self.check(self.crypto.EVP_PKEY_get_raw_public_key(self.key, public, ctypes.byref(length)))
            self.public = public.raw[:length.value]
        except BaseException:
            self.close()
            raise
        finally:
            self.crypto.EVP_PKEY_CTX_free(context)

    @staticmethod
    def check(value):
        if value != 1:
            raise RuntimeError("libcrypto signing operation failed")

    def sign(self, message):
        context = self.crypto.EVP_MD_CTX_new()
        if not context:
            raise RuntimeError("libcrypto cannot allocate signing context")
        try:
            self.check(self.crypto.EVP_DigestSignInit(context, None, None, None, self.key))
            signature, length = ctypes.create_string_buffer(64), ctypes.c_size_t(64)
            self.check(self.crypto.EVP_DigestSign(context, signature, ctypes.byref(length), message, len(message)))
            return signature.raw[:length.value]
        finally:
            self.crypto.EVP_MD_CTX_free(context)

    def close(self):
        if self.key:
            self.crypto.EVP_PKEY_free(self.key)
            self.key = None


class Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, status, value=None):
        body = json.dumps(value).encode() if value is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(405)

    def do_DELETE(self):
        self.reply(200)

    def do_POST(self):
        rpc = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path.endswith("/chat/completions"):
            self.chat(rpc)
            return
        method = rpc["method"]
        with self.server.lock:
            self.server.calls[method] += 1
        if "id" not in rpc:
            self.reply(202)
            return
        if method == "initialize":
            result = {
                "protocolVersion": rpc["params"]["protocolVersion"],
                "serverInfo": {"name": "fault-upstream", "version": "1"},
                "capabilities": {"tools": {}, "resources": {"subscribe": True}, "tasks": {
                    "requests": {"tools": {"call": {}}}, "cancel": {}}},
            }
        elif method == "tools/list":
            result = {"tools": [
                {"name": name, "description": name,
                 "inputSchema": {"type": "object", "properties": {}},
                 "execution": {"taskSupport": "optional"}}
                for name in ("echo", "commit", "forbidden")
            ]}
        elif method == "tools/call":
            name = rpc["params"]["name"]
            with self.server.lock:
                self.server.effects[name] += 1
            if "task" in rpc["params"]:
                now = datetime.now(timezone.utc).isoformat()
                result = {"task": {"taskId": str(uuid.uuid4()), "status": "working",
                                   "ttl": rpc["params"]["task"]["ttl"],
                                   "createdAt": now, "lastUpdatedAt": now}}
                self.reply(200, {"jsonrpc": "2.0", "id": rpc["id"], "result": result})
                return
            if name == "commit":
                # The side effect is committed; lose the response on the actual TCP socket.
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            result = {"content": [{"type": "text", "text": "ok"}]}
        elif method == "tasks/cancel":
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        elif method == "resources/subscribe":
            if self.server.hold_subscription:
                self.server.subscription_pending.set()
                if not self.server.subscription_release.wait(timeout=5):
                    raise TimeoutError("subscription test did not release upstream ACK")
            result = {}
        elif method == "resources/unsubscribe":
            result = {}
        else:
            self.reply(200, {"jsonrpc": "2.0", "id": rpc["id"],
                             "error": {"code": -32601, "message": "unknown method"}})
            return
        self.reply(200, {"jsonrpc": "2.0", "id": rpc["id"], "result": result})

    def chat(self, request):
        with self.server.lock:
            self.server.calls["chat"] += 1
        if not request.get("stream"):
            self.reply(200, {"id": "chat-1", "object": "chat.completion", "created": 1,
                             "model": "local", "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": "ok"}}]})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def chunk(text):
            event = {"id": "chat-1", "object": "chat.completion.chunk", "created": 1,
                     "model": "local", "choices": [{"index": 0, "finish_reason": None,
                                                       "delta": {"content": text}}]}
            data = ("data: " + json.dumps(event) + "\n\n").encode()
            self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
            self.wfile.flush()

        try:
            chunk("BEFORE_REVOCATION")
            if not self.server.model_release.wait(timeout=10):
                raise TimeoutError("model test did not release pending stream")
            chunk("AFTER_REVOCATION")
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


class Gateway:
    def __init__(self, binary, directory, upstream_port, *, llm_only=False, mcp_only=False):
        if llm_only and mcp_only:
            raise ValueError("choose one acceptance profile")
        self.binary = binary
        self.directory = directory
        self.role_ports = RolePorts()
        self.port = self.role_ports.ports["mcp"]
        self.model_port = self.role_ports.ports["llm"]
        self.process = None
        self.log = None
        self.diagnostics = []
        self.diagnostics_lock = threading.RLock()
        self.artifacts = ARTIFACTS
        try:
            self.signer = Signer()
            jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                              "kid": "local", "x": b64(self.signer.public)}]}
            allow = lambda name, action, **extra: dict(
                id=name, actionType=action, effect="allow", enabled=True, tenantId="tenant-a", **extra)
            config = {
                "config": {"management": {"mode": "edge"},
                           "adminAddr": f"127.0.0.1:{self.role_ports.ports['admin']}",
                           "statsAddr": f"127.0.0.1:{self.role_ports.ports['stats']}",
                           "readinessAddr": f"127.0.0.1:{self.role_ports.ports['readiness']}"},
                "aiSystems": [{"name": "fault-acceptance", "security": {
                    "mode": "enforce", "mcpSessions": {"maxSessions": 2, "tasks": {"tools": ["echo"]}},
                    "policies": [allow("sessions", "mcpSessionOperation"),
                                 allow("discovery", "toolList"),
                                 allow("echo", "toolInvoke", resourceId="echo"),
                                 allow("tasks", "mcpTaskOperation"),
                                 allow("source", "mcpOperation", resourceType="mcpServer", resourceId="local"),
                                 allow("resources", "mcpOperation", resourceType="mcpResource"),
                                 allow("model", "modelInvoke"),
                                 allow("commit", "toolInvoke", resourceId="commit")]},
                    "llm": {"port": self.model_port, "models": [{"name": "local", "provider": "openAI",
                             "params": {"baseUrl": f"http://127.0.0.1:{upstream_port}/v1"}}],
                            "policies": {"jwtAuth": {"mode": "strict", "issuer": "https://issuer.example",
                                                     "audiences": ["mcp"], "jwks": json.dumps(jwks)}}},
                    "mcp": {"port": self.port, "statefulMode": "stateful",
                            "policies": {"jwtAuth": {"mode": "strict", "issuer": "https://issuer.example",
                                                     "audiences": ["mcp"], "jwks": json.dumps(jwks)}},
                            "targets": [{"name": "local", "mcp": {
                                "host": f"http://127.0.0.1:{upstream_port}/mcp"}}]}}],
            }
            self.listener_ports = (self.port, self.model_port)
            if llm_only:
                system = config["aiSystems"][0]
                del system["mcp"]
                del system["security"]["mcpSessions"]
                system["security"]["policies"] = [p for p in system["security"]["policies"] if p["id"] == "model"]
                self.listener_ports = (self.model_port,)
            if mcp_only:
                system = config["aiSystems"][0]
                del system["llm"]
                system["security"]["policies"] = [p for p in system["security"]["policies"] if p["id"] != "model"]
                self.listener_ports = (self.port,)
            self.config = directory / "gateway.json"
            self.config.write_text(json.dumps(config))
        except BaseException:
            self.role_ports.close()
            if hasattr(self, "signer"):
                self.signer.close()
            raise

    def token(self, user="alice", tenant="tenant-a"):
        header = b64(json.dumps({"alg": "EdDSA", "kid": "local"}).encode())
        claims = b64(json.dumps({"sub": user, "tenant_id": tenant, "client_id": "client-a",
                                 "iss": "https://issuer.example", "aud": "mcp",
                                 "exp": int(time.time()) + 600}).encode())
        message = f"{header}.{claims}".encode()
        signature = self.signer.sign(message)
        return f"{header}.{claims}.{b64(signature)}"

    def snapshot(self, phase, error=None):
        """Read local process/socket state before cleanup can destroy failure evidence."""
        process = self.process
        evidence = {"phase": phase, "monotonic": time.monotonic(),
                    "pid": process.pid if process else None,
                    "exitCode": process.poll() if process else None,
                    "wallNs": time.time_ns(), "monotonicNs": time.monotonic_ns(),
                    "ports": self.role_ports.ports.copy(), "scenario": getattr(self, "scenario", None)}
        if error is not None:
            evidence["errorChain"] = []
            while error is not None:
                evidence["errorChain"].append({"type": type(error).__name__, "errno": getattr(error, "errno", None)})
                error = error.__cause__
        if process:
            proc = Path(f"/proc/{process.pid}")
            try:
                evidence["netns"] = os.readlink(proc / "ns/net")
                owned = {}
                for fd in (proc / "fd").iterdir():
                    try:
                        target = os.readlink(fd)
                        if target.startswith("socket:["):
                            owned.setdefault(target[8:-1], []).append(fd.name)
                    except OSError:
                        pass  # Connection FDs may close while enumerating.
                evidence["sockets"] = []
                ports = set(self.role_ports.ports.values())
                for family in ("tcp", "tcp6"):
                    for line in (proc / "net" / family).read_text().splitlines()[1:]:
                        fields = line.split()
                        if int(fields[1].rsplit(":", 1)[1], 16) in ports:
                            evidence["sockets"].append({"family": family, "local": fields[1], "state": fields[3],
                                                        "inode": fields[9], "ownedFds": owned.get(fields[9], [])})
            except OSError as snapshot_error:
                evidence["procError"] = {"type": type(snapshot_error).__name__, "errno": snapshot_error.errno}
        with self.diagnostics_lock:
            self.diagnostics.append(evidence)
            self.persist_evidence()
        return evidence

    def persist_evidence(self):
        if self.artifacts is None:
            return
        with self.diagnostics_lock:
            self.artifacts.mkdir(parents=True, exist_ok=True)
            log = self.directory / "gateway.log"
            if log.exists():
                shutil.copyfile(log, self.artifacts / "gateway.log")
            (self.artifacts / "diagnostics.json").write_text(json.dumps(self.diagnostics, indent=2) + "\n")

    def start(self):
        self.log = (self.directory / "gateway.log").open("ab")
        env = {k: v for k, v in os.environ.items()
               if k not in ("ADMIN_ADDR", "STATS_ADDR", "READINESS_ADDR")}
        # Observe successful config publication in reload acceptance without
        # racing a request against deliberate revocation of its response body.
        env["RUST_LOG"] = "info,ai_security_platform_runtime::state_manager=debug"
        ready_read, ready_write = os.pipe()
        env["READY_FD"] = str(ready_write)
        try:
            self.role_ports.close()
            self.process = subprocess.Popen([self.binary, "--file", str(self.config)],
                                            stdout=self.log, stderr=self.log, env=env,
                                            pass_fds=(ready_write,))
        except BaseException:
            os.close(ready_read)
            raise
        finally:
            os.close(ready_write)
        try:
            if not select.select([ready_read], [], [], 30)[0]:
                raise TimeoutError("gateway readiness timeout")
            assert os.read(ready_read, 1) == b"", "unexpected readiness payload"
        finally:
            os.close(ready_read)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError((self.directory / "gateway.log").read_text()[-12000:])
            try:
                for listener in self.listener_ports:
                    with socket.create_connection(("127.0.0.1", listener), timeout=.2):
                        pass
                return
            except OSError:
                time.sleep(.05)
        raise TimeoutError("gateway listener did not start")

    def stop(self):
        self.role_ports.close()
        self.snapshot("stop-before-cleanup")
        status = None
        if self.process is not None:
            if self.process.poll() is None:
                self.process.kill()
            status = self.process.wait(timeout=10)
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None
        return status

    def request(self, rpc=None, session=None, user="alice", method="POST", auth=True, tenant="tenant-a"):
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": "2025-11-25"}
        if auth:
            headers["Authorization"] = f"Bearer {self.token(user, tenant)}"
        if session:
            headers["Mcp-Session-Id"] = session
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            connection.request(method, "/mcp", json.dumps(rpc) if rpc is not None else None, headers)
            response = connection.getresponse()
            body = response.read().decode()
            values = []
            if "text/event-stream" in response.getheader("Content-Type", ""):
                for line in body.splitlines():
                    if line.startswith("data:"):
                        values.append(json.loads(line[5:]))
            elif body:
                try:
                    values.append(json.loads(body))
                except json.JSONDecodeError:
                    pass
            return response.status, dict(response.getheaders()), values
        except OSError as error:
            evidence = self.snapshot("request-error", error)
            raise RuntimeError(json.dumps(evidence) + "\n" + (self.directory / "gateway.log").read_text()[-10000:]) from error
        finally:
            connection.close()

    def initialize(self):
        status, headers, values = self.request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "fault-client", "version": "1"}}})
        assert status == 200 and any("result" in v for v in values), (status, values)
        session = next(v for k, v in headers.items() if k.lower() == "mcp-session-id")
        status, _, _ = self.request({"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
        assert status in (200, 202, 204), status
        return session


def rpc(method, **params):
    return {"jsonrpc": "2.0", "id": 2, "method": method, "params": params}


class Acceptance(unittest.TestCase):
    mcp_only = False
    @classmethod
    def setUpClass(cls):
        cls.evidence = {}
        cls.temp = tempfile.TemporaryDirectory(prefix="aisp-gateway-faults-")
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        cls.server.daemon_threads = True
        cls.server.lock = threading.Lock()
        cls.server.calls = collections.Counter()
        cls.server.effects = collections.Counter()
        cls.server.hold_subscription = False
        cls.server.subscription_pending = threading.Event()
        cls.server.subscription_release = threading.Event()
        cls.server.model_release = threading.Event()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        try:
            cls.gateway = Gateway(BINARY, Path(cls.temp.name), cls.server.server_port, mcp_only=cls.mcp_only)
            cls.gateway.start()
        except BaseException:
            if hasattr(cls, "gateway"):
                cls.gateway.stop()
                cls.gateway.signer.close()
            cls.server.shutdown()
            cls.server.server_close()
            cls.temp.cleanup()
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
        self.gateway.scenario = self.id()
        self.sessions = []
        self.observations = {}
        with self.server.lock:
            self.before_calls = self.server.calls.copy()
            self.before_effects = self.server.effects.copy()
        self.addCleanup(self.record_evidence)

    def record_evidence(self):
        with self.server.lock:
            self.evidence[self.id()] = {
                "upstreamCalls": dict(self.server.calls - self.before_calls),
                "upstreamEffects": dict(self.server.effects - self.before_effects),
                "observations": self.observations,
            }

    def tearDown(self):
        for session in self.sessions:
            self.gateway.request(session=session, method="DELETE")

    def session(self):
        session = self.gateway.initialize()
        self.sessions.append(session)
        return session

    def count(self, name, effects=False):
        with self.server.lock:
            return (self.server.effects if effects else self.server.calls)[name]

    def denied(self, response):
        status, _, values = response
        self.assertTrue(status >= 400 or any("error" in v for v in values), response)
        self.assertFalse(any("result" in v for v in values), response)

    def test_authenticated_tool_dispatch_and_policy_denial(self):
        session = self.session()
        self.gateway.request(rpc("tools/list"), session)
        before = self.count("echo", effects=True)
        status, _, values = self.gateway.request(rpc("tools/call", name="echo", arguments={}), session)
        self.assertEqual(status, 200)
        self.assertTrue(any("result" in v for v in values), values)
        self.assertEqual(self.count("echo", effects=True), before + 1)
        before = self.count("forbidden", effects=True)
        self.denied(self.gateway.request(rpc("tools/call", name="forbidden", arguments={}), session))
        self.assertEqual(self.count("forbidden", effects=True), before)

    def test_foreign_owner_and_missing_identity_never_dispatch(self):
        session = self.session()
        before = self.count("tools/call")
        self.denied(self.gateway.request(rpc("tools/call", name="echo", arguments={}), session, user="bob"))
        self.denied(self.gateway.request(rpc("tools/call", name="echo", arguments={}), session, auth=False))
        self.assertEqual(self.count("tools/call"), before)

    def test_authenticated_model_call_and_missing_identity_denial(self):
        payload = json.dumps({"model": "local", "messages": [{"role": "user", "content": "hello"}]})
        before = self.count("chat")
        for authorized in (True, False):
            headers = {"Content-Type": "application/json"}
            if authorized:
                headers["Authorization"] = f"Bearer {self.gateway.token()}"
            with contextlib.closing(http.client.HTTPConnection(
                    "127.0.0.1", self.gateway.model_port, timeout=8)) as connection:
                connection.request("POST", "/v1/chat/completions", payload, headers)
                response = connection.getresponse()
                body = response.read()
                if authorized:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(body)["choices"][0]["message"]["content"], "ok")
                else:
                    self.assertGreaterEqual(response.status, 400)
        self.assertEqual(self.count("chat"), before + 1)

    def test_committed_side_effect_with_lost_response_is_not_replayed(self):
        session = self.session()
        self.gateway.request(rpc("tools/list"), session)
        before = self.count("commit", effects=True)
        self.denied(self.gateway.request(rpc("tools/call", name="commit", arguments={}), session))
        # Observe beyond immediate error propagation, not just the response status.
        time.sleep(.5)
        self.assertEqual(self.count("commit", effects=True), before + 1)

    def test_sigkill_restart_rejects_old_session(self):
        old = self.session()
        self.assertEqual(self.gateway.stop(), -signal.SIGKILL)
        self.gateway.start()
        before = self.count("tools/call")
        self.denied(self.gateway.request(rpc("tools/call", name="echo", arguments={}), old))
        self.assertEqual(self.count("tools/call"), before)
        self.sessions.remove(old)
        self.session()  # New authenticated initialization must still work.

    def test_graceful_shutdown_drains_and_restart_rejects_old_session(self):
        old = self.session()
        self.gateway.process.send_signal(signal.SIGTERM)
        status = self.gateway.process.wait(timeout=30)
        self.assertEqual(status, 0)
        self.observations["gracefulExitCode"] = status
        self.gateway.stop()  # Close the old log and process handles without killing.
        self.gateway.start()
        before = self.count("tools/call")
        self.denied(self.gateway.request(rpc("tools/call", name="echo", arguments={}), old))
        self.assertEqual(self.count("tools/call"), before)
        self.sessions.remove(old)
        self.session()

    def test_session_capacity_is_bounded_and_delete_releases_slot(self):
        first = self.session()
        self.session()
        before = self.count("initialize")
        self.denied(self.gateway.request(rpc("initialize", protocolVersion="2025-11-25",
            capabilities={}, clientInfo={"name": "overflow", "version": "1"})))
        self.assertEqual(self.count("initialize"), before)
        status, _, _ = self.gateway.request(session=first, method="DELETE")
        self.assertIn(status, (200, 202, 204))
        self.sessions.remove(first)
        self.session()

    def test_cancel_response_lost_client_retry_does_not_repeat_upstream_cancel(self):
        session = self.session()
        self.gateway.request(rpc("tools/list"), session)
        status, _, values = self.gateway.request(
            rpc("tools/call", name="echo", arguments={}, task={"ttl": 60000}), session)
        self.assertEqual(status, 200)
        self.assertTrue(any("result" in v for v in values), values)
        task = next(v["result"]["task"]["taskId"] for v in values if "result" in v)
        before = self.count("tasks/cancel")
        barrier = threading.Barrier(2, timeout=5)

        def cancel():
            barrier.wait()
            return self.gateway.request(rpc("tasks/cancel", taskId=task), session)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            pending = [executor.submit(cancel) for _ in range(2)]
            for result in pending:
                self.denied(result.result(timeout=10))
        self.denied(self.gateway.request(rpc("tasks/cancel", taskId=task), session))
        self.assertEqual(self.count("tasks/cancel"), before + 1)

    def test_unsubscribe_before_ack_prevents_late_subscription_commit(self):
        session = self.session()
        self.server.hold_subscription = True
        self.server.subscription_pending.clear()
        self.server.subscription_release.clear()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(self.gateway.request,
                    rpc("resources/subscribe", uri="test://resource"), session)
                try:
                    self.assertTrue(self.server.subscription_pending.wait(timeout=5),
                                    "subscribe never reached upstream")
                    status, _, values = self.gateway.request(
                        rpc("resources/unsubscribe", uri="test://resource"), session)
                    self.assertEqual(status, 200)
                    self.assertTrue(any("result" in v for v in values), values)
                finally:
                    self.server.subscription_release.set()
                self.denied(pending.result(timeout=10))
        finally:
            self.server.hold_subscription = False
            self.server.subscription_release.set()
        # The cancelled Pending ticket must not leave a reservation behind.
        status, _, values = self.gateway.request(rpc("resources/subscribe", uri="test://resource"), session)
        self.assertEqual(status, 200)
        self.assertTrue(any("result" in v for v in values), values)

    def test_stream_stops_after_live_policy_revocation(self):
        original = self.gateway.config.read_text()
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.gateway.token()}"}
        payload = {"model": "local", "messages": [{"role": "user", "content": "hello"}]}

        def wait_model_status(expected):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with contextlib.closing(http.client.HTTPConnection("127.0.0.1", self.gateway.model_port, timeout=2)) as client:
                    client.request("POST", "/v1/chat/completions", json.dumps(payload),
                                   dict(headers, Authorization=f"Bearer {self.gateway.token()}"))
                    response = client.getresponse()
                    response.read()
                    if response.status == expected:
                        return
                time.sleep(.05)
            self.fail(f"model route did not reach HTTP {expected}")

        def replace_config(contents):
            temporary = self.gateway.config.with_suffix(".next")
            temporary.write_text(contents)
            temporary.replace(self.gateway.config)

        def restore_config():
            replace_config(original)
            wait_model_status(200)

        self.addCleanup(restore_config)
        self.server.model_release.clear()
        connection = http.client.HTTPConnection("127.0.0.1", self.gateway.model_port, timeout=12)
        try:
            connection.request("POST", "/v1/chat/completions", json.dumps(dict(payload, stream=True)), headers)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            initial = response.read1(4096)
            self.assertIn(b"BEFORE_REVOCATION", initial)
            changed = json.loads(original)
            policies = changed["aiSystems"][0]["security"]["policies"]
            changed["aiSystems"][0]["security"]["policies"] = [p for p in policies if p["id"] != "model"]
            replace_config(json.dumps(changed))
            wait_model_status(403)  # Observe that the production file watcher applied revocation.
            self.server.model_release.set()
            remaining = bytearray()
            while True:
                try:
                    data = response.read1(4096)
                except http.client.IncompleteRead as error:
                    remaining.extend(error.partial)
                    break
                except ConnectionResetError:
                    break
                if not data:
                    break
                remaining.extend(data)
            self.observations.update(streamInitialBytes=len(initial), streamPostRevocationBytes=len(remaining),
                                     postRevocationMarkerSeen=b"AFTER_REVOCATION" in initial + remaining)
            self.assertNotIn(b"AFTER_REVOCATION", initial + remaining)
        finally:
            self.server.model_release.set()
            connection.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument("--report", type=Path, help="Write JSON acceptance results to this path")
    parser.add_argument("--artifacts", type=Path, help="Preserve complete gateway logs and failure process/socket state")
    args, remaining = parser.parse_known_args()
    BINARY = args.binary
    if args.artifacts or args.report:
        artifact_root = args.artifacts or args.report.with_suffix(".artifacts")
        artifact_root.mkdir(parents=True, exist_ok=True)
        ARTIFACTS = Path(tempfile.mkdtemp(prefix="run-", dir=artifact_root))
    result = unittest.main(argv=[__file__, *remaining], verbosity=2, exit=False).result
    if args.report:
        args.report.write_text(json.dumps({
            "successful": result.wasSuccessful(), "testsRun": result.testsRun,
            "failures": [str(test) for test, _ in result.failures],
            "errors": [str(test) for test, _ in result.errors],
            "skipped": [str(test) for test, _ in result.skipped],
            "scenarios": getattr(Acceptance, "evidence", {}),
            "diagnostics": getattr(getattr(Acceptance, "gateway", None), "diagnostics", []),
            "artifacts": str(ARTIFACTS) if ARTIFACTS else None,
        }, indent=2) + "\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
