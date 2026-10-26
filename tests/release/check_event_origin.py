#!/usr/bin/env python3
"""Verify old demo settings cannot seed the real audit feed; real denials still persist."""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "protocol"))
import gateway_faults


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.report.exists():
        parser.error("report exists; use a new path to preserve earlier evidence")
    with args.binary.open("rb") as stream:
        binary_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    result = {"successful": False, "binarySha256": binary_hash}
    try:
        with tempfile.TemporaryDirectory(prefix="audit-origin-") as directory:
            root = Path(directory)
            gateway = gateway_faults.Gateway(str(args.binary.resolve()), root, 9, llm_only=True)
            journal = root / "audit.jsonl"
            config = json.loads(gateway.config.read_text())
            config["config"]["securityAuditPath"] = str(journal)
            gateway.config.write_text(json.dumps(config))
            try:
                with patch.dict(os.environ, SECURITY_UI_DEMO="1", SECURITY_UI_DEMO_PROFILE="full"):
                    gateway.start()
                assert journal.is_file(), "persistent audit store was not initialized"
                initial = [json.loads(line) for line in journal.read_text().splitlines()]
                result["startupEvents"] = len(initial)
                assert not initial, "startup manufactured audit events"
                connection = http.client.HTTPConnection("127.0.0.1", gateway.model_port, timeout=5)
                try:
                    connection.request("POST", "/v1/chat/completions",
                                       json.dumps({"model": "local", "messages": [{"role": "user", "content": "question"}]}),
                                       {"Content-Type": "application/json",
                                        "Authorization": "Bearer " + gateway.token(tenant="tenant-b")})
                    response = connection.getresponse()
                    response.read()
                    assert response.status == 403, f"foreign tenant was not denied: {response.status}"
                finally:
                    connection.close()
                events = [json.loads(line) for line in journal.read_text().splitlines()]
                assert events, "real authorization events were not persisted"
                assert any(str(event.get("decision")).lower() == "deny" for event in events), "denial was not audited"
                assert not any(event.get("details", {}).get("source") == "demo" for event in events)
                result.update(successful=True, startupEvents=len(initial),
                              persistedEvents=len(events), foreignTenantDenied=True)
            finally:
                gateway.stop()
    except Exception as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 0 if result["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
