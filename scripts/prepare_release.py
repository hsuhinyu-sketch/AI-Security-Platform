#!/usr/bin/env python3
"""Build and package one native release candidate from a clean checkout; never publish."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {
    "llm": "gateway-llm,security-s1,tls-aws-lc",
    "mcp": "gateway-mcp,security-s1,tls-aws-lc",
    "a2a": "gateway-a2a,security-s1,security-a2a-sqlite,tls-aws-lc",
    "rag": "gateway-rag,security-s1,tls-aws-lc",
    "full": "gateway-full,security-a2a-sqlite,tls-aws-lc",
}
VERSION = re.compile(r"v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")


def output(command, **kwargs):
    return subprocess.check_output(command, cwd=ROOT, text=True, **kwargs).strip()


def validate_version(value):
    if not VERSION.fullmatch(value):
        raise ValueError("version must be a tag such as v0.1.0-rc.1")
    return value


def check_source():
    if output(["git", "status", "--porcelain", "--untracked-files=all"]):
        raise ValueError("release packaging requires a clean committed checkout")
    return output(["git", "rev-parse", "HEAD"])


def validate_build(info, version, revision, target):
    expected = {"version": version, "git_revision": revision,
                "build_profile": "release", "build_target": target}
    if any(info.get(key) != value for key, value in expected.items()):
        raise ValueError("binary build metadata does not match the release inputs")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def package(binary, destination, version, profile, revision, target, info, command):
    validate_build(info, version, revision, target)
    name = f"ai-security-platform-{profile}-{version}-{target}"
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / f"{name}.tar.gz"
    checksum = destination / f"{name}.sha256"
    if archive.exists() or checksum.exists():
        raise ValueError("release output already exists; use a new output directory")
    with tempfile.TemporaryDirectory(prefix=".package-", dir=destination) as temporary:
        staging = Path(temporary) / name
        staging.mkdir()
        shutil.copy2(binary, staging / "ai-security-platform")
        for source, filename in ((ROOT / "LICENSE", "LICENSE"),
                                 (ROOT / "Cargo.lock", "Cargo.lock"),
                                 (ROOT / "docs/release/README.md", "RELEASE.md"),
                                 (ROOT / "crates/platform/pool/LICENSE", "LICENSE-platform-pool")):
            shutil.copy2(source, staging / filename)
        manifest = {"version": version, "profile": profile, "features": PROFILES[profile].split(","),
                    "gitRevision": revision, "buildInfo": info, "buildCommand": command,
                    "files": {path.name: digest(path) for path in sorted(staging.iterdir())}}
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        pending = Path(temporary) / archive.name
        with tarfile.open(pending, "w:gz") as stream:
            stream.add(staging, arcname=name)
        pending.rename(archive)
    checksum.write_text(f"{digest(archive)}  {archive.name}\n")
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, type=validate_version)
    parser.add_argument("--profile", required=True, choices=PROFILES)
    parser.add_argument("--output", type=Path, default=ROOT / "target/release-dist")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--check", action="store_true", help="Check source and inputs without building")
    args = parser.parse_args()
    revision = check_source()
    target = next(line.removeprefix("host: ") for line in output(["rustc", "-vV"]).splitlines()
                  if line.startswith("host: "))
    if not target.endswith("-linux-gnu"):
        raise ValueError("this candidate packaging supports native Linux GNU builds only")
    command = ["cargo", "build", "--locked", "--release", "--target", target,
               "-p", "ai-security-platform-app", "--no-default-features",
               "--features", PROFILES[args.profile], "--bin", "ai-security-platform"]
    if args.offline:
        command.append("--offline")
    if args.check:
        print(json.dumps({"gitRevision": revision, "buildCommand": command}))
        return
    env = dict(os.environ, VERSION=args.version, GIT_REVISION=revision)
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    target_dir = Path(env.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target_dir.is_absolute():
        target_dir = ROOT / target_dir
    binary = target_dir / target / "release/ai-security-platform"
    info = json.loads(output([str(binary), "--version"]))
    if check_source() != revision:
        raise ValueError("checkout changed during the release build")
    print(package(binary, args.output.resolve(), args.version, args.profile, revision, target, info, command))


if __name__ == "__main__":
    main()
