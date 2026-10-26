"""Release identity, clean-source and archive checks; no production test interfaces."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prepare_release", ROOT / "scripts/prepare_release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.info = {"version": "v0.1.0-rc.1", "git_revision": "a" * 40,
                     "build_profile": "release", "build_target": "x86_64-unknown-linux-gnu"}

    def test_version_cannot_inject_paths_or_shell(self):
        for value in ("../v1.0.0", "v1.0.0;pwd", "v01.0.0", "1.0.0", "v1.0.0\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                release.validate_version(value)
        self.assertEqual(release.validate_version(self.info["version"]), self.info["version"])

    def test_dirty_checkout_is_rejected(self):
        with patch.object(release, "output", return_value="?? source.rs"), self.assertRaises(ValueError):
            release.check_source()

    def test_clean_checkout_has_exact_identity(self):
        with patch.object(release, "output", side_effect=["", "a" * 40]):
            self.assertEqual(release.check_source(), "a" * 40)

    def test_mismatched_binary_is_rejected(self):
        for key in self.info:
            info = dict(self.info, **{key: "wrong"})
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.validate_build(info, self.info["version"], "a" * 40,
                                       self.info["build_target"])

    def test_archive_is_minimal_and_checksum_is_verifiable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "gateway"
            binary.write_bytes(b"test executable")
            binary.chmod(0o755)
            archive = release.package(binary, root / "dist", self.info["version"], "llm",
                                      "a" * 40, self.info["build_target"], self.info, ["cargo", "build"])
            self.assertEqual(archive.with_suffix("").with_suffix(".sha256").read_text(),
                             f"{release.digest(archive)}  {archive.name}\n")
            with tarfile.open(archive) as stream:
                files = [entry for entry in stream.getmembers() if entry.isfile()]
                self.assertEqual({Path(entry.name).name for entry in files},
                                 {"ai-security-platform", "LICENSE", "Cargo.lock", "RELEASE.md",
                                  "LICENSE-platform-pool", "manifest.json"})
                manifest_member = next(entry for entry in files if entry.name.endswith("/manifest.json"))
                manifest = json.load(stream.extractfile(manifest_member))
                for entry in files:
                    if entry is not manifest_member:
                        self.assertEqual(hashlib.sha256(stream.extractfile(entry).read()).hexdigest(),
                                         manifest["files"][Path(entry.name).name])
                executable = next(entry for entry in files if entry.name.endswith("/ai-security-platform"))
                self.assertTrue(executable.mode & 0o111)
            with self.assertRaises(ValueError):
                release.package(binary, root / "dist", self.info["version"], "llm",
                                "a" * 40, self.info["build_target"], self.info, ["cargo", "build"])


if __name__ == "__main__":
    unittest.main()
