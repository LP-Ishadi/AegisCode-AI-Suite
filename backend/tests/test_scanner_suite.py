import asyncio
import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.models.dispatch import ScanMetadata, ScanResult
from app.services.adapter_errors import AdapterError
from app.services.repository_snapshot import RepositorySnapshotProvider, Snapshot
from app.services.scan_pipeline import ScannerPipeline
from app.services.scanner_suite import (
    ScannerSuite,
    image_references,
    parse_semgrep,
    parse_trivy_image,
    parse_trufflehog,
    semgrep_rule_messages,
)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        (self.root / "Dockerfile").write_text("FROM python:3.12 AS base\nFROM base\n")
        (self.root / "app.py").write_text("print('hello')\n")
        self.snapshot = Snapshot(self.root, frozenset({"Dockerfile", "app.py"}), "a" * 40)

    def tearDown(self):
        self.directory.cleanup()

    def test_immutable_snapshot_from_git_blobs(self):
        metadata = ScanMetadata.model_construct(
            github_repository_id=10,
            installation_id=20,
            repository_full_name="owner/repo",
            commit_sha="a" * 40,
        )
        provider = RepositorySnapshotProvider(authorize=lambda _: {})
        calls = []

        async def request(method, path, token):
            calls.append(path)
            if path == "/repositories/10":
                return {"id": 10, "full_name": "owner/repo"}
            if "/git/trees/" in path:
                return {
                    "truncated": False,
                    "tree": [
                        {
                            "path": "app.py",
                            "type": "blob",
                            "mode": "100644",
                            "sha": "b" * 40,
                            "size": 7,
                        }
                    ],
                }
            return {"encoding": "base64", "content": base64.b64encode(b"print()").decode()}

        provider.api.installation_token = lambda _: asyncio.sleep(0, result="token")
        provider.api.request = request
        snapshot = asyncio.run(provider.fetch_into(metadata, self.root))
        self.assertEqual((self.root / "app.py").read_bytes(), b"print()")
        self.assertEqual(snapshot.commit_sha, metadata.commit_sha)
        self.assertTrue(any(metadata.commit_sha in path for path in calls))

    def test_snapshot_rejects_symlinks(self):
        metadata = ScanMetadata.model_construct(
            github_repository_id=10,
            installation_id=20,
            repository_full_name="owner/repo",
            commit_sha="a" * 40,
        )
        provider = RepositorySnapshotProvider(authorize=lambda _: {})

        async def request(method, path, token):
            if path == "/repositories/10":
                return {"id": 10, "full_name": "owner/repo"}
            return {
                "truncated": False,
                "tree": [
                    {"path": "link", "type": "blob", "mode": "120000", "sha": "b" * 40, "size": 3}
                ],
            }

        provider.api.installation_token = lambda _: asyncio.sleep(0, result="token")
        provider.api.request = request
        with self.assertRaises(AdapterError):
            asyncio.run(provider.fetch_into(metadata, self.root))

    def test_secret_value_is_not_persisted_in_finding(self):
        item = {
            "DetectorName": "Generic",
            "Raw": "TOP_SECRET_VALUE",
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": str(self.root / "app.py"), "line": 1}}
            },
        }
        findings = parse_trufflehog(json.dumps(item).encode() + b"\n", self.snapshot)
        self.assertEqual(len(findings), 1)
        self.assertNotIn("TOP_SECRET_VALUE", findings[0].message)
        self.assertIn("unverified", findings[0].message)

    def test_semgrep_uses_static_rule_explanation(self):
        data = {
            "results": [
                {
                    "check_id": "opt.aegis.rules.aegis.python-pickle-deserialization",
                    "path": str(self.root / "app.py"),
                    "start": {"line": 1},
                    "extra": {
                        "severity": "ERROR",
                        "message": "UNTRUSTED_SOURCE_CONTENT",
                    },
                }
            ]
        }
        rules = Path(__file__).resolve().parents[1] / "rules" / "aegis.yaml"
        semgrep_rule_messages.cache_clear()
        with patch("app.services.scanner_suite.RULES", rules):
            findings = parse_semgrep(data, self.snapshot)
        semgrep_rule_messages.cache_clear()
        self.assertIn("Pickle", findings[0].message)
        self.assertNotIn("UNTRUSTED_SOURCE_CONTENT", findings[0].message)

    def test_image_findings_map_to_dockerfile_line(self):
        self.assertEqual(image_references(self.snapshot), [("Dockerfile", 1, "python:3.12")])
        data = {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-123", "PkgName": "openssl", "Severity": "CRITICAL"}
                    ]
                }
            ],
        }
        result = parse_trivy_image(data, "Dockerfile", 1, "python:3.12")
        self.assertEqual((result[0].file_path, result[0].line), ("Dockerfile", 1))

    def test_suite_runs_all_scanners(self):
        async def fake_run(argv, **_):
            if argv[0] == "semgrep":
                return b'{"results": []}'
            if argv[0] == "trufflehog":
                return b""
            return b'{"SchemaVersion": 2, "Results": []}'

        with patch("app.services.scanner_suite.run_command", side_effect=fake_run) as run:
            result = asyncio.run(ScannerSuite().scan(self.snapshot))
        self.assertEqual(result.findings, [])
        self.assertEqual(run.call_count, 4)

    def test_scanner_pipeline_finishes_without_openai_key(self):
        metadata = ScanMetadata.model_construct(commit_sha="a" * 40)
        roots = []

        class FakeSnapshot:
            async def fetch_into(self, metadata, root):
                roots.append(root)
                return Snapshot(root, frozenset({"app.py"}), metadata.commit_sha)

        class FakeScanners:
            async def scan(self, snapshot):
                return ScanResult(findings=[], engine_version="scanner-suite-test")

        pipeline = ScannerPipeline(
            snapshot=FakeSnapshot(), scanners=FakeScanners(), source=object(), engine=object()
        )
        with patch(
            "app.services.scan_pipeline.get_settings",
            return_value=SimpleNamespace(ai_scanning_enabled=False, openai_api_key=None),
        ):
            result = asyncio.run(pipeline.run(metadata))
        self.assertEqual(result.engine_version, "scanner-suite-test")
        self.assertFalse(roots[0].exists())


if __name__ == "__main__":
    unittest.main()
