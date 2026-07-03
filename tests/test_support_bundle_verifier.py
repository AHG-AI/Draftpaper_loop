from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from draftpaper_cli.project_scaffold import create_project


def load_portal_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_serviceconsole_app", root / "scripts" / "serviceconsole_app.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load serviceconsole_app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_verifier_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_verify_support_bundle", root / "scripts" / "verify_support_bundle.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load verify_support_bundle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SupportBundleVerifierTests(unittest.TestCase):
    def test_verifier_accepts_generated_redacted_support_bundle(self) -> None:
        portal = load_portal_module()
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            runtime_root = Path(tmp) / "runtime"
            project = create_project(root=projects_root, idea="Support verifier smoke", field="workflow engineering")
            (project.path / "data" / "raw" / "private.csv").write_text("raw-secret-value\n", encoding="utf-8")
            portal.JOBS.clear()
            portal.JOB_PROCESSES.clear()
            portal.JOBS["support-job"] = {
                "id": "support-job",
                "action": "status",
                "status": "failed",
                "request_payload": {"project": project.path.name, "token": "plain-token", "params": {"secret": "plain-secret"}},
                "stdout": "manuscript output should not be bundled",
                "stderr": "private stack trace should not be bundled",
                "created_at": 1.0,
                "returncode": 2,
            }
            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                    archive_bytes, _manifest = portal.build_support_bundle()

        report = verifier.verify_support_bundle_bytes(archive_bytes, source="unit-test")

        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["summary"]["errors"], 0)
        checks = {item["id"]: item for item in report["checks"]}
        self.assertTrue(checks["support_bundle_json_readable_and_redacted"]["passed"])
        self.assertTrue(checks["support_bundle_private_members_excluded"]["passed"])
        self.assertTrue(checks["support_bundle_path_roots_redacted"]["passed"])

    def test_verifier_rejects_private_member_and_unredacted_sensitive_key(self) -> None:
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bad-support.zip"
            with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("draftpaper-support-test/health.json", json.dumps({"token": "plain-token", "repo_root": "/Users/nullin/private"}))
                archive.writestr("draftpaper-support-test/data/raw/private.csv", "raw-secret-value\n")
                archive.writestr(
                    "draftpaper-support-test/support_manifest.json",
                    json.dumps(
                        {
                            "schema_version": "draftpaper.support-bundle/v1",
                            "status": "generated",
                            "privacy": {
                                "redacted_value": "[redacted]",
                                "includes_project_files": False,
                                "includes_raw_or_processed_data": False,
                            },
                            "files": [],
                        }
                    ),
                )

            report = verifier.verify_support_bundle(bundle)

        self.assertEqual(report["status"], "attention")
        failed = {item["id"]: item for item in report["checks"] if not item["passed"]}
        self.assertIn("support_bundle_private_members_excluded", failed)
        self.assertIn("support_bundle_json_readable_and_redacted", failed)
        self.assertIn("support_bundle_path_roots_redacted", failed)


if __name__ == "__main__":
    unittest.main()
