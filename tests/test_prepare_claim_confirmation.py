from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from draftpaper_cli.project_scaffold import create_project


def load_preparer_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_prepare_claim_confirmation", root / "scripts" / "prepare_claim_confirmation.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load prepare_claim_confirmation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrepareClaimConfirmationTests(unittest.TestCase):
    def test_prepares_private_draft_with_project_artifact_hashes(self) -> None:
        preparer = load_preparer_module()

        with tempfile.TemporaryDirectory() as tmp:
            project = create_project(root=Path(tmp) / "projects", idea="Prepare claim confirmation", field="workflow engineering")
            (project.path / "result_validity" / "result_validity_report.json").write_text('{"status":"passed"}\n', encoding="utf-8")
            (project.path / "core_evidence" / "core_evidence_report.json").write_text('{"status":"passed"}\n', encoding="utf-8")
            output = Path(tmp) / "private" / "claim-confirmation.json"

            report = preparer.prepare_claim_confirmation(
                project=project.path,
                output=output,
                claims=["The workflow produces auditable local evidence."],
            )

            payload = json.loads(output.read_text(encoding="utf-8"))
            output_mode = output.stat().st_mode & 0o077

        self.assertEqual(report["status"], "prepared")
        self.assertEqual(report["confirmation_status"], "draft")
        self.assertEqual(report["verification_status"], "attention")
        self.assertGreaterEqual(report["artifacts_count"], 3)
        self.assertEqual(output_mode, 0)
        self.assertEqual(payload["schema_version"], "draftpaper.claim-confirmation/v1")
        self.assertEqual(payload["status"], "draft")
        self.assertEqual(payload["claims"][0]["status"], "needs_review")
        self.assertTrue(any(item["path"] == "project.json" for item in payload["artifacts"]))

    def test_confirmed_evidence_requires_claim_and_reviewer(self) -> None:
        preparer = load_preparer_module()

        with tempfile.TemporaryDirectory() as tmp:
            project = create_project(root=Path(tmp) / "projects", idea="Confirmed claim confirmation", field="workflow engineering")
            output = Path(tmp) / "private" / "claim-confirmation.json"

            with self.assertRaises(ValueError):
                preparer.prepare_claim_confirmation(project=project.path, output=output, status="confirmed")

            report = preparer.prepare_claim_confirmation(
                project=project.path,
                output=output,
                status="confirmed",
                confirmed_by="domain reviewer",
                confirmation_reference="CLAIM-REVIEW-001",
                confirmed_at="2020-01-02T00:00:00Z",
                claims=["The local package includes verifier-backed claim confirmation evidence."],
            )

        self.assertEqual(report["confirmation_status"], "confirmed")
        self.assertEqual(report["verification_status"], "verified")
        self.assertEqual(report["verification_summary"]["errors"], 0)


if __name__ == "__main__":
    unittest.main()
