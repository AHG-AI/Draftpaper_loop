from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from draftpaper_cli.project_scaffold import create_project


def load_verifier_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_verify_claim_confirmation", root / "scripts" / "verify_claim_confirmation.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load verify_claim_confirmation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def confirmation_payload(project_path: Path, artifact: Path) -> dict[str, object]:
    artifact_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
    return {
        "schema_version": "draftpaper.claim-confirmation/v1",
        "status": "confirmed",
        "project_id": project_path.name,
        "project_slug": project_path.name,
        "confirmation_reference": "CLAIM-REVIEW-001",
        "confirmed_by": "domain reviewer",
        "confirmed_at": "2020-01-02T00:00:00Z",
        "scope": ["result_claims", "domain_data", "figures"],
        "claims": [
            {
                "id": "C1",
                "claim": "The staged loop has a reproducible local handoff evidence chain.",
                "status": "confirmed",
                "reviewer": "domain reviewer",
                "evidence_refs": ["review/claim-confirmation-note.txt"],
            }
        ],
        "artifacts": [
            {
                "path": "review/claim-confirmation-note.txt",
                "sha256": artifact_hash,
                "description": "Reviewer confirmation note",
            }
        ],
    }


class ClaimConfirmationVerifierTests(unittest.TestCase):
    def test_valid_confirmation_with_project_artifact_hashes_verifies(self) -> None:
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            project = create_project(root=Path(tmp) / "projects", idea="Claim confirmation smoke", field="workflow engineering")
            artifact = project.path / "review" / "claim-confirmation-note.txt"
            artifact.write_text("reviewed claims and artifacts\n", encoding="utf-8")
            confirmation_file = Path(tmp) / "private" / "claim-confirmation.json"
            write_json(confirmation_file, confirmation_payload(project.path, artifact))

            report = verifier.verify_claim_confirmation(confirmation_file=confirmation_file, project=project.path)

        self.assertEqual(report["schema_version"], "draftpaper.claim-confirmation-verification/v1")
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["summary"]["errors"], 0)
        checks = {item["id"]: item for item in report["checks"]}
        self.assertTrue(checks["claim_confirmation_all_claims_confirmed"]["passed"])
        self.assertTrue(checks["claim_confirmation_artifact_0_sha256_matches"]["passed"])

    def test_unconfirmed_status_and_tampered_artifact_require_attention(self) -> None:
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            project = create_project(root=Path(tmp) / "projects", idea="Tampered confirmation smoke", field="workflow engineering")
            artifact = project.path / "review" / "claim-confirmation-note.txt"
            artifact.write_text("reviewed claims and artifacts\n", encoding="utf-8")
            payload = confirmation_payload(project.path, artifact)
            payload["status"] = "draft"
            payload["claims"] = [
                {
                    "id": "C1",
                    "claim": "A claim that still needs review.",
                    "status": "draft",
                    "reviewer": "domain reviewer",
                    "evidence_refs": ["review/claim-confirmation-note.txt"],
                }
            ]
            payload["artifacts"] = [{"path": "review/claim-confirmation-note.txt", "sha256": "0" * 64}]
            confirmation_file = Path(tmp) / "private" / "claim-confirmation.json"
            write_json(confirmation_file, payload)

            report = verifier.verify_claim_confirmation(confirmation_file=confirmation_file, project=project.path)

        self.assertEqual(report["status"], "attention")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertFalse(checks["claim_confirmation_status"]["passed"])
        self.assertFalse(checks["claim_confirmation_all_claims_confirmed"]["passed"])
        self.assertFalse(checks["claim_confirmation_artifact_0_sha256_matches"]["passed"])

    def test_secret_material_is_rejected(self) -> None:
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            project = create_project(root=Path(tmp) / "projects", idea="Secret confirmation smoke", field="workflow engineering")
            artifact = project.path / "review" / "claim-confirmation-note.txt"
            artifact.write_text("reviewed claims and artifacts\n", encoding="utf-8")
            payload = confirmation_payload(project.path, artifact)
            payload["api_key"] = "should-not-be-here"
            confirmation_file = Path(tmp) / "private" / "claim-confirmation.json"
            write_json(confirmation_file, payload)

            report = verifier.verify_claim_confirmation(confirmation_file=confirmation_file, project=project.path)

        self.assertEqual(report["status"], "attention")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertFalse(checks["claim_confirmation_no_secret_material"]["passed"])


if __name__ == "__main__":
    unittest.main()
