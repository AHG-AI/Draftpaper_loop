from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_review_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_verify_security_review", root / "scripts" / "verify_security_review.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load verify_security_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SecurityReviewTests(unittest.TestCase):
    def test_verifies_security_review_artifacts_and_clean_audit(self) -> None:
        module = load_review_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "security-review-report.txt"
            artifact.write_text("external review report\n", encoding="utf-8")
            audit = root / "security-audit.json"
            audit.write_text(json.dumps({"status": "passed", "summary": {"errors": 0, "warnings": 0}}), encoding="utf-8")
            review = root / "security-review.json"
            payload = {
                "schema_version": module.REVIEW_SCHEMA,
                "status": "verified",
                "review_type": "third_party_security_review",
                "review_authority": "external-security-provider",
                "review_reference": "SEC-2000-001",
                "reviewed_by": "security@example.invalid",
                "reviewed_at": "2000-01-02T00:00:00Z",
                "target": "draftpaper-loop-local-commercial-release",
                "scope": ["operator_console", "release_package", "local_data_controls"],
                "evidence_refs": ["security-review/SEC-2000-001"],
                "findings_summary": {
                    "critical_open": 0,
                    "high_open": 0,
                    "medium_open": 0,
                    "low_open": 1,
                    "informational_open": 2,
                },
                "artifacts": [{"path": artifact.name, "sha256": sha256(artifact), "description": "redacted external report"}],
                "security_audit_sha256": sha256(audit),
            }
            review.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            review.chmod(0o600)

            report = module.verify_security_review(review_file=review, security_audit_file=audit)

        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["summary"]["errors"], 0)
        checks = {item["id"]: item for item in report["checks"]}
        self.assertTrue(checks["security_review_no_open_critical"]["passed"])
        self.assertTrue(checks["security_review_artifact_0_sha256_matches"]["passed"])
        self.assertTrue(checks["security_review_audit_errors_clear"]["passed"])

    def test_flags_open_high_findings_tampered_artifact_and_secret_fields(self) -> None:
        module = load_review_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "security-review-report.txt"
            artifact.write_text("external review report\n", encoding="utf-8")
            original_sha = sha256(artifact)
            artifact.write_text("tampered report\n", encoding="utf-8")
            review = root / "security-review.json"
            payload = {
                "schema_version": module.REVIEW_SCHEMA,
                "status": "verified",
                "review_type": "penetration_test",
                "review_authority": "external-security-provider",
                "review_reference": "SEC-2000-002",
                "reviewed_by": "security@example.invalid",
                "reviewed_at": "2000-01-02",
                "target": "draftpaper-loop-local-commercial-release",
                "scope": ["operator_console"],
                "evidence_refs": ["security-review/SEC-2000-002"],
                "findings_summary": {
                    "critical_open": 0,
                    "high_open": 1,
                    "medium_open": 0,
                    "low_open": 0,
                    "informational_open": 0,
                },
                "artifacts": [{"path": artifact.name, "sha256": original_sha}],
                "token": "plain-token",
            }
            review.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            review.chmod(0o600)

            report = module.verify_security_review(review_file=review)

        self.assertEqual(report["status"], "attention")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertFalse(checks["security_review_no_open_high"]["passed"])
        self.assertFalse(checks["security_review_artifact_0_sha256_matches"]["passed"])
        self.assertFalse(checks["security_review_no_secret_material"]["passed"])


if __name__ == "__main__":
    unittest.main()
