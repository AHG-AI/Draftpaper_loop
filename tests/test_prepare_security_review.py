from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_preparer_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_prepare_security_review", root / "scripts" / "prepare_security_review.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load prepare_security_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_clean_security_audit(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "status": "passed",
                "summary": {"checks": 3, "errors": 0, "warnings": 0, "passed": 3},
                "findings_summary": {
                    "critical_open": 0,
                    "high_open": 0,
                    "medium_open": 0,
                    "low_open": 0,
                    "informational_open": 0,
                },
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


class PrepareSecurityReviewTests(unittest.TestCase):
    def test_prepares_private_draft_bound_to_security_audit(self) -> None:
        preparer = load_preparer_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            audit = root / "private" / "security-audit.json"
            output = root / "private" / "security-review.json"
            write_clean_security_audit(audit)

            report = preparer.prepare_security_review(output=output, security_audit_file=audit)
            payload = json.loads(output.read_text(encoding="utf-8"))
            output_mode = output.stat().st_mode & 0o077

        self.assertEqual(report["status"], "prepared")
        self.assertEqual(report["review_status"], "draft")
        self.assertEqual(report["verification_status"], "attention")
        self.assertEqual(report["security_audit_status"], "passed")
        self.assertEqual(output_mode, 0)
        self.assertEqual(payload["schema_version"], "draftpaper.security-review/v1")
        self.assertEqual(payload["status"], "draft")
        self.assertTrue(payload["security_audit_sha256"])
        self.assertEqual(payload["findings_summary"]["critical_open"], 0)

    def test_verified_evidence_requires_external_review_fields(self) -> None:
        preparer = load_preparer_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            audit = root / "private" / "security-audit.json"
            output = root / "private" / "security-review.json"
            write_clean_security_audit(audit)

            with self.assertRaises(ValueError):
                preparer.prepare_security_review(output=output, security_audit_file=audit, status="verified")

            report = preparer.prepare_security_review(
                output=output,
                security_audit_file=audit,
                status="verified",
                review_authority="external security provider",
                review_reference="SEC-REVIEW-001",
                reviewed_by="security reviewer",
                reviewed_at="2020-01-02T00:00:00Z",
                evidence_refs=["security-review/SEC-REVIEW-001"],
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(report["review_status"], "verified")
        self.assertEqual(report["verification_status"], "verified")
        self.assertEqual(report["verification_summary"]["errors"], 0)
        self.assertEqual(payload["status"], "verified")
        self.assertEqual(payload["review_reference"], "SEC-REVIEW-001")


if __name__ == "__main__":
    unittest.main()
