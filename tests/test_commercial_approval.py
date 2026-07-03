from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_approval_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_verify_commercial_approval", root / "scripts" / "verify_commercial_approval.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load verify_commercial_approval.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def write_commercial_docs(root: Path, module) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in module.REQUIRED_DOCUMENT_HASHES:
        path = root / relative
        path.write_text(f"{relative}\ncommercial boundary\n", encoding="utf-8")
        hashes[relative] = module._sha256_file(path)
    return hashes


class CommercialApprovalTests(unittest.TestCase):
    def test_verifies_approval_against_license_and_document_hashes(self) -> None:
        module = load_approval_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            doc_hashes = write_commercial_docs(root, module)
            license_file = root / "private" / "commercial-license-grant.json"
            approval_file = root / "private" / "commercial-approval.json"
            license_payload = {
                "schema_version": "draftpaper.commercial-license/v1",
                "license_id": "DPL-COMM-APPROVED",
                "customer_id": "CUST-APPROVED",
                "customer_name": "Approved Customer",
                "grant_type": "paid-local-pilot",
                "issued_at": "2000-01-01",
                "expires_at": "2099-12-31",
                "seats": 2,
                "features": ["local_console", "paper_loop"],
                "workspaces": ["approved-workspace"],
            }
            license_payload["grant_sha256"] = module.license_digest(license_payload)
            write_json(license_file, license_payload)
            approval_payload = {
                "schema_version": module.APPROVAL_SCHEMA,
                "status": "approved",
                "approval_reference": "LEGAL-2000-001",
                "approval_authority": "external-contract",
                "approved_by": "legal@example.invalid",
                "approved_at": "2000-01-02T00:00:00Z",
                "customer_id": "CUST-APPROVED",
                "customer_name": "Approved Customer",
                "license_id": "DPL-COMM-APPROVED",
                "scope": ["paid_local_handoff"],
                "evidence_refs": [{"id": "contract-hash", "sha256": "f" * 64}],
                "license_grant_sha256": license_payload["grant_sha256"],
                "license_file_sha256": module._sha256_file(license_file),
                "document_hashes": doc_hashes,
            }
            write_json(approval_file, approval_payload)

            report = module.verify_commercial_approval(approval_file=approval_file, license_file=license_file, root=root)

        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["summary"]["errors"], 0)
        checks = {item["id"]: item for item in report["checks"]}
        self.assertTrue(checks["approval_license_grant_sha256_matches"]["passed"])
        self.assertTrue(checks["approval_no_secret_material"]["passed"])

    def test_flags_tampered_license_and_secret_fields(self) -> None:
        module = load_approval_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            doc_hashes = write_commercial_docs(root, module)
            license_file = root / "private" / "commercial-license-grant.json"
            approval_file = root / "private" / "commercial-approval.json"
            license_payload = {
                "schema_version": "draftpaper.commercial-license/v1",
                "license_id": "DPL-COMM-TAMPERED",
                "customer_id": "CUST-TAMPERED",
                "customer_name": "Tampered Customer",
                "grant_type": "paid-local-pilot",
                "issued_at": "2000-01-01",
                "expires_at": "2099-12-31",
                "seats": 1,
                "features": ["local_console"],
                "workspaces": ["tampered-workspace"],
            }
            original_digest = module.license_digest(license_payload)
            license_payload["features"] = ["local_console", "paper_loop"]
            license_payload["grant_sha256"] = module.license_digest(license_payload)
            write_json(license_file, license_payload)
            approval_payload = {
                "schema_version": module.APPROVAL_SCHEMA,
                "status": "approved",
                "approval_reference": "LEGAL-2000-002",
                "approval_authority": "external-contract",
                "approved_by": "legal@example.invalid",
                "approved_at": "2000-01-02",
                "customer_id": "CUST-TAMPERED",
                "customer_name": "Tampered Customer",
                "license_id": "DPL-COMM-TAMPERED",
                "scope": ["paid_local_handoff"],
                "evidence_refs": ["contract:LEGAL-2000-002"],
                "license_grant_sha256": original_digest,
                "document_hashes": doc_hashes,
                "token": "plaintext-token-must-not-be-here",
            }
            write_json(approval_file, approval_payload)

            report = module.verify_commercial_approval(approval_file=approval_file, license_file=license_file, root=root)

        self.assertEqual(report["status"], "attention")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertFalse(checks["approval_license_grant_sha256_matches"]["passed"])
        self.assertFalse(checks["approval_no_secret_material"]["passed"])


if __name__ == "__main__":
    unittest.main()
