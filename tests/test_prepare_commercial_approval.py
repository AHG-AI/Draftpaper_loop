from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_preparer_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_prepare_commercial_approval", root / "scripts" / "prepare_commercial_approval.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load prepare_commercial_approval.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_license(path: Path, preparer) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "draftpaper.commercial-license/v1",
        "license_id": "DPL-COMM-PREP",
        "customer_id": "CUST-PREP",
        "customer_name": "Preparation Customer",
        "grant_type": "paid-local-pilot",
        "issued_at": "2020-01-01",
        "expires_at": "2030-01-01",
        "seats": 1,
        "features": ["local_console", "paper_loop"],
        "workspaces": ["prep"],
        "terms": "Local paid pilot handoff.",
    }
    payload["grant_sha256"] = preparer.license_digest(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return payload


class PrepareCommercialApprovalTests(unittest.TestCase):
    def test_prepares_private_draft_bound_to_license_and_documents(self) -> None:
        preparer = load_preparer_module()
        root = Path(__file__).resolve().parents[1]

        with tempfile.TemporaryDirectory() as tmp:
            license_file = Path(tmp) / "private" / "commercial-license-grant.json"
            write_license(license_file, preparer)
            output = Path(tmp) / "private" / "commercial-approval.json"

            report = preparer.prepare_commercial_approval(output=output, license_file=license_file, root=root)
            payload = json.loads(output.read_text(encoding="utf-8"))
            output_mode = output.stat().st_mode & 0o077

        self.assertEqual(report["status"], "prepared")
        self.assertEqual(report["approval_status"], "draft")
        self.assertEqual(report["verification_status"], "attention")
        self.assertEqual(report["document_hashes_count"], 4)
        self.assertEqual(output_mode, 0)
        self.assertEqual(payload["schema_version"], "draftpaper.commercial-approval/v1")
        self.assertEqual(payload["status"], "draft")
        self.assertEqual(payload["license_id"], "DPL-COMM-PREP")
        self.assertIn("COMMERCIAL_LICENSE.md", payload["document_hashes"])

    def test_approved_evidence_requires_external_approval_reference(self) -> None:
        preparer = load_preparer_module()
        root = Path(__file__).resolve().parents[1]

        with tempfile.TemporaryDirectory() as tmp:
            license_file = Path(tmp) / "private" / "commercial-license-grant.json"
            write_license(license_file, preparer)
            output = Path(tmp) / "private" / "commercial-approval.json"

            with self.assertRaises(ValueError):
                preparer.prepare_commercial_approval(output=output, license_file=license_file, root=root, status="approved")

            report = preparer.prepare_commercial_approval(
                output=output,
                license_file=license_file,
                root=root,
                status="approved",
                approval_authority="customer procurement",
                approval_reference="CONTRACT-001",
                approved_by="legal approver",
                approved_at="2020-01-02T00:00:00Z",
                evidence_refs=["contract/CONTRACT-001"],
            )

        self.assertEqual(report["approval_status"], "approved")
        self.assertEqual(report["verification_status"], "verified")
        self.assertEqual(report["verification_summary"]["errors"], 0)


if __name__ == "__main__":
    unittest.main()
