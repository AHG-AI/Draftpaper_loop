from __future__ import annotations

import importlib.util
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


def load_dossier_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_build_handoff_dossier", root / "scripts" / "build_handoff_dossier.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load build_handoff_dossier.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_verifier_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_verify_handoff_dossier", root / "scripts" / "verify_handoff_dossier.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load verify_handoff_dossier.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def acceptance_payload(*, pin_matched: bool = True) -> dict[str, object]:
    return {
        "schema_version": "draftpaper.handoff-acceptance/v1",
        "status": "passed",
        "generated_at": "2026-07-03T00:00:00Z",
        "base_url": "http://127.0.0.1:4888",
        "target_track": "paid_local_handoff",
        "commercial_grade": "paid_local_handoff_ready",
        "summary": {"checks": 20, "errors": 0, "warnings": 0},
        "evidence_summary": {
            "target_track": {"id": "paid_local_handoff", "status": "ready"},
            "license": {
                "status": "valid",
                "signature_configured": True,
                "signature_verified": True,
                "public_key_pin_configured": True,
                "public_key_pin_matched": pin_matched,
                "failed_errors": [],
                "failed_warnings": [],
            },
            "security_audit": {"status": "passed", "errors": 0, "warnings": 0, "failed_errors": [], "failed_warnings": []},
            "release_package": {"status": "verified", "zip_sha256": "a" * 64, "signature_verified": True, "errors": 0, "warnings": 0},
            "backup_recovery": {"verification_status": "verified", "rehearsal_status": "passed"},
            "hosted_readiness": {"status": "not_ready", "passed_gates": 0, "total_gates": 5, "failed_gates": ["hosted_enterprise_auth"]},
            "support_bundle": {"downloaded": True, "bytes": 128, "sha256": "b" * 64},
        },
        "release_verification": {"status": "verified", "summary": {"errors": 0, "warnings": 0}, "zip_sha256": "a" * 64, "signature_path": "/private/release.zip.sig"},
        "hosted_readiness": {"status": "not_ready", "summary": {"errors": 5}},
        "support_bundle": {"url": "http://127.0.0.1:4888/api/support-bundle", "bytes": 128, "sha256": "b" * 64},
        "next_required_actions": [],
        "payloads": {"license": {"token": "plain-token", "signature": {"signature_path": "/private/license.sig"}}},
        "report_sha256": "c" * 64,
    }


class HandoffDossierTests(unittest.TestCase):
    def test_build_handoff_dossier_creates_customer_safe_summary(self) -> None:
        dossier = load_dossier_module()
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            acceptance_path = root / "handoff-acceptance.json"
            acceptance_path.write_text(json.dumps(acceptance_payload()), encoding="utf-8")
            release_zip = root / "draftpaper-loop.zip"
            release_manifest = root / "draftpaper-loop.manifest.json"
            release_sha = root / "draftpaper-loop.zip.sha256"
            release_sig = root / "draftpaper-loop.zip.sig"
            release_public_key = root / "draftpaper-loop.public.pem"
            release_zip.write_bytes(b"release")
            release_sha256 = hashlib.sha256(release_zip.read_bytes()).hexdigest()
            release_manifest.write_text(json.dumps({"status": "packaged", "zip_path": str(release_zip), "zip_sha256": release_sha256}), encoding="utf-8")
            release_sha.write_text(f"{release_sha256}  {release_zip.name}\n", encoding="utf-8")
            for path, content in [
                (release_sig, b"signature"),
                (release_public_key, b"public key"),
            ]:
                path.write_bytes(content)

            result = dossier.build_handoff_dossier(
                acceptance_report=acceptance_path,
                output_dir=root / "dossier",
                customer_id="CUST-A",
                customer_name="Customer A",
                release_zip=release_zip,
                release_manifest=release_manifest,
                release_sha256_file=release_sha,
                release_signature=release_sig,
                release_public_key=release_public_key,
            )

            self.assertEqual(result["status"], "ready")
            self.assertRegex(result["dossier_sha256"], r"^[0-9a-f]{64}$")
            dossier_payload = json.loads(Path(result["dossier_path"]).read_text(encoding="utf-8"))
            self.assertEqual(dossier_payload["summary"]["errors"], 0)
            self.assertNotIn("payloads", dossier_payload["acceptance"])
            self.assertEqual(dossier_payload["acceptance"]["evidence_summary"]["license"]["public_key_pin_matched"], True)

            with zipfile.ZipFile(result["zip_path"]) as archive:
                names = set(archive.namelist())
                self.assertIn("handoff-dossier.json", names)
                self.assertIn("handoff-acceptance-summary.json", names)
                self.assertIn("release-artifacts/draftpaper-loop.manifest.json", names)
                self.assertNotIn("draftpaper-loop.zip", names)
                combined = "\n".join(archive.read(name).decode("utf-8", errors="ignore") for name in names if name.endswith(".json"))
            self.assertNotIn("plain-token", combined)
            self.assertNotIn("/private/license.sig", combined)
            self.assertNotIn("/private/release.zip.sig", combined)

            verification = verifier.verify_handoff_dossier(Path(result["zip_path"]))
            self.assertEqual(verification["status"], "verified")
            verify_checks = {item["id"]: item for item in verification["checks"]}
            self.assertTrue(verify_checks["dossier_sha256_matches"]["passed"])
            self.assertTrue(verify_checks["acceptance_summary_matches_dossier"]["passed"])
            self.assertTrue(verify_checks["release_sha256_sidecar_matches_zip_record"]["passed"])
            self.assertTrue(verify_checks["private_members_excluded"]["passed"])

    def test_build_handoff_dossier_flags_unpinned_license_key(self) -> None:
        dossier = load_dossier_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            acceptance_path = root / "handoff-acceptance.json"
            acceptance_path.write_text(json.dumps(acceptance_payload(pin_matched=False)), encoding="utf-8")

            result = dossier.build_handoff_dossier(
                acceptance_report=acceptance_path,
                output_dir=root / "dossier",
            )

            self.assertEqual(result["status"], "attention")
            payload = json.loads(Path(result["dossier_path"]).read_text(encoding="utf-8"))
            failed = {item["id"]: item for item in payload["checks"] if not item["passed"]}
            self.assertIn("license_public_key_pin_matched", failed)

    def test_verify_handoff_dossier_flags_tampering_and_private_members(self) -> None:
        dossier = load_dossier_module()
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            acceptance_path = root / "handoff-acceptance.json"
            acceptance_path.write_text(json.dumps(acceptance_payload()), encoding="utf-8")
            result = dossier.build_handoff_dossier(
                acceptance_report=acceptance_path,
                output_dir=root / "dossier",
            )
            original = Path(result["zip_path"])

            tampered = root / "tampered.zip"
            with zipfile.ZipFile(original) as src, zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as dst:
                for name in src.namelist():
                    data = src.read(name)
                    if name == "handoff-dossier.json":
                        payload = json.loads(data.decode("utf-8"))
                        payload["status"] = "attention"
                        data = json.dumps(payload).encode("utf-8")
                    dst.writestr(name, data)
            tampered_report = verifier.verify_handoff_dossier(tampered)
            self.assertEqual(tampered_report["status"], "attention")
            tampered_checks = {item["id"]: item for item in tampered_report["checks"] if not item["passed"]}
            self.assertIn("dossier_status_ready", tampered_checks)
            self.assertIn("dossier_sha256_matches", tampered_checks)

            leaked = root / "leaked.zip"
            with zipfile.ZipFile(original) as src, zipfile.ZipFile(leaked, "w", compression=zipfile.ZIP_DEFLATED) as dst:
                for name in src.namelist():
                    dst.writestr(name, src.read(name))
                dst.writestr("operator-token.txt", "plain-token")
            leaked_report = verifier.verify_handoff_dossier(leaked)
            self.assertEqual(leaked_report["status"], "attention")
            leaked_checks = {item["id"]: item for item in leaked_report["checks"] if not item["passed"]}
            self.assertIn("private_members_excluded", leaked_checks)


if __name__ == "__main__":
    unittest.main()
