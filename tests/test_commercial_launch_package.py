from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


def load_script(name: str):
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(f"draftpaper_{name}", root / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def fake_support_bundle_bytes() -> bytes:
    payloads = {
        "health.json": {"status": "ok"},
        "commercial_readiness.json": {"status": "assessed"},
        "handoff_readiness.json": {"status": "assessed"},
        "hosted_readiness.json": {"status": "not_ready"},
        "security_audit.json": {"status": "passed"},
        "license.json": {"status": "valid"},
        "license_entitlements.json": {"status": "passed"},
        "claim_confirmation.json": {"status": "unconfigured"},
        "license_approval.json": {"status": "unconfigured"},
        "release_trust.json": {"status": "unconfigured"},
        "security_review.json": {"status": "unconfigured"},
        "access_policy.json": {"status": "reported"},
        "usage.json": {"status": "reported"},
        "quota.json": {"status": "reported"},
        "billing.json": {"status": "reported"},
        "backup_verification.json": {"status": "verified"},
        "backup_rehearsals.json": {"status": "passed"},
        "projects.json": {"status": "listed", "projects": []},
        "jobs.json": {"status": "listed", "jobs": [{"request_payload": {"token": "[redacted]"}}]},
        "audit.json": {"status": "listed", "events": []},
        "service_console_manifest.json": {"schema_version": "ahouse.service-console/v1"},
    }
    prefix = "draftpaper-support-test"
    buffer = io.BytesIO()
    entries = []
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in payloads.items():
            raw = json.dumps(payload, sort_keys=True).encode("utf-8")
            archive.writestr(f"{prefix}/{name}", raw)
            entries.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        manifest = {
            "schema_version": "draftpaper.support-bundle/v1",
            "status": "generated",
            "generated_at": "2026-07-03T00:00:00Z",
            "files": entries,
            "privacy": {
                "redacted_value": "[redacted]",
                "redacted_key_parts": ["authorization", "api_key", "apikey", "cookie", "password", "secret", "token"],
                "redacted_path_roots": True,
                "includes_project_files": False,
                "includes_raw_or_processed_data": False,
            },
        }
        archive.writestr(f"{prefix}/support_manifest.json", json.dumps(manifest, sort_keys=True).encode("utf-8"))
    return buffer.getvalue()


def acceptance_payload(*, release_sha: str, support_sha: str) -> dict[str, object]:
    return {
        "schema_version": "draftpaper.handoff-acceptance/v1",
        "status": "passed",
        "generated_at": "2026-07-03T00:00:00Z",
        "base_url": "http://127.0.0.1:4888",
        "target_track": "paid_local_handoff",
        "commercial_grade": "paid_local_handoff_ready",
        "summary": {"checks": 22, "errors": 0, "warnings": 0},
        "evidence_summary": {
            "target_track": {"id": "paid_local_handoff", "status": "ready"},
            "license": {
                "status": "valid",
                "signature_configured": True,
                "signature_verified": True,
                "public_key_pin_configured": True,
                "public_key_pin_matched": True,
                "failed_errors": [],
                "failed_warnings": [],
            },
            "security_audit": {"status": "passed", "errors": 0, "warnings": 0, "failed_errors": [], "failed_warnings": []},
            "release_package": {"status": "verified", "zip_sha256": release_sha, "signature_verified": True, "errors": 0, "warnings": 0},
            "backup_recovery": {"verification_status": "verified", "rehearsal_status": "passed"},
            "hosted_readiness": {"status": "not_ready", "passed_gates": 0, "total_gates": 5, "failed_gates": ["hosted_enterprise_auth"]},
            "support_bundle": {
                "downloaded": True,
                "bytes": 128,
                "sha256": support_sha,
                "verification_status": "verified",
                "verification_errors": 0,
                "verification_warnings": 0,
            },
        },
        "release_verification": {
            "status": "verified",
            "summary": {"errors": 0, "warnings": 0},
            "zip_sha256": release_sha,
        },
        "hosted_readiness": {"status": "not_ready", "summary": {"errors": 5}},
        "support_bundle_verification": {"status": "verified", "summary": {"errors": 0, "warnings": 0}, "zip_sha256": support_sha},
        "next_required_actions": [],
        "report_sha256": "c" * 64,
    }


@unittest.skipUnless(shutil.which("openssl"), "openssl is required for signed launch-package verification")
class CommercialLaunchPackageTests(unittest.TestCase):
    def test_build_and_verify_paid_local_launch_package(self) -> None:
        package_release = load_script("package_release")
        build_dossier = load_script("build_handoff_dossier")
        launch_builder = load_script("build_commercial_launch_package")
        launch_verifier = load_script("verify_commercial_launch_package")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Draftpaper_loop"
            root.mkdir()
            write_file(root / "pyproject.toml", '[project]\nversion = "1.2.3"\n')
            for relative in package_release.REQUIRED_COMMERCIAL_FILES:
                write_file(root / relative, f"{relative}\n")
            private_key = Path(tmp) / "release-signing.pem"
            subprocess.run(
                [
                    shutil.which("openssl") or "openssl",
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-out",
                    str(private_key),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            release = package_release.build_release_package(
                root=root,
                output_dir=Path(tmp) / "dist",
                version_label="commercial-launch",
                signing_key=private_key,
            )

            support_bundle = Path(tmp) / "draftpaper-support-bundle.zip"
            support_bundle.write_bytes(fake_support_bundle_bytes())
            support_sha = hashlib.sha256(support_bundle.read_bytes()).hexdigest()
            acceptance_report = Path(tmp) / "handoff-acceptance.json"
            acceptance_report.write_text(json.dumps(acceptance_payload(release_sha=release["zip_sha256"], support_sha=support_sha)), encoding="utf-8")

            signature = release["signature"]
            dossier = build_dossier.build_handoff_dossier(
                acceptance_report=acceptance_report,
                output_dir=Path(tmp) / "handoff-dossier",
                release_zip=Path(release["zip_path"]),
                release_manifest=Path(release["manifest_path"]),
                release_sha256_file=Path(release["sha256_path"]),
                release_signature=Path(signature["signature_path"]),
                release_public_key=Path(signature["public_key_path"]),
            )
            self.assertEqual(dossier["status"], "ready")

            launch = launch_builder.build_commercial_launch_package(
                acceptance_report=acceptance_report,
                output_dir=Path(tmp) / "launch",
                target_track="paid_local_handoff",
                customer_id="CUST-LAUNCH",
                customer_name="Launch Customer",
                release_zip=Path(release["zip_path"]),
                release_manifest=Path(release["manifest_path"]),
                release_sha256_file=Path(release["sha256_path"]),
                release_signature=Path(signature["signature_path"]),
                release_public_key=Path(signature["public_key_path"]),
                handoff_dossier=Path(dossier["zip_path"]),
                support_bundle=support_bundle,
            )

            self.assertEqual(launch["status"], "ready")
            self.assertEqual(launch["summary"]["errors"], 0)
            zip_path = Path(launch["zip_path"])
            self.assertTrue(zip_path.exists())
            self.assertEqual(zip_path.stat().st_mode & 0o077, 0)
            with zipfile.ZipFile(zip_path) as archive:
                names = set(archive.namelist())
                self.assertIn("commercial-launch-package.json", names)
                self.assertTrue(any(name.startswith("release/") and name.endswith(".zip") for name in names))
                self.assertTrue(any(name.startswith("dossiers/") and name.endswith(".zip") for name in names))
                self.assertTrue(any(name.startswith("support/") and name.endswith(".zip") for name in names))
                launch_payload = json.loads(archive.read("commercial-launch-package.json"))
                combined_json = "\n".join(archive.read(name).decode("utf-8", errors="ignore") for name in names if name.endswith(".json"))
            self.assertNotIn("payloads", launch_payload["acceptance"])
            self.assertFalse(any("path" in artifact for artifact in launch_payload["artifacts"].values()))
            self.assertNotIn(str(Path(tmp)), combined_json)
            self.assertNotIn("plain-token", combined_json)

            verification = launch_verifier.verify_commercial_launch_package(zip_path)
            self.assertEqual(verification["status"], "verified")
            self.assertEqual(verification["summary"]["errors"], 0)
            checks = {item["id"]: item for item in verification["checks"]}
            self.assertTrue(checks["release_package_reverified"]["passed"])
            self.assertTrue(checks["handoff_dossier_reverified"]["passed"])
            self.assertTrue(checks["support_bundle_reverified"]["passed"])

    def test_verifier_rejects_private_member(self) -> None:
        launch_verifier = load_script("verify_commercial_launch_package")

        with tempfile.TemporaryDirectory() as tmp:
            launch_zip = Path(tmp) / "bad-launch.zip"
            with zipfile.ZipFile(launch_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    "commercial-launch-package.json",
                    json.dumps(
                        {
                            "schema_version": "draftpaper.commercial-launch-package/v1",
                            "status": "ready",
                            "package_sha256": "0" * 64,
                            "target_track": "paid_local_handoff",
                            "artifacts": {},
                            "acceptance": {},
                            "checks": [],
                        }
                    ),
                )
                archive.writestr("operator-token.txt", "plain-token")

            report = launch_verifier.verify_commercial_launch_package(launch_zip)

        self.assertEqual(report["status"], "attention")
        failed = {item["id"]: item for item in report["checks"] if not item["passed"]}
        self.assertIn("private_members_excluded", failed)


if __name__ == "__main__":
    unittest.main()
