from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


def load_release_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_package_release", root / "scripts" / "package_release.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load package_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_verifier_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_verify_release_package", root / "scripts" / "verify_release_package.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load verify_release_package.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class ReleasePackagingTests(unittest.TestCase):
    def test_release_package_excludes_runtime_state_and_verifies_checksums(self) -> None:
        package_release = load_release_module()
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Draftpaper_loop"
            root.mkdir()
            for relative in package_release.REQUIRED_COMMERCIAL_FILES:
                write_file(root / relative, f"{relative}\n")
            write_file(root / "pyproject.toml", '[project]\nversion = "1.2.3"\n')
            write_file(root / "draftpaper_cli" / "__init__.py", "__version__ = '1.2.3'\n")
            write_file(root / "projects" / "private-project" / "project.json", "{}\n")
            write_file(root / "var" / "serviceconsole" / "audit.jsonl", "{}\n")
            write_file(root / ".venv" / "bin" / "python", "ignored\n")
            write_file(root / ".env.local", "SECRET=ignored\n")
            write_file(root / ".env.production", "SECRET=ignored\n")
            write_file(root / "private.pem", "ignored\n")
            write_file(root / "client.key", "ignored\n")
            write_file(root / "console-users.json", "ignored\n")
            write_file(root / "active-handoff.env", "ignored\n")
            write_file(root / "billing-rates.json", "ignored\n")
            write_file(root / "claim-confirmation.json", "ignored\n")
            write_file(root / "claim-confirmation-verification.json", "ignored\n")
            write_file(root / "commercial-approval.json", "ignored\n")
            write_file(root / "commercial-approval-verification.json", "ignored\n")
            write_file(root / "commercial-license-grant.json", "ignored\n")
            write_file(root / "commercial-license-grant.json.sig", "ignored\n")
            write_file(root / "hosted-acceptance.json", "ignored\n")
            write_file(root / "hosted-readiness.json", "ignored\n")
            write_file(root / "license-grant.json", "ignored\n")
            write_file(root / "release-trust.json", "ignored\n")
            write_file(root / "release-trust-verification.json", "ignored\n")
            write_file(root / "security-review.json", "ignored\n")
            write_file(root / "security-review-verification.json", "ignored\n")
            write_file(root / "draftpaper-support-bundle.zip", "ignored\n")
            write_file(root / "old-release.zip", "ignored\n")
            write_file(root / "draftpaper_cli" / "__pycache__" / "module.cpython-311.pyc", "ignored\n")

            result = package_release.build_release_package(
                root=root,
                output_dir=root / "dist",
                version_label="test release",
            )

            self.assertEqual(result["status"], "packaged")
            self.assertEqual(result["missing_required_files"], [])

            zip_path = Path(result["zip_path"])
            manifest_path = Path(result["manifest_path"])
            zip_sha_path = Path(result["sha256_path"])
            self.assertTrue(zip_path.exists())
            self.assertTrue(manifest_path.exists())
            self.assertTrue(zip_sha_path.exists())

            package_prefix = result["package"]
            with zipfile.ZipFile(zip_path) as archive:
                names = set(archive.namelist())
                self.assertIn(f"{package_prefix}/release_manifest.json", names)
                self.assertIn(f"{package_prefix}/SHA256SUMS", names)
                self.assertIn(f"{package_prefix}/draftpaper_cli/__init__.py", names)
                self.assertNotIn(f"{package_prefix}/projects/private-project/project.json", names)
                self.assertNotIn(f"{package_prefix}/var/serviceconsole/audit.jsonl", names)
                self.assertNotIn(f"{package_prefix}/.venv/bin/python", names)
                self.assertNotIn(f"{package_prefix}/.env.local", names)
                self.assertNotIn(f"{package_prefix}/.env.production", names)
                self.assertNotIn(f"{package_prefix}/private.pem", names)
                self.assertNotIn(f"{package_prefix}/client.key", names)
                self.assertNotIn(f"{package_prefix}/console-users.json", names)
                self.assertNotIn(f"{package_prefix}/active-handoff.env", names)
                self.assertNotIn(f"{package_prefix}/billing-rates.json", names)
                self.assertNotIn(f"{package_prefix}/claim-confirmation.json", names)
                self.assertNotIn(f"{package_prefix}/claim-confirmation-verification.json", names)
                self.assertNotIn(f"{package_prefix}/commercial-approval.json", names)
                self.assertNotIn(f"{package_prefix}/commercial-approval-verification.json", names)
                self.assertNotIn(f"{package_prefix}/commercial-license-grant.json", names)
                self.assertNotIn(f"{package_prefix}/commercial-license-grant.json.sig", names)
                self.assertNotIn(f"{package_prefix}/hosted-acceptance.json", names)
                self.assertNotIn(f"{package_prefix}/hosted-readiness.json", names)
                self.assertNotIn(f"{package_prefix}/license-grant.json", names)
                self.assertNotIn(f"{package_prefix}/release-trust.json", names)
                self.assertNotIn(f"{package_prefix}/release-trust-verification.json", names)
                self.assertNotIn(f"{package_prefix}/security-review.json", names)
                self.assertNotIn(f"{package_prefix}/security-review-verification.json", names)
                self.assertNotIn(f"{package_prefix}/draftpaper-support-bundle.zip", names)
                self.assertNotIn(f"{package_prefix}/old-release.zip", names)
                self.assertNotIn(f"{package_prefix}/draftpaper_cli/__pycache__/module.cpython-311.pyc", names)

                release_manifest = json.loads(archive.read(f"{package_prefix}/release_manifest.json"))
                self.assertEqual(release_manifest["project_version"], "1.2.3")
                self.assertIn(".dockerignore", release_manifest["commercial_required_files"])
                self.assertIn("deploy/production/Dockerfile", release_manifest["commercial_required_files"])
                self.assertIn("deploy/production/docker-compose.example.yml", release_manifest["commercial_required_files"])
                self.assertIn("deploy/production/draftpaper-loop.env.example", release_manifest["commercial_required_files"])
                self.assertIn("deploy/production/draftpaper-loop.service", release_manifest["commercial_required_files"])
                self.assertIn("scripts/build_commercial_launch_package.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/build_commercial_operations_report.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/build_handoff_dossier.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/build_hosted_readiness_dossier.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/collect_hosted_readiness_evidence.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/install_verified_release.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/package_release.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/prepare_commercial_approval.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/prepare_claim_confirmation.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/prepare_release_trust.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/prepare_security_review.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/prepare_hosted_readiness.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/run_commercial_acceptance_suite.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/run_hosted_production_acceptance.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/run_sample_workflow_acceptance.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/smoke_installed_release.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/validate_hosted_readiness.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_claim_confirmation.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_commercial_approval.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_commercial_launch_package.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_commercial_acceptance_suite.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_commercial_operations_report.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_handoff_dossier.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_hosted_evidence_collection.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_hosted_readiness_dossier.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_production_deployment_artifacts.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_release_package.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_release_trust.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_security_review.py", release_manifest["commercial_required_files"])
                self.assertIn("scripts/verify_support_bundle.py", release_manifest["commercial_required_files"])

                sums_text = archive.read(f"{package_prefix}/SHA256SUMS").decode("utf-8")
                for line in sums_text.splitlines():
                    expected_hash, relative = line.split("  ", 1)
                    actual = hashlib.sha256(archive.read(f"{package_prefix}/{relative}")).hexdigest()
                    self.assertEqual(actual, expected_hash)

            external_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(external_manifest["zip_sha256"], package_release.sha256_file(zip_path))
            self.assertEqual(zip_sha_path.read_text(encoding="utf-8").split("  ", 1)[0], external_manifest["zip_sha256"])

            verification = verifier.verify_release_package(zip_path, manifest_path=manifest_path, sha256_path=zip_sha_path)
            self.assertEqual(verification["status"], "verified")
            verification_checks = {item["id"]: item for item in verification["checks"]}
            self.assertTrue(verification_checks["private_path_exclusions"]["passed"])
            self.assertTrue(verification_checks["release_manifest_file_hashes"]["passed"])

            bad_sha_path = root / "dist" / "bad.zip.sha256"
            bad_sha_path.write_text(f"{'0' * 64}  {zip_path.name}\n", encoding="utf-8")
            bad_sha = verifier.verify_release_package(zip_path, manifest_path=manifest_path, sha256_path=bad_sha_path)
            self.assertEqual(bad_sha["status"], "attention")
            bad_checks = {item["id"]: item for item in bad_sha["checks"]}
            self.assertFalse(bad_checks["external_sha256_file"]["passed"])

            with zipfile.ZipFile(zip_path, "a") as archive:
                archive.writestr(f"{package_prefix}/.env.production", "SECRET=bad\n")
            private_file = verifier.verify_release_package(zip_path)
            self.assertEqual(private_file["status"], "attention")
            private_checks = {item["id"]: item for item in private_file["checks"]}
            self.assertFalse(private_checks["private_path_exclusions"]["passed"])
            self.assertFalse(private_checks["manifest_covers_entries"]["passed"])

    def test_release_package_reports_missing_required_files(self) -> None:
        package_release = load_release_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Draftpaper_loop"
            root.mkdir()
            write_file(root / "pyproject.toml", '[project]\nversion = "1.2.3"\n')

            result = package_release.build_release_package(
                root=root,
                output_dir=root / "dist",
                version_label="missing-required",
            )

            self.assertIn("LICENSE", result["missing_required_files"])

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required for release signing")
    def test_release_package_can_be_signed_and_verified(self) -> None:
        package_release = load_release_module()
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Draftpaper_loop"
            root.mkdir()
            for relative in package_release.REQUIRED_COMMERCIAL_FILES:
                write_file(root / relative, f"{relative}\n")
            write_file(root / "pyproject.toml", '[project]\nversion = "1.2.3"\n')
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

            result = package_release.build_release_package(
                root=root,
                output_dir=root / "dist",
                version_label="signed-release",
                signing_key=private_key,
            )

            signature = result["signature"]
            signature_path = Path(signature["signature_path"])
            public_key_path = Path(signature["public_key_path"])
            self.assertTrue(signature_path.exists())
            self.assertTrue(public_key_path.exists())
            self.assertEqual(signature["signature_algorithm"], "openssl-dgst-sha256")

            verified = verifier.verify_release_package(
                Path(result["zip_path"]),
                manifest_path=Path(result["manifest_path"]),
                sha256_path=Path(result["sha256_path"]),
                require_signature=True,
            )
            self.assertEqual(verified["status"], "verified")
            checks = {item["id"]: item for item in verified["checks"]}
            self.assertTrue(checks["signature_verified"]["passed"])

            signature_path.write_bytes(b"corrupt")
            tampered = verifier.verify_release_package(
                Path(result["zip_path"]),
                manifest_path=Path(result["manifest_path"]),
                sha256_path=Path(result["sha256_path"]),
                require_signature=True,
            )
            self.assertEqual(tampered["status"], "attention")
            tampered_checks = {item["id"]: item for item in tampered["checks"]}
            self.assertFalse(tampered_checks["signature_verified"]["passed"])


if __name__ == "__main__":
    unittest.main()
