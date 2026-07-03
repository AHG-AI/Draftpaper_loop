from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


def load_package_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_package_release", root / "scripts" / "package_release.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load package_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_installer_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_install_verified_release", root / "scripts" / "install_verified_release.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load install_verified_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def minimal_release_root(root: Path, package_release) -> None:
    root.mkdir(parents=True, exist_ok=True)
    write_file(root / "pyproject.toml", '[project]\nversion = "1.2.3"\n')
    for relative in package_release.REQUIRED_COMMERCIAL_FILES:
        write_file(root / relative, f"{relative}\n")


class InstallVerifiedReleaseTests(unittest.TestCase):
    def test_required_install_files_follow_release_manifest(self) -> None:
        installer = load_installer_module()

        with tempfile.TemporaryDirectory() as tmp:
            install_dir = Path(tmp) / "installed"
            install_dir.mkdir()
            write_file(install_dir / "LICENSE", "license\n")
            write_file(install_dir / "COMMERCIAL_LICENSE.md", "commercial\n")
            write_file(install_dir / "COMPLIANCE.md", "compliance\n")
            write_file(install_dir / "SHA256SUMS", "\n")
            write_file(
                install_dir / "release_manifest.json",
                json.dumps({"commercial_required_files": ["LICENSE", "scripts/missing_required.py"]}),
            )

            missing = installer._required_install_files(install_dir)

        self.assertIn("scripts/missing_required.py", missing)
        self.assertIn("service-console.manifest.json", missing)

    def test_install_verified_release_extracts_after_release_verification(self) -> None:
        package_release = load_package_module()
        installer = load_installer_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Draftpaper_loop"
            minimal_release_root(root, package_release)
            release = package_release.build_release_package(
                root=root,
                output_dir=Path(tmp) / "dist",
                version_label="customer-install",
            )
            install_root = Path(tmp) / "install"

            result = installer.install_verified_release(
                release_zip=Path(release["zip_path"]),
                release_manifest=Path(release["manifest_path"]),
                release_sha256_file=Path(release["sha256_path"]),
                install_root=install_root,
            )

            self.assertEqual(result["status"], "installed")
            self.assertEqual(result["summary"]["errors"], 0)
            installed_dir = Path(result["installed_dir"])
            self.assertTrue((installed_dir / "deploy" / "production" / "Dockerfile").exists())
            self.assertTrue((installed_dir / "deploy" / "production" / "docker-compose.example.yml").exists())
            self.assertTrue((installed_dir / "scripts" / "install_verified_release.py").exists())
            self.assertTrue((installed_dir / "scripts" / "run_commercial_acceptance_suite.py").exists())
            self.assertTrue((installed_dir / "scripts" / "collect_hosted_readiness_evidence.py").exists())
            self.assertTrue((installed_dir / "scripts" / "prepare_hosted_readiness.py").exists())
            self.assertTrue((installed_dir / "scripts" / "run_hosted_production_acceptance.py").exists())
            self.assertTrue((installed_dir / "scripts" / "run_sample_workflow_acceptance.py").exists())
            self.assertTrue((installed_dir / "scripts" / "smoke_installed_release.py").exists())
            self.assertTrue((installed_dir / "scripts" / "build_commercial_launch_package.py").exists())
            self.assertTrue((installed_dir / "scripts" / "verify_commercial_launch_package.py").exists())
            self.assertTrue((installed_dir / "scripts" / "verify_commercial_acceptance_suite.py").exists())
            self.assertTrue((installed_dir / "scripts" / "build_commercial_operations_report.py").exists())
            self.assertTrue((installed_dir / "scripts" / "verify_commercial_operations_report.py").exists())
            self.assertTrue((installed_dir / "scripts" / "verify_handoff_dossier.py").exists())
            self.assertTrue((installed_dir / "scripts" / "verify_hosted_evidence_collection.py").exists())
            self.assertTrue((installed_dir / "scripts" / "build_hosted_readiness_dossier.py").exists())
            self.assertTrue((installed_dir / "scripts" / "verify_hosted_readiness_dossier.py").exists())
            self.assertTrue((installed_dir / "scripts" / "verify_production_deployment_artifacts.py").exists())
            manifest = json.loads((install_root / "draftpaper-install-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "installed")
            self.assertEqual((install_root / "draftpaper-install-manifest.json").stat().st_mode & 0o077, 0)

            second = installer.install_verified_release(
                release_zip=Path(release["zip_path"]),
                release_manifest=Path(release["manifest_path"]),
                release_sha256_file=Path(release["sha256_path"]),
                install_root=install_root,
            )
            self.assertEqual(second["status"], "attention")
            failed = {item["id"]: item for item in second["checks"] if not item["passed"]}
            self.assertIn("release_extracted", failed)

            replaced = installer.install_verified_release(
                release_zip=Path(release["zip_path"]),
                release_manifest=Path(release["manifest_path"]),
                release_sha256_file=Path(release["sha256_path"]),
                install_root=install_root,
                force=True,
            )
            self.assertEqual(replaced["status"], "installed")

    def test_install_verified_release_can_run_installed_smoke_for_real_package(self) -> None:
        package_release = load_package_module()
        installer = load_installer_module()
        repo_root = Path(__file__).resolve().parents[1]

        with tempfile.TemporaryDirectory() as tmp:
            release = package_release.build_release_package(
                root=repo_root,
                output_dir=Path(tmp) / "dist",
                version_label="installed-smoke",
            )
            install_root = Path(tmp) / "install"

            result = installer.install_verified_release(
                release_zip=Path(release["zip_path"]),
                release_manifest=Path(release["manifest_path"]),
                release_sha256_file=Path(release["sha256_path"]),
                install_root=install_root,
                run_smoke=True,
            )

            self.assertEqual(result["status"], "installed")
            self.assertEqual(result["summary"]["errors"], 0)
            self.assertTrue(result["installed_smoke_output"])
            smoke_output = Path(result["installed_smoke_output"])
            self.assertTrue(smoke_output.exists())
            self.assertEqual(smoke_output.stat().st_mode & 0o077, 0)
            self.assertEqual(result["installed_smoke"]["status"], "passed")
            self.assertEqual(result["installed_smoke"]["summary"]["errors"], 0)

    def test_install_verified_release_blocks_when_required_dossier_missing(self) -> None:
        package_release = load_package_module()
        installer = load_installer_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Draftpaper_loop"
            minimal_release_root(root, package_release)
            release = package_release.build_release_package(
                root=root,
                output_dir=Path(tmp) / "dist",
                version_label="customer-install",
            )

            result = installer.install_verified_release(
                release_zip=Path(release["zip_path"]),
                release_manifest=Path(release["manifest_path"]),
                release_sha256_file=Path(release["sha256_path"]),
                install_root=Path(tmp) / "install",
                require_dossier=True,
            )

            self.assertEqual(result["status"], "attention")
            self.assertFalse(result["installed_dir"])
            failed = {item["id"]: item for item in result["checks"] if not item["passed"]}
            self.assertIn("handoff_dossier_verified", failed)

    def test_install_verified_release_rejects_unsafe_zip_members(self) -> None:
        installer = load_installer_module()

        with tempfile.TemporaryDirectory() as tmp:
            release_zip = Path(tmp) / "unsafe.zip"
            with zipfile.ZipFile(release_zip, "w") as archive:
                archive.writestr("../escape.txt", "bad")
                archive.writestr("package/LICENSE", "ok")

            installer.verify_release_package = lambda *_args, **_kwargs: {"status": "verified"}
            result = installer.install_verified_release(
                release_zip=release_zip,
                install_root=Path(tmp) / "install",
            )

            self.assertEqual(result["status"], "attention")
            failed = {item["id"]: item for item in result["checks"] if not item["passed"]}
            self.assertIn("release_extracted", failed)


if __name__ == "__main__":
    unittest.main()
