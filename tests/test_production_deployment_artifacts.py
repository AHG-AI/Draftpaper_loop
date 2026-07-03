from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


def load_verifier_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_verify_production_deployment_artifacts", root / "scripts" / "verify_production_deployment_artifacts.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load verify_production_deployment_artifacts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_deployment_fixture(target: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    (target / "deploy" / "production").mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / ".dockerignore", target / ".dockerignore")
    for name in ["Dockerfile", "docker-compose.example.yml", "draftpaper-loop.env.example", "draftpaper-loop.service", "README.md"]:
        shutil.copy2(root / "deploy" / "production" / name, target / "deploy" / "production" / name)


class ProductionDeploymentArtifactTests(unittest.TestCase):
    def test_verifier_accepts_current_deployment_artifacts(self) -> None:
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_deployment_fixture(root)
            report = verifier.verify_production_deployment_artifacts(root=root)

        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["summary"]["errors"], 0)
        check_ids = {item["id"] for item in report["checks"]}
        self.assertIn("dockerfile_non_root_user", check_ids)
        self.assertIn("compose_no_new_privileges", check_ids)
        self.assertIn("systemd_hardening", check_ids)

    def test_verifier_flags_missing_private_exclusions(self) -> None:
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_deployment_fixture(root)
            (root / ".dockerignore").write_text("projects\n", encoding="utf-8")
            report = verifier.verify_production_deployment_artifacts(root=root)

        failed = {item["id"] for item in report["checks"] if not item["passed"]}
        self.assertEqual(report["status"], "attention")
        self.assertIn("dockerignore_private_exclusions", failed)

    def test_verifier_flags_dockerfile_without_non_root_user(self) -> None:
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_deployment_fixture(root)
            dockerfile = root / "deploy" / "production" / "Dockerfile"
            dockerfile.write_text(dockerfile.read_text(encoding="utf-8").replace("USER draftpaper", "USER root"), encoding="utf-8")
            report = verifier.verify_production_deployment_artifacts(root=root)

        failed = {item["id"] for item in report["checks"] if not item["passed"]}
        self.assertEqual(report["status"], "attention")
        self.assertIn("dockerfile_non_root_user", failed)


if __name__ == "__main__":
    unittest.main()
