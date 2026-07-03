from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_suite_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_run_commercial_acceptance_suite", root / "scripts" / "run_commercial_acceptance_suite.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load run_commercial_acceptance_suite.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_file(path: Path, text: str = "artifact\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class CommercialAcceptanceSuiteTests(unittest.TestCase):
    def test_suite_runs_full_paid_handoff_chain(self) -> None:
        suite = load_suite_module()
        calls: list[str] = []

        def fake_build_release_package(**kwargs):
            calls.append("build_release")
            output_dir = Path(kwargs["output_dir"])
            zip_path = write_file(output_dir / "release.zip")
            manifest_path = write_file(output_dir / "release.manifest.json", "{}\n")
            sha_path = write_file(output_dir / "release.zip.sha256", "a" * 64 + "  release.zip\n")
            sig_path = write_file(output_dir / "release.zip.sig")
            pub_path = write_file(output_dir / "release.public.pem")
            return {
                "status": "packaged",
                "zip_path": str(zip_path),
                "manifest_path": str(manifest_path),
                "sha256_path": str(sha_path),
                "signature": {"signature_path": str(sig_path), "public_key_path": str(pub_path)},
                "summary": {"errors": 0, "warnings": 0},
            }

        def fake_verify_release_package(*_args, **_kwargs):
            calls.append("verify_release")
            return {"status": "verified", "zip_sha256": "a" * 64, "summary": {"errors": 0, "warnings": 0}}

        def fake_run_handoff_acceptance(**kwargs):
            calls.append("acceptance")
            Path(kwargs["support_bundle_output"]).parent.mkdir(parents=True, exist_ok=True)
            Path(kwargs["support_bundle_output"]).write_bytes(b"support")
            return {"status": "passed", "target_track": kwargs["target_track"], "commercial_grade": "paid_local_handoff_ready", "summary": {"errors": 0, "warnings": 0}}

        def fake_build_handoff_dossier(**kwargs):
            calls.append("build_dossier")
            zip_path = write_file(Path(kwargs["output_dir"]) / "handoff-dossier.zip")
            return {"status": "ready", "zip_path": str(zip_path), "dossier_sha256": "b" * 64, "summary": {"errors": 0, "warnings": 0}}

        def fake_verify_handoff_dossier(*_args, **_kwargs):
            calls.append("verify_dossier")
            return {"status": "verified", "summary": {"errors": 0, "warnings": 0}}

        def fake_build_launch(**kwargs):
            calls.append("build_launch")
            zip_path = write_file(Path(kwargs["output_dir"]) / "commercial-launch-package.zip")
            return {"status": "ready", "zip_path": str(zip_path), "package_sha256": "c" * 64, "summary": {"errors": 0, "warnings": 0}}

        def fake_verify_launch(*_args, **_kwargs):
            calls.append("verify_launch")
            return {"status": "verified", "zip_sha256": "d" * 64, "package_sha256": "c" * 64, "summary": {"errors": 0, "warnings": 0}}

        def fake_build_ops(**kwargs):
            calls.append("build_ops")
            output = Path(kwargs["output"])
            markdown = Path(kwargs["markdown_output"])
            write_file(output, json.dumps({"status": "ready"}) + "\n")
            write_file(markdown, "# ops\n")
            return {"status": "ready", "report_sha256": "e" * 64, "summary": {"errors": 0, "warnings": 0}}

        def fake_verify_ops(*_args, **_kwargs):
            calls.append("verify_ops")
            return {"status": "verified", "summary": {"errors": 0, "warnings": 0}}

        suite.build_release_package = fake_build_release_package
        suite.verify_release_package = fake_verify_release_package
        suite.run_handoff_acceptance = fake_run_handoff_acceptance
        suite.build_handoff_dossier = fake_build_handoff_dossier
        suite.verify_handoff_dossier = fake_verify_handoff_dossier
        suite.build_commercial_launch_package = fake_build_launch
        suite.verify_commercial_launch_package = fake_verify_launch
        suite.build_commercial_operations_report = fake_build_ops
        suite.verify_commercial_operations_report = fake_verify_ops

        with tempfile.TemporaryDirectory() as tmp:
            report = suite.run_commercial_acceptance_suite(
                output_dir=Path(tmp) / "suite",
                customer_id="CUST-1",
                customer_name="Customer One",
                signing_key=Path(tmp) / "signing.pem",
                force=True,
            )

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["summary"]["passed"], 9)
        self.assertEqual(calls, ["build_release", "verify_release", "acceptance", "build_dossier", "verify_dossier", "build_launch", "verify_launch", "build_ops", "verify_ops"])
        self.assertTrue(report["suite_sha256"])
        self.assertEqual(report["customer"]["id"], "CUST-1")

    def test_suite_attention_when_a_required_step_fails(self) -> None:
        suite = load_suite_module()

        def fake_build_release_package(**kwargs):
            output_dir = Path(kwargs["output_dir"])
            return {
                "status": "packaged",
                "zip_path": str(write_file(output_dir / "release.zip")),
                "manifest_path": str(write_file(output_dir / "release.manifest.json")),
                "sha256_path": str(write_file(output_dir / "release.zip.sha256")),
                "signature": {"signature_path": str(write_file(output_dir / "release.zip.sig")), "public_key_path": str(write_file(output_dir / "release.public.pem"))},
            }

        suite.build_release_package = fake_build_release_package
        suite.verify_release_package = lambda *_args, **_kwargs: {"status": "attention", "summary": {"errors": 1, "warnings": 0}}
        suite.run_handoff_acceptance = lambda **kwargs: {"status": "passed", "target_track": kwargs["target_track"], "summary": {"errors": 0, "warnings": 0}}
        suite.build_handoff_dossier = lambda **kwargs: {"status": "ready", "zip_path": str(write_file(Path(kwargs["output_dir"]) / "handoff-dossier.zip"))}
        suite.verify_handoff_dossier = lambda *_args, **_kwargs: {"status": "verified"}
        suite.build_commercial_launch_package = lambda **kwargs: {"status": "ready", "zip_path": str(write_file(Path(kwargs["output_dir"]) / "commercial-launch-package.zip"))}
        suite.verify_commercial_launch_package = lambda *_args, **_kwargs: {"status": "verified"}
        suite.build_commercial_operations_report = lambda **kwargs: {"status": "ready"}
        suite.verify_commercial_operations_report = lambda *_args, **_kwargs: {"status": "verified"}

        with tempfile.TemporaryDirectory() as tmp:
            report = suite.run_commercial_acceptance_suite(
                output_dir=Path(tmp) / "suite",
                customer_id="CUST-1",
                customer_name="Customer One",
                signing_key=Path(tmp) / "signing.pem",
                force=True,
            )

        failed = {item["id"] for item in report["steps"] if not item["passed"]}
        self.assertEqual(report["status"], "attention")
        self.assertIn("release_verified", failed)

    def test_hosted_suite_requires_hosted_readiness_dossier(self) -> None:
        suite = load_suite_module()

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                suite.run_commercial_acceptance_suite(
                    output_dir=Path(tmp) / "suite",
                    target_track="hosted_saas",
                    customer_id="CUST-1",
                    customer_name="Customer One",
                    signing_key=Path(tmp) / "signing.pem",
                )


if __name__ == "__main__":
    unittest.main()
