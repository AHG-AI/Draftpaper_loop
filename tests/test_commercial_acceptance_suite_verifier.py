from __future__ import annotations

import hashlib
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


def load_verifier_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_verify_commercial_acceptance_suite", root / "scripts" / "verify_commercial_acceptance_suite.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load verify_commercial_acceptance_suite.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_artifact(path: Path, text: str) -> dict[str, object]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    data = path.read_bytes()
    return {"path": str(path), "exists": True, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def suite_payload(root: Path) -> dict[str, object]:
    suite_mod = load_suite_module()
    artifacts = {
        "release_zip": write_artifact(root / "release" / "release.zip", "release\n"),
        "release_manifest": write_artifact(root / "release" / "release.manifest.json", "{}\n"),
        "release_sha256_file": write_artifact(root / "release" / "release.zip.sha256", "a" * 64 + "  release.zip\n"),
        "release_signature": write_artifact(root / "release" / "release.zip.sig", "sig\n"),
        "release_public_key": write_artifact(root / "release" / "release.public.pem", "pub\n"),
        "handoff_acceptance": write_artifact(root / "acceptance" / "handoff-acceptance.json", "{}\n"),
        "support_bundle": write_artifact(root / "acceptance" / "handoff-support-bundle.zip", "support\n"),
        "handoff_dossier": write_artifact(root / "customer-dossier" / "handoff-dossier.zip", "dossier\n"),
        "commercial_launch_package": write_artifact(root / "launch-package" / "commercial-launch-package.zip", "launch\n"),
        "commercial_operations_report": write_artifact(root / "operations" / "commercial-operations.json", "{}\n"),
        "commercial_operations_markdown": write_artifact(root / "operations" / "commercial-operations.md", "# ops\n"),
    }
    steps = [
        ("release_packaged", "packaged"),
        ("release_verified", "verified"),
        ("handoff_acceptance", "passed"),
        ("handoff_dossier_built", "ready"),
        ("handoff_dossier_verified", "verified"),
        ("commercial_launch_package_built", "ready"),
        ("commercial_launch_package_verified", "verified"),
        ("commercial_operations_report_built", "ready"),
        ("commercial_operations_report_verified", "verified"),
    ]
    payload = {
        "schema_version": "draftpaper.commercial-acceptance-suite/v1",
        "status": "passed",
        "generated_at": "2026-07-03T00:00:00Z",
        "base_url": "http://127.0.0.1:4888",
        "target_track": "paid_local_handoff",
        "customer": {"id": "CUST-1", "name": "Customer One"},
        "output_dir": str(root),
        "steps": [
            {"id": step_id, "passed": True, "expected_status": status, "status": status, "artifact": {}, "summary": {}}
            for step_id, status in steps
        ],
        "artifacts": artifacts,
        "reports": {},
        "summary": {"steps": 9, "passed": 9, "errors": 0, "warnings": 0},
        "notes": ["test suite"],
    }
    payload["suite_sha256"] = suite_mod._digest(payload)
    return payload


class CommercialAcceptanceSuiteVerifierTests(unittest.TestCase):
    def test_verifier_accepts_valid_suite_without_artifact_reverify(self) -> None:
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "commercial-acceptance-suite.json"
            payload = suite_payload(Path(tmp))
            report_path.write_text(json.dumps(payload), encoding="utf-8")

            result = verifier.verify_commercial_acceptance_suite(report_path, reverify_artifacts=False)

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["summary"]["errors"], 0)
        self.assertTrue({item["id"] for item in result["checks"]} >= {"suite_sha256_matches", "embedded_steps_passed", "release_zip_artifact_hash_matches"})

    def test_verifier_flags_tampered_suite_digest(self) -> None:
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "commercial-acceptance-suite.json"
            payload = suite_payload(Path(tmp))
            payload["target_track"] = "hosted_saas"
            report_path.write_text(json.dumps(payload), encoding="utf-8")

            result = verifier.verify_commercial_acceptance_suite(report_path, reverify_artifacts=False)

        failed = {item["id"] for item in result["checks"] if not item["passed"]}
        self.assertEqual(result["status"], "attention")
        self.assertIn("suite_sha256_matches", failed)

    def test_verifier_flags_artifact_hash_mismatch(self) -> None:
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "commercial-acceptance-suite.json"
            payload = suite_payload(root)
            Path(payload["artifacts"]["release_zip"]["path"]).write_text("tampered\n", encoding="utf-8")  # type: ignore[index]
            report_path.write_text(json.dumps(payload), encoding="utf-8")

            result = verifier.verify_commercial_acceptance_suite(report_path, reverify_artifacts=False)

        failed = {item["id"] for item in result["checks"] if not item["passed"]}
        self.assertEqual(result["status"], "attention")
        self.assertIn("release_zip_artifact_hash_matches", failed)

    def test_verifier_reverifies_underlying_artifacts_when_enabled(self) -> None:
        verifier = load_verifier_module()
        calls: list[str] = []
        verifier.verify_release_package = lambda *_args, **_kwargs: calls.append("release") or {"status": "verified", "summary": {"errors": 0}}
        verifier.verify_handoff_dossier = lambda *_args, **_kwargs: calls.append("dossier") or {"status": "verified", "summary": {"errors": 0}}
        verifier.verify_support_bundle = lambda *_args, **_kwargs: calls.append("support") or {"status": "verified", "summary": {"errors": 0}}
        verifier.verify_commercial_launch_package = lambda *_args, **_kwargs: calls.append("launch") or {"status": "verified", "summary": {"errors": 0}}
        verifier.verify_commercial_operations_report = lambda *_args, **_kwargs: calls.append("operations") or {"status": "verified", "summary": {"errors": 0}}

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "commercial-acceptance-suite.json"
            report_path.write_text(json.dumps(suite_payload(Path(tmp))), encoding="utf-8")

            result = verifier.verify_commercial_acceptance_suite(report_path)

        self.assertEqual(result["status"], "verified")
        self.assertEqual(calls, ["release", "dossier", "support", "launch", "operations"])


if __name__ == "__main__":
    unittest.main()
