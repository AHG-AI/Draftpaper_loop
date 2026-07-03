from __future__ import annotations

import io
import hashlib
import importlib.util
import json
import tempfile
import threading
import unittest
import zipfile
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def load_acceptance_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_run_handoff_acceptance", root / "scripts" / "run_handoff_acceptance.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load run_handoff_acceptance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


class FakeConsole:
    def __init__(self, payloads: dict[str, object]) -> None:
        self.payloads = payloads
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __enter__(self) -> "FakeConsole":
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _handler(self):
        payloads = self.payloads

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/api/support-bundle":
                    data = fake_support_bundle_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                payload = payloads.get(self.path)
                if payload is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                data = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return Handler


def ready_payloads() -> dict[str, object]:
    paid_track = {"id": "paid_local_handoff", "status": "ready", "summary": {"total": 8, "passed": 8, "errors": 0, "warnings": 0}, "gates": []}
    return {
        "/health": {"status": "ok"},
        "/api/commercial-readiness": {"status": "assessed", "commercial_grade": "paid_local_handoff_ready"},
        "/api/handoff-readiness": {"status": "assessed", "commercial_grade": "paid_local_handoff_ready", "tracks": [paid_track], "next_required_actions": []},
        "/api/hosted-readiness": {"status": "not_ready", "summary": {"gates": 5, "passed": 0, "errors": 5}, "gates": []},
        "/api/security-audit": {"status": "passed", "summary": {"errors": 0, "warnings": 0}, "checks": []},
        "/api/license": {"status": "valid", "signature": {"configured": True, "verified": True, "public_key_pin_configured": True, "public_key_pin_matched": True}, "checks": []},
        "/api/license-entitlements": {"status": "passed", "seat_limit": 3, "subjects_count": 1, "checks": []},
        "/api/access-policy": {"status": "reported", "auth_required": True},
        "/api/quota": {"status": "reported"},
        "/api/billing": {"status": "reported", "billing_config_status": "configured"},
        "/api/backups/verify": {"status": "verified", "summary": {"total": 1, "verified": 1, "attention": 0}},
        "/api/backups/rehearsals": {"status": "passed", "summary": {"total_backups": 1, "passed": 1}},
    }


def hosted_ready_payloads() -> dict[str, object]:
    payloads = ready_payloads()
    hosted_track = {"id": "hosted_saas", "status": "ready", "summary": {"total": 5, "passed": 5, "errors": 0, "warnings": 0}, "gates": []}
    payloads["/api/commercial-readiness"] = {"status": "assessed", "commercial_grade": "hosted_saas_ready"}
    payloads["/api/handoff-readiness"] = {"status": "assessed", "commercial_grade": "hosted_saas_ready", "tracks": [hosted_track], "next_required_actions": []}
    payloads["/api/hosted-readiness"] = {
        "status": "ready",
        "summary": {"gates": 5, "passed": 5, "errors": 0, "warnings": 0},
        "gates": [
            {"id": "hosted_enterprise_auth", "passed": True},
            {"id": "hosted_payment_collection", "passed": True},
            {"id": "managed_storage_dr", "passed": True},
            {"id": "hosted_worker_isolation", "passed": True},
            {"id": "deployment_hardening", "passed": True},
        ],
    }
    return payloads


class HandoffAcceptanceTests(unittest.TestCase):
    def test_handoff_acceptance_passes_with_ready_console_and_verified_release(self) -> None:
        acceptance = load_acceptance_module()

        with tempfile.TemporaryDirectory() as tmp:
            release_zip = Path(tmp) / "release.zip"
            release_manifest = Path(tmp) / "release.manifest.json"
            release_sha = Path(tmp) / "release.zip.sha256"
            release_zip.write_bytes(b"zip")
            release_manifest.write_text("{}\n", encoding="utf-8")
            release_sha.write_text("0" * 64 + "  release.zip\n", encoding="utf-8")

            def fake_verify(*_args, **_kwargs):
                return {
                    "status": "verified",
                    "zip_sha256": "a" * 64,
                    "signature_path": "/private/release.zip.sig",
                    "public_key_path": "/private/release.public.pem",
                    "summary": {"errors": 0, "warnings": 0},
                    "checks": [{"id": "signature_verified", "passed": True}],
                }

            acceptance.verify_release_package = fake_verify
            with FakeConsole(ready_payloads()) as console:
                support_output = Path(tmp) / "support-bundle.zip"
                report = acceptance.run_handoff_acceptance(
                    base_url=console.url,
                    target_track="paid_local_handoff",
                    release_zip=release_zip,
                    release_manifest=release_manifest,
                    release_sha256_file=release_sha,
                    require_release=True,
                    download_support_bundle=True,
                    support_bundle_output=support_output,
                )
            self.assertTrue(support_output.exists())
            self.assertEqual(support_output.stat().st_mode & 0o077, 0)
            self.assertEqual(hashlib.sha256(support_output.read_bytes()).hexdigest(), report["support_bundle"]["sha256"])

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["commercial_grade"], "paid_local_handoff_ready")
        self.assertEqual(report["summary"]["errors"], 0)
        self.assertEqual(report["support_bundle"]["bytes"], len(fake_support_bundle_bytes()))
        self.assertEqual(report["support_bundle_verification"]["status"], "verified")
        summary = report["evidence_summary"]
        self.assertEqual(summary["target_track"]["status"], "ready")
        self.assertTrue(summary["license"]["signature_verified"])
        self.assertTrue(summary["license"]["public_key_pin_matched"])
        self.assertEqual(summary["security_audit"]["errors"], 0)
        self.assertEqual(summary["release_package"]["status"], "verified")
        self.assertTrue(summary["release_package"]["signature_verified"])
        self.assertEqual(summary["support_bundle"]["bytes"], len(fake_support_bundle_bytes()))
        self.assertEqual(summary["support_bundle"]["verification_status"], "verified")
        self.assertRegex(report["report_sha256"], r"^[0-9a-f]{64}$")

    def test_handoff_acceptance_reports_attention_for_blocked_paid_handoff(self) -> None:
        acceptance = load_acceptance_module()
        payloads = ready_payloads()
        payloads["/api/handoff-readiness"] = {
            "status": "assessed",
            "commercial_grade": "local_operator_pilot_ready",
            "tracks": [{"id": "paid_local_handoff", "status": "blocked", "summary": {"errors": 2}}],
            "next_required_actions": ["Set DRAFTPAPER_LICENSE_FILE."],
        }
        payloads["/api/license"] = {"status": "unconfigured"}

        with FakeConsole(payloads) as console:
            report = acceptance.run_handoff_acceptance(base_url=console.url, target_track="paid_local_handoff", require_release=True)

        self.assertEqual(report["status"], "attention")
        failed = {item["id"]: item for item in report["checks"] if not item["passed"]}
        self.assertIn("target_track_ready", failed)
        self.assertIn("license_valid", failed)
        self.assertIn("release_package_verified", failed)
        self.assertIn("Set DRAFTPAPER_LICENSE_FILE.", report["next_required_actions"])
        self.assertEqual(report["evidence_summary"]["target_track"]["status"], "blocked")
        self.assertEqual(report["evidence_summary"]["license"]["status"], "unconfigured")

    def test_handoff_acceptance_output_file_is_owner_only(self) -> None:
        acceptance = load_acceptance_module()

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "private" / "handoff-acceptance.json"
            with FakeConsole(ready_payloads()) as console:
                with redirect_stdout(io.StringIO()):
                    code = acceptance.main(
                        [
                            "--base-url",
                            console.url,
                            "--target-track",
                            "paid_local_handoff",
                            "--download-support-bundle",
                            "--output",
                            str(output_path),
                        ]
                    )

            self.assertEqual(code, 0)
            self.assertTrue(output_path.exists())
            self.assertEqual(output_path.stat().st_mode & 0o077, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "passed")

    def test_hosted_saas_acceptance_requires_verified_hosted_readiness(self) -> None:
        acceptance = load_acceptance_module()

        with tempfile.TemporaryDirectory() as tmp:
            dossier_zip = Path(tmp) / "hosted-readiness-dossier.zip"
            dossier_zip.write_bytes(b"hosted dossier")

            def fake_verify_hosted_dossier(*_args, **_kwargs):
                return {
                    "status": "verified",
                    "zip_sha256": "b" * 64,
                    "dossier_sha256": "c" * 64,
                    "summary": {"checks": 20, "errors": 0, "warnings": 0},
                    "checks": [],
                }

            acceptance.verify_hosted_readiness_dossier = fake_verify_hosted_dossier
            with FakeConsole(hosted_ready_payloads()) as console:
                report = acceptance.run_handoff_acceptance(
                    base_url=console.url,
                    target_track="hosted_saas",
                    hosted_readiness_dossier=dossier_zip,
                )

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["commercial_grade"], "hosted_saas_ready")
        self.assertEqual(report["hosted_readiness"]["status"], "ready")
        self.assertEqual(report["hosted_dossier_verification"]["status"], "verified")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertTrue(checks["hosted_readiness_ready"]["passed"])
        self.assertTrue(checks["hosted_readiness_gates_verified"]["passed"])
        self.assertTrue(checks["hosted_readiness_dossier_verified"]["passed"])
        self.assertEqual(report["evidence_summary"]["hosted_readiness"]["status"], "ready")
        self.assertEqual(report["evidence_summary"]["hosted_readiness"]["passed_gates"], 5)
        self.assertEqual(report["evidence_summary"]["hosted_readiness_dossier"]["status"], "verified")

    def test_hosted_saas_acceptance_fails_without_hosted_dossier(self) -> None:
        acceptance = load_acceptance_module()

        with FakeConsole(hosted_ready_payloads()) as console:
            report = acceptance.run_handoff_acceptance(base_url=console.url, target_track="hosted_saas")

        self.assertEqual(report["status"], "attention")
        failed = {item["id"]: item for item in report["checks"] if not item["passed"]}
        self.assertIn("hosted_readiness_dossier_verified", failed)
        self.assertEqual(report["evidence_summary"]["hosted_readiness"]["status"], "ready")
        self.assertEqual(report["evidence_summary"]["hosted_readiness_dossier"]["status"], "")

    def test_hosted_saas_acceptance_fails_when_hosted_readiness_is_not_ready(self) -> None:
        acceptance = load_acceptance_module()
        payloads = ready_payloads()
        payloads["/api/handoff-readiness"] = {
            "status": "assessed",
            "commercial_grade": "paid_local_handoff_ready",
            "tracks": [{"id": "hosted_saas", "status": "not_ready", "summary": {"errors": 5}}],
            "next_required_actions": ["Set DRAFTPAPER_HOSTED_READINESS_FILE."],
        }

        with FakeConsole(payloads) as console:
            report = acceptance.run_handoff_acceptance(base_url=console.url, target_track="hosted_saas")

        self.assertEqual(report["status"], "attention")
        failed = {item["id"]: item for item in report["checks"] if not item["passed"]}
        self.assertIn("target_track_ready", failed)
        self.assertIn("hosted_readiness_ready", failed)
        self.assertIn("hosted_readiness_gates_verified", failed)
        self.assertEqual(report["evidence_summary"]["hosted_readiness"]["status"], "not_ready")


if __name__ == "__main__":
    unittest.main()
