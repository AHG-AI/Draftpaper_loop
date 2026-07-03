from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def load_script(name: str):
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(f"draftpaper_{name}", root / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
                payload = payloads.get(self.path)
                if payload is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        return Handler


def ready_payloads() -> dict[str, object]:
    paid_track = {"id": "paid_local_handoff", "label": "Paid local", "status": "ready", "summary": {"total": 14, "passed": 14, "errors": 0, "warnings": 0}, "gates": []}
    return {
        "/health": {"status": "ok", "auth_required": True, "cli_importable": True},
        "/api/commercial-readiness": {"status": "assessed", "score": 1.0, "commercial_grade": "paid_local_handoff_ready", "remaining_gaps": []},
        "/api/handoff-readiness": {"status": "assessed", "commercial_grade": "paid_local_handoff_ready", "tracks": [paid_track], "next_required_actions": []},
        "/api/hosted-readiness": {"status": "not_ready", "summary": {"gates": 5, "passed": 0, "errors": 5, "warnings": 0}},
        "/api/security-audit": {"status": "passed", "summary": {"total": 35, "errors": 0, "warnings": 0, "passed": 35}},
        "/api/license": {
            "status": "valid",
            "configured": True,
            "grant": {"license_id": "LIC-1", "customer_id": "CUST-1", "customer_name": "Customer", "grant_type": "paid", "expires_at": "2027-01-01T00:00:00Z", "seats": 3},
            "summary": {"total": 21, "errors": 0, "warnings": 0, "passed": 21},
            "signature": {
                "configured": True,
                "verified": True,
                "signature_path": "/Users/nullin/private/license.sig",
                "public_key_path": "/Users/nullin/private/license.public.pem",
                "signature_sha256": "a" * 64,
                "public_key_sha256": "b" * 64,
                "public_key_pin_configured": True,
                "public_key_pin_matched": True,
                "algorithm": "openssl-dgst-sha256",
            },
        },
        "/api/license-entitlements": {
            "status": "passed",
            "license_status": "valid",
            "license_id": "LIC-1",
            "customer_id": "CUST-1",
            "seat_limit": 3,
            "subjects_count": 1,
            "licensed_workspaces": ["client-1"],
            "licensed_action_scope": {"source": "features", "allow_all": True, "actions": []},
            "violations": {"workspaces": [], "customers": [], "actions": []},
            "summary": {"total": 9, "errors": 0, "warnings": 0, "passed": 9},
        },
        "/api/billing": {"status": "reported", "billing_config_status": "configured", "currency": "USD", "totals": {"jobs_count": 1, "amount": 2.5}, "period": {"start": "2026-07-03T00:00:00Z", "end": "2026-07-03T01:00:00Z"}},
        "/api/quota": {"status": "reported", "limits": {"daily_job_limit": 10}, "usage": {"jobs_today": 1, "projects_count": 2}},
        "/api/backups/verify": {"status": "verified", "summary": {"total": 1, "verified": 1, "attention": 0}},
        "/api/backups/rehearsals": {"status": "passed", "summary": {"total_backups": 1, "passed": 1, "failed": 0}},
    }


class CommercialOperationsReportTests(unittest.TestCase):
    def test_build_and_verify_ready_operations_report(self) -> None:
        builder = load_script("build_commercial_operations_report")
        verifier = load_script("verify_commercial_operations_report")

        with tempfile.TemporaryDirectory() as tmp:
            launch_package = Path(tmp) / "commercial-launch-package.zip"
            launch_package.write_bytes(b"launch")
            launch_zip_sha = hashlib.sha256(launch_package.read_bytes()).hexdigest()

            def fake_launch_verify(_path):
                return {
                    "status": "verified",
                    "target_track": "paid_local_handoff",
                    "zip_sha256": launch_zip_sha,
                    "package_sha256": "c" * 64,
                    "summary": {"checks": 36, "errors": 0, "warnings": 0},
                }

            builder.verify_commercial_launch_package = fake_launch_verify
            verifier.verify_commercial_launch_package = fake_launch_verify
            output = Path(tmp) / "ops" / "commercial-operations.json"
            markdown = Path(tmp) / "ops" / "commercial-operations.md"
            with FakeConsole(ready_payloads()) as console:
                report = builder.build_commercial_operations_report(
                    base_url=console.url,
                    target_track="paid_local_handoff",
                    launch_package=launch_package,
                    require_launch_package=True,
                    customer_id="CUST-1",
                    customer_name="Customer",
                    output=output,
                    markdown_output=markdown,
                )

            self.assertEqual(report["status"], "ready")
            self.assertEqual(report["summary"]["errors"], 0)
            self.assertTrue(output.exists())
            self.assertTrue(markdown.exists())
            self.assertEqual(output.stat().st_mode & 0o077, 0)
            self.assertEqual(markdown.stat().st_mode & 0o077, 0)
            text = output.read_text(encoding="utf-8")
            self.assertNotIn("/Users/nullin", text)
            self.assertNotIn("plain-token", text)
            self.assertNotIn("payloads", report)

            verification = verifier.verify_commercial_operations_report(output, launch_package=launch_package)
            self.assertEqual(verification["status"], "verified")
            self.assertEqual(verification["summary"]["errors"], 0)
            checks = {item["id"]: item for item in verification["checks"]}
            self.assertTrue(checks["operations_report_sha256_matches"]["passed"])
            self.assertTrue(checks["launch_package_matches_report"]["passed"])

    def test_verifier_rejects_unredacted_sensitive_values_and_paths(self) -> None:
        builder = load_script("build_commercial_operations_report")
        verifier = load_script("verify_commercial_operations_report")

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "bad-operations.json"
            payload = {
                "schema_version": "draftpaper.commercial-operations-report/v1",
                "status": "ready",
                "target_track": "paid_local_handoff",
                "generated_at": "2026-07-03T00:00:00Z",
                "evidence": {"security_audit": {"summary": {"errors": 0}}, "token": "plain-token", "repo_root": "/Users/nullin/private"},
                "checks": [],
                "summary": {"checks": 0, "errors": 0, "warnings": 0},
            }
            payload["report_sha256"] = builder._ops_digest(payload)
            report_path.write_text(json.dumps(payload), encoding="utf-8")

            report = verifier.verify_commercial_operations_report(report_path)

        self.assertEqual(report["status"], "attention")
        failed = {item["id"]: item for item in report["checks"] if not item["passed"]}
        self.assertIn("sensitive_values_redacted", failed)
        self.assertIn("local_paths_redacted", failed)


if __name__ == "__main__":
    unittest.main()
