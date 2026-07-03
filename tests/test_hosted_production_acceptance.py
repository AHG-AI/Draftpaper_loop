from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def load_acceptance_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_run_hosted_production_acceptance", root / "scripts" / "run_hosted_production_acceptance.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load run_hosted_production_acceptance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeHostedConsole:
    def __init__(self, payloads: dict[str, object]) -> None:
        self.payloads = payloads
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __enter__(self) -> "FakeHostedConsole":
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
                data = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return Handler


def hosted_evidence_payload() -> dict[str, object]:
    return {
        "schema_version": "draftpaper.hosted-readiness/v1",
        "environment": "production",
        "enterprise_auth": {
            "status": "verified",
            "provider": "oidc-provider",
            "sso_protocol": "oidc",
            "rbac_model": "organization-workspace-role",
            "tenant_isolation": "workspace-scoped policies",
            "mfa_supported": True,
            "audit_events": True,
            "evidence": [],
        },
        "payment_collection": {
            "status": "verified",
            "provider": "payment-provider",
            "ledger": "server-side ledger",
            "webhook_validation": True,
            "invoice_reconciliation": True,
            "customer_portal": True,
            "evidence": [],
        },
        "managed_storage_dr": {
            "status": "verified",
            "storage_provider": "managed-object-storage",
            "backup_region": "separate-region",
            "restore_runbook": "runbooks/restore.md",
            "off_machine_backups": True,
            "restore_rehearsal_passed": True,
            "evidence": [],
        },
        "worker_isolation": {
            "status": "verified",
            "queue_backend": "managed-queue",
            "isolation_boundary": "per-tenant worker identity",
            "retry_policy": "bounded exponential backoff",
            "automatic_retries": True,
            "progress_streaming": True,
            "evidence": [],
        },
        "deployment_hardening": {
            "status": "verified",
            "environment": "production",
            "secrets_manager": "managed-secret-store",
            "security_review_id": "SEC-REVIEW-001",
            "tls_enforced": True,
            "least_privilege": True,
            "incident_response_plan": True,
            "evidence": [],
        },
    }


def write_hosted_evidence(root: Path) -> Path:
    payload = hosted_evidence_payload()
    for key in ["enterprise_auth", "payment_collection", "managed_storage_dr", "worker_isolation", "deployment_hardening"]:
        artifact = root / "evidence" / f"{key}.txt"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(f"{key} verified\n", encoding="utf-8")
        section = payload[key]
        assert isinstance(section, dict)
        section["evidence"] = [
            {
                "path": artifact.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "description": f"{key} evidence",
            }
        ]
    evidence_file = root / "hosted-readiness.json"
    evidence_file.write_text(json.dumps(payload), encoding="utf-8")
    evidence_file.chmod(0o600)
    return evidence_file


def ready_payloads() -> dict[str, object]:
    gates = [
        {"id": "hosted_enterprise_auth", "passed": True},
        {"id": "hosted_payment_collection", "passed": True},
        {"id": "managed_storage_dr", "passed": True},
        {"id": "hosted_worker_isolation", "passed": True},
        {"id": "deployment_hardening", "passed": True},
    ]
    hosted_track = {"id": "hosted_saas", "status": "ready", "summary": {"total": 5, "passed": 5, "errors": 0, "warnings": 0}, "gates": gates}
    return {
        "/health": {"status": "ok"},
        "/api/commercial-readiness": {"status": "assessed", "commercial_grade": "hosted_saas_ready"},
        "/api/handoff-readiness": {"status": "assessed", "commercial_grade": "hosted_saas_ready", "tracks": [hosted_track]},
        "/api/hosted-readiness": {"status": "ready", "summary": {"gates": 5, "passed": 5, "errors": 0, "warnings": 0}, "gates": gates},
        "/api/security-audit": {"status": "passed", "summary": {"errors": 0, "warnings": 0}},
        "/api/license": {"status": "valid"},
        "/api/license-entitlements": {"status": "passed"},
        "/api/backups/verify": {"status": "verified"},
        "/api/backups/rehearsals": {"status": "passed"},
    }


def fake_dossier_report() -> dict[str, object]:
    return {
        "status": "verified",
        "zip_sha256": "a" * 64,
        "dossier_sha256": "b" * 64,
        "summary": {"checks": 10, "errors": 0, "warnings": 0},
    }


class HostedProductionAcceptanceTests(unittest.TestCase):
    def test_rejects_localhost_and_http_without_rehearsal_flags(self) -> None:
        acceptance = load_acceptance_module()
        acceptance.verify_hosted_readiness_dossier = lambda _path: fake_dossier_report()

        with tempfile.TemporaryDirectory() as tmp, FakeHostedConsole(ready_payloads()) as console:
            report = acceptance.run_hosted_production_acceptance(
                base_url=console.url,
                evidence_file=write_hosted_evidence(Path(tmp)),
                hosted_readiness_dossier=Path(tmp) / "hosted-readiness-dossier.zip",
            )

        self.assertEqual(report["status"], "attention")
        failed = {item["id"] for item in report["checks"] if item["severity"] == "error" and not item["passed"]}
        self.assertIn("base_url_not_localhost", failed)
        self.assertIn("base_url_https", failed)

    def test_passes_ready_console_evidence_and_dossier_for_local_rehearsal(self) -> None:
        acceptance = load_acceptance_module()
        acceptance.verify_hosted_readiness_dossier = lambda _path: fake_dossier_report()

        with tempfile.TemporaryDirectory() as tmp, FakeHostedConsole(ready_payloads()) as console:
            report = acceptance.run_hosted_production_acceptance(
                base_url=console.url,
                evidence_file=write_hosted_evidence(Path(tmp)),
                hosted_readiness_dossier=Path(tmp) / "hosted-readiness-dossier.zip",
                allow_localhost=True,
                allow_insecure_http=True,
            )

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["summary"]["errors"], 0)
        self.assertEqual(report["evidence_summary"]["hosted_readiness"]["passed_gates"], 5)
        self.assertEqual(report["evidence_summary"]["local_validation"]["status"], "ready")
        self.assertEqual(report["evidence_summary"]["hosted_readiness_dossier"]["status"], "verified")

    def test_fails_when_remote_hosted_readiness_is_not_ready(self) -> None:
        acceptance = load_acceptance_module()
        acceptance.verify_hosted_readiness_dossier = lambda _path: fake_dossier_report()
        payloads = ready_payloads()
        payloads["/api/hosted-readiness"] = {
            "status": "not_ready",
            "summary": {"gates": 5, "passed": 0, "errors": 5, "warnings": 0},
            "gates": [{"id": "hosted_enterprise_auth", "passed": False}],
        }

        with tempfile.TemporaryDirectory() as tmp, FakeHostedConsole(payloads) as console:
            report = acceptance.run_hosted_production_acceptance(
                base_url=console.url,
                evidence_file=write_hosted_evidence(Path(tmp)),
                hosted_readiness_dossier=Path(tmp) / "hosted-readiness-dossier.zip",
                allow_localhost=True,
                allow_insecure_http=True,
            )

        failed = {item["id"] for item in report["checks"] if item["severity"] == "error" and not item["passed"]}
        self.assertEqual(report["status"], "attention")
        self.assertIn("hosted_readiness_ready", failed)
        self.assertIn("hosted_required_gates_passed", failed)


if __name__ == "__main__":
    unittest.main()
