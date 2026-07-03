from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def load_module(name: str, relative: str):
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(name, root / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {relative}")
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


def hosted_payloads() -> dict[str, object]:
    hosted_track = {"id": "hosted_saas", "status": "not_ready", "summary": {"total": 9, "passed": 4, "errors": 5}, "gates": []}
    return {
        "/health": {"status": "ok"},
        "/api/commercial-readiness": {"status": "assessed", "commercial_grade": "paid_local_handoff_ready"},
        "/api/handoff-readiness": {"status": "assessed", "commercial_grade": "paid_local_handoff_ready", "tracks": [hosted_track]},
        "/api/hosted-readiness": {"status": "not_ready", "summary": {"gates": 5, "passed": 0, "errors": 5}, "gates": []},
        "/api/security-audit": {"status": "passed", "summary": {"errors": 0, "warnings": 0}},
        "/api/access-policy": {"status": "configured"},
        "/api/quota": {"status": "configured"},
        "/api/billing": {"status": "configured"},
        "/api/license": {"status": "valid"},
        "/api/license-entitlements": {"status": "passed"},
        "/api/backups/verify": {"status": "verified"},
        "/api/backups/rehearsals": {"status": "passed"},
    }


SECTION_FIELDS = {
    "enterprise_auth": {
        "provider": "oidc-provider",
        "sso_protocol": "oidc",
        "rbac_model": "organization-workspace-role",
        "tenant_isolation": "workspace-scoped policies",
        "mfa_supported": True,
        "audit_events": True,
    },
    "payment_collection": {
        "provider": "payment-provider",
        "ledger": "server-side ledger",
        "webhook_validation": True,
        "invoice_reconciliation": True,
        "customer_portal": True,
    },
    "managed_storage_dr": {
        "storage_provider": "managed-object-storage",
        "backup_region": "separate-region",
        "restore_runbook": "runbooks/restore.md",
        "off_machine_backups": True,
        "restore_rehearsal_passed": True,
    },
    "worker_isolation": {
        "queue_backend": "managed-queue",
        "isolation_boundary": "per-tenant worker identity",
        "retry_policy": "bounded exponential backoff",
        "automatic_retries": True,
        "progress_streaming": True,
    },
    "deployment_hardening": {
        "environment": "production",
        "secrets_manager": "managed-secret-store",
        "security_review_id": "SEC-REVIEW-001",
        "tls_enforced": True,
        "least_privilege": True,
        "incident_response_plan": True,
    },
}


def controls_payload(root: Path) -> dict[str, object]:
    controls: dict[str, object] = {
        "schema_version": "draftpaper.hosted-readiness-controls/v1",
        "attestation": {
            "approved_by": "security-owner@example.invalid",
            "approval_reference": "CHANGE-123",
            "prepared_by": "release-operator",
        },
        "sections": {},
    }
    sections = controls["sections"]
    assert isinstance(sections, dict)
    for key, fields in SECTION_FIELDS.items():
        artifact = root / "operator-source" / f"{key}.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(json.dumps({"section": key, "status": "verified"}) + "\n", encoding="utf-8")
        sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
        sections[key] = {
            "status": "verified",
            **fields,
            "evidence": [{"path": artifact.relative_to(root).as_posix(), "sha256": sha, "description": f"{key} external control review"}],
        }
    return controls


class PrepareHostedReadinessTests(unittest.TestCase):
    def test_prepares_ready_hosted_readiness_from_verified_collection_and_controls(self) -> None:
        collector = load_module("draftpaper_collect_hosted_readiness_evidence", "scripts/collect_hosted_readiness_evidence.py")
        preparer = load_module("draftpaper_prepare_hosted_readiness", "scripts/prepare_hosted_readiness.py")
        validator = load_module("draftpaper_validate_hosted_readiness", "scripts/validate_hosted_readiness.py")

        with tempfile.TemporaryDirectory() as tmp, FakeHostedConsole(hosted_payloads()) as console:
            root = Path(tmp)
            collection = collector.collect_hosted_readiness_evidence(
                base_url=console.url,
                output_dir=root / "collection",
                allow_localhost=True,
                allow_insecure_http=True,
                timeout=3,
            )
            controls_file = root / "hosted-controls.json"
            controls_file.write_text(json.dumps(controls_payload(root)), encoding="utf-8")
            output_file = root / "ready" / "hosted-readiness.json"
            report_file = root / "ready" / "preparation-report.json"

            result = preparer.prepare_hosted_readiness(
                collection_report=Path(collection["report_path"]),
                controls_file=controls_file,
                output_file=output_file,
                report_output=report_file,
            )

            self.assertEqual(result["status"], "ready")
            self.assertEqual(result["summary"]["errors"], 0)
            self.assertEqual(result["summary"]["operator_evidence_artifacts"], 5)
            self.assertTrue(output_file.exists())
            self.assertEqual(output_file.stat().st_mode & 0o077, 0)
            self.assertTrue(report_file.exists())
            evidence = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertEqual(evidence["enterprise_auth"]["status"], "verified")
            self.assertTrue(any(item["source"] == "operator" for item in evidence["enterprise_auth"]["evidence"]))
            self.assertTrue(any(item["source"] == "collected" for item in evidence["deployment_hardening"]["evidence"]))

            validation = validator.validate_hosted_readiness(output_file)
            self.assertEqual(validation["status"], "ready")
            self.assertEqual(validation["summary"]["passed"], 5)

    def test_missing_operator_evidence_fails_closed_without_output(self) -> None:
        collector = load_module("draftpaper_collect_hosted_readiness_evidence", "scripts/collect_hosted_readiness_evidence.py")
        preparer = load_module("draftpaper_prepare_hosted_readiness", "scripts/prepare_hosted_readiness.py")

        with tempfile.TemporaryDirectory() as tmp, FakeHostedConsole(hosted_payloads()) as console:
            root = Path(tmp)
            collection = collector.collect_hosted_readiness_evidence(
                base_url=console.url,
                output_dir=root / "collection",
                allow_localhost=True,
                allow_insecure_http=True,
                timeout=3,
            )
            controls = controls_payload(root)
            sections = controls["sections"]
            assert isinstance(sections, dict)
            sections["enterprise_auth"]["evidence"] = []
            controls_file = root / "hosted-controls.json"
            controls_file.write_text(json.dumps(controls), encoding="utf-8")
            output_file = root / "ready" / "hosted-readiness.json"

            result = preparer.prepare_hosted_readiness(
                collection_report=Path(collection["report_path"]),
                controls_file=controls_file,
                output_file=output_file,
            )

        self.assertEqual(result["status"], "attention")
        self.assertFalse(output_file.exists())
        failed = {item["id"] for item in result["checks"] if item["severity"] == "error" and not item["passed"]}
        self.assertIn("enterprise_auth_operator_evidence_verified", failed)
        self.assertIn("prepared_hosted_readiness_written", failed)

    def test_tampered_operator_hash_fails_closed(self) -> None:
        collector = load_module("draftpaper_collect_hosted_readiness_evidence", "scripts/collect_hosted_readiness_evidence.py")
        preparer = load_module("draftpaper_prepare_hosted_readiness", "scripts/prepare_hosted_readiness.py")

        with tempfile.TemporaryDirectory() as tmp, FakeHostedConsole(hosted_payloads()) as console:
            root = Path(tmp)
            collection = collector.collect_hosted_readiness_evidence(
                base_url=console.url,
                output_dir=root / "collection",
                allow_localhost=True,
                allow_insecure_http=True,
                timeout=3,
            )
            controls = controls_payload(root)
            sections = controls["sections"]
            assert isinstance(sections, dict)
            sections["payment_collection"]["evidence"][0]["sha256"] = "0" * 64
            controls_file = root / "hosted-controls.json"
            controls_file.write_text(json.dumps(controls), encoding="utf-8")

            result = preparer.prepare_hosted_readiness(
                collection_report=Path(collection["report_path"]),
                controls_file=controls_file,
                output_file=root / "ready" / "hosted-readiness.json",
            )

        self.assertEqual(result["status"], "attention")
        failed = {item["id"] for item in result["checks"] if item["severity"] == "error" and not item["passed"]}
        self.assertIn("payment_collection_operator_1_sha256_matches", failed)


if __name__ == "__main__":
    unittest.main()
