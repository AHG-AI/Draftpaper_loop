from __future__ import annotations

import io
import hashlib
import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


def load_validator_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_validate_hosted_readiness", root / "scripts" / "validate_hosted_readiness.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load validate_hosted_readiness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def hosted_readiness_payload() -> dict[str, object]:
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
            "evidence": ["security-review/AUTH-001"],
        },
        "payment_collection": {
            "status": "verified",
            "provider": "payment-provider",
            "ledger": "server-side ledger",
            "webhook_validation": True,
            "invoice_reconciliation": True,
            "customer_portal": True,
            "evidence": ["billing-review/BILL-001"],
        },
        "managed_storage_dr": {
            "status": "verified",
            "storage_provider": "managed-object-storage",
            "backup_region": "separate-region",
            "restore_runbook": "runbooks/restore.md",
            "off_machine_backups": True,
            "restore_rehearsal_passed": True,
            "evidence": ["dr-rehearsal/DR-001"],
        },
        "worker_isolation": {
            "status": "verified",
            "queue_backend": "managed-queue",
            "isolation_boundary": "per-tenant worker identity",
            "retry_policy": "bounded exponential backoff",
            "automatic_retries": True,
            "progress_streaming": True,
            "evidence": ["worker-review/WORKER-001"],
        },
        "deployment_hardening": {
            "status": "verified",
            "environment": "production",
            "secrets_manager": "managed-secret-store",
            "security_review_id": "SEC-REVIEW-001",
            "tls_enforced": True,
            "least_privilege": True,
            "incident_response_plan": True,
            "evidence": ["security-review/SEC-001"],
        },
    }


def attach_evidence_artifacts(payload: dict[str, object], root: Path) -> None:
    for key in ["enterprise_auth", "payment_collection", "managed_storage_dr", "worker_isolation", "deployment_hardening"]:
        artifact = root / "evidence" / f"{key}.txt"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(f"{key} verified\n", encoding="utf-8")
        sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
        section = payload[key]
        assert isinstance(section, dict)
        section["evidence"] = [{"path": artifact.relative_to(root).as_posix(), "sha256": sha, "description": f"{key} evidence"}]


class HostedReadinessValidatorTests(unittest.TestCase):
    def test_template_generation_writes_owner_only_pending_evidence(self) -> None:
        validator = load_validator_module()

        with tempfile.TemporaryDirectory() as tmp:
            template_path = Path(tmp) / "hosted-readiness.json"
            with redirect_stdout(io.StringIO()) as stdout:
                code = validator.main(["--write-template", str(template_path)])

            self.assertEqual(code, 0)
            self.assertTrue(template_path.exists())
            self.assertEqual(template_path.stat().st_mode & 0o077, 0)
            payload = json.loads(template_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "draftpaper.hosted-readiness/v1")
            self.assertEqual(payload["enterprise_auth"]["status"], "pending")
            self.assertEqual(payload["enterprise_auth"]["evidence"][0]["path"], "")
            self.assertIn("template_written", stdout.getvalue())

            with redirect_stdout(io.StringIO()):
                failed_code = validator.main(["--evidence-file", str(template_path), "--require-ready"])
            self.assertEqual(failed_code, 1)

    def test_validator_accepts_complete_hosted_readiness_evidence(self) -> None:
        validator = load_validator_module()

        with tempfile.TemporaryDirectory() as tmp:
            evidence_file = Path(tmp) / "hosted-readiness.json"
            payload = hosted_readiness_payload()
            attach_evidence_artifacts(payload, Path(tmp))
            evidence_file.write_text(json.dumps(payload), encoding="utf-8")
            evidence_file.chmod(0o600)
            output_path = Path(tmp) / "hosted-report.json"

            with redirect_stdout(io.StringIO()) as stdout:
                code = validator.main(
                    [
                        "--evidence-file",
                        str(evidence_file),
                        "--require-ready",
                        "--output",
                        str(output_path),
                    ]
                )

            self.assertEqual(code, 0)
            self.assertIn('"status": "ready"', stdout.getvalue())
            self.assertTrue(output_path.exists())
            self.assertEqual(output_path.stat().st_mode & 0o077, 0)
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "ready")
            self.assertEqual(report["summary"]["passed"], 5)

    def test_validator_reports_incomplete_evidence(self) -> None:
        validator = load_validator_module()

        with tempfile.TemporaryDirectory() as tmp:
            evidence = hosted_readiness_payload()
            evidence["deployment_hardening"] = {"status": "verified", "environment": "production", "evidence": []}
            attach_evidence_artifacts(evidence, Path(tmp))
            evidence["deployment_hardening"] = {"status": "verified", "environment": "production", "evidence": []}
            evidence_file = Path(tmp) / "hosted-readiness.json"
            evidence_file.write_text(json.dumps(evidence), encoding="utf-8")
            evidence_file.chmod(0o600)

            report = validator.validate_hosted_readiness(evidence_file)

        gates = {item["id"]: item for item in report["gates"]}
        self.assertEqual(report["status"], "attention")
        self.assertFalse(gates["deployment_hardening"]["passed"])
        self.assertIn("missing_fields", gates["deployment_hardening"]["note"])


if __name__ == "__main__":
    unittest.main()
