from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


def load_builder_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_build_hosted_readiness_dossier", root / "scripts" / "build_hosted_readiness_dossier.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load build_hosted_readiness_dossier.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_verifier_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_verify_hosted_readiness_dossier", root / "scripts" / "verify_hosted_readiness_dossier.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load verify_hosted_readiness_dossier.py")
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


def attach_artifacts(payload: dict[str, object], root: Path) -> None:
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


class HostedReadinessDossierTests(unittest.TestCase):
    def test_build_and_verify_hosted_readiness_dossier(self) -> None:
        builder = load_builder_module()
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = hosted_readiness_payload()
            attach_artifacts(payload, root)
            evidence_file = root / "hosted-readiness.json"
            evidence_file.write_text(json.dumps(payload), encoding="utf-8")
            evidence_file.chmod(0o600)

            result = builder.build_hosted_readiness_dossier(
                evidence_file=evidence_file,
                output_dir=root / "dossier",
                customer_id="CUST-HOSTED",
                customer_name="Hosted Customer",
            )

            self.assertEqual(result["status"], "ready")
            self.assertEqual(result["summary"]["errors"], 0)
            self.assertEqual(result["summary"]["copied_evidence_artifacts"], 5)
            zip_path = Path(result["zip_path"])
            self.assertTrue(zip_path.exists())
            self.assertEqual(zip_path.stat().st_mode & 0o077, 0)

            with zipfile.ZipFile(zip_path) as archive:
                names = set(archive.namelist())
                self.assertIn("hosted-readiness-dossier.json", names)
                self.assertIn("hosted-readiness-summary.json", names)
                self.assertIn("hosted-readiness-validation-report.json", names)
                self.assertFalse(any(Path(name).name == "hosted-readiness.json" for name in names))
                self.assertEqual(sum(1 for name in names if name.startswith("evidence-artifacts/")), 5)

            verification = verifier.verify_hosted_readiness_dossier(zip_path)
            self.assertEqual(verification["status"], "verified")
            self.assertEqual(verification["summary"]["errors"], 0)

    def test_verifier_rejects_raw_hosted_evidence_member(self) -> None:
        builder = load_builder_module()
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = hosted_readiness_payload()
            attach_artifacts(payload, root)
            evidence_file = root / "hosted-readiness.json"
            evidence_file.write_text(json.dumps(payload), encoding="utf-8")
            evidence_file.chmod(0o600)
            result = builder.build_hosted_readiness_dossier(evidence_file=evidence_file, output_dir=root / "dossier")
            zip_path = Path(result["zip_path"])

            with zipfile.ZipFile(zip_path, "a") as archive:
                archive.writestr("hosted-readiness.json", "{}\n")

            verification = verifier.verify_hosted_readiness_dossier(zip_path)
            self.assertEqual(verification["status"], "attention")
            failed = {item["id"]: item for item in verification["checks"] if not item["passed"]}
            self.assertIn("private_members_excluded", failed)
            self.assertIn("raw_hosted_evidence_file_excluded", failed)


if __name__ == "__main__":
    unittest.main()
