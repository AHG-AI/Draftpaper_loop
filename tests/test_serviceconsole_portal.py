from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import time
import tempfile
import unittest
import zipfile
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from draftpaper_cli.project_scaffold import create_project
from draftpaper_cli.project_state import mark_stage_stale, update_stage_status


def load_portal_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_serviceconsole_app", root / "scripts" / "serviceconsole_app.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load serviceconsole_app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeRequest:
    def __init__(self, *, path: str = "/api/projects", authorization: str = "", token: str = "") -> None:
        self.path = path
        self.headers = Message()
        if authorization:
            self.headers["Authorization"] = authorization
        if token:
            self.headers["X-Draftpaper-Token"] = token


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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


def attach_hosted_evidence_artifacts(payload: dict[str, object], root: Path) -> None:
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


class ServiceConsolePortalTests(unittest.TestCase):
    def test_action_registry_covers_latest_loop_boundaries(self) -> None:
        portal = load_portal_module()

        for action in [
            "status",
            "sync-artifact-stale",
            "search-literature-live",
            "assess-core-evidence",
            "audit-citations",
            "run-citation-repair-loop",
            "assess-publication-readiness",
            "generate-revision-plan",
        ]:
            self.assertIn(action, portal.ACTION_REGISTRY)

    def test_index_html_exposes_operator_readiness_dashboard(self) -> None:
        portal = load_portal_module()

        html = portal.index_html()

        self.assertIn("Commercial readiness", html)
        self.assertIn("tokenInput", html)
        self.assertIn("saveTokenBtn", html)
        self.assertIn("releaseZipPath", html)
        self.assertIn("hostedBaseUrl", html)
        self.assertIn("releasePackageBtn", html)
        self.assertIn("releaseOutputDir", html)
        self.assertIn("releaseVersionLabel", html)
        self.assertIn("releaseSigningKey", html)
        self.assertIn("releasePublicKey", html)
        self.assertIn("releaseRequireSignature", html)
        self.assertIn("launchPackageBtn", html)
        self.assertIn("launchAcceptanceReportPath", html)
        self.assertIn("launchOutputDir", html)
        self.assertIn("launchOutputZipPath", html)
        self.assertIn("launchTargetTrack", html)
        self.assertIn("launchReleaseManifestPath", html)
        self.assertIn("launchSha256Path", html)
        self.assertIn("launchSignaturePath", html)
        self.assertIn("launchPublicKeyPath", html)
        self.assertIn("launchHandoffDossierPath", html)
        self.assertIn("launchSupportBundlePath", html)
        self.assertIn("supportFileBtn", html)
        self.assertIn("supportOutputPath", html)
        self.assertIn("/api/commercial-launch-package", html)
        self.assertIn("/api/support-bundle-file", html)
        self.assertIn("paidConfigBtn", html)
        self.assertIn("suiteBtn", html)
        self.assertIn("opsReportBtn", html)
        self.assertIn("installBtn", html)
        self.assertIn("handoffCustomerId", html)
        self.assertIn("handoffCustomerName", html)
        self.assertIn("handoffOutputDir", html)
        self.assertIn("handoffExpiresAt", html)
        self.assertIn("handoffActivate", html)
        self.assertIn("suiteOutputDir", html)
        self.assertIn("suiteTargetTrack", html)
        self.assertIn("suiteVersionLabel", html)
        self.assertIn("suitePublicKey", html)
        self.assertIn("suiteTimeout", html)
        self.assertIn("opsOutputPath", html)
        self.assertIn("opsMarkdownPath", html)
        self.assertIn("opsLaunchPackagePath", html)
        self.assertIn("opsTargetTrack", html)
        self.assertIn("opsTimeout", html)
        self.assertIn("opsRequireLaunchPackage", html)
        self.assertIn("opsRequireReady", html)
        self.assertIn("installReleaseZipPath", html)
        self.assertIn("installRootPath", html)
        self.assertIn("installManifestPath", html)
        self.assertIn("installSha256Path", html)
        self.assertIn("installSignaturePath", html)
        self.assertIn("installPublicKeyPath", html)
        self.assertIn("installHandoffDossierPath", html)
        self.assertIn("installSmokeOutputPath", html)
        self.assertIn("installRequireSignature", html)
        self.assertIn("installRequireDossier", html)
        self.assertIn("installRunSmoke", html)
        self.assertIn("installForce", html)
        self.assertIn("hostedDraftBtn", html)
        self.assertIn("hostedFinalizeBtn", html)
        self.assertIn("hostedDossierBtn", html)
        self.assertIn("hostedAcceptBtn", html)
        self.assertIn("hostedCollectionReportPath", html)
        self.assertIn("hostedControlsPath", html)
        self.assertIn("hostedEvidenceFilePath", html)
        self.assertIn("hostedOutputPath", html)
        self.assertIn("hostedDossierZipPath", html)
        self.assertIn("hostedAcceptanceOutputPath", html)
        self.assertIn("readinessSummary", html)
        self.assertIn("refreshReadiness", html)
        self.assertIn("Hosted gaps", html)
        self.assertIn("Stage graph", html)
        self.assertIn("/api/project-stage-graph", html)
        self.assertIn("/api/commercial-readiness", html)
        self.assertIn("/api/handoff-readiness", html)
        self.assertIn("/api/release-package", html)
        self.assertIn("/api/paid-handoff-config", html)
        self.assertIn("/api/commercial-acceptance-suite", html)
        self.assertIn("/api/commercial-operations-report", html)
        self.assertIn("/api/verified-release-install", html)
        self.assertIn("/api/hosted-readiness-draft", html)
        self.assertIn("/api/hosted-readiness-finalize", html)
        self.assertIn("/api/hosted-readiness-dossier", html)
        self.assertIn("/api/hosted-production-acceptance", html)
        self.assertNotIn("prompt(", html)

    def test_project_summary_reports_next_action(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            project = create_project(root=tmp, idea="Console summary smoke", field="workflow engineering")

            summary = portal.project_summary(project.path)

            self.assertEqual(summary["slug"], "console-summary-smoke")
            self.assertEqual(summary["pipeline_state"], "ready")
            self.assertEqual(summary["next_action"]["command"], "search-literature")

    def test_project_stage_graph_reports_dependencies_and_stale_propagation(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            project = create_project(root=tmp, idea="Stage graph smoke", field="workflow engineering")
            update_stage_status(project.path, "references", "draft")
            update_stage_status(project.path, "journal_profile", "draft")
            update_stage_status(project.path, "research_plan", "draft")
            mark_stage_stale(project.path, "references", include_self=True)

            graph = portal.project_stage_graph(project.path)

        self.assertEqual(graph["schema_version"], "draftpaper.stage-graph/v1")
        self.assertEqual(graph["status"], "reported")
        nodes = {node["id"]: node for node in graph["nodes"]}
        edges = {(edge["from"], edge["to"]) for edge in graph["edges"]}
        self.assertIn(("references", "research_plan"), edges)
        self.assertTrue(nodes["references"]["stale"])
        self.assertIn("research_plan", graph["stale_propagation"]["stale_stages"])
        self.assertEqual(nodes["research_plan"]["state"], "stale")
        self.assertEqual(graph["summary"]["stale"], len(graph["stale_propagation"]["stale_stages"]))
        self.assertIn(graph["next_action"]["command"], {"sync-artifact-stale", "search-literature"})

    def test_live_search_action_builds_bounded_environment(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            project = create_project(root=tmp, idea="Bounded search smoke", field="machine learning")
            with patch.object(portal, "PROJECTS_ROOT", Path(tmp).resolve()):
                command, env = portal.cli_command(
                    "search-literature-live",
                    {"project": project.path.name, "params": {"query": "AI research loop", "limit": "5"}},
                )

            self.assertIn("search-literature", command)
            self.assertIn("--query", command)
            self.assertEqual(env["DRAFTPAPER_SEARCH_MAX_QUERIES"], "4")
            self.assertIn("semantic_scholar", env["DRAFTPAPER_SEARCH_PROVIDERS"])

    def test_commercial_readiness_exposes_remaining_gaps(self) -> None:
        portal = load_portal_module()

        readiness = portal.commercial_readiness()

        self.assertEqual(readiness["status"], "assessed")
        self.assertGreaterEqual(readiness["score"], 0.8)
        self.assertIn("local_license_grant", {item["id"] for item in readiness["checks"]})
        self.assertIn("job_timeline_retry", {item["id"] for item in readiness["checks"]})
        self.assertIn("stage_dependency_graph", {item["id"] for item in readiness["checks"]})
        self.assertIn("support_bundle", {item["id"] for item in readiness["checks"]})
        self.assertIn("support_bundle_verification", {item["id"] for item in readiness["checks"]})
        self.assertIn("support_bundle_file_console", {item["id"] for item in readiness["checks"]})
        self.assertIn("backup_integrity_audit", {item["id"] for item in readiness["checks"]})
        self.assertIn("release_package_console", {item["id"] for item in readiness["checks"]})
        self.assertIn("hosted_readiness_dossier", {item["id"] for item in readiness["checks"]})
        self.assertIn("commercial_launch_package", {item["id"] for item in readiness["checks"]})
        self.assertIn("commercial_launch_package_console", {item["id"] for item in readiness["checks"]})
        self.assertIn("commercial_operations_report", {item["id"] for item in readiness["checks"]})
        self.assertIn("commercial_operations_report_console", {item["id"] for item in readiness["checks"]})
        self.assertIn("commercial_acceptance_suite", {item["id"] for item in readiness["checks"]})
        self.assertIn("commercial_acceptance_suite_console", {item["id"] for item in readiness["checks"]})
        self.assertIn("verified_release_install_console", {item["id"] for item in readiness["checks"]})
        self.assertIn("paid_handoff_config_generation", {item["id"] for item in readiness["checks"]})
        self.assertIn("sample_workflow_acceptance", {item["id"] for item in readiness["checks"]})
        self.assertIn("hosted_evidence_collection", {item["id"] for item in readiness["checks"]})
        self.assertIn("hosted_evidence_collection_verification", {item["id"] for item in readiness["checks"]})
        self.assertIn("hosted_readiness_preparation", {item["id"] for item in readiness["checks"]})
        self.assertIn("hosted_readiness_finalization", {item["id"] for item in readiness["checks"]})
        self.assertIn("hosted_production_acceptance", {item["id"] for item in readiness["checks"]})
        self.assertIn("commercial_approval_preparation", {item["id"] for item in readiness["checks"]})
        self.assertIn("claim_confirmation_preparation", {item["id"] for item in readiness["checks"]})
        self.assertIn("release_trust_preparation", {item["id"] for item in readiness["checks"]})
        self.assertIn("security_review_preparation", {item["id"] for item in readiness["checks"]})
        self.assertIn("claim_confirmation_verification", {item["id"] for item in readiness["checks"]})
        self.assertIn("commercial_approval_verification", {item["id"] for item in readiness["checks"]})
        self.assertIn("release_trust_verification", {item["id"] for item in readiness["checks"]})
        self.assertIn("security_review_verification", {item["id"] for item in readiness["checks"]})
        self.assertEqual(readiness["commercial_grade"], "local_operator_pilot_ready")
        tracks = {track["id"]: track for track in readiness["readiness_tracks"]}
        self.assertEqual(tracks["local_operator_pilot"]["status"], "ready")
        self.assertEqual(tracks["paid_local_handoff"]["status"], "blocked")
        self.assertEqual(tracks["hosted_saas"]["status"], "not_ready")
        self.assertTrue(readiness["remaining_gaps"])

    def test_build_release_package_from_console_verifies_generated_package(self) -> None:
        portal = load_portal_module()
        captured: dict[str, object] = {}

        def fake_build_release_package(**kwargs):
            captured.update(kwargs)
            output_dir = Path(kwargs["output_dir"])
            output_dir.mkdir(parents=True, exist_ok=True)
            output_dir.chmod(0o700)
            zip_path = output_dir / "draftpaper-loop-cust-a.zip"
            manifest_path = output_dir / "draftpaper-loop-cust-a.manifest.json"
            sha_path = output_dir / "draftpaper-loop-cust-a.zip.sha256"
            signature_path = output_dir / "draftpaper-loop-cust-a.zip.sig"
            public_key_path = output_dir / "draftpaper-loop-cust-a.public.pem"
            for path in [zip_path, manifest_path, sha_path, signature_path, public_key_path]:
                path.write_text("artifact\n", encoding="utf-8")
            return {
                "status": "packaged",
                "package": "draftpaper-loop-cust-a",
                "zip_path": str(zip_path),
                "manifest_path": str(manifest_path),
                "sha256_path": str(sha_path),
                "zip_sha256": "a" * 64,
                "zip_bytes": 9,
                "file_count": 42,
                "missing_required_files": [],
                "signature": {
                    "signature_path": str(signature_path),
                    "public_key_path": str(public_key_path),
                    "signature_sha256": "b" * 64,
                    "public_key_sha256": "c" * 64,
                },
            }

        def fake_verify_release_package(path, **kwargs):
            captured["verify_path"] = path
            captured["verify_kwargs"] = kwargs
            return {"status": "verified", "zip_path": str(path), "summary": {"checks": 11, "errors": 0, "warnings": 0}}

        builder = type("FakeReleaseBuilder", (), {"build_release_package": staticmethod(fake_build_release_package)})
        verifier = type("FakeReleaseVerifier", (), {"verify_release_package": staticmethod(fake_verify_release_package)})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime_root = root / "runtime"
            signing_key = root / "release-signing.pem"
            signing_public = root / "release.public.pem"
            signing_key.write_text("private key placeholder\n", encoding="utf-8")
            signing_public.write_text("public key placeholder\n", encoding="utf-8")
            signing_key.chmod(0o600)

            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.object(portal, "_release_package_builder_module", return_value=builder):
                    with patch.object(portal, "_release_package_verifier_module", return_value=verifier):
                        report = portal.build_release_package_from_console(
                            version_label="CUST-A release",
                            signing_key=str(signing_key),
                            signing_public_key=str(signing_public),
                            require_signature=True,
                            context=portal._local_admin_context(),
                        )

            self.assertEqual(report["schema_version"], "draftpaper.release-package-build/v1")
            self.assertEqual(report["status"], "verified")
            self.assertEqual(report["package_status"], "packaged")
            self.assertEqual(report["verification_status"], "verified")
            self.assertEqual(captured["root"], portal.REPO_ROOT)
            self.assertEqual(captured["version_label"], "CUST-A release")
            self.assertEqual(captured["signing_key"], signing_key.resolve())
            self.assertEqual(captured["signing_public_key"], signing_public.resolve())
            self.assertEqual(captured["verify_path"], Path(report["zip_path"]).resolve())
            self.assertTrue(captured["verify_kwargs"]["require_signature"])
            self.assertEqual(captured["verify_kwargs"]["signature_path"], Path(report["signature"]["signature_path"]).resolve())
            self.assertEqual(captured["verify_kwargs"]["public_key_path"], Path(report["signature"]["public_key_path"]).resolve())
            self.assertIn("release_packages", str(Path(report["output_dir"])))
            self.assertNotIn(str(signing_key), json.dumps(report))

    def test_build_commercial_launch_package_from_console_reverifies_zip(self) -> None:
        portal = load_portal_module()
        captured: dict[str, object] = {}

        def fake_build_commercial_launch_package(**kwargs):
            captured.update(kwargs)
            output_dir = Path(kwargs["output_dir"])
            output_dir.mkdir(parents=True, exist_ok=True)
            output_dir.chmod(0o700)
            zip_path = output_dir / "commercial-launch-package.zip"
            package_path = output_dir / "commercial-launch-package.json"
            summary_path = output_dir / "commercial-launch-summary.json"
            for path in [zip_path, package_path, summary_path]:
                path.write_text("{}\n", encoding="utf-8")
                path.chmod(0o600)
            return {
                "status": "ready",
                "target_track": kwargs["target_track"],
                "zip_path": str(zip_path),
                "package_path": str(package_path),
                "summary_path": str(summary_path),
                "zip_sha256": "d" * 64,
                "package_sha256": "e" * 64,
                "summary": {"checks": 13, "errors": 0, "warnings": 0},
            }

        def fake_verify_commercial_launch_package(path):
            captured["verify_path"] = path
            return {"status": "verified", "zip_path": str(path), "summary": {"checks": 14, "errors": 0, "warnings": 0}}

        builder = type("FakeLaunchBuilder", (), {"build_commercial_launch_package": staticmethod(fake_build_commercial_launch_package)})
        verifier = type("FakeLaunchVerifier", (), {"verify_commercial_launch_package": staticmethod(fake_verify_commercial_launch_package)})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime_root = root / "runtime"
            artifact_names = [
                "handoff-acceptance.json",
                "release.zip",
                "release.manifest.json",
                "release.zip.sha256",
                "release.zip.sig",
                "release.public.pem",
                "handoff-dossier.zip",
                "support-bundle.zip",
            ]
            artifacts: dict[str, Path] = {}
            for name in artifact_names:
                path = root / name
                path.write_text("artifact\n", encoding="utf-8")
                artifacts[name] = path

            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.object(portal, "_commercial_launch_package_builder_module", return_value=builder):
                    with patch.object(portal, "_commercial_launch_package_verifier_module", return_value=verifier):
                        report = portal.build_commercial_launch_package_from_console(
                            acceptance_report=str(artifacts["handoff-acceptance.json"]),
                            release_zip=str(artifacts["release.zip"]),
                            release_manifest=str(artifacts["release.manifest.json"]),
                            release_sha256_file=str(artifacts["release.zip.sha256"]),
                            release_signature=str(artifacts["release.zip.sig"]),
                            release_public_key=str(artifacts["release.public.pem"]),
                            handoff_dossier=str(artifacts["handoff-dossier.zip"]),
                            support_bundle=str(artifacts["support-bundle.zip"]),
                            customer_id="CUST-A",
                            customer_name="Customer A",
                            context=portal._local_admin_context(),
                        )

            zip_path = Path(report["zip_path"])

            self.assertEqual(report["schema_version"], "draftpaper.commercial-launch-package-build/v1")
            self.assertEqual(report["status"], "verified")
            self.assertEqual(report["launch_status"], "ready")
            self.assertEqual(report["verification_status"], "verified")
            self.assertEqual(captured["target_track"], "paid_local_handoff")
            self.assertEqual(captured["acceptance_report"], artifacts["handoff-acceptance.json"].resolve())
            self.assertEqual(captured["release_zip"], artifacts["release.zip"].resolve())
            self.assertEqual(captured["release_manifest"], artifacts["release.manifest.json"].resolve())
            self.assertEqual(captured["release_sha256_file"], artifacts["release.zip.sha256"].resolve())
            self.assertEqual(captured["release_signature"], artifacts["release.zip.sig"].resolve())
            self.assertEqual(captured["release_public_key"], artifacts["release.public.pem"].resolve())
            self.assertEqual(captured["handoff_dossier"], artifacts["handoff-dossier.zip"].resolve())
            self.assertEqual(captured["support_bundle"], artifacts["support-bundle.zip"].resolve())
            self.assertEqual(captured["verify_path"], zip_path.resolve())
            self.assertTrue(zip_path.exists())
            self.assertEqual(zip_path.stat().st_mode & 0o077, 0)
            self.assertIn("commercial_launch_packages", str(Path(report["output_dir"])))

    def test_generate_paid_handoff_config_from_console_activates_current_process(self) -> None:
        portal = load_portal_module()

        def fake_generate_handoff_config(**kwargs):
            output_dir = Path(kwargs["output_dir"])
            output_dir.mkdir(parents=True, exist_ok=True)
            output_dir.chmod(0o700)
            license_file = output_dir / "commercial-license-grant.json"
            users_file = output_dir / "console-users.json"
            billing_file = output_dir / "billing-rates.json"
            env_file = output_dir / "handoff-env.sh"
            manifest_file = output_dir / "handoff-manifest.json"
            token_file = output_dir / "operator-token.txt"
            for path in [license_file, users_file, billing_file, env_file, manifest_file, token_file]:
                path.write_text("{}\n", encoding="utf-8")
                path.chmod(0o600)
            return {
                "schema_version": "draftpaper.handoff-config/v1",
                "status": "generated",
                "output_dir": str(output_dir),
                "customer_id": kwargs["customer_id"],
                "customer_name": kwargs["customer_name"],
                "license_id": "DPL-COMM-CUST",
                "workspace": "cust-a",
                "operator_id": kwargs["operator_id"],
                "operator_role": kwargs["operator_role"],
                "token_sha256": "b" * 64,
                "grant_sha256": "c" * 64,
                "files": {
                    "license": str(license_file),
                    "users": str(users_file),
                    "billing": str(billing_file),
                    "env": str(env_file),
                    "manifest": str(manifest_file),
                    "token": str(token_file),
                    "active_env": str(portal.DEFAULT_ACTIVE_HANDOFF_ENV),
                    "license_public_key_sha256": "d" * 64,
                },
                "activated": kwargs["activate"],
                "license_signed": False,
            }

        generator = type("FakeHandoffGenerator", (), {"generate_handoff_config": staticmethod(fake_generate_handoff_config)})

        with tempfile.TemporaryDirectory() as tmp:
            runtime_root = Path(tmp) / "runtime"
            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.object(portal, "DEFAULT_ACTIVE_HANDOFF_ENV", runtime_root / "active-handoff.env"):
                    with patch.object(portal, "_handoff_config_generator_module", return_value=generator):
                        with patch.dict(
                            os.environ,
                            {
                                "DRAFTPAPER_LICENSE_FILE": "",
                                "DRAFTPAPER_CONSOLE_USERS_FILE": "",
                                "DRAFTPAPER_BILLING_RATES_FILE": "",
                                "DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256": "",
                            },
                        ):
                            report = portal.generate_paid_handoff_config_from_console(
                                customer_id="CUST-A",
                                customer_name="Customer A",
                                activate=True,
                                context=portal._local_admin_context(),
                            )
                            active_license = os.environ.get("DRAFTPAPER_LICENSE_FILE")
                            active_users = os.environ.get("DRAFTPAPER_CONSOLE_USERS_FILE")
                            active_billing = os.environ.get("DRAFTPAPER_BILLING_RATES_FILE")
                            active_pin = os.environ.get("DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256")

            files = report["files"]

            self.assertEqual(report["schema_version"], "draftpaper.paid-handoff-config-preparation/v1")
            self.assertEqual(report["status"], "generated")
            self.assertTrue(report["activated_in_process"])
            self.assertEqual(report["token_sha256"], "b" * 64)
            self.assertNotIn("operator-token-value", json.dumps(report))
            self.assertEqual(active_license, files["license"])
            self.assertEqual(active_users, files["users"])
            self.assertEqual(active_billing, files["billing"])
            self.assertEqual(active_pin, "d" * 64)
            self.assertIn("paid_handoff_configs", str(Path(report["output_dir"])))
            self.assertEqual(Path(files["token"]).stat().st_mode & 0o077, 0)

    def test_run_commercial_acceptance_suite_from_console_reverifies_report(self) -> None:
        portal = load_portal_module()
        captured: dict[str, object] = {}

        def fake_run_commercial_acceptance_suite(**kwargs):
            captured.update(kwargs)
            output_dir = Path(kwargs["output_dir"])
            output_dir.mkdir(parents=True, exist_ok=True)
            output_dir.chmod(0o700)
            suite_path = output_dir / "commercial-acceptance-suite.json"
            suite_path.write_text(json.dumps({"schema_version": "draftpaper.commercial-acceptance-suite/v1", "status": "passed"}), encoding="utf-8")
            suite_path.chmod(0o600)
            return {
                "schema_version": "draftpaper.commercial-acceptance-suite/v1",
                "status": "passed",
                "summary": {"steps": 9, "passed": 9, "errors": 0, "warnings": 0},
                "suite_sha256": "e" * 64,
                "output_dir": str(output_dir),
            }

        def fake_verify_commercial_acceptance_suite(path):
            return {"status": "verified", "suite_path": str(path), "summary": {"checks": 10, "errors": 0, "warnings": 0}}

        suite = type("FakeCommercialSuite", (), {"run_commercial_acceptance_suite": staticmethod(fake_run_commercial_acceptance_suite)})
        verifier = type("FakeCommercialSuiteVerifier", (), {"verify_commercial_acceptance_suite": staticmethod(fake_verify_commercial_acceptance_suite)})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime_root = root / "runtime"
            signing_key = root / "signing.pem"
            signing_key.write_text("private key placeholder\n", encoding="utf-8")
            signing_key.chmod(0o600)

            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.object(portal, "_commercial_acceptance_suite_module", return_value=suite):
                    with patch.object(portal, "_commercial_acceptance_suite_verifier_module", return_value=verifier):
                        report = portal.run_commercial_acceptance_suite_from_console(
                            customer_id="CUST-A",
                            customer_name="Customer A",
                            signing_key=str(signing_key),
                            base_url="http://127.0.0.1:4888",
                            token="operator-token",
                            context=portal._local_admin_context(),
                        )

            suite_path = Path(report["suite_path"])

            self.assertEqual(report["schema_version"], "draftpaper.commercial-acceptance-suite-run/v1")
            self.assertEqual(report["status"], "verified")
            self.assertEqual(report["suite_status"], "passed")
            self.assertEqual(report["verification_status"], "verified")
            self.assertEqual(captured["token"], "operator-token")
            self.assertEqual(captured["customer_id"], "CUST-A")
            self.assertEqual(captured["target_track"], "paid_local_handoff")
            self.assertTrue(suite_path.exists())
            self.assertEqual(suite_path.stat().st_mode & 0o077, 0)
            self.assertIn("commercial_acceptance_suites", str(Path(report["output_dir"])))

    def test_build_commercial_operations_report_from_console_reverifies_report(self) -> None:
        portal = load_portal_module()
        captured: dict[str, object] = {}

        def fake_build_commercial_operations_report(**kwargs):
            captured.update(kwargs)
            output = Path(kwargs["output"])
            markdown = Path(kwargs["markdown_output"])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.parent.chmod(0o700)
            output.write_text(json.dumps({"schema_version": "draftpaper.commercial-operations-report/v1", "status": "ready"}), encoding="utf-8")
            output.chmod(0o600)
            markdown.write_text("# Ops\n", encoding="utf-8")
            markdown.chmod(0o600)
            return {
                "schema_version": "draftpaper.commercial-operations-report/v1",
                "status": "ready",
                "summary": {"checks": 12, "errors": 0, "warnings": 0},
                "report_sha256": "f" * 64,
            }

        def fake_verify_commercial_operations_report(path, **kwargs):
            captured["verify_path"] = path
            captured["verify_kwargs"] = kwargs
            return {"status": "verified", "report_path": str(path), "summary": {"checks": 8, "errors": 0, "warnings": 0}}

        builder = type("FakeCommercialOperationsBuilder", (), {"build_commercial_operations_report": staticmethod(fake_build_commercial_operations_report)})
        verifier = type("FakeCommercialOperationsVerifier", (), {"verify_commercial_operations_report": staticmethod(fake_verify_commercial_operations_report)})

        with tempfile.TemporaryDirectory() as tmp:
            runtime_root = Path(tmp) / "runtime"
            launch_package = Path(tmp) / "commercial-launch-package.zip"
            launch_package.write_bytes(b"launch")

            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.object(portal, "_commercial_operations_report_builder_module", return_value=builder):
                    with patch.object(portal, "_commercial_operations_report_verifier_module", return_value=verifier):
                        report = portal.build_commercial_operations_report_from_console(
                            customer_id="CUST-A",
                            customer_name="Customer A",
                            base_url="http://127.0.0.1:4888",
                            token="operator-token",
                            launch_package=str(launch_package),
                            require_launch_package=True,
                            context=portal._local_admin_context(),
                        )

            output_path = Path(report["output_file"])
            markdown_path = Path(report["markdown_output"])

            self.assertEqual(report["schema_version"], "draftpaper.commercial-operations-report-build/v1")
            self.assertEqual(report["status"], "verified")
            self.assertEqual(report["report_status"], "ready")
            self.assertEqual(report["verification_status"], "verified")
            self.assertEqual(captured["token"], "operator-token")
            self.assertEqual(captured["customer_id"], "CUST-A")
            self.assertEqual(captured["target_track"], "paid_local_handoff")
            self.assertTrue(captured["require_launch_package"])
            self.assertEqual(captured["launch_package"], launch_package.resolve())
            self.assertEqual(captured["verify_path"], output_path)
            self.assertEqual(captured["verify_kwargs"]["launch_package"], launch_package.resolve())
            self.assertTrue(captured["verify_kwargs"]["require_ready"])
            self.assertTrue(output_path.exists())
            self.assertTrue(markdown_path.exists())
            self.assertEqual(output_path.stat().st_mode & 0o077, 0)
            self.assertEqual(markdown_path.stat().st_mode & 0o077, 0)
            self.assertIn("commercial_operations_reports", str(output_path))

    def test_install_verified_release_from_console_runs_installer_and_smoke(self) -> None:
        portal = load_portal_module()
        captured: dict[str, object] = {}

        def fake_install_verified_release(**kwargs):
            captured.update(kwargs)
            install_root = Path(kwargs["install_root"])
            install_root.mkdir(parents=True, exist_ok=True)
            install_root.chmod(0o700)
            installed_dir = install_root / "draftpaper-loop-test"
            installed_dir.mkdir()
            manifest = install_root / "draftpaper-install-manifest.json"
            smoke = install_root / "draftpaper-installed-smoke.json"
            manifest.write_text("{}\n", encoding="utf-8")
            smoke.write_text("{}\n", encoding="utf-8")
            manifest.chmod(0o600)
            smoke.chmod(0o600)
            return {
                "schema_version": "draftpaper.install-verified-release/v1",
                "status": "installed",
                "release_zip": str(kwargs["release_zip"]),
                "install_root": str(install_root),
                "installed_dir": str(installed_dir),
                "install_manifest": str(manifest),
                "installed_smoke_output": str(smoke),
                "summary": {"checks": 4, "errors": 0, "warnings": 0},
                "release_verification": {"status": "verified"},
                "dossier_verification": {"status": "verified"},
                "installed_smoke": {"status": "passed", "summary": {"checks": 3, "errors": 0, "warnings": 0}},
            }

        installer = type("FakeVerifiedReleaseInstaller", (), {"install_verified_release": staticmethod(fake_install_verified_release)})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release_zip = root / "draftpaper-loop-test.zip"
            release_manifest = root / "draftpaper-loop-test.manifest.json"
            release_sha = root / "draftpaper-loop-test.zip.sha256"
            release_sig = root / "draftpaper-loop-test.zip.sig"
            release_pub = root / "draftpaper-loop-test.public.pem"
            dossier = root / "handoff-dossier.zip"
            for path in [release_zip, release_manifest, release_sha, release_sig, release_pub, dossier]:
                path.write_text("artifact\n", encoding="utf-8")
            runtime_root = root / "runtime"

            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.object(portal, "_verified_release_installer_module", return_value=installer):
                    report = portal.install_verified_release_from_console(
                        release_zip=str(release_zip),
                        release_manifest=str(release_manifest),
                        release_sha256_file=str(release_sha),
                        release_signature=str(release_sig),
                        release_public_key=str(release_pub),
                        handoff_dossier=str(dossier),
                        require_signature=True,
                        require_dossier=True,
                        run_smoke=True,
                        force=True,
                        context=portal._local_admin_context(),
                    )

            install_root = Path(report["install_root"])
            manifest = Path(report["install_manifest"])
            smoke = Path(report["installed_smoke_output"])

            self.assertEqual(report["schema_version"], "draftpaper.verified-release-install-run/v1")
            self.assertEqual(report["status"], "installed")
            self.assertEqual(report["release_verification_status"], "verified")
            self.assertEqual(report["dossier_verification_status"], "verified")
            self.assertEqual(report["installed_smoke_status"], "passed")
            self.assertEqual(captured["release_zip"], release_zip.resolve())
            self.assertEqual(captured["release_manifest"], release_manifest.resolve())
            self.assertEqual(captured["release_sha256_file"], release_sha.resolve())
            self.assertEqual(captured["release_signature"], release_sig.resolve())
            self.assertEqual(captured["release_public_key"], release_pub.resolve())
            self.assertEqual(captured["handoff_dossier"], dossier.resolve())
            self.assertTrue(captured["require_signature"])
            self.assertTrue(captured["require_dossier"])
            self.assertTrue(captured["run_smoke"])
            self.assertTrue(captured["force"])
            self.assertIn("verified_release_installs", str(install_root))
            self.assertTrue(manifest.exists())
            self.assertTrue(smoke.exists())
            self.assertEqual(manifest.stat().st_mode & 0o077, 0)
            self.assertEqual(smoke.stat().st_mode & 0o077, 0)

    def test_handoff_readiness_blocks_paid_handoff_without_license_or_auth(self) -> None:
        portal = load_portal_module()

        readiness = portal.handoff_readiness()

        tracks = {track["id"]: track for track in readiness["tracks"]}
        paid_gates = {item["id"]: item for item in tracks["paid_local_handoff"]["gates"]}
        self.assertEqual(readiness["commercial_grade"], "local_operator_pilot_ready")
        self.assertEqual(tracks["local_operator_pilot"]["status"], "ready")
        self.assertEqual(tracks["paid_local_handoff"]["status"], "blocked")
        self.assertFalse(paid_gates["commercial_license_valid"]["passed"])
        self.assertFalse(paid_gates["access_control_configured"]["passed"])
        self.assertIn("DRAFTPAPER_LICENSE_FILE", " ".join(readiness["next_required_actions"]))

    def test_hosted_readiness_requires_configured_evidence_file(self) -> None:
        portal = load_portal_module()

        with patch.dict("os.environ", {"DRAFTPAPER_HOSTED_READINESS_FILE": ""}):
            hosted = portal.hosted_readiness_summary()
            readiness = portal.handoff_readiness()

        self.assertEqual(hosted["status"], "not_ready")
        self.assertEqual(hosted["summary"]["passed"], 0)
        tracks = {track["id"]: track for track in readiness["tracks"]}
        self.assertEqual(tracks["hosted_saas"]["status"], "not_ready")
        self.assertIn("DRAFTPAPER_HOSTED_READINESS_FILE", " ".join(readiness["next_required_actions"]))

    def test_handoff_readiness_accepts_verified_hosted_saas_evidence(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            evidence_file = Path(tmp) / "hosted-readiness.json"
            evidence = hosted_readiness_payload()
            attach_hosted_evidence_artifacts(evidence, Path(tmp))
            evidence_file.write_text(json.dumps(evidence), encoding="utf-8")
            evidence_file.chmod(0o600)

            with patch.dict("os.environ", {"DRAFTPAPER_HOSTED_READINESS_FILE": str(evidence_file)}):
                hosted = portal.hosted_readiness_summary()
                readiness = portal.handoff_readiness()

        hosted_gates = {item["id"]: item for item in hosted["gates"]}
        tracks = {track["id"]: track for track in readiness["tracks"]}
        self.assertEqual(hosted["status"], "ready")
        self.assertEqual(hosted["summary"]["passed"], 5)
        self.assertTrue(hosted_gates["hosted_enterprise_auth"]["passed"])
        self.assertTrue(hosted_gates["hosted_payment_collection"]["passed"])
        self.assertEqual(readiness["commercial_grade"], "hosted_saas_ready")
        self.assertEqual(tracks["hosted_saas"]["status"], "ready")

    def test_hosted_readiness_flags_incomplete_evidence(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            evidence = hosted_readiness_payload()
            attach_hosted_evidence_artifacts(evidence, Path(tmp))
            evidence["worker_isolation"] = {
                "status": "verified",
                "queue_backend": "managed-queue",
                "automatic_retries": True,
            }
            evidence_file = Path(tmp) / "hosted-readiness.json"
            evidence_file.write_text(json.dumps(evidence), encoding="utf-8")
            evidence_file.chmod(0o600)

            with patch.dict("os.environ", {"DRAFTPAPER_HOSTED_READINESS_FILE": str(evidence_file)}):
                hosted = portal.hosted_readiness_summary()

        gates = {item["id"]: item for item in hosted["gates"]}
        self.assertEqual(hosted["status"], "attention")
        self.assertFalse(gates["hosted_worker_isolation"]["passed"])
        self.assertIn("missing_fields", gates["hosted_worker_isolation"]["note"])
        self.assertIn("evidence_refs=missing", gates["hosted_worker_isolation"]["note"])

    def test_prepare_hosted_readiness_draft_writes_private_runtime_material(self) -> None:
        portal = load_portal_module()

        def fake_collect_hosted_readiness_evidence(**kwargs):
            output_dir = Path(kwargs["output_dir"])
            output_dir.mkdir(parents=True, exist_ok=True)
            output_dir.chmod(0o700)
            draft = output_dir / "hosted-readiness.draft.json"
            report = output_dir / "hosted-readiness-evidence-collection.json"
            draft.write_text(json.dumps({"schema_version": "draftpaper.hosted-readiness/v1", "environment": kwargs["environment"]}), encoding="utf-8")
            report.write_text(json.dumps({"schema_version": "draftpaper.hosted-readiness-evidence-collection/v1", "status": "collected"}), encoding="utf-8")
            draft.chmod(0o600)
            report.chmod(0o600)
            return {
                "status": "collected",
                "summary": {"errors": 0, "warnings": 0, "artifacts": 2},
                "report_path": str(report),
                "hosted_readiness_draft": {"path": str(draft), "sha256": "a" * 64},
            }

        def fake_write_controls_template(*, collection_report, output_file, force=False):
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(
                json.dumps(
                    {
                        "schema_version": "draftpaper.hosted-readiness-controls/v1",
                        "collection_report": Path(collection_report).name,
                    }
                ),
                encoding="utf-8",
            )
            output_file.chmod(0o600)
            return {"status": "template_written", "path": str(output_file)}

        collector = type("FakeCollector", (), {"collect_hosted_readiness_evidence": staticmethod(fake_collect_hosted_readiness_evidence)})
        preparer = type("FakePreparer", (), {"write_controls_template": staticmethod(fake_write_controls_template)})

        with tempfile.TemporaryDirectory() as tmp:
            runtime_root = Path(tmp) / "runtime"
            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.object(portal, "_hosted_evidence_collector_module", return_value=collector):
                    with patch.object(portal, "_hosted_readiness_preparer_module", return_value=preparer):
                        report = portal.prepare_hosted_readiness_draft(
                            base_url="http://127.0.0.1:4888",
                            token="operator-token",
                            context=portal._local_admin_context(),
                        )

            output_dir = Path(report["output_dir"])
            collection_report = Path(report["collection_report"])
            hosted_draft = Path(report["hosted_readiness_draft"])
            controls_template = Path(report["controls_template"])

            self.assertEqual(report["status"], "prepared")
            self.assertEqual(report["collection_status"], "collected")
            self.assertEqual(report["controls_template_status"], "template_written")
            self.assertIn("hosted_readiness_drafts", str(output_dir))
            self.assertEqual(collection_report.stat().st_mode & 0o077, 0)
            self.assertEqual(hosted_draft.stat().st_mode & 0o077, 0)
            self.assertEqual(controls_template.stat().st_mode & 0o077, 0)

    def test_finalize_hosted_readiness_writes_private_runtime_material(self) -> None:
        portal = load_portal_module()

        def fake_prepare_hosted_readiness(
            *,
            collection_report,
            controls_file,
            output_file,
            report_output,
            force=False,
            write_attention_candidate=False,
        ):
            output_file.parent.mkdir(parents=True, exist_ok=True)
            report_output.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(json.dumps({"schema_version": "draftpaper.hosted-readiness/v1", "status": "ready"}), encoding="utf-8")
            report_output.write_text(json.dumps({"schema_version": "draftpaper.hosted-readiness-preparation/v1", "status": "ready"}), encoding="utf-8")
            output_file.chmod(0o600)
            report_output.chmod(0o600)
            return {
                "schema_version": "draftpaper.hosted-readiness-preparation/v1",
                "status": "ready",
                "collection_report": str(collection_report),
                "controls_file": str(controls_file),
                "output_file": str(output_file),
                "validation": {"status": "ready", "summary": {"errors": 0}},
                "summary": {"checks": 6, "errors": 0, "warnings": 0},
            }

        preparer = type("FakePreparer", (), {"prepare_hosted_readiness": staticmethod(fake_prepare_hosted_readiness)})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime_root = root / "runtime"
            collection_report = root / "hosted-readiness-evidence-collection.json"
            controls_file = root / "hosted-readiness-controls.json"
            collection_report.write_text(json.dumps({"status": "verified"}), encoding="utf-8")
            controls_file.write_text(json.dumps({"status": "verified"}), encoding="utf-8")

            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.object(portal, "_hosted_readiness_preparer_module", return_value=preparer):
                    with patch.dict(os.environ, {"DRAFTPAPER_HOSTED_READINESS_FILE": ""}):
                        report = portal.finalize_hosted_readiness(
                            collection_report=collection_report,
                            controls_file=controls_file,
                            activate=True,
                            context=portal._local_admin_context(),
                        )
                        activated_path = os.environ.get("DRAFTPAPER_HOSTED_READINESS_FILE")

            output_file = Path(report["output_file"])
            report_output = Path(report["report_output"])

            self.assertEqual(report["schema_version"], "draftpaper.hosted-readiness-finalization/v1")
            self.assertEqual(report["status"], "ready")
            self.assertTrue(report["activated_in_process"])
            self.assertEqual(activated_path, str(output_file.resolve()))
            self.assertIn("hosted_readiness_final", str(output_file.parent))
            self.assertEqual(output_file.stat().st_mode & 0o077, 0)
            self.assertEqual(report_output.stat().st_mode & 0o077, 0)

    def test_build_hosted_readiness_dossier_from_console_verifies_zip(self) -> None:
        portal = load_portal_module()

        def fake_build_hosted_readiness_dossier(*, evidence_file, output_dir, output_zip=None, customer_id="", customer_name=""):
            output_dir.mkdir(parents=True, exist_ok=True)
            output_dir.chmod(0o700)
            zip_path = output_zip or output_dir / "hosted-readiness-dossier.zip"
            zip_path.write_bytes(b"zip")
            zip_path.chmod(0o600)
            return {
                "status": "ready",
                "zip_path": str(zip_path),
                "summary": {"checks": 4, "errors": 0, "warnings": 0},
                "customer": {"id": customer_id, "name": customer_name},
                "source": str(evidence_file),
            }

        def fake_verify_hosted_readiness_dossier(path):
            return {"status": "verified", "zip_path": str(path), "summary": {"checks": 6, "errors": 0, "warnings": 0}}

        builder = type("FakeHostedDossierBuilder", (), {"build_hosted_readiness_dossier": staticmethod(fake_build_hosted_readiness_dossier)})
        verifier = type("FakeHostedDossierVerifier", (), {"verify_hosted_readiness_dossier": staticmethod(fake_verify_hosted_readiness_dossier)})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime_root = root / "runtime"
            evidence_file = root / "hosted-readiness.json"
            evidence_file.write_text(json.dumps({"schema_version": "draftpaper.hosted-readiness/v1"}), encoding="utf-8")
            evidence_file.chmod(0o600)

            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.object(portal, "_hosted_readiness_dossier_builder_module", return_value=builder):
                    with patch.object(portal, "_hosted_readiness_dossier_verifier_module", return_value=verifier):
                        report = portal.build_hosted_readiness_dossier_from_console(
                            hosted_readiness_file=str(evidence_file),
                            customer_id="CUST-HOSTED",
                            customer_name="Hosted Customer",
                            context=portal._local_admin_context(),
                        )

            zip_path = Path(report["zip_path"])

            self.assertEqual(report["schema_version"], "draftpaper.hosted-readiness-dossier-build/v1")
            self.assertEqual(report["status"], "verified")
            self.assertEqual(report["verification_status"], "verified")
            self.assertTrue(zip_path.exists())
            self.assertEqual(zip_path.stat().st_mode & 0o077, 0)
            self.assertIn("hosted_readiness_dossiers", str(zip_path.parent))

    def test_run_hosted_production_acceptance_from_console_writes_private_report(self) -> None:
        portal = load_portal_module()
        captured: dict[str, object] = {}

        def fake_run_hosted_production_acceptance(**kwargs):
            captured.update(kwargs)
            return {
                "schema_version": "draftpaper.hosted-production-acceptance/v1",
                "status": "passed",
                "summary": {"checks": 12, "errors": 0, "warnings": 0},
                "evidence_summary": {"base_url": kwargs["base_url"]},
            }

        acceptance = type("FakeHostedAcceptance", (), {"run_hosted_production_acceptance": staticmethod(fake_run_hosted_production_acceptance)})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime_root = root / "runtime"
            evidence_file = root / "hosted-readiness.json"
            dossier_zip = root / "hosted-readiness-dossier.zip"
            evidence_file.write_text(json.dumps({"schema_version": "draftpaper.hosted-readiness/v1"}), encoding="utf-8")
            dossier_zip.write_bytes(b"zip")
            evidence_file.chmod(0o600)
            dossier_zip.chmod(0o600)

            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.object(portal, "_hosted_production_acceptance_module", return_value=acceptance):
                    report = portal.run_hosted_production_acceptance_from_console(
                        base_url="https://draftpaper.example.com",
                        token="operator-token",
                        hosted_readiness_file=str(evidence_file),
                        hosted_readiness_dossier=str(dossier_zip),
                        context=portal._local_admin_context(),
                    )

            output_file = Path(report["output_file"])

            self.assertEqual(report["schema_version"], "draftpaper.hosted-production-acceptance-run/v1")
            self.assertEqual(report["status"], "passed")
            self.assertEqual(captured["base_url"], "https://draftpaper.example.com")
            self.assertEqual(captured["token"], "operator-token")
            self.assertFalse(captured["allow_localhost"])
            self.assertFalse(captured["allow_insecure_http"])
            self.assertTrue(output_file.exists())
            self.assertEqual(output_file.stat().st_mode & 0o077, 0)
            self.assertIn("hosted_production_acceptance", str(output_file.parent))

    def test_handoff_readiness_accepts_configured_paid_local_customer_handoff(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            projects_root = root / "projects"
            runtime_root = root / "runtime"
            license_file = root / "commercial-license-grant.json"
            billing_file = root / "billing-rates.json"
            payload = {
                "schema_version": "draftpaper.commercial-license/v1",
                "license_id": "DPL-COMM-HANDOFF",
                "customer_id": "CUST-HANDOFF",
                "customer_name": "Handoff Customer",
                "grant_type": "paid-local-pilot",
                "issued_at": "2026-07-01",
                "expires_at": "2099-12-31",
                "seats": 3,
                "features": ["local_console", "paper_loop", "backup_restore"],
                "workspaces": ["client-handoff"],
            }
            payload["grant_sha256"] = portal._license_digest(payload)
            license_file.write_text(json.dumps(payload), encoding="utf-8")
            license_file.chmod(0o600)
            billing_file.write_text(json.dumps({"currency": "USD", "rates": {"job": 1.0, "backup": 2.0, "storage_gb_month": 3.0}}), encoding="utf-8")
            billing_file.chmod(0o600)
            project = create_project(root=projects_root, idea="Paid handoff smoke", field="workflow engineering")

            env = {
                "DRAFTPAPER_LICENSE_FILE": str(license_file),
                "DRAFTPAPER_BILLING_RATES_FILE": str(billing_file),
                "DRAFTPAPER_CONSOLE_TOKEN": "handoff-token",
            }
            with patch.dict("os.environ", env):
                with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                    with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                        portal.create_project_backup(project.path.name, context=portal._legacy_token_context())
                        rehearsal = portal.rehearse_project_backups(context=portal._legacy_token_context())
                        self.assertEqual(rehearsal["status"], "passed")
                        readiness = portal.handoff_readiness(context=portal._legacy_token_context())

        tracks = {track["id"]: track for track in readiness["tracks"]}
        self.assertEqual(readiness["commercial_grade"], "paid_local_handoff_ready")
        self.assertEqual(tracks["paid_local_handoff"]["status"], "ready")
        paid_gates = {item["id"]: item for item in tracks["paid_local_handoff"]["gates"]}
        self.assertTrue(paid_gates["commercial_license_valid"]["passed"])
        self.assertTrue(paid_gates["sample_workflow_acceptance"]["passed"])
        self.assertTrue(paid_gates["access_control_configured"]["passed"])
        self.assertTrue(paid_gates["backups_verified"]["passed"])
        self.assertTrue(paid_gates["backup_sample_present"]["passed"])
        self.assertTrue(paid_gates["backup_restore_rehearsal"]["passed"])
        self.assertTrue(paid_gates["billing_rates_configured"]["passed"])

    def test_payload_int_preserves_zero_for_cleanup_requests(self) -> None:
        portal = load_portal_module()

        self.assertEqual(portal._payload_int({"keep": 0}, "keep", 10), 0)
        self.assertEqual(portal._payload_int({"keep": "0"}, "keep", 10), 0)
        self.assertEqual(portal._payload_int({}, "keep", 10), 10)

    def test_optional_console_token_authorizes_operator_api(self) -> None:
        portal = load_portal_module()

        with patch.dict("os.environ", {"DRAFTPAPER_CONSOLE_TOKEN": "secret"}):
            self.assertFalse(portal._path_requires_auth("/health"))
            self.assertFalse(portal._path_requires_auth("/favicon.ico"))
            self.assertTrue(portal._path_requires_auth("/api/projects"))
            self.assertFalse(portal._request_authorized(FakeRequest()))
            self.assertTrue(portal._request_authorized(FakeRequest(token="secret")))
            self.assertTrue(portal._request_authorized(FakeRequest(authorization="Bearer secret")))

    def test_security_audit_flags_public_bind_without_auth(self) -> None:
        portal = load_portal_module()

        with patch.dict("os.environ", {"DRAFTPAPER_HOST": "0.0.0.0", "DRAFTPAPER_CONSOLE_TOKEN": "", "DRAFTPAPER_CONSOLE_USERS_FILE": ""}):
            audit = portal.security_audit()

        self.assertEqual(audit["status"], "attention")
        checks = {item["id"]: item for item in audit["checks"]}
        self.assertFalse(checks["bind_host_auth"]["passed"])

    def test_security_audit_flags_plaintext_or_bad_user_tokens(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            users_file = Path(tmp) / "users.json"
            users_file.write_text(
                json.dumps({"users": [{"id": "bad-user", "role": "operator", "token_sha256": "bad", "token": "plaintext"}]}),
                encoding="utf-8",
            )
            users_file.chmod(0o644)

            with patch.dict("os.environ", {"DRAFTPAPER_CONSOLE_USERS_FILE": str(users_file), "DRAFTPAPER_CONSOLE_TOKEN": ""}):
                audit = portal.security_audit()

        checks = {item["id"]: item for item in audit["checks"]}
        self.assertFalse(checks["users_no_plaintext_tokens"]["passed"])
        self.assertFalse(checks["users_token_hashes"]["passed"])
        self.assertFalse(checks["users_file_permissions"]["passed"])

    def test_security_audit_accepts_hashed_user_policy_for_public_bind(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            users_file = Path(tmp) / "users.json"
            users_file.write_text(
                json.dumps({"users": [{"id": "admin-user", "role": "admin", "token_sha256": token_sha256("admin-token")}]}),
                encoding="utf-8",
            )
            users_file.chmod(0o600)

            with patch.dict("os.environ", {"DRAFTPAPER_HOST": "0.0.0.0", "DRAFTPAPER_CONSOLE_USERS_FILE": str(users_file), "DRAFTPAPER_CONSOLE_TOKEN": ""}):
                audit = portal.security_audit()

        checks = {item["id"]: item for item in audit["checks"]}
        self.assertTrue(checks["bind_host_auth"]["passed"])
        self.assertTrue(checks["users_no_plaintext_tokens"]["passed"])
        self.assertTrue(checks["users_token_hashes"]["passed"])
        self.assertEqual(audit["summary"]["errors"], 0)

    def test_license_grant_reports_unconfigured_without_remote_activation(self) -> None:
        portal = load_portal_module()

        with patch.dict("os.environ", {"DRAFTPAPER_LICENSE_FILE": ""}):
            license_report = portal.license_grant_summary()
            audit = portal.security_audit()

        self.assertEqual(license_report["status"], "unconfigured")
        self.assertFalse(license_report["configured"])
        license_checks = {item["id"]: item for item in license_report["checks"]}
        self.assertFalse(license_checks["license_file_configured"]["passed"])
        self.assertEqual(audit["status"], "passed")
        audit_checks = {item["id"]: item for item in audit["checks"]}
        self.assertFalse(audit_checks["license_file_configured"]["passed"])

    def test_license_grant_validates_offline_customer_handoff_record(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            license_file = Path(tmp) / "commercial-license-grant.json"
            payload = {
                "schema_version": 1,
                "license_id": "DPL-COMM-TEST",
                "customer_id": "CUST-TEST",
                "customer_name": "Customer Test",
                "grant_type": "commercial_pilot",
                "issued_at": "2026-07-03T00:00:00Z",
                "expires_at": "2099-12-31",
                "seats": 3,
                "features": ["local_console", "paper_loop"],
                "workspaces": ["client-test"],
                "terms": "COMMERCIAL_LICENSE.md",
            }
            payload["grant_sha256"] = portal._license_digest(payload)
            license_file.write_text(json.dumps(payload), encoding="utf-8")
            license_file.chmod(0o600)

            with patch.dict("os.environ", {"DRAFTPAPER_LICENSE_FILE": str(license_file)}):
                report = portal.license_grant_summary()
                audit = portal.security_audit()

        self.assertEqual(report["status"], "valid")
        self.assertEqual(report["grant"]["license_id"], "DPL-COMM-TEST")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertTrue(checks["license_hash_matches"]["passed"])
        self.assertTrue(checks["license_no_remote_activation"]["passed"])
        self.assertEqual(report["summary"]["errors"], 0)
        audit_checks = {item["id"]: item for item in audit["checks"]}
        self.assertTrue(audit_checks["license_hash_matches"]["passed"])

    def test_commercial_approval_summary_reports_unconfigured_by_default(self) -> None:
        portal = load_portal_module()

        with patch.dict("os.environ", {"DRAFTPAPER_COMMERCIAL_APPROVAL_FILE": "", "DRAFTPAPER_LICENSE_FILE": ""}):
            report = portal.commercial_approval_summary()

        self.assertEqual(report["status"], "unconfigured")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertFalse(checks["commercial_approval_file_configured"]["passed"])

    def test_prepare_commercial_approval_draft_writes_private_runtime_evidence(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            runtime_root = Path(tmp) / "runtime"
            license_file = Path(tmp) / "private" / "commercial-license-grant.json"
            license_payload = {
                "schema_version": "draftpaper.commercial-license/v1",
                "license_id": "DPL-COMM-APPROVAL-DRAFT",
                "customer_id": "CUST-APPROVAL-DRAFT",
                "customer_name": "Approval Draft Customer",
                "grant_type": "paid-local-pilot",
                "issued_at": "2020-01-01",
                "expires_at": "2030-01-01",
                "seats": 1,
                "features": ["local_console", "paper_loop"],
                "workspaces": ["approval-draft"],
                "terms": "Local paid pilot handoff.",
            }
            license_payload["grant_sha256"] = portal._license_digest(license_payload)
            license_file.parent.mkdir(parents=True, exist_ok=True)
            license_file.write_text(json.dumps(license_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.dict("os.environ", {"DRAFTPAPER_LICENSE_FILE": str(license_file)}):
                    report = portal.prepare_commercial_approval_draft(context=portal._local_admin_context())

            output = Path(report["output"])
            payload = json.loads(output.read_text(encoding="utf-8"))
            output_mode = output.stat().st_mode & 0o077

        self.assertEqual(report["status"], "prepared")
        self.assertEqual(report["approval_status"], "draft")
        self.assertEqual(report["verification_status"], "attention")
        self.assertIn("commercial_approval_drafts", report["output"])
        self.assertEqual(output_mode, 0)
        self.assertEqual(payload["status"], "draft")
        self.assertEqual(payload["license_id"], "DPL-COMM-APPROVAL-DRAFT")

    def test_claim_confirmation_summary_reports_unconfigured_by_default(self) -> None:
        portal = load_portal_module()

        with patch.dict("os.environ", {"DRAFTPAPER_CLAIM_CONFIRMATION_FILE": "", "DRAFTPAPER_CLAIM_CONFIRMATION_PROJECT": ""}):
            report = portal.claim_confirmation_summary()
            readiness = portal.handoff_readiness(context=portal._local_admin_context())

        self.assertEqual(report["status"], "unconfigured")
        self.assertEqual(readiness["claim_confirmation_status"], "unconfigured")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertFalse(checks["claim_confirmation_file_configured"]["passed"])

    def test_prepare_project_claim_confirmation_draft_writes_private_runtime_evidence(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            runtime_root = Path(tmp) / "runtime"
            project = create_project(root=projects_root, idea="Portal claim draft", field="workflow engineering")
            (project.path / "result_validity" / "result_validity_report.json").write_text('{"status":"passed"}\n', encoding="utf-8")
            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                    report = portal.prepare_project_claim_confirmation_draft(
                        project.path.name,
                        claims=["The project has a hash-bound review draft."],
                        context=portal._local_admin_context(),
                    )

            output = Path(report["output"])
            payload = json.loads(output.read_text(encoding="utf-8"))
            output_mode = output.stat().st_mode & 0o077

        self.assertEqual(report["status"], "prepared")
        self.assertEqual(report["confirmation_status"], "draft")
        self.assertEqual(report["verification_status"], "attention")
        self.assertIn("claim_confirmation_drafts", report["output"])
        self.assertEqual(output_mode, 0)
        self.assertEqual(payload["status"], "draft")
        self.assertEqual(payload["claims"][0]["status"], "needs_review")

    def test_release_trust_summary_reports_unconfigured_by_default(self) -> None:
        portal = load_portal_module()

        with patch.dict("os.environ", {"DRAFTPAPER_RELEASE_TRUST_FILE": ""}):
            report = portal.release_trust_summary()
            readiness = portal.handoff_readiness(context=portal._local_admin_context())

        self.assertEqual(report["status"], "unconfigured")
        self.assertEqual(readiness["release_trust_status"], "unconfigured")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertFalse(checks["release_trust_file_configured"]["passed"])

    def test_prepare_release_trust_draft_writes_private_runtime_evidence(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            runtime_root = tmp_path / "runtime"
            release_zip = tmp_path / "draftpaper-loop-test.zip"
            release_zip.write_bytes(b"release zip bytes\n")
            release_manifest = tmp_path / "draftpaper-loop-test.manifest.json"
            release_manifest.write_text(
                json.dumps(
                    {
                        "status": "packaged",
                        "package": "draftpaper-loop-test",
                        "zip_sha256": hashlib.sha256(release_zip.read_bytes()).hexdigest(),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            release_sha256 = tmp_path / "draftpaper-loop-test.zip.sha256"
            release_sha256.write_text(f"{hashlib.sha256(release_zip.read_bytes()).hexdigest()}  draftpaper-loop-test.zip\n", encoding="utf-8")
            release_signature = tmp_path / "draftpaper-loop-test.zip.sig"
            release_signature.write_bytes(b"signature bytes\n")
            release_public_key = tmp_path / "draftpaper-loop-test.public.pem"
            release_public_key.write_text("public key bytes\n", encoding="utf-8")
            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                report = portal.prepare_release_trust_draft(
                    release_zip=release_zip,
                    release_manifest=release_manifest,
                    release_sha256_file=release_sha256,
                    release_signature=release_signature,
                    release_public_key=release_public_key,
                    context=portal._local_admin_context(),
                )

            output = Path(report["output"])
            payload = json.loads(output.read_text(encoding="utf-8"))
            output_mode = output.stat().st_mode & 0o077

        self.assertEqual(report["status"], "prepared")
        self.assertEqual(report["trust_status"], "draft")
        self.assertEqual(report["verification_status"], "attention")
        self.assertIn("release_trust_drafts", report["output"])
        self.assertEqual(output_mode, 0)
        self.assertEqual(payload["status"], "draft")
        self.assertEqual(payload["package"], "draftpaper-loop-test")

    def test_security_review_summary_reports_unconfigured_by_default(self) -> None:
        portal = load_portal_module()

        with patch.dict("os.environ", {"DRAFTPAPER_SECURITY_REVIEW_FILE": ""}):
            report = portal.security_review_summary()
            readiness = portal.handoff_readiness(context=portal._local_admin_context())

        self.assertEqual(report["status"], "unconfigured")
        self.assertEqual(readiness["security_review_status"], "unconfigured")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertFalse(checks["security_review_file_configured"]["passed"])

    def test_prepare_security_review_draft_writes_private_runtime_evidence(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            runtime_root = Path(tmp) / "runtime"
            with patch.object(portal, "RUNTIME_ROOT", runtime_root.resolve()):
                with patch.dict("os.environ", {"DRAFTPAPER_SECURITY_REVIEW_FILE": "", "DRAFTPAPER_SECURITY_AUDIT_FILE": ""}):
                    report = portal.prepare_security_review_draft(context=portal._local_admin_context())

            output = Path(report["output"])
            audit_file = Path(report["security_audit_file"])
            payload = json.loads(output.read_text(encoding="utf-8"))
            output_mode = output.stat().st_mode & 0o077
            audit_mode = audit_file.stat().st_mode & 0o077

        self.assertEqual(report["status"], "prepared")
        self.assertEqual(report["review_status"], "draft")
        self.assertEqual(report["verification_status"], "attention")
        self.assertIn("security_review_drafts", report["output"])
        self.assertEqual(output_mode, 0)
        self.assertEqual(audit_mode, 0)
        self.assertEqual(payload["schema_version"], "draftpaper.security-review/v1")
        self.assertEqual(payload["status"], "draft")
        self.assertTrue(payload["security_audit_sha256"])

    def test_commercial_approval_summary_verifies_private_approval_record(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            license_file = root / "commercial-license-grant.json"
            approval_file = root / "commercial-approval.json"
            license_payload = {
                "schema_version": "draftpaper.commercial-license/v1",
                "license_id": "DPL-COMM-APPROVAL-API",
                "customer_id": "CUST-APPROVAL-API",
                "customer_name": "Approval API Customer",
                "grant_type": "paid-local-pilot",
                "issued_at": "2000-01-01",
                "expires_at": "2099-12-31",
                "seats": 1,
                "features": ["local_console", "paper_loop"],
                "workspaces": ["approval-api"],
            }
            license_payload["grant_sha256"] = portal._license_digest(license_payload)
            license_file.write_text(json.dumps(license_payload), encoding="utf-8")
            license_file.chmod(0o600)
            document_hashes = {
                relative: hashlib.sha256((portal.REPO_ROOT / relative).read_bytes()).hexdigest()
                for relative in ["LICENSE", "NOTICE", "COMMERCIAL_LICENSE.md", "COMPLIANCE.md"]
            }
            approval_payload = {
                "schema_version": "draftpaper.commercial-approval/v1",
                "status": "approved",
                "approval_reference": "LEGAL-2000-API",
                "approval_authority": "external-contract",
                "approved_by": "legal@example.invalid",
                "approved_at": "2000-01-02T00:00:00Z",
                "customer_id": "CUST-APPROVAL-API",
                "customer_name": "Approval API Customer",
                "license_id": "DPL-COMM-APPROVAL-API",
                "scope": ["paid_local_handoff"],
                "evidence_refs": ["contract:LEGAL-2000-API"],
                "license_grant_sha256": license_payload["grant_sha256"],
                "document_hashes": document_hashes,
            }
            approval_file.write_text(json.dumps(approval_payload), encoding="utf-8")
            approval_file.chmod(0o600)

            with patch.dict("os.environ", {"DRAFTPAPER_LICENSE_FILE": str(license_file), "DRAFTPAPER_COMMERCIAL_APPROVAL_FILE": str(approval_file)}):
                report = portal.commercial_approval_summary()
                readiness = portal.handoff_readiness(context=portal._local_admin_context())

        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["summary"]["errors"], 0)
        self.assertEqual(readiness["commercial_approval_status"], "verified")

    def test_license_grant_flags_expired_tampered_or_remote_activation_records(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            license_file = Path(tmp) / "commercial-license-grant.json"
            license_file.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "license_id": "DPL-COMM-BAD",
                        "customer_name": "Customer Bad",
                        "grant_type": "commercial_pilot",
                        "issued_at": "2020-01-01T00:00:00Z",
                        "expires_at": "2020-12-31",
                        "seats": 1,
                        "features": ["local_console"],
                        "remote_check_url": "https://licenses.example.invalid/check",
                        "grant_sha256": "0" * 64,
                    }
                ),
                encoding="utf-8",
            )
            license_file.chmod(0o600)

            with patch.dict("os.environ", {"DRAFTPAPER_LICENSE_FILE": str(license_file)}):
                report = portal.license_grant_summary()

        self.assertEqual(report["status"], "expired")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertFalse(checks["license_not_expired"]["passed"])
        self.assertFalse(checks["license_hash_matches"]["passed"])
        self.assertFalse(checks["license_no_remote_activation"]["passed"])

    def test_license_entitlements_validate_users_against_license_scope(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            license_file = root / "commercial-license-grant.json"
            users_file = root / "console-users.json"
            license_payload = {
                "schema_version": "draftpaper.commercial-license/v1",
                "license_id": "DPL-COMM-ENTITLEMENTS",
                "customer_id": "CUST-ENT",
                "customer_name": "Entitlement Customer",
                "grant_type": "paid-local-pilot",
                "issued_at": "2026-07-03",
                "expires_at": "2099-12-31",
                "seats": 2,
                "features": ["paper_loop"],
                "workspaces": ["client-ent"],
            }
            license_payload["grant_sha256"] = portal._license_digest(license_payload)
            license_file.write_text(json.dumps(license_payload), encoding="utf-8")
            license_file.chmod(0o600)
            users_file.write_text(
                json.dumps(
                    {
                        "users": [
                            {
                                "id": "operator-a",
                                "role": "operator",
                                "workspace": "client-ent",
                                "billing_customer_id": "CUST-ENT",
                                "token_sha256": token_sha256("operator-a"),
                                "allowed_actions": ["*"],
                            },
                            {
                                "id": "viewer-a",
                                "role": "viewer",
                                "workspace": "client-ent",
                                "billing_customer_id": "CUST-ENT",
                                "token_sha256": token_sha256("viewer-a"),
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            users_file.chmod(0o600)

            with patch.dict("os.environ", {"DRAFTPAPER_LICENSE_FILE": str(license_file), "DRAFTPAPER_CONSOLE_USERS_FILE": str(users_file), "DRAFTPAPER_CONSOLE_TOKEN": ""}):
                report = portal.license_entitlement_summary()

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["seat_limit"], 2)
        self.assertEqual(report["subjects_count"], 2)
        self.assertEqual(report["summary"]["errors"], 0)
        checks = {item["id"]: item for item in report["checks"]}
        self.assertTrue(checks["license_entitlement_seat_limit"]["passed"])
        self.assertTrue(checks["license_entitlement_workspace_scope"]["passed"])
        self.assertTrue(checks["license_entitlement_customer_scope"]["passed"])
        self.assertTrue(checks["license_entitlement_action_scope"]["passed"])
        self.assertNotIn("token_sha256", json.dumps(report["subjects"]).lower())

    def test_license_entitlements_flag_seat_workspace_customer_and_action_violations(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            license_file = root / "commercial-license-grant.json"
            users_file = root / "console-users.json"
            license_payload = {
                "schema_version": "draftpaper.commercial-license/v1",
                "license_id": "DPL-COMM-BAD-ENTITLEMENTS",
                "customer_id": "CUST-OK",
                "customer_name": "Bad Entitlement Customer",
                "grant_type": "paid-local-pilot",
                "issued_at": "2026-07-03",
                "expires_at": "2099-12-31",
                "seats": 1,
                "features": ["local_console"],
                "workspaces": ["client-ok"],
            }
            license_payload["grant_sha256"] = portal._license_digest(license_payload)
            license_file.write_text(json.dumps(license_payload), encoding="utf-8")
            license_file.chmod(0o600)
            users_file.write_text(
                json.dumps(
                    {
                        "users": [
                            {
                                "id": "operator-ok",
                                "role": "operator",
                                "workspace": "client-ok",
                                "billing_customer_id": "CUST-OK",
                                "token_sha256": token_sha256("operator-ok"),
                                "allowed_actions": ["status"],
                            },
                            {
                                "id": "operator-bad",
                                "role": "operator",
                                "workspace": "client-other",
                                "billing_customer_id": "CUST-OTHER",
                                "token_sha256": token_sha256("operator-bad"),
                                "allowed_actions": ["write-results"],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            users_file.chmod(0o600)

            with patch.dict("os.environ", {"DRAFTPAPER_LICENSE_FILE": str(license_file), "DRAFTPAPER_CONSOLE_USERS_FILE": str(users_file), "DRAFTPAPER_CONSOLE_TOKEN": ""}):
                report = portal.license_entitlement_summary()

        self.assertEqual(report["status"], "attention")
        self.assertEqual(report["summary"]["errors"], 4)
        checks = {item["id"]: item for item in report["checks"]}
        self.assertFalse(checks["license_entitlement_seat_limit"]["passed"])
        self.assertFalse(checks["license_entitlement_workspace_scope"]["passed"])
        self.assertFalse(checks["license_entitlement_customer_scope"]["passed"])
        self.assertFalse(checks["license_entitlement_action_scope"]["passed"])
        self.assertIn("client-other", report["violations"]["workspaces"])
        self.assertIn("operator-bad", report["violations"]["customers"])
        self.assertIn("operator-bad:write-results", report["violations"]["actions"])

    def test_local_access_policy_authorizes_hashed_tokens_and_scopes_projects(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            allowed = create_project(root=projects_root, idea="Allowed scoped project", field="workflow engineering")
            hidden = create_project(root=projects_root, idea="Hidden scoped project", field="workflow engineering")
            users_file = Path(tmp) / "users.json"
            users_file.write_text(
                json.dumps(
                    {
                        "users": [
                            {
                                "id": "viewer-a",
                                "role": "viewer",
                                "workspace": "client-a",
                                "token_sha256": token_sha256("viewer-token"),
                                "projects": [allowed.path.name],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.dict("os.environ", {"DRAFTPAPER_CONSOLE_USERS_FILE": str(users_file), "DRAFTPAPER_CONSOLE_TOKEN": ""}):
                    context = portal._request_access_context(FakeRequest(token="viewer-token"))
                    self.assertIsNotNone(context)
                    self.assertEqual(context["id"], "viewer-a")
                    self.assertEqual(context["role"], "viewer")
                    self.assertTrue(portal._path_requires_auth("/api/projects"))
                    self.assertTrue(portal._request_authorized(FakeRequest(token="viewer-token")))
                    self.assertFalse(portal._request_authorized(FakeRequest(token="wrong-token")))

                    listed = portal.list_projects(context=context)
                    self.assertEqual([item["slug"] for item in listed], [allowed.path.name])
                    portal._project_from_value(allowed.path.name, context=context)
                    with self.assertRaises(PermissionError):
                        portal._project_from_value(hidden.path.name, context=context)
                    self.assertEqual(portal._visible_actions(context), [])

    def test_local_access_policy_blocks_raw_export_and_restricted_actions(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            project = create_project(root=projects_root, idea="Operator scoped project", field="workflow engineering")
            (project.path / "data" / "raw" / "private.csv").write_text("secret\n", encoding="utf-8")
            users_file = Path(tmp) / "users.json"
            users_file.write_text(
                json.dumps(
                    {
                        "users": [
                            {
                                "id": "operator-a",
                                "role": "operator",
                                "workspace": "client-a",
                                "token_sha256": token_sha256("operator-token"),
                                "projects": [project.path.name],
                                "allowed_actions": ["status"],
                                "can_export_data": False,
                                "max_concurrent_jobs": 1,
                                "daily_job_limit": 10,
                                "daily_backup_limit": 10,
                                "backup_storage_bytes_limit": 1000000,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", Path(tmp) / "runtime"):
                    with patch.dict("os.environ", {"DRAFTPAPER_CONSOLE_USERS_FILE": str(users_file), "DRAFTPAPER_CONSOLE_TOKEN": ""}):
                        context = portal._request_access_context(FakeRequest(token="operator-token"))
                        self.assertIsNotNone(context)
                        archive, _manifest = portal.export_project_archive(project.path.name, context=context)
                        names = set(zipfile.ZipFile(io.BytesIO(archive)).namelist())
                        self.assertNotIn(f"{project.path.name}/data/raw/private.csv", names)
                        with self.assertRaises(PermissionError):
                            portal.export_project_archive(project.path.name, include_data=True, context=context)
                        backup = portal.create_project_backup(project.path.name, context=context)
                        self.assertEqual(backup["project"], project.path.name)
                        self.assertFalse(backup["include_data"])
                        self.assertNotIn("archive_path", backup)
                        self.assertNotIn("manifest_path", backup)
                        with self.assertRaises(PermissionError):
                            portal.create_project_backup(project.path.name, include_data=True, context=context)
                        with self.assertRaises(PermissionError):
                            portal.restore_project_backup(backup["backup_id"], context=context)
                        portal.cli_command("status", {"project": project.path.name}, context=context)
                        with self.assertRaises(PermissionError):
                            portal.cli_command("search-literature-live", {"project": project.path.name}, context=context)

                        portal.JOBS.clear()
                        portal.JOB_PROCESSES.clear()
                        with patch.object(
                            portal,
                            "cli_command",
                            return_value=([portal.PYTHON_BIN, "-c", "import time; time.sleep(30)"], {}),
                        ):
                            job = portal.start_job("status", {"project": project.path.name}, context=context)
                            deadline = time.time() + 5
                            while time.time() < deadline and job["status"] not in {"running", "cancelled"}:
                                time.sleep(0.05)
                            with self.assertRaisesRegex(ValueError, "max concurrent jobs"):
                                portal.start_job("status", {"project": project.path.name}, context=context)
                            portal.cancel_job(job["id"], context=context)
                            deadline = time.time() + 5
                            while time.time() < deadline and job["status"] != "cancelled":
                                time.sleep(0.05)

                        summary = portal.access_policy_summary(context=context)
                        self.assertEqual(summary["users_count"], 1)
                        self.assertEqual(summary["actor"]["id"], "operator-a")
                        self.assertEqual(summary["actor"]["daily_job_limit"], 10)
                        self.assertNotIn("operator-token", json.dumps(summary))

    def test_local_quota_policy_blocks_jobs_backups_storage_and_projects(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            runtime_root = Path(tmp) / "runtime"
            project = create_project(root=projects_root, idea="Quota scoped project", field="workflow engineering")
            users_file = Path(tmp) / "users.json"
            users_file.write_text(
                json.dumps(
                    {
                        "users": [
                            {
                                "id": "quota-operator",
                                "role": "operator",
                                "workspace": "client-quota",
                                "token_sha256": token_sha256("quota-token"),
                                "projects": [project.path.name],
                                "allowed_actions": ["status"],
                                "daily_job_limit": 1,
                                "daily_backup_limit": 1,
                                "backup_storage_bytes_limit": 1000000,
                                "max_projects": 1,
                            },
                            {
                                "id": "tiny-backup-operator",
                                "role": "operator",
                                "workspace": "client-quota",
                                "token_sha256": token_sha256("tiny-backup-token"),
                                "projects": [project.path.name],
                                "allowed_actions": ["status"],
                                "backup_storage_bytes_limit": 1,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                    with patch.dict("os.environ", {"DRAFTPAPER_CONSOLE_USERS_FILE": str(users_file), "DRAFTPAPER_CONSOLE_TOKEN": ""}):
                        context = portal._request_access_context(FakeRequest(token="quota-token"))
                        self.assertIsNotNone(context)
                        portal.JOBS.clear()
                        portal.JOB_PROCESSES.clear()
                        portal.JOBS["job-1"] = {
                            "id": "job-1",
                            "actor": "quota-operator",
                            "workspace": "client-quota",
                            "project": project.path.name,
                            "action": "status",
                            "status": "succeeded",
                            "created_at": time.time(),
                        }
                        with patch.object(
                            portal,
                            "cli_command",
                            return_value=([portal.PYTHON_BIN, "-c", "print('ok')"], {}),
                        ):
                            with self.assertRaisesRegex(PermissionError, "daily job quota"):
                                portal.start_job("status", {"project": project.path.name}, context=context)

                        backup = portal.create_project_backup(project.path.name, context=context)
                        self.assertEqual(backup["project"], project.path.name)
                        with self.assertRaisesRegex(PermissionError, "daily backup quota"):
                            portal.create_project_backup(project.path.name, context=context)

                        tiny_context = portal._request_access_context(FakeRequest(token="tiny-backup-token"))
                        with self.assertRaisesRegex(PermissionError, "backup storage quota"):
                            portal.create_project_backup(project.path.name, context=tiny_context)

                        with self.assertRaisesRegex(PermissionError, "project quota"):
                            portal._enforce_project_quota(context)

                        quota = portal.quota_summary(context=context)
                        self.assertEqual(quota["limits"]["daily_job_limit"], 1)
                        self.assertEqual(quota["limits"]["daily_backup_limit"], 1)
                        self.assertEqual(quota["usage"]["jobs_today"], 1)
                        self.assertEqual(quota["usage"]["backups_today"], 1)
                        self.assertGreater(quota["usage"]["backup_storage_bytes"], 0)

    def test_local_billing_report_uses_configured_rates_and_actor_usage(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            runtime_root = Path(tmp) / "runtime"
            project = create_project(root=projects_root, idea="Billing report smoke", field="workflow engineering")
            users_file = Path(tmp) / "users.json"
            rates_file = Path(tmp) / "rates.json"
            users_file.write_text(
                json.dumps(
                    {
                        "users": [
                            {
                                "id": "billing-operator",
                                "role": "operator",
                                "workspace": "client-billing",
                                "billing_customer_id": "CUST-001",
                                "billing_plan": "pilot-paid",
                                "token_sha256": token_sha256("billing-token"),
                                "projects": [project.path.name],
                                "allowed_actions": ["status"],
                                "daily_job_limit": 10,
                                "daily_backup_limit": 10,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            rates_file.write_text(
                json.dumps(
                    {
                        "currency": "USD",
                        "rates": {
                            "job": 2.5,
                            "backup": 1.25,
                            "backup_gb": 0,
                            "project": 10,
                        },
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                    with patch.dict(
                        "os.environ",
                        {
                            "DRAFTPAPER_CONSOLE_USERS_FILE": str(users_file),
                            "DRAFTPAPER_BILLING_RATES_FILE": str(rates_file),
                            "DRAFTPAPER_CONSOLE_TOKEN": "",
                        },
                    ):
                        context = portal._request_access_context(FakeRequest(token="billing-token"))
                        self.assertIsNotNone(context)
                        portal.JOBS.clear()
                        portal.JOB_PROCESSES.clear()
                        portal.JOBS["job-1"] = {
                            "id": "job-1",
                            "actor": "billing-operator",
                            "workspace": "client-billing",
                            "project": project.path.name,
                            "action": "status",
                            "status": "succeeded",
                            "created_at": time.time(),
                        }
                        backup = portal.create_project_backup(project.path.name, context=context)

                        report = portal.billing_report(context=context)

                        self.assertEqual(report["status"], "reported")
                        self.assertEqual(report["currency"], "USD")
                        self.assertEqual(report["billing_config_status"], "configured")
                        self.assertEqual(len(report["subjects"]), 1)
                        subject = report["subjects"][0]
                        self.assertEqual(subject["billing_customer_id"], "CUST-001")
                        self.assertEqual(subject["billing_plan"], "pilot-paid")
                        self.assertEqual(subject["usage"]["jobs_count"], 1)
                        self.assertEqual(subject["usage"]["backups_count"], 1)
                        self.assertEqual(subject["usage"]["projects_count"], 1)
                        self.assertEqual(subject["amount"], 13.75)
                        self.assertEqual(report["totals"]["amount"], 13.75)
                        self.assertEqual(backup["actor"], "billing-operator")

    def test_project_export_excludes_raw_data_by_default(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            project = create_project(root=tmp, idea="Export package smoke", field="workflow engineering")
            (project.path / "references" / "literature_review_notes.html").write_text("<html>ok</html>", encoding="utf-8")
            (project.path / "data" / "raw" / "private.csv").write_text("secret\n", encoding="utf-8")

            archive, manifest = portal.export_project_archive(project.path)
            names = set(zipfile.ZipFile(io.BytesIO(archive)).namelist())

            self.assertEqual(manifest["status"], "exported")
            self.assertIn("export-package-smoke/project.json", names)
            self.assertIn("export-package-smoke/references/literature_review_notes.html", names)
            self.assertIn("export-package-smoke/export_manifest.json", names)
            self.assertNotIn("export-package-smoke/data/raw/private.csv", names)

    def test_project_export_can_include_raw_data_explicitly(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            project = create_project(root=tmp, idea="Export with data smoke", field="workflow engineering")
            (project.path / "data" / "raw" / "private.csv").write_text("secret\n", encoding="utf-8")

            archive, _manifest = portal.export_project_archive(project.path, include_data=True)
            names = set(zipfile.ZipFile(io.BytesIO(archive)).namelist())

            self.assertIn("export-with-data-smoke/data/raw/private.csv", names)

    def test_project_backup_restore_and_retention_cleanup(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            runtime_root = Path(tmp) / "runtime"
            project = create_project(root=projects_root, idea="Backup restore smoke", field="workflow engineering")
            (project.path / "references" / "literature_review_notes.html").write_text("<html>ok</html>", encoding="utf-8")
            (project.path / "data" / "raw" / "private.csv").write_text("secret\n", encoding="utf-8")

            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                    with patch.dict("os.environ", {"DRAFTPAPER_BACKUPS_DIR": ""}):
                        backup = portal.create_project_backup(project.path.name, reason="unit-test")

                        archive_path = Path(backup["archive_path"])
                        manifest_path = Path(backup["manifest_path"])
                        self.assertTrue(archive_path.exists())
                        self.assertTrue(manifest_path.exists())
                        self.assertEqual(backup["archive_sha256"], portal._sha256_file(archive_path))
                        self.assertFalse(backup["include_data"])

                        with zipfile.ZipFile(archive_path) as archive:
                            names = set(archive.namelist())
                        self.assertIn(f"{project.path.name}/project.json", names)
                        self.assertIn(f"{project.path.name}/export_manifest.json", names)
                        self.assertNotIn(f"{project.path.name}/data/raw/private.csv", names)

                        listed = portal.list_project_backups()
                        self.assertEqual([item["backup_id"] for item in listed], [backup["backup_id"]])

                        shutil.rmtree(project.path)
                        restored = portal.restore_project_backup(backup["backup_id"])
                        self.assertEqual(restored["status"], "restored")
                        self.assertTrue((project.path / "project.json").exists())
                        self.assertFalse((project.path / "data" / "raw" / "private.csv").exists())

                        cleanup = portal.cleanup_project_backups(keep=0)
                        self.assertEqual(cleanup["removed_count"], 1)
                        self.assertFalse(archive_path.exists())
                        self.assertFalse(manifest_path.exists())

    def test_project_backup_restore_rejects_checksum_mismatch(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            runtime_root = Path(tmp) / "runtime"
            project = create_project(root=projects_root, idea="Backup checksum smoke", field="workflow engineering")

            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                    backup = portal.create_project_backup(project.path.name)
                    Path(backup["archive_path"]).write_bytes(b"corrupt")
                    shutil.rmtree(project.path)

                    with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                        portal.restore_project_backup(backup["backup_id"])

    def test_project_backup_verification_reports_valid_and_corrupt_archives(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            runtime_root = Path(tmp) / "runtime"
            project = create_project(root=projects_root, idea="Backup verify smoke", field="workflow engineering")

            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                    backup = portal.create_project_backup(project.path.name)
                    verified = portal.verify_project_backups(record_audit=False)
                    self.assertEqual(verified["status"], "verified")
                    self.assertEqual(verified["summary"]["verified"], 1)
                    self.assertEqual(verified["backups"][0]["status"], "verified")

                    Path(backup["archive_path"]).write_bytes(b"corrupt")
                    attention = portal.verify_project_backups(record_audit=False)
                    self.assertEqual(attention["status"], "attention")
                    self.assertEqual(attention["summary"]["attention"], 1)
                    checks = {item["id"]: item for item in attention["backups"][0]["checks"]}
                    self.assertFalse(checks["archive_sha256"]["passed"])
                    self.assertFalse(checks["zip_readable"]["passed"])

    def test_project_backup_restore_rehearsal_records_passed_and_failed_attempts(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            runtime_root = Path(tmp) / "runtime"
            project = create_project(root=projects_root, idea="Backup rehearsal smoke", field="workflow engineering")

            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                    backup = portal.create_project_backup(project.path.name)
                    before = portal.backup_rehearsal_summary()
                    self.assertEqual(before["status"], "attention")
                    self.assertEqual(before["summary"]["missing_or_stale"], 1)

                    rehearsal = portal.rehearse_project_backups(backup_id=backup["backup_id"])
                    self.assertEqual(rehearsal["status"], "passed")
                    self.assertEqual(rehearsal["summary"]["passed"], 1)
                    self.assertTrue(rehearsal["rehearsals"][0]["temporary_path_removed"])
                    self.assertFalse(any(runtime_root.glob("rehearse-*")))

                    after = portal.backup_rehearsal_summary()
                    self.assertEqual(after["status"], "passed")
                    self.assertEqual(after["summary"]["passed"], 1)
                    events = portal.read_backup_rehearsals(limit=10)
                    self.assertEqual(events[-1]["backup_id"], backup["backup_id"])

                    Path(backup["archive_path"]).write_bytes(b"corrupt")
                    failed = portal.rehearse_project_backups(backup_id=backup["backup_id"], record_audit=False)
                    self.assertEqual(failed["status"], "attention")
                    self.assertEqual(failed["summary"]["failed"], 1)
                    checks = {item["id"]: item for item in failed["rehearsals"][0]["checks"]}
                    self.assertFalse(checks["archive_sha256"]["passed"])

    def test_audit_log_records_and_reads_events(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(portal, "RUNTIME_ROOT", Path(tmp)):
                event = portal.append_audit("unit_test_event", project="demo")
                events = portal.read_audit_events(limit=10)

            self.assertEqual(event["event"], "unit_test_event")
            self.assertEqual(events[-1]["event"], "unit_test_event")
            self.assertEqual(events[-1]["details"]["project"], "demo")

    def test_usage_summary_reports_projects_jobs_and_audit(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            runtime_root = Path(tmp) / "runtime"
            create_project(root=projects_root, idea="Usage summary smoke", field="workflow engineering")
            portal.JOBS.clear()
            portal.JOB_PROCESSES.clear()
            portal.JOBS["job-1"] = {"id": "job-1", "action": "status", "status": "succeeded", "created_at": 1.0}
            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                    portal.append_audit("usage_test")
                    summary = portal.usage_summary()

            self.assertEqual(summary["projects_count"], 1)
            self.assertEqual(summary["jobs_count"], 1)
            self.assertEqual(summary["job_status_counts"]["succeeded"], 1)
            self.assertGreaterEqual(summary["audit_event_count"], 1)

    def test_support_bundle_exports_redacted_diagnostics_without_project_data(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            runtime_root = Path(tmp) / "runtime"
            project = create_project(root=projects_root, idea="Support bundle smoke", field="workflow engineering")
            (project.path / "data" / "raw" / "private.csv").write_text("raw-secret-value\n", encoding="utf-8")
            portal.JOBS.clear()
            portal.JOB_PROCESSES.clear()
            portal.JOBS["support-job"] = {
                "id": "support-job",
                "action": "status",
                "label": "Status",
                "status": "failed",
                "request_payload": {"project": project.path.name, "token": "plain-token", "params": {"secret": "plain-secret"}},
                "events": [{"event": "queued", "status": "queued"}],
                "stdout": "manuscript output should not be bundled",
                "stderr": "private stack trace should not be bundled",
                "created_at": 1.0,
                "returncode": 2,
            }
            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                    portal.append_audit("support_test", token="plain-token", project=project.path.name)
                    archive_bytes, manifest = portal.build_support_bundle()

            self.assertEqual(manifest["status"], "generated")
            self.assertFalse(manifest["privacy"]["includes_project_files"])
            self.assertFalse(manifest["privacy"]["includes_raw_or_processed_data"])
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                names = set(archive.namelist())
                self.assertTrue(any(name.endswith("/support_manifest.json") for name in names))
                self.assertTrue(any(name.endswith("/backup_verification.json") for name in names))
                self.assertTrue(any(name.endswith("/backup_rehearsals.json") for name in names))
                self.assertTrue(any(name.endswith("/handoff_readiness.json") for name in names))
                self.assertTrue(any(name.endswith("/license_entitlements.json") for name in names))
                self.assertTrue(any(name.endswith("/claim_confirmation.json") for name in names))
                self.assertTrue(any(name.endswith("/license_approval.json") for name in names))
                self.assertTrue(any(name.endswith("/release_trust.json") for name in names))
                self.assertTrue(any(name.endswith("/security_review.json") for name in names))
                self.assertTrue(any(name.endswith("/jobs.json") for name in names))
                self.assertFalse(any(name.endswith("data/raw/private.csv") for name in names))
                combined = "\n".join(archive.read(name).decode("utf-8") for name in names if name.endswith(".json"))

            self.assertIn(portal.SUPPORT_REDACTED, combined)
            self.assertNotIn("plain-token", combined)
            self.assertNotIn("plain-secret", combined)
            self.assertNotIn("raw-secret-value", combined)
            self.assertNotIn("manuscript output should not be bundled", combined)
            self.assertNotIn("private stack trace should not be bundled", combined)

    def test_support_bundle_file_from_console_writes_private_verified_zip(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            projects_root = Path(tmp) / "projects"
            runtime_root = Path(tmp) / "runtime"
            create_project(root=projects_root, idea="Support file smoke", field="workflow engineering")

            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                    report = portal.build_support_bundle_file_from_console(context=portal._local_admin_context())

            zip_path = Path(report["zip_path"])

            self.assertEqual(report["schema_version"], "draftpaper.support-bundle-file/v1")
            self.assertEqual(report["status"], "verified")
            self.assertEqual(report["verification_status"], "verified")
            self.assertEqual(report["verification_summary"]["errors"], 0)
            self.assertTrue(zip_path.exists())
            self.assertEqual(zip_path.stat().st_mode & 0o077, 0)
            self.assertEqual(zip_path.parent.stat().st_mode & 0o077, 0)
            self.assertIn("support_bundles", str(zip_path))
            self.assertEqual(report["archive_sha256"], report["verification"]["zip_sha256"])

    def test_max_concurrent_jobs_blocks_new_jobs(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            portal.JOBS.clear()
            portal.JOB_PROCESSES.clear()
            with patch.object(portal, "RUNTIME_ROOT", Path(tmp)):
                with patch.dict("os.environ", {"DRAFTPAPER_MAX_CONCURRENT_JOBS": "1"}):
                    with patch.object(
                        portal,
                        "cli_command",
                        return_value=([portal.PYTHON_BIN, "-c", "import time; time.sleep(30)"], {}),
                    ):
                        job = portal.start_job("status", {})
                        deadline = time.time() + 5
                        while time.time() < deadline and job["status"] not in {"running", "cancelled"}:
                            time.sleep(0.05)

                        with self.assertRaisesRegex(ValueError, "max concurrent jobs"):
                            portal.start_job("status", {})

                        portal.cancel_job(job["id"])
                        deadline = time.time() + 5
                        while time.time() < deadline and job["status"] != "cancelled":
                            time.sleep(0.05)
                        self.assertEqual(job["status"], "cancelled")

    def test_job_events_and_retry_persist_operator_timeline(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            portal.JOBS.clear()
            portal.JOB_PROCESSES.clear()
            projects_root = Path(tmp) / "projects"
            project = create_project(root=projects_root, idea="Retry timeline smoke", field="workflow engineering")
            with patch.object(portal, "PROJECTS_ROOT", projects_root.resolve()):
                with patch.object(portal, "RUNTIME_ROOT", Path(tmp) / "runtime"):
                    with patch.object(
                        portal,
                        "cli_command",
                        return_value=([portal.PYTHON_BIN, "-c", "import sys; sys.exit(7)"], {}),
                    ):
                        job = portal.start_job("status", {"project": project.path.name, "params": {"limit": "1"}})
                        deadline = time.time() + 5
                        while time.time() < deadline and job["status"] not in portal.TERMINAL_JOB_STATUSES:
                            time.sleep(0.05)

                        self.assertEqual(job["status"], "failed")
                        self.assertEqual(job["request_payload"]["project"], project.path.name)
                        events = portal.job_events(job["id"])["events"]
                        self.assertIn("queued", [item["event"] for item in events])
                        self.assertIn("started", [item["event"] for item in events])
                        self.assertIn("finished", [item["event"] for item in events])

                        retry = portal.retry_job(job["id"])
                        retry_job = retry["job"]
                        self.assertEqual(retry["status"], "queued")
                        self.assertEqual(retry_job["retry_of"], job["id"])
                        self.assertEqual(retry_job["attempt"], 2)
                        self.assertEqual(retry_job["request_payload"]["project"], project.path.name)
                        source_events = portal.job_events(job["id"])["events"]
                        self.assertIn("retry_requested", [item["event"] for item in source_events])
                        deadline = time.time() + 5
                        while time.time() < deadline and retry_job["status"] not in portal.TERMINAL_JOB_STATUSES:
                            time.sleep(0.05)

    def test_load_jobs_marks_interrupted_jobs_unknown_with_timeline_event(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            portal.JOBS.clear()
            runtime_root = Path(tmp)
            interrupted = {
                "id": "interrupted-job",
                "action": "status",
                "status": "running",
                "created_at": 1.0,
                "request_payload": {"project": "demo"},
            }
            jobs_dir = runtime_root / "jobs"
            jobs_dir.mkdir(parents=True)
            (jobs_dir / "interrupted-job.json").write_text(json.dumps(interrupted), encoding="utf-8")

            with patch.object(portal, "RUNTIME_ROOT", runtime_root):
                portal._load_jobs()

            loaded = portal.JOBS["interrupted-job"]
            self.assertEqual(loaded["status"], "unknown")
            self.assertIn("console_restarted", [item["event"] for item in loaded["events"]])
            persisted = json.loads((jobs_dir / "interrupted-job.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["status"], "unknown")

    def test_cancel_running_job_marks_it_cancelled(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            portal.JOBS.clear()
            portal.JOB_PROCESSES.clear()
            with patch.object(portal, "RUNTIME_ROOT", Path(tmp)):
                with patch.object(
                    portal,
                    "cli_command",
                    return_value=([portal.PYTHON_BIN, "-c", "import time; time.sleep(30)"], {}),
                ):
                    job = portal.start_job("status", {})
                    deadline = time.time() + 5
                    while time.time() < deadline and job["status"] not in {"running", "cancelled"}:
                        time.sleep(0.05)

                    cancelled = portal.cancel_job(job["id"])
                    self.assertIn(cancelled["status"], {"cancelling", "cancelled"})

                    deadline = time.time() + 5
                    while time.time() < deadline and job["status"] != "cancelled":
                        time.sleep(0.05)

                    self.assertEqual(job["status"], "cancelled")
                    self.assertIsNotNone(job["returncode"])

    def test_cleanup_and_delete_jobs_remove_terminal_job_files(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            portal.JOBS.clear()
            portal.JOB_PROCESSES.clear()
            with patch.object(portal, "RUNTIME_ROOT", Path(tmp)):
                for index in range(3):
                    job = {
                        "id": f"job-{index}",
                        "status": "succeeded",
                        "label": "done",
                        "created_at": float(index),
                    }
                    portal.JOBS[job["id"]] = job
                    portal._persist_job(job)

                cleanup = portal.cleanup_jobs(keep=1)
                self.assertEqual(cleanup["removed_count"], 2)
                self.assertEqual(len(portal.JOBS), 1)

                remaining_id = next(iter(portal.JOBS))
                deleted = portal.delete_job(remaining_id)
                self.assertEqual(deleted["status"], "deleted")
                self.assertFalse((Path(tmp) / "jobs" / f"{remaining_id}.json").exists())


if __name__ == "__main__":
    unittest.main()
