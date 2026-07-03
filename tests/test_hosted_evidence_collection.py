from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def load_collector_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_collect_hosted_readiness_evidence", root / "scripts" / "collect_hosted_readiness_evidence.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load collect_hosted_readiness_evidence.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_verifier_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_verify_hosted_evidence_collection", root / "scripts" / "verify_hosted_evidence_collection.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load verify_hosted_evidence_collection.py")
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
                self.send_header("X-Draftpaper-Token", "should-not-be-stored")
                self.send_header("Set-Cookie", "session=should-not-be-stored")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return Handler


def hosted_payloads() -> dict[str, object]:
    hosted_track = {"id": "hosted_saas", "status": "not_ready", "summary": {"total": 7, "passed": 2, "errors": 5}, "gates": []}
    return {
        "/health": {"status": "ok"},
        "/api/commercial-readiness": {"status": "assessed", "commercial_grade": "paid_local_handoff_ready"},
        "/api/handoff-readiness": {"status": "assessed", "commercial_grade": "paid_local_handoff_ready", "tracks": [hosted_track]},
        "/api/hosted-readiness": {"status": "not_ready", "summary": {"gates": 5, "passed": 0, "errors": 5}, "gates": []},
        "/api/security-audit": {"status": "passed", "summary": {"errors": 0, "warnings": 0}, "authorization": "should-not-be-stored"},
        "/api/access-policy": {"status": "configured"},
        "/api/quota": {"status": "configured"},
        "/api/billing": {"status": "configured"},
        "/api/license": {"status": "valid"},
        "/api/license-entitlements": {"status": "passed"},
        "/api/backups/verify": {"status": "verified"},
        "/api/backups/rehearsals": {"status": "passed"},
    }


class HostedEvidenceCollectionTests(unittest.TestCase):
    def test_collects_rehearsal_artifacts_and_draft_template(self) -> None:
        collector = load_collector_module()
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp, FakeHostedConsole(hosted_payloads()) as console:
            report = collector.collect_hosted_readiness_evidence(
                base_url=console.url,
                output_dir=Path(tmp) / "collection",
                token="operator-token-value",
                allow_localhost=True,
                allow_insecure_http=True,
                timeout=3,
            )

            self.assertEqual(report["status"], "collected")
            self.assertEqual(report["summary"]["errors"], 0)
            draft_path = Path(report["hosted_readiness_draft"]["path"])
            self.assertTrue(draft_path.exists())
            self.assertEqual(draft_path.stat().st_mode & 0o077, 0)
            draft = json.loads(draft_path.read_text(encoding="utf-8"))
            self.assertEqual(draft["schema_version"], "draftpaper.hosted-readiness/v1")
            self.assertEqual(draft["deployment_hardening"]["status"], "pending")
            self.assertTrue(draft["managed_storage_dr"]["evidence"])

            security_artifact = Path(report["artifacts"]["security_audit"]["path"])
            security_payload = json.loads(security_artifact.read_text(encoding="utf-8"))
            serialized = json.dumps(security_payload)
            self.assertNotIn("operator-token-value", serialized)
            self.assertNotIn("should-not-be-stored", serialized)
            self.assertFalse(collector._contains_sensitive_key(security_payload))
            self.assertTrue(report["collection_sha256"])

            verification = verifier.verify_hosted_evidence_collection(Path(report["report_path"]))

            self.assertEqual(verification["status"], "verified")
            self.assertEqual(verification["summary"]["errors"], 0)
            self.assertEqual(verification["collection_sources"]["health_status"], "ok")
            self.assertEqual(verification["collection_sources"]["hosted_status"], "not_ready")

    def test_local_http_is_attention_without_rehearsal_flags(self) -> None:
        collector = load_collector_module()
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp, FakeHostedConsole(hosted_payloads()) as console:
            report = collector.collect_hosted_readiness_evidence(
                base_url=console.url,
                output_dir=Path(tmp) / "collection",
                timeout=3,
            )
            strict_verification = verifier.verify_hosted_evidence_collection(Path(report["report_path"]))
            relaxed_verification = verifier.verify_hosted_evidence_collection(Path(report["report_path"]), require_collected=False)

            self.assertEqual(relaxed_verification["status"], "verified")
        self.assertEqual(report["status"], "attention")
        failed = {item["id"] for item in report["checks"] if item["severity"] == "error" and not item["passed"]}
        self.assertIn("base_url_not_localhost", failed)
        self.assertIn("base_url_https", failed)
        self.assertEqual(strict_verification["status"], "attention")

    def test_refuses_non_empty_output_without_force(self) -> None:
        collector = load_collector_module()

        with tempfile.TemporaryDirectory() as tmp, FakeHostedConsole(hosted_payloads()) as console:
            output_dir = Path(tmp) / "collection"
            output_dir.mkdir()
            (output_dir / "existing.txt").write_text("keep me\n", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                collector.collect_hosted_readiness_evidence(
                    base_url=console.url,
                    output_dir=output_dir,
                    allow_localhost=True,
                    allow_insecure_http=True,
                    timeout=3,
                )

    def test_verifier_rejects_tampered_artifact_hash(self) -> None:
        collector = load_collector_module()
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp, FakeHostedConsole(hosted_payloads()) as console:
            report = collector.collect_hosted_readiness_evidence(
                base_url=console.url,
                output_dir=Path(tmp) / "collection",
                allow_localhost=True,
                allow_insecure_http=True,
                timeout=3,
            )
            health_artifact = Path(report["artifacts"]["health"]["path"])
            health_artifact.write_text('{"schema_version":"draftpaper.hosted-api-probe/v1","path":"/health","status_code":500}\n', encoding="utf-8")

            verification = verifier.verify_hosted_evidence_collection(Path(report["report_path"]))

        self.assertEqual(verification["status"], "attention")
        failed = {item["id"] for item in verification["checks"] if item["severity"] == "error" and not item["passed"]}
        self.assertIn("artifact_health_sha256_matches", failed)

    def test_verifier_rejects_draft_that_marks_external_controls_verified(self) -> None:
        collector = load_collector_module()
        verifier = load_verifier_module()

        with tempfile.TemporaryDirectory() as tmp, FakeHostedConsole(hosted_payloads()) as console:
            report = collector.collect_hosted_readiness_evidence(
                base_url=console.url,
                output_dir=Path(tmp) / "collection",
                allow_localhost=True,
                allow_insecure_http=True,
                timeout=3,
            )
            draft_path = Path(report["hosted_readiness_draft"]["path"])
            draft = json.loads(draft_path.read_text(encoding="utf-8"))
            draft["enterprise_auth"]["status"] = "verified"
            draft["enterprise_auth"]["mfa_supported"] = True
            draft_path.write_text(json.dumps(draft), encoding="utf-8")

            verification = verifier.verify_hosted_evidence_collection(Path(report["report_path"]))

        self.assertEqual(verification["status"], "attention")
        failed = {item["id"] for item in verification["checks"] if item["severity"] == "error" and not item["passed"]}
        self.assertIn("hosted_readiness_draft_sha256_matches", failed)
        self.assertIn("hosted_readiness_draft_pending", failed)


if __name__ == "__main__":
    unittest.main()
