from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_script(name: str):
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(f"draftpaper_{name}", root / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evidence_item(item_id: str, *, required: bool, passed: bool, status: str = "verified") -> dict[str, object]:
    return {
        "id": item_id,
        "label": item_id.replace("_", " ").title(),
        "status": status,
        "passed": passed,
        "required": required,
        "required_for": ["paid_local_handoff", "hosted_saas"] if item_id != "hosted_readiness" else ["hosted_saas"],
        "configured": passed,
        "evidence_paths": {},
        "summary": {"checks": 1, "passed": 1 if passed else 0, "errors": 0 if passed else 1, "warnings": 0},
        "blocking": required and not passed,
        "next_action": "" if passed else f"Configure {item_id}.",
    }


def write_pack(root: Path, pack: dict[str, object], verifier) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    json_path = root / "commercial-evidence-pack.json"
    markdown_path = root / "commercial-evidence-pack.md"
    pack["output_dir"] = str(root)
    pack["json_path"] = str(json_path)
    pack["markdown_path"] = str(markdown_path)
    pack["pack_sha256"] = verifier.commercial_evidence_pack_digest(pack)
    json_path.write_text(json.dumps(pack, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(
        "\n".join(
            [
                "# Draftpaper Commercial Evidence Pack",
                "",
                f"Target track: {pack['target_track']}",
                f"Status: {pack['status']}",
                "",
                "Claim Confirmation",
                "Commercial Approval",
                "Release Trust",
                "Security Review",
                "Hosted Readiness",
                "",
            ]
        ),
        encoding="utf-8",
    )
    json_path.chmod(0o600)
    markdown_path.chmod(0o600)
    return json_path


def ready_paid_pack() -> dict[str, object]:
    evidence = [
        evidence_item("claim_confirmation", required=True, passed=True),
        evidence_item("commercial_approval", required=True, passed=True),
        evidence_item("release_trust", required=True, passed=True),
        evidence_item("security_review", required=True, passed=True),
        evidence_item("hosted_readiness", required=False, passed=False, status="not_ready"),
    ]
    return {
        "schema_version": "draftpaper.commercial-evidence-pack/v1",
        "status": "ready",
        "generated_at": "2026-07-03T00:00:00Z",
        "target_track": "paid_local_handoff",
        "commercial_grade": "paid_local_handoff_ready",
        "readiness_tracks": [],
        "evidence": evidence,
        "blocking_evidence_ids": [],
        "next_actions": [],
        "reports": {
            "claim_confirmation": {"status": "verified"},
            "commercial_approval": {"status": "verified"},
            "release_trust": {"status": "verified"},
            "security_review": {"status": "verified"},
            "hosted_readiness": {"status": "not_ready"},
        },
        "notes": ["private operator material"],
    }


class CommercialEvidencePackTests(unittest.TestCase):
    def test_verifier_accepts_ready_paid_handoff_pack(self) -> None:
        verifier = load_script("verify_commercial_evidence_pack")

        with tempfile.TemporaryDirectory() as tmp:
            pack_path = write_pack(Path(tmp) / "pack", ready_paid_pack(), verifier)
            report = verifier.verify_commercial_evidence_pack(pack_path)

        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["summary"]["errors"], 0)
        checks = {item["id"]: item for item in report["checks"]}
        self.assertTrue(checks["evidence_pack_sha256_matches"]["passed"])
        self.assertTrue(checks["paid_external_evidence_required"]["passed"])
        self.assertTrue(checks["blocking_ids_match_evidence"]["passed"])

    def test_verifier_allows_attention_pack_only_when_requested(self) -> None:
        verifier = load_script("verify_commercial_evidence_pack")

        with tempfile.TemporaryDirectory() as tmp:
            pack = ready_paid_pack()
            evidence = pack["evidence"]
            assert isinstance(evidence, list)
            approval = evidence[1]
            assert isinstance(approval, dict)
            approval["passed"] = False
            approval["status"] = "unconfigured"
            approval["configured"] = False
            approval["blocking"] = True
            approval["next_action"] = "Configure commercial approval."
            pack["status"] = "attention"
            pack["commercial_grade"] = "local_operator_pilot_ready"
            pack["blocking_evidence_ids"] = ["commercial_approval"]
            pack["next_actions"] = ["Configure commercial approval."]
            pack_path = write_pack(Path(tmp) / "pack", pack, verifier)
            strict = verifier.verify_commercial_evidence_pack(pack_path)
            allowed = verifier.verify_commercial_evidence_pack(pack_path, require_ready=False)

        self.assertEqual(strict["status"], "attention")
        strict_failed = {item["id"]: item for item in strict["checks"] if not item["passed"]}
        self.assertIn("evidence_pack_status_ready", strict_failed)
        self.assertEqual(allowed["status"], "verified")

    def test_verifier_rejects_tampered_digest_and_private_key_paths(self) -> None:
        verifier = load_script("verify_commercial_evidence_pack")

        with tempfile.TemporaryDirectory() as tmp:
            pack = ready_paid_pack()
            evidence = pack["evidence"]
            assert isinstance(evidence, list)
            trust = evidence[2]
            assert isinstance(trust, dict)
            trust["evidence_paths"] = {"release_private_key": "/tmp/license-signing.pem"}
            pack_path = write_pack(Path(tmp) / "pack", pack, verifier)
            payload = json.loads(pack_path.read_text(encoding="utf-8"))
            payload["target_track"] = "hosted_saas"
            pack_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            pack_path.chmod(0o600)
            report = verifier.verify_commercial_evidence_pack(pack_path)

        self.assertEqual(report["status"], "attention")
        failed = {item["id"]: item for item in report["checks"] if not item["passed"]}
        self.assertIn("evidence_pack_sha256_matches", failed)
        self.assertIn("forbidden_private_key_paths_excluded", failed)
        self.assertIn("hosted_readiness_required_for_hosted_track", failed)


if __name__ == "__main__":
    unittest.main()
