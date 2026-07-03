from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_preparer_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_prepare_release_trust", root / "scripts" / "prepare_release_trust.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load prepare_release_trust.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_release_sidecars(tmp: Path, preparer) -> dict[str, Path]:
    release_zip = tmp / "draftpaper-loop-test.zip"
    release_zip.write_bytes(b"release zip bytes\n")
    release_manifest = tmp / "draftpaper-loop-test.manifest.json"
    release_manifest.write_text(
        json.dumps(
            {
                "status": "packaged",
                "package": "draftpaper-loop-test",
                "zip_sha256": preparer._sha256_file(release_zip),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    release_sha256 = tmp / "draftpaper-loop-test.zip.sha256"
    release_sha256.write_text(f"{preparer._sha256_file(release_zip)}  draftpaper-loop-test.zip\n", encoding="utf-8")
    release_signature = tmp / "draftpaper-loop-test.zip.sig"
    release_signature.write_bytes(b"signature bytes\n")
    release_public_key = tmp / "draftpaper-loop-test.public.pem"
    release_public_key.write_text("public key bytes\n", encoding="utf-8")
    return {
        "release_zip": release_zip,
        "release_manifest": release_manifest,
        "release_sha256_file": release_sha256,
        "release_signature": release_signature,
        "release_public_key": release_public_key,
    }


class PrepareReleaseTrustTests(unittest.TestCase):
    def test_prepares_private_draft_bound_to_release_sidecars(self) -> None:
        preparer = load_preparer_module()

        with tempfile.TemporaryDirectory() as tmp:
            paths = write_release_sidecars(Path(tmp), preparer)
            output = Path(tmp) / "private" / "release-trust.json"

            report = preparer.prepare_release_trust(output=output, **paths)
            payload = json.loads(output.read_text(encoding="utf-8"))
            output_mode = output.stat().st_mode & 0o077

        self.assertEqual(report["status"], "prepared")
        self.assertEqual(report["trust_status"], "draft")
        self.assertEqual(report["verification_status"], "attention")
        self.assertEqual(report["package"], "draftpaper-loop-test")
        self.assertEqual(output_mode, 0)
        self.assertEqual(payload["schema_version"], "draftpaper.release-trust/v1")
        self.assertEqual(payload["status"], "draft")
        self.assertTrue(payload["release_zip_sha256"])
        self.assertTrue(payload["release_signature_sha256"])

    def test_verified_evidence_requires_external_trust_fields_and_sidecars(self) -> None:
        preparer = load_preparer_module()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            release_zip = tmp_path / "draftpaper-loop-test.zip"
            release_zip.write_bytes(b"release zip bytes\n")
            output = tmp_path / "private" / "release-trust.json"

            with self.assertRaises(ValueError):
                preparer.prepare_release_trust(output=output, release_zip=release_zip, status="verified")

            paths = write_release_sidecars(tmp_path, preparer)
            report = preparer.prepare_release_trust(
                output=output,
                status="verified",
                trust_authority="external trust authority",
                trust_reference="TRUST-001",
                verified_by="release reviewer",
                verified_at="2020-01-02T00:00:00Z",
                evidence_refs=["trust/TRUST-001"],
                verify=False,
                **paths,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(report["trust_status"], "verified")
        self.assertEqual(report["evidence_refs_count"], 1)
        self.assertEqual(payload["status"], "verified")
        self.assertEqual(payload["trust_reference"], "TRUST-001")


if __name__ == "__main__":
    unittest.main()
