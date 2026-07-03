from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


def load_trust_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_verify_release_trust", root / "scripts" / "verify_release_trust.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load verify_release_trust.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_signed_release(root: Path) -> dict[str, Path | str]:
    package = "draftpaper-loop-trust-test"
    zip_path = root / f"{package}.zip"
    readme_bytes = b"release\n"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{package}/README.md", readme_bytes)
        release_manifest = {
            "schema_version": "draftpaper.release/v1",
            "package": package,
            "missing_required_files": [],
            "files": [{"path": "README.md", "sha256": hashlib.sha256(readme_bytes).hexdigest(), "bytes": len(readme_bytes)}],
        }
        manifest_bytes = json.dumps(release_manifest, sort_keys=True).encode("utf-8")
        archive.writestr(f"{package}/release_manifest.json", manifest_bytes)
        archive.writestr(
            f"{package}/SHA256SUMS",
            f"{hashlib.sha256(readme_bytes).hexdigest()}  README.md\n{hashlib.sha256(manifest_bytes).hexdigest()}  release_manifest.json\n",
        )
    manifest_path = root / f"{package}.manifest.json"
    manifest_path.write_text(json.dumps({"status": "packaged", "package": package, "zip_sha256": sha256(zip_path)}, indent=2) + "\n", encoding="utf-8")
    sha_path = root / f"{package}.zip.sha256"
    sha_path.write_text(f"{sha256(zip_path)}  {zip_path.name}\n", encoding="utf-8")
    private_key = root / "release.key"
    public_key = root / "release.public.pem"
    signature = root / f"{zip_path.name}.sig"
    openssl = shutil.which("openssl")
    if not openssl:
        raise unittest.SkipTest("openssl unavailable")
    subprocess.run([openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private_key)], check=True, capture_output=True)
    subprocess.run([openssl, "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)], check=True, capture_output=True)
    subprocess.run([openssl, "dgst", "-sha256", "-sign", str(private_key), "-out", str(signature), str(zip_path)], check=True, capture_output=True)
    return {
        "package": package,
        "zip": zip_path,
        "manifest": manifest_path,
        "sha": sha_path,
        "signature": signature,
        "public_key": public_key,
    }


class ReleaseTrustTests(unittest.TestCase):
    def test_verifies_release_trust_against_signed_release_sidecars(self) -> None:
        module = load_trust_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release = create_signed_release(root)
            trust_file = root / "release-trust.json"
            payload = {
                "schema_version": module.TRUST_SCHEMA,
                "status": "verified",
                "trust_type": "third_party_release_trust",
                "trust_authority": "external-review-provider",
                "trust_reference": "TRUST-2000-001",
                "verified_by": "release@example.invalid",
                "verified_at": "2000-01-02T00:00:00Z",
                "package": release["package"],
                "evidence_refs": ["third-party-release-review/TRUST-2000-001"],
                "release_zip_sha256": sha256(release["zip"]),
                "release_manifest_sha256": sha256(release["manifest"]),
                "release_sha256_file_sha256": sha256(release["sha"]),
                "release_signature_sha256": sha256(release["signature"]),
                "release_public_key_sha256": sha256(release["public_key"]),
            }
            trust_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            trust_file.chmod(0o600)

            report = module.verify_release_trust(
                trust_file=trust_file,
                release_zip=release["zip"],
                release_manifest=release["manifest"],
                release_sha256_file=release["sha"],
                release_signature=release["signature"],
                release_public_key=release["public_key"],
            )

        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["summary"]["errors"], 0)
        checks = {item["id"]: item for item in report["checks"]}
        self.assertTrue(checks["release_trust_release_package_verified"]["passed"])
        self.assertTrue(checks["release_trust_release_signature_verified"]["passed"])

    def test_flags_tampered_release_and_secret_fields(self) -> None:
        module = load_trust_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release = create_signed_release(root)
            original_zip_hash = sha256(release["zip"])
            release["zip"].write_bytes(release["zip"].read_bytes() + b"tamper")
            trust_file = root / "release-trust.json"
            payload = {
                "schema_version": module.TRUST_SCHEMA,
                "status": "verified",
                "trust_type": "notarization",
                "trust_authority": "notary-provider",
                "trust_reference": "TRUST-2000-002",
                "verified_by": "release@example.invalid",
                "verified_at": "2000-01-02",
                "package": release["package"],
                "evidence_refs": ["notary:TRUST-2000-002"],
                "release_zip_sha256": original_zip_hash,
                "release_signature_sha256": sha256(release["signature"]),
                "token": "plain-token",
            }
            trust_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            trust_file.chmod(0o600)

            report = module.verify_release_trust(
                trust_file=trust_file,
                release_zip=release["zip"],
                release_signature=release["signature"],
                release_public_key=release["public_key"],
            )

        self.assertEqual(report["status"], "attention")
        checks = {item["id"]: item for item in report["checks"]}
        self.assertFalse(checks["release_zip_sha256_matches"]["passed"])
        self.assertFalse(checks["release_trust_no_secret_material"]["passed"])


if __name__ == "__main__":
    unittest.main()
