from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def load_script_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_generate_handoff_config", root / "scripts" / "generate_handoff_config.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load generate_handoff_config.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_portal_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_serviceconsole_app", root / "scripts" / "serviceconsole_app.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load serviceconsole_app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HandoffConfigTests(unittest.TestCase):
    def test_handoff_config_generates_private_runtime_files_accepted_by_portal(self) -> None:
        generator = load_script_module()
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "handoff"
            result = generator.generate_handoff_config(
                output_dir=output_dir,
                customer_id="CUST-LOCAL",
                customer_name="Local Customer",
                expires_at="2099-12-31",
                seats=2,
                operator_token="customer-secret-token",
                job_rate=1.5,
                backup_rate=2.0,
                storage_gb_month_rate=3.0,
            )

            files = result["files"]
            license_path = Path(files["license"])
            users_path = Path(files["users"])
            billing_path = Path(files["billing"])
            env_path = Path(files["env"])
            manifest_path = Path(files["manifest"])
            token_path = Path(files["token"])

            for path in [license_path, users_path, billing_path, env_path, manifest_path, token_path]:
                self.assertTrue(path.exists())
                self.assertEqual(path.stat().st_mode & 0o077, 0)

            license_payload = json.loads(license_path.read_text(encoding="utf-8"))
            users_text = users_path.read_text(encoding="utf-8")
            self.assertEqual(license_payload["grant_sha256"], generator.license_digest(license_payload))
            self.assertNotIn("customer-secret-token", users_text)
            self.assertIn(result["token_sha256"], users_text)
            self.assertEqual(token_path.read_text(encoding="utf-8").strip(), "customer-secret-token")
            self.assertIn("DRAFTPAPER_LICENSE_FILE", env_path.read_text(encoding="utf-8"))

            with patch.dict(
                "os.environ",
                {
                    "DRAFTPAPER_LICENSE_FILE": str(license_path),
                    "DRAFTPAPER_CONSOLE_USERS_FILE": str(users_path),
                    "DRAFTPAPER_BILLING_RATES_FILE": str(billing_path),
                    "DRAFTPAPER_CONSOLE_TOKEN": "",
                },
            ):
                license_report = portal.license_grant_summary()
                security = portal.security_audit()
                billing = portal.billing_report()

            self.assertEqual(license_report["status"], "valid")
            self.assertEqual(security["summary"]["errors"], 0)
            self.assertEqual(billing["billing_config_status"], "configured")

    def test_handoff_config_can_activate_standard_service_console_startup(self) -> None:
        generator = load_script_module()
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "handoff"
            active_env = Path(tmp) / "active-handoff.env"
            result = generator.generate_handoff_config(
                output_dir=output_dir,
                customer_id="CUST-ACTIVE",
                customer_name="Active Customer",
                expires_at="2099-12-31",
                operator_token="active-secret-token",
                job_rate=1.0,
                activate=True,
                active_env_path=active_env,
            )

            active_path = Path(result["files"]["active_env"])
            self.assertTrue(result["activated"])
            self.assertEqual(active_path, active_env.resolve())
            self.assertTrue(active_path.exists())
            self.assertEqual(active_path.stat().st_mode & 0o077, 0)
            self.assertNotIn("active-secret-token", active_path.read_text(encoding="utf-8"))

            with patch.dict(
                "os.environ",
                {
                    "DRAFTPAPER_LICENSE_FILE": "",
                    "DRAFTPAPER_CONSOLE_USERS_FILE": "",
                    "DRAFTPAPER_BILLING_RATES_FILE": "",
                    "DRAFTPAPER_CONSOLE_TOKEN": "",
                },
            ):
                loaded = portal.load_handoff_env_file(active_path)
                license_report = portal.license_grant_summary()
                billing = portal.billing_report()
                access = portal.access_policy_summary()

            self.assertEqual(loaded["status"], "loaded")
            self.assertCountEqual(
                loaded["loaded_keys"],
                ["DRAFTPAPER_LICENSE_FILE", "DRAFTPAPER_CONSOLE_USERS_FILE", "DRAFTPAPER_BILLING_RATES_FILE"],
            )
            self.assertEqual(license_report["status"], "valid")
            self.assertEqual(billing["billing_config_status"], "configured")
            self.assertTrue(access["auth_required"])

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required for license grant signing")
    def test_handoff_config_can_sign_and_verify_license_grant(self) -> None:
        generator = load_script_module()
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            private_key = Path(tmp) / "license-signing.pem"
            subprocess.run(
                [
                    shutil.which("openssl") or "openssl",
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-out",
                    str(private_key),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            result = generator.generate_handoff_config(
                output_dir=Path(tmp) / "handoff",
                customer_id="CUST-SIGNED",
                customer_name="Signed Customer",
                expires_at="2099-12-31",
                operator_token="signed-secret-token",
                license_signing_key=private_key,
            )

            files = result["files"]
            license_path = Path(files["license"])
            signature_path = Path(files["license_signature"])
            public_key_path = Path(files["license_public_key"])
            env_path = Path(files["env"])
            self.assertTrue(result["license_signed"])
            self.assertRegex(files["license_public_key_sha256"], r"^[0-9a-f]{64}$")
            self.assertIn("DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256", env_path.read_text(encoding="utf-8"))
            for path in [license_path, signature_path, public_key_path]:
                self.assertTrue(path.exists())
                self.assertEqual(path.stat().st_mode & 0o077, 0)

            with patch.dict(
                "os.environ",
                {
                    "DRAFTPAPER_LICENSE_FILE": str(license_path),
                    "DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256": files["license_public_key_sha256"],
                },
            ):
                report = portal.license_grant_summary()
            checks = {item["id"]: item for item in report["checks"]}
            self.assertEqual(report["status"], "valid")
            self.assertTrue(report["signature"]["verified"])
            self.assertTrue(report["signature"]["public_key_pin_configured"])
            self.assertTrue(report["signature"]["public_key_pin_matched"])
            self.assertTrue(checks["license_signature_verified"]["passed"])
            self.assertTrue(checks["license_signature_public_key_sha256_matches"]["passed"])
            self.assertTrue(checks["license_public_key_pin"]["passed"])

            with patch.dict(
                "os.environ",
                {
                    "DRAFTPAPER_LICENSE_FILE": str(license_path),
                    "DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256": "0" * 64,
                },
            ):
                bad_pin = portal.license_grant_summary()
            bad_pin_checks = {item["id"]: item for item in bad_pin["checks"]}
            self.assertEqual(bad_pin["status"], "invalid")
            self.assertFalse(bad_pin_checks["license_public_key_pin"]["passed"])

            signature_path.write_bytes(b"corrupt")
            with patch.dict(
                "os.environ",
                {
                    "DRAFTPAPER_LICENSE_FILE": str(license_path),
                    "DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256": files["license_public_key_sha256"],
                },
            ):
                tampered = portal.license_grant_summary()
            tampered_checks = {item["id"]: item for item in tampered["checks"]}
            self.assertEqual(tampered["status"], "invalid")
            self.assertFalse(tampered_checks["license_signature_verified"]["passed"])
            self.assertFalse(tampered_checks["license_signature_sha256_matches"]["passed"])

    def test_handoff_env_loader_rejects_unapproved_environment_keys(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "active-handoff.env"
            env_path.write_text("export DRAFTPAPER_CONSOLE_TOKEN=raw-secret\n", encoding="utf-8")
            env_path.chmod(0o600)

            with self.assertRaises(ValueError):
                portal.load_handoff_env_file(env_path)

    def test_handoff_env_loader_accepts_hosted_readiness_file(self) -> None:
        portal = load_portal_module()

        with tempfile.TemporaryDirectory() as tmp:
            hosted_path = Path(tmp) / "hosted-readiness.json"
            hosted_path.write_text("{}\n", encoding="utf-8")
            env_path = Path(tmp) / "active-handoff.env"
            env_path.write_text(f"export DRAFTPAPER_HOSTED_READINESS_FILE={hosted_path}\n", encoding="utf-8")
            env_path.chmod(0o600)

            with patch.dict("os.environ", {"DRAFTPAPER_HOSTED_READINESS_FILE": ""}):
                loaded = portal.load_handoff_env_file(env_path)
                self.assertEqual(loaded["status"], "loaded")
                self.assertIn("DRAFTPAPER_HOSTED_READINESS_FILE", loaded["loaded_keys"])
                self.assertEqual(Path(os.environ["DRAFTPAPER_HOSTED_READINESS_FILE"]), hosted_path)

    def test_handoff_config_refuses_to_overwrite_without_force(self) -> None:
        generator = load_script_module()

        with tempfile.TemporaryDirectory() as tmp:
            kwargs = {
                "output_dir": Path(tmp) / "handoff",
                "customer_id": "CUST-LOCAL",
                "customer_name": "Local Customer",
                "expires_at": "2099-12-31",
            }
            generator.generate_handoff_config(**kwargs)
            with self.assertRaises(FileExistsError):
                generator.generate_handoff_config(**kwargs)


if __name__ == "__main__":
    unittest.main()
