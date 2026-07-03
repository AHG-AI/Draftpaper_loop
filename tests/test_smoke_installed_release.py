from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_smoke_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_smoke_installed_release", root / "scripts" / "smoke_installed_release.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load smoke_installed_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SmokeInstalledReleaseTests(unittest.TestCase):
    def test_current_checkout_smoke_passes_and_writes_private_report(self) -> None:
        smoke = load_smoke_module()
        root = Path(__file__).resolve().parents[1]

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "installed-smoke.json"
            report = smoke.smoke_installed_release(install_dir=root, output=output)

            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["summary"]["errors"], 0)
            self.assertTrue(output.exists())
            self.assertEqual(output.stat().st_mode & 0o077, 0)

            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(saved["schema_version"], "draftpaper.installed-smoke/v1")
            self.assertEqual(saved["status"], "passed")
            project_smoke = saved["observations"]["project_smoke"]
            self.assertTrue(project_smoke["project_slug"])
            self.assertTrue(project_smoke["pipeline_state"])
            self.assertTrue(project_smoke["next_action"])

    def test_missing_install_files_report_attention(self) -> None:
        smoke = load_smoke_module()

        with tempfile.TemporaryDirectory() as tmp:
            report = smoke.smoke_installed_release(install_dir=Path(tmp), skip_project_smoke=True)

            self.assertEqual(report["status"], "attention")
            checks = {item["id"]: item for item in report["checks"]}
            self.assertFalse(checks["required_files_present"]["passed"])
            self.assertIn("LICENSE", checks["required_files_present"]["note"])


if __name__ == "__main__":
    unittest.main()
