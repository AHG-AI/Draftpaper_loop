from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_sample_acceptance_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("draftpaper_run_sample_workflow_acceptance", root / "scripts" / "run_sample_workflow_acceptance.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load run_sample_workflow_acceptance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SampleWorkflowAcceptanceTests(unittest.TestCase):
    def test_sample_workflow_acceptance_runs_offline_loop_and_writes_report(self) -> None:
        sample = load_sample_acceptance_module()

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "sample-acceptance.json"
            report = sample.run_sample_workflow_acceptance(work_dir=Path(tmp) / "work", output=output)

            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["summary"]["errors"], 0)
            self.assertTrue(output.exists())
            self.assertEqual(output.stat().st_mode & 0o077, 0)
            checks = {item["id"]: item for item in report["checks"]}
            self.assertTrue(checks["method_verification_success"]["passed"])
            self.assertTrue(checks["figure_quality_report_passed"]["passed"])
            self.assertTrue(checks["result_validity_gate_reported"]["passed"])
            self.assertGreater(report["observations"]["generated_figure_count"], 0)

            project_path = Path(report["work_dir"]) / report["artifacts"]["project"]
            run_manifest = json.loads((project_path / report["artifacts"]["run_manifest"]).read_text(encoding="utf-8"))
            figure_quality = json.loads((project_path / report["artifacts"]["figure_quality"]).read_text(encoding="utf-8"))
            result_validity = json.loads((project_path / report["artifacts"]["result_validity"]).read_text(encoding="utf-8"))
            self.assertEqual(run_manifest["status"], "success")
            self.assertEqual(figure_quality["status"], "passed")
            self.assertIn(result_validity["decision"], {"pass", "conditional_pass", "revise_required"})


if __name__ == "__main__":
    unittest.main()
