#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]

import sys

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from draftpaper_cli.analysis_code import generate_analysis_code
from draftpaper_cli.data_feasibility import assess_data_feasibility, assess_data_quality, inventory_data
from draftpaper_cli.figure_plan import plan_figures
from draftpaper_cli.method_plan import collect_method_plan
from draftpaper_cli.methods import verify_methods
from draftpaper_cli.orchestrator import status_project
from draftpaper_cli.project_scaffold import create_project
from draftpaper_cli.references import write_reference_outputs
from draftpaper_cli.result_validity import assess_result_validity


SAMPLE_LITERATURE = [
    {
        "title": "Remote sensing NDVI yield proxy analysis",
        "authors": ["A. Liu", "M. Rivera"],
        "year": 2024,
        "abstract": (
            "NDVI-yield association studies use quality-controlled vegetation "
            "indices, transparent correlation diagnostics, and field validation."
        ),
        "publication": "Remote Sensing Methods",
        "doi": "10.0000/draftpaper.sample.001",
        "url": "https://example.org/draftpaper-sample-ndvi",
        "source": "offline_sample",
        "citation_count": 12,
        "deep_summary": {
            "methods": (
                "Linear response, correlation diagnostics, missingness checks, "
                "and transparent result-validity gates for NDVI-yield proxy analysis."
            )
        },
        "citation_weight": 0.95,
    },
    {
        "title": "Auditable vegetation index workflows for pilot agronomy studies",
        "authors": ["S. Chen"],
        "year": 2023,
        "abstract": (
            "Pilot agronomy workflows should separate reproducible feature "
            "generation, data-quality gates, and cautious exploratory claims."
        ),
        "publication": "Journal of Reproducible Agronomy",
        "url": "https://example.org/draftpaper-sample-audit",
        "source": "offline_sample",
        "citation_count": 7,
        "deep_summary": {
            "methods": (
                "The workflow validates tabular inputs, generated figures, scalar "
                "metrics, and the claim boundary before manuscript writing."
            )
        },
        "citation_weight": 0.82,
    },
]


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _read_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return fallback


def _write_sample_data(project_path: Path) -> Path:
    processed = project_path / "data" / "processed" / "wheat_ndvi_yield_proxy.csv"
    processed.parent.mkdir(parents=True, exist_ok=True)
    rows = "\n".join(f"{i},{0.2 + i / 1000:.3f},{i % 8}" for i in range(1, 41))
    processed.write_text("sample_id,ndvi,yield\n" + rows + "\n", encoding="utf-8")
    raw = project_path / "data" / "raw" / "field_clusters.csv"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text("sample_id,cluster\n" + "\n".join(f"{i},{i % 3}" for i in range(1, 101)) + "\n", encoding="utf-8")
    return processed


def _report_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def run_sample_workflow_acceptance(
    *,
    work_dir: Path | None = None,
    keep_work_dir: bool = False,
    output: Path | None = None,
) -> dict[str, Any]:
    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    if work_dir is None:
        temp_dir = tempfile.TemporaryDirectory(prefix="draftpaper-sample-acceptance-")
        root = Path(temp_dir.name)
    else:
        root = work_dir.expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)

    checks: list[dict[str, Any]] = []
    artifacts: dict[str, Any] = {}
    observations: dict[str, Any] = {}
    generated_at = _utc_timestamp()

    try:
        projects_root = root / "projects"
        project = create_project(
            root=projects_root,
            idea="Sample NDVI yield proxy analysis",
            field="remote sensing agronomy",
            target_journal="General Academic Journal",
            overwrite=True,
        )
        project_path = project.path
        artifacts["project"] = _report_path(project_path, root)
        checks.append(_check("project_created", project_path.exists(), "error", artifacts["project"]))

        references = write_reference_outputs(project_path, SAMPLE_LITERATURE, query="offline sample NDVI yield proxy analysis")
        checks.append(_check("references_written", references.get("status") == "written", "error", str(references.get("status") or ""), "Reference import must work from offline sample JSON."))

        research_plan = project_path / "research_plan" / "research_plan.md"
        research_plan.parent.mkdir(parents=True, exist_ok=True)
        research_plan.write_text(
            "# Research Plan\n\n"
            "Use a local processed NDVI-yield proxy table to demonstrate the Draftpaper-loop "
            "data-quality, analysis-code, figure-rendering, and result-validity gates. "
            "The sample is an acceptance fixture, not a scientific claim.\n",
            encoding="utf-8",
        )
        checks.append(_check("research_plan_seeded", research_plan.exists(), "error", "research_plan/research_plan.md"))

        sample_data = _write_sample_data(project_path)
        inventory = inventory_data(project_path)
        quality = assess_data_quality(project_path, required_columns=["ndvi", "yield"])
        feasibility = assess_data_feasibility(project_path, min_rows=30)
        checks.append(_check("sample_data_written", sample_data.exists(), "error", _report_path(sample_data, project_path)))
        checks.append(_check("data_inventory_written", inventory.get("status") == "written", "error", str(inventory.get("status") or "")))
        checks.append(_check("data_quality_passed", quality.get("overall_status") == "pass", "error", str(quality.get("overall_status") or ""), "Sample acceptance data should pass basic quality checks."))
        feasibility_decision = str(feasibility.get("decision") or "")
        checks.append(_check(
            "data_feasibility_reported",
            feasibility_decision in {"pass", "conditional_pass"},
            "error",
            feasibility_decision,
            "Data feasibility must complete for the sample project.",
        ))
        checks.append(_check(
            "data_feasibility_claim_boundary_visible",
            feasibility_decision == "conditional_pass",
            "warning",
            feasibility_decision,
            "The sample fixture should stay clearly bounded as exploratory or pilot evidence.",
        ))

        method_plan = collect_method_plan(
            project_path,
            user_method=(
                "Use data/processed/wheat_ndvi_yield_proxy.csv as the main analysis table "
                "for NDVI and yield association."
            ),
            primary_metric="r2",
            minimum_primary_metric=0.001,
        )
        figures = plan_figures(project_path)
        codegen = generate_analysis_code(project_path)
        verify = verify_methods(
            project_path,
            command=codegen["verify_command"],
            output_files=codegen["declared_outputs"],
            input_data=[str(codegen.get("selected_input_data") or "")],
        )
        validity = assess_result_validity(project_path)
        checks.append(_check("method_plan_written", method_plan.get("status") == "written", "error", str(method_plan.get("status") or "")))
        checks.append(_check("figure_plan_written", figures.get("status") == "written", "error", str(figures.get("status") or "")))
        checks.append(_check("analysis_code_written", codegen.get("status") == "written", "error", str(codegen.get("status") or "")))
        checks.append(_check("method_verification_success", verify.get("status") == "success", "error", str(verify.get("status") or ""), "Generated analysis code must run and produce every declared output."))
        checks.append(_check("method_outputs_complete", not verify.get("missing_outputs"), "error", ", ".join(verify.get("missing_outputs") or []) or "ok"))
        checks.append(_check("figure_quality_clear", not verify.get("figure_quality_issues"), "error", ", ".join(verify.get("figure_quality_issues") or []) or "ok"))

        run_manifest = _read_json(project_path / "methods" / "run_manifest.yaml", {})
        figure_quality = _read_json(project_path / "results" / "figure_quality_report.json", {})
        figure_metadata = _read_json(project_path / "results" / "figure_metadata.json", {})
        validity_decision = str(validity.get("decision") or "")
        generated_figures = figure_metadata.get("figures") if isinstance(figure_metadata.get("figures"), list) else []
        checks.append(_check("figure_quality_report_passed", figure_quality.get("status") == "passed", "error", str(figure_quality.get("status") or ""), "Generated figures must pass the local figure-quality gate."))
        checks.append(_check("generated_figures_present", len(generated_figures) > 0, "error", str(len(generated_figures)), "Sample acceptance must render at least one figure."))
        checks.append(_check(
            "result_validity_gate_reported",
            validity_decision in {"pass", "conditional_pass", "revise_required"},
            "error",
            validity_decision,
            "Result validity must emit a clear gate decision.",
        ))
        checks.append(_check(
            "result_validity_claim_boundary_visible",
            validity_decision != "pass",
            "warning",
            validity_decision,
            "The sample should remain a functional acceptance fixture, not a final scientific claim.",
        ))

        status = status_project(project_path)
        checks.append(_check("orchestrator_status_available", status.get("status") == "reported", "error", str(status.get("status") or "")))

        observations = {
            "project_slug": project.project_slug,
            "selected_input_data": codegen.get("selected_input_data"),
            "declared_output_count": len(codegen.get("declared_outputs") or []),
            "generated_figure_count": len(generated_figures),
            "data_quality": {
                "overall_status": quality.get("overall_status"),
                "issue_count": quality.get("issue_count"),
            },
            "data_feasibility": {
                "decision": feasibility_decision,
                "supported_claim_level": _read_json(project_path / "data" / "data_feasibility_report.json", {}).get("supported_claim_level"),
            },
            "method_metrics": run_manifest.get("metrics") if isinstance(run_manifest.get("metrics"), dict) else {},
            "result_validity": {
                "decision": validity_decision,
                "failure_causes": validity.get("failure_causes") or [],
            },
            "next_action": (status.get("next_action") or {}).get("command"),
        }
        artifacts.update(
            {
                "references": "references/literature_items.json",
                "data_quality": "data/data_quality_report.json",
                "data_feasibility": "data/data_feasibility_report.json",
                "method_code_manifest": "methods/method_code_manifest.json",
                "run_manifest": "methods/run_manifest.yaml",
                "figure_metadata": "results/figure_metadata.json",
                "figure_quality": "results/figure_quality_report.json",
                "result_validity": "results/result_validity_report.json",
            }
        )
    except Exception as exc:
        checks.append(_check("sample_workflow_acceptance_exception", False, "error", str(exc), "Inspect the sample workflow acceptance traceback and fix the failing stage."))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    report = {
        "schema_version": "draftpaper.sample-workflow-acceptance/v1",
        "status": "passed" if not errors else "attention",
        "generated_at": generated_at,
        "work_dir": str(root) if (keep_work_dir or work_dir is not None) else "",
        "work_dir_retained": keep_work_dir or work_dir is not None,
        "artifacts": artifacts,
        "observations": observations,
        "checks": checks,
        "summary": {"checks": len(checks), "errors": len(errors), "warnings": len(warnings)},
        "notes": [
            "This sample acceptance is offline and deterministic.",
            "It proves the local loop can create a project, import references, validate data, generate and run analysis code, render figures, and emit result-validity gates.",
            "It does not certify a real scientific result; domain data and user confirmation are still required for customer papers.",
        ],
    }
    if output is not None:
        output = output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        output.chmod(0o600)
    if temp_dir is not None and keep_work_dir:
        retained = Path(temp_dir.name)
        temp_dir = None
        report["work_dir"] = str(retained)
        report["work_dir_retained"] = True
        if output is not None:
            output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            output.chmod(0o600)
    if temp_dir is not None:
        temp_dir.cleanup()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an offline Draftpaper-loop sample workflow acceptance check.")
    parser.add_argument("--work-dir", default="", help="Optional work directory to retain sample project artifacts.")
    parser.add_argument("--keep-work-dir", action="store_true", help="Retain the temporary work directory when --work-dir is not supplied.")
    parser.add_argument("--output", default="", help="Optional owner-only JSON report path.")
    args = parser.parse_args(argv)
    report = run_sample_workflow_acceptance(
        work_dir=Path(args.work_dir) if args.work_dir else None,
        keep_work_dir=args.keep_work_dir,
        output=Path(args.output) if args.output else None,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
