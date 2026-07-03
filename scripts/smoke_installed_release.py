#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


REQUIRED_FILES = [
    "LICENSE",
    "COMMERCIAL_LICENSE.md",
    "COMPLIANCE.md",
    "pyproject.toml",
    "service-console.manifest.json",
    ".dockerignore",
    "deploy/production/Dockerfile",
    "deploy/production/docker-compose.example.yml",
    "deploy/production/draftpaper-loop.env.example",
    "deploy/production/draftpaper-loop.service",
    "draftpaper_cli/__init__.py",
    "draftpaper_cli/cli.py",
    "draftpaper_cli/project_scaffold.py",
    "draftpaper_cli/orchestrator.py",
    "scripts/deploy_local.sh",
    "scripts/build_commercial_launch_package.py",
    "scripts/build_commercial_operations_report.py",
    "scripts/build_hosted_readiness_dossier.py",
    "scripts/collect_hosted_readiness_evidence.py",
    "scripts/install_verified_release.py",
    "scripts/prepare_commercial_approval.py",
    "scripts/prepare_hosted_readiness.py",
    "scripts/prepare_claim_confirmation.py",
    "scripts/prepare_release_trust.py",
    "scripts/prepare_security_review.py",
    "scripts/run_commercial_acceptance_suite.py",
    "scripts/run_hosted_production_acceptance.py",
    "scripts/run_sample_workflow_acceptance.py",
    "scripts/smoke_installed_release.py",
    "scripts/validate_hosted_readiness.py",
    "scripts/verify_claim_confirmation.py",
    "scripts/verify_commercial_approval.py",
    "scripts/verify_commercial_launch_package.py",
    "scripts/verify_commercial_acceptance_suite.py",
    "scripts/verify_commercial_operations_report.py",
    "scripts/verify_hosted_evidence_collection.py",
    "scripts/verify_hosted_readiness_dossier.py",
    "scripts/verify_production_deployment_artifacts.py",
    "scripts/verify_release_package.py",
    "scripts/verify_release_trust.py",
    "scripts/verify_security_review.py",
    "scripts/verify_handoff_dossier.py",
    "scripts/verify_support_bundle.py",
]


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _python_env(install_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    current = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(install_dir) + (os.pathsep + current if current else "")
    return env


def _run_python(install_dir: Path, args: list[str], *, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=install_dir,
        env=_python_env(install_dir),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def smoke_installed_release(
    *,
    install_dir: Path,
    output: Path | None = None,
    skip_project_smoke: bool = False,
) -> dict[str, Any]:
    install_dir = install_dir.expanduser().resolve()
    checks: list[dict[str, Any]] = []
    observations: dict[str, Any] = {}

    checks.append(_check("install_dir_exists", install_dir.exists() and install_dir.is_dir(), "error", str(install_dir), "Run scripts/install_verified_release.py first."))
    missing = [relative for relative in REQUIRED_FILES if not (install_dir / relative).exists()]
    checks.append(_check("required_files_present", not missing, "error", ", ".join(missing) if missing else "ok", "Install a complete release package."))

    manifest_path = install_dir / "service-console.manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        checks.append(_check("service_console_manifest_readable", manifest.get("schema_version") == "ahouse.service-console/v1", "error", str(manifest.get("schema_version") or "")))
        observations["service_console"] = {
            "name": manifest.get("name"),
            "access_urls": len(manifest.get("access_urls") or []),
        }
    except Exception as exc:
        checks.append(_check("service_console_manifest_readable", False, "error", str(exc)))

    for relative in ["scripts/serviceconsole_app.py", "scripts/install_verified_release.py", "scripts/run_commercial_acceptance_suite.py", "scripts/verify_commercial_acceptance_suite.py", "scripts/run_hosted_production_acceptance.py", "scripts/run_sample_workflow_acceptance.py", "scripts/smoke_installed_release.py", "scripts/build_commercial_launch_package.py", "scripts/verify_commercial_launch_package.py", "scripts/build_commercial_operations_report.py", "scripts/verify_commercial_operations_report.py", "scripts/verify_production_deployment_artifacts.py", "scripts/collect_hosted_readiness_evidence.py", "scripts/verify_hosted_evidence_collection.py", "scripts/prepare_commercial_approval.py", "scripts/prepare_hosted_readiness.py", "scripts/prepare_claim_confirmation.py", "scripts/prepare_release_trust.py", "scripts/prepare_security_review.py", "scripts/validate_hosted_readiness.py", "scripts/verify_claim_confirmation.py", "scripts/verify_commercial_approval.py", "scripts/verify_release_trust.py", "scripts/verify_security_review.py"]:
        path = install_dir / relative
        if not path.exists():
            checks.append(_check(f"py_compile_{Path(relative).stem}", False, "error", f"{relative} missing"))
            continue
        completed = _run_python(install_dir, ["-m", "py_compile", relative])
        checks.append(_check(f"py_compile_{Path(relative).stem}", completed.returncode == 0, "error", (completed.stderr or completed.stdout or "ok").strip()))

    help_completed = _run_python(install_dir, ["-m", "draftpaper_cli.cli", "--help"])
    checks.append(_check("cli_help", help_completed.returncode == 0 and "create-project" in help_completed.stdout, "error", (help_completed.stderr or help_completed.stdout[:200] or "").strip(), "Check Python dependencies and package import path."))

    if skip_project_smoke:
        checks.append(_check("project_create_status_smoke", True, "info", "skipped"))
    else:
        script = """
import json
import tempfile
from draftpaper_cli.project_scaffold import create_project
from draftpaper_cli.orchestrator import status_project
with tempfile.TemporaryDirectory() as tmp:
    project = create_project(root=tmp, idea="Installed smoke project", field="workflow engineering")
    status = status_project(project.path)
    print(json.dumps({
        "project_slug": project.project_slug,
        "pipeline_state": status.get("pipeline_state"),
        "next_action": (status.get("next_action") or {}).get("command"),
    }, sort_keys=True))
"""
        project_completed = _run_python(install_dir, ["-c", script])
        if project_completed.returncode == 0:
            try:
                observations["project_smoke"] = json.loads(project_completed.stdout.strip().splitlines()[-1])
                project_ok = bool(observations["project_smoke"].get("pipeline_state"))
            except Exception:
                project_ok = False
        else:
            project_ok = False
        checks.append(_check("project_create_status_smoke", project_ok, "error", (project_completed.stderr or project_completed.stdout or "").strip(), "Verify draftpaper_cli can create a project and compute status in this install."))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    report = {
        "schema_version": "draftpaper.installed-smoke/v1",
        "status": "passed" if not errors else "attention",
        "generated_at": _utc_timestamp(),
        "install_dir": str(install_dir),
        "python": sys.executable,
        "observations": observations,
        "checks": checks,
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "notes": [
            "This smoke test is local-only and does not run external literature search, hosted services, customer jobs, or data imports.",
        ],
    }
    if output is not None:
        output = output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        output.chmod(0o600)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a local smoke test against an extracted Draftpaper-loop release.")
    parser.add_argument("--install-dir", required=True)
    parser.add_argument("--output", default="")
    parser.add_argument("--skip-project-smoke", action="store_true")
    args = parser.parse_args(argv)
    report = smoke_installed_release(
        install_dir=Path(args.install_dir),
        output=Path(args.output) if args.output else None,
        skip_project_smoke=args.skip_project_smoke,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
