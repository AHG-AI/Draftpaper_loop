#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from run_commercial_acceptance_suite import SUITE_SCHEMA  # noqa: E402
from run_commercial_acceptance_suite import _digest as suite_digest  # noqa: E402
from verify_commercial_launch_package import verify_commercial_launch_package  # noqa: E402
from verify_commercial_operations_report import verify_commercial_operations_report  # noqa: E402
from verify_handoff_dossier import verify_handoff_dossier  # noqa: E402
from verify_release_package import verify_release_package  # noqa: E402
from verify_support_bundle import verify_support_bundle  # noqa: E402


SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")
EXPECTED_STEPS = [
    "release_packaged",
    "release_verified",
    "handoff_acceptance",
    "handoff_dossier_built",
    "handoff_dossier_verified",
    "commercial_launch_package_built",
    "commercial_launch_package_verified",
    "commercial_operations_report_built",
    "commercial_operations_report_verified",
]


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_path(suite: dict[str, Any], role: str) -> Path | None:
    artifacts = suite.get("artifacts") if isinstance(suite.get("artifacts"), dict) else {}
    record = artifacts.get(role) if isinstance(artifacts, dict) else None
    if not isinstance(record, dict):
        return None
    raw = str(record.get("path") or "").strip()
    return Path(raw).expanduser() if raw else None


def _artifact_record_checks(suite: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    artifacts = suite.get("artifacts") if isinstance(suite.get("artifacts"), dict) else {}
    if not isinstance(artifacts, dict):
        return [_check("artifact_records_present", False, "error", "artifacts is missing")]
    for role, record in sorted(artifacts.items()):
        if not isinstance(record, dict):
            checks.append(_check(f"{role}_artifact_shape", False, "error", "not an object"))
            continue
        raw_path = str(record.get("path") or "").strip()
        expected_sha = str(record.get("sha256") or "").strip().lower()
        expected_bytes = int(record.get("bytes") or 0)
        path = Path(raw_path).expanduser() if raw_path else None
        checks.append(_check(f"{role}_artifact_path_recorded", bool(path), "error", raw_path or "missing"))
        if path is None:
            continue
        path = path.resolve()
        checks.append(_check(f"{role}_artifact_exists", path.exists() and path.is_file(), "error", str(path)))
        if not path.exists() or not path.is_file():
            continue
        actual_sha = sha256_file(path)
        actual_bytes = path.stat().st_size
        checks.append(_check(f"{role}_artifact_hash_matches", bool(expected_sha) and actual_sha == expected_sha and actual_bytes == expected_bytes, "error", f"{actual_sha} bytes={actual_bytes}"))
    return checks


def _contains_sensitive_key(value: Any, *, path: str = "") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            child = f"{path}.{key_text}" if path else key_text
            if any(part in key_text.lower() for part in SENSITIVE_KEY_PARTS):
                findings.append(child)
                continue
            findings.extend(_contains_sensitive_key(item, path=child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_contains_sensitive_key(item, path=f"{path}[{index}]"))
    return findings


def _step_checks(suite: dict[str, Any], *, require_passed: bool) -> list[dict[str, Any]]:
    steps = suite.get("steps") if isinstance(suite.get("steps"), list) else []
    ids = [str(item.get("id") or "") for item in steps if isinstance(item, dict)]
    failed = [str(item.get("id") or "") for item in steps if isinstance(item, dict) and not item.get("passed")]
    return [
        _check("expected_steps_present", ids == EXPECTED_STEPS, "error", ",".join(ids)),
        _check("embedded_steps_passed", (not require_passed) or not failed, "error", ",".join(failed) if failed else "ok"),
    ]


def _report_status(report: dict[str, Any] | None, expected: str) -> bool:
    return isinstance(report, dict) and report.get("status") == expected


def verify_commercial_acceptance_suite(
    suite_path: Path,
    *,
    require_passed: bool = True,
    reverify_artifacts: bool = True,
) -> dict[str, Any]:
    suite_path = suite_path.expanduser().resolve()
    checks: list[dict[str, Any]] = []
    reports: dict[str, Any] = {}
    suite: dict[str, Any] = {}
    try:
        suite = _read_json(suite_path)
        checks.append(_check("suite_report_exists", True, "error", str(suite_path)))
        checks.append(_check("suite_schema", suite.get("schema_version") == SUITE_SCHEMA, "error", str(suite.get("schema_version") or "")))
        checks.append(_check("suite_status_passed", (not require_passed) or suite.get("status") == "passed", "error", str(suite.get("status") or "")))
        expected_digest = str(suite.get("suite_sha256") or "").lower()
        checks.append(_check("suite_sha256_matches", bool(expected_digest) and suite_digest(suite) == expected_digest, "error", expected_digest))
        checks.extend(_step_checks(suite, require_passed=require_passed))
        sensitive = _contains_sensitive_key(suite)
        checks.append(_check("sensitive_keys_excluded", not sensitive, "error", ",".join(sensitive[:20]) if sensitive else "ok"))
        checks.extend(_artifact_record_checks(suite))
    except Exception as exc:
        checks.append(_check("suite_report_readable", False, "error", str(exc)))

    if suite and reverify_artifacts:
        release_zip = _artifact_path(suite, "release_zip")
        release_manifest = _artifact_path(suite, "release_manifest")
        release_sha256_file = _artifact_path(suite, "release_sha256_file")
        release_signature = _artifact_path(suite, "release_signature")
        release_public_key = _artifact_path(suite, "release_public_key")
        handoff_dossier = _artifact_path(suite, "handoff_dossier")
        support_bundle = _artifact_path(suite, "support_bundle")
        launch_package = _artifact_path(suite, "commercial_launch_package")
        operations_report = _artifact_path(suite, "commercial_operations_report")
        try:
            reports["release_package"] = verify_release_package(
                release_zip or Path(""),
                manifest_path=release_manifest,
                sha256_path=release_sha256_file,
                signature_path=release_signature,
                public_key_path=release_public_key,
                require_signature=True,
            )
        except Exception as exc:
            reports["release_package"] = {"status": "attention", "summary": {"errors": 1, "warnings": 0}, "message": str(exc)}
        checks.append(_check("release_package_reverified", _report_status(reports.get("release_package"), "verified"), "error", str(reports["release_package"].get("status") or "")))

        try:
            reports["handoff_dossier"] = verify_handoff_dossier(handoff_dossier or Path(""), release_zip=release_zip, require_release_zip=True)
        except Exception as exc:
            reports["handoff_dossier"] = {"status": "attention", "summary": {"errors": 1, "warnings": 0}, "message": str(exc)}
        checks.append(_check("handoff_dossier_reverified", _report_status(reports.get("handoff_dossier"), "verified"), "error", str(reports["handoff_dossier"].get("status") or "")))

        try:
            reports["support_bundle"] = verify_support_bundle(support_bundle or Path(""))
        except Exception as exc:
            reports["support_bundle"] = {"status": "attention", "summary": {"errors": 1, "warnings": 0}, "message": str(exc)}
        checks.append(_check("support_bundle_reverified", _report_status(reports.get("support_bundle"), "verified"), "error", str(reports["support_bundle"].get("status") or "")))

        try:
            reports["commercial_launch_package"] = verify_commercial_launch_package(launch_package or Path(""))
        except Exception as exc:
            reports["commercial_launch_package"] = {"status": "attention", "summary": {"errors": 1, "warnings": 0}, "message": str(exc)}
        checks.append(_check("commercial_launch_package_reverified", _report_status(reports.get("commercial_launch_package"), "verified"), "error", str(reports["commercial_launch_package"].get("status") or "")))

        try:
            reports["commercial_operations_report"] = verify_commercial_operations_report(operations_report or Path(""), launch_package=launch_package)
        except Exception as exc:
            reports["commercial_operations_report"] = {"status": "attention", "summary": {"errors": 1, "warnings": 0}, "message": str(exc)}
        checks.append(_check("commercial_operations_report_reverified", _report_status(reports.get("commercial_operations_report"), "verified"), "error", str(reports["commercial_operations_report"].get("status") or "")))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "schema_version": "draftpaper.commercial-acceptance-suite-verification/v1",
        "status": "verified" if not errors else "attention",
        "suite_path": str(suite_path),
        "suite_sha256": str(suite.get("suite_sha256") or ""),
        "target_track": str(suite.get("target_track") or ""),
        "reports": {
            key: {
                "status": str(report.get("status") or ""),
                "summary": report.get("summary") if isinstance(report.get("summary"), dict) else {},
                "zip_sha256": str(report.get("zip_sha256") or ""),
                "package_sha256": str(report.get("package_sha256") or ""),
                "dossier_sha256": str(report.get("dossier_sha256") or ""),
                "report_sha256": str(report.get("report_sha256") or ""),
            }
            for key, report in reports.items()
            if isinstance(report, dict)
        },
        "summary": {"checks": len(checks), "errors": len(errors), "warnings": len(warnings)},
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Draftpaper-loop commercial acceptance suite report and artifacts.")
    parser.add_argument("suite_path")
    parser.add_argument("--allow-attention", action="store_true", help="Do not fail only because suite status is attention or embedded steps failed.")
    parser.add_argument("--skip-artifact-reverify", action="store_true", help="Only verify suite schema, digest, steps, and artifact hash records.")
    args = parser.parse_args(argv)
    result = verify_commercial_acceptance_suite(
        Path(args.suite_path),
        require_passed=not args.allow_attention,
        reverify_artifacts=not args.skip_artifact_reverify,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
