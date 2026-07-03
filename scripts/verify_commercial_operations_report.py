#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from build_commercial_operations_report import OPERATIONS_REPORT_SCHEMA  # noqa: E402
from build_commercial_operations_report import _ops_digest  # noqa: E402
from verify_commercial_launch_package import verify_commercial_launch_package  # noqa: E402


REDACTED = "[redacted]"
SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")
LOCAL_PATH_PATTERNS = (
    re.compile(r"/Users/[^\"'\s]+"),
    re.compile(r"/private/tmp/[^\"'\s]+"),
    re.compile(r"/var/folders/[^\"'\s]+"),
)


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _sensitive_findings(value: Any, *, path: str = "") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            lowered = key_text.lower()
            if any(part in lowered for part in SENSITIVE_KEY_PARTS):
                if item != REDACTED:
                    findings.append(child_path)
                continue
            findings.extend(_sensitive_findings(item, path=child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_sensitive_findings(item, path=f"{path}[{index}]"))
    return findings


def _path_findings(text: str) -> list[str]:
    findings: list[str] = []
    for pattern in LOCAL_PATH_PATTERNS:
        findings.extend(match.group(0) for match in pattern.finditer(text))
    return findings


def verify_commercial_operations_report(
    report_path: Path,
    *,
    launch_package: Path | None = None,
    require_ready: bool = True,
) -> dict[str, Any]:
    report_path = report_path.expanduser().resolve()
    checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {}
    try:
        text = report_path.read_text(encoding="utf-8-sig")
        report = json.loads(text)
        if not isinstance(report, dict):
            raise ValueError("report must be a JSON object")
        checks.append(_check("operations_report_exists", True, "error", str(report_path)))
        checks.append(_check("operations_report_schema", report.get("schema_version") == OPERATIONS_REPORT_SCHEMA, "error", str(report.get("schema_version") or "")))
        checks.append(_check("operations_report_status_ready", (not require_ready) or report.get("status") == "ready", "error", str(report.get("status") or "")))
        expected_digest = str(report.get("report_sha256") or "").lower()
        checks.append(_check("operations_report_sha256_matches", bool(expected_digest) and _ops_digest(report) == expected_digest, "error", expected_digest))
        sensitive = _sensitive_findings(report)
        checks.append(_check("sensitive_values_redacted", not sensitive, "error", ", ".join(sensitive[:20]) if sensitive else "ok"))
        paths = _path_findings(text)
        checks.append(_check("local_paths_redacted", not paths, "error", ", ".join(paths[:20]) if paths else "ok"))
        failed_embedded = [item.get("id") for item in report.get("checks", []) if isinstance(item, dict) and item.get("severity") == "error" and not item.get("passed")]
        checks.append(_check("embedded_error_checks_passed", not failed_embedded, "error", ", ".join(str(item) for item in failed_embedded)))
        evidence = report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
        security = evidence.get("security_audit") if isinstance(evidence.get("security_audit"), dict) else {}
        security_summary = security.get("summary") if isinstance(security.get("summary"), dict) else {}
        checks.append(_check("security_errors_clear", int(security_summary.get("errors") or 0) == 0, "error", f"errors={security_summary.get('errors')}"))
    except Exception as exc:
        checks.append(_check("operations_report_readable", False, "error", str(exc)))

    launch_report: dict[str, Any] | None = None
    if launch_package is not None:
        try:
            launch_report = verify_commercial_launch_package(launch_package)
            checks.append(_check("launch_package_reverified", launch_report.get("status") == "verified", "error", str(launch_report.get("status") or "")))
            recorded = ((report.get("evidence") or {}).get("launch_package") or {}) if isinstance(report.get("evidence"), dict) else {}
            checks.append(_check(
                "launch_package_matches_report",
                launch_report.get("zip_sha256") == recorded.get("zip_sha256") and launch_report.get("package_sha256") == recorded.get("package_sha256"),
                "error",
                str(recorded.get("zip_sha256") or ""),
            ))
        except Exception as exc:
            checks.append(_check("launch_package_reverified", False, "error", str(exc)))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "schema_version": "draftpaper.commercial-operations-report-verification/v1",
        "status": "verified" if not errors else "attention",
        "report_path": str(report_path),
        "report_sha256": str(report.get("report_sha256") or ""),
        "target_track": str(report.get("target_track") or ""),
        "launch_package": {
            "status": (launch_report or {}).get("status") if isinstance(launch_report, dict) else "",
            "zip_sha256": (launch_report or {}).get("zip_sha256") if isinstance(launch_report, dict) else "",
            "package_sha256": (launch_report or {}).get("package_sha256") if isinstance(launch_report, dict) else "",
        },
        "summary": {"checks": len(checks), "errors": len(errors), "warnings": len(warnings)},
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Draftpaper-loop commercial operations report.")
    parser.add_argument("report_path")
    parser.add_argument("--launch-package", default="")
    parser.add_argument("--allow-attention", action="store_true", help="Do not fail only because report status is attention.")
    args = parser.parse_args(argv)
    result = verify_commercial_operations_report(
        Path(args.report_path),
        launch_package=Path(args.launch_package).expanduser() if args.launch_package else None,
        require_ready=not args.allow_attention,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
