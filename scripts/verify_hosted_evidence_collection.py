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

from collect_hosted_readiness_evidence import API_PROBE_SCHEMA, ENDPOINTS, SCHEMA_VERSION, TLS_PROBE_SCHEMA, collection_digest  # noqa: E402
from serviceconsole_app import HOSTED_READINESS_REQUIREMENTS, HOSTED_READINESS_SCHEMA  # noqa: E402


SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")
SENSITIVE_KEY_EXCEPTIONS = {"secrets_manager"}
REDACTED = "[redacted]"


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _contains_sensitive_key(value: Any, *, path: str = "") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            child = f"{path}.{key_text}" if path else key_text
            if key_text.lower() not in SENSITIVE_KEY_EXCEPTIONS and any(part in key_text.lower() for part in SENSITIVE_KEY_PARTS):
                if item != REDACTED:
                    findings.append(child)
                continue
            findings.extend(_contains_sensitive_key(item, path=child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_contains_sensitive_key(item, path=f"{path}[{index}]"))
    return findings


def _safe_relative_path(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _resolve_record_path(record: dict[str, Any], output_dir: Path) -> Path:
    raw_path = str(record.get("path") or "").strip()
    relative = str(record.get("relative_path") or "").strip()
    candidates: list[Path] = []
    if raw_path:
        candidates.append(Path(raw_path).expanduser())
    if relative:
        candidates.append(output_dir / relative)
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return candidates[0].resolve() if candidates else output_dir / "__missing__"


def _artifact_checks(report: dict[str, Any], output_dir: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    artifacts = report.get("artifacts") if isinstance(report.get("artifacts"), dict) else {}
    artifact_payloads: dict[str, dict[str, Any]] = {}
    checks.append(_check("artifact_records_present", bool(artifacts), "error", f"count={len(artifacts) if isinstance(artifacts, dict) else 0}"))
    missing = sorted(set(ENDPOINTS) - set(artifacts)) if isinstance(artifacts, dict) else sorted(ENDPOINTS)
    checks.append(_check("required_api_artifacts_present", not missing, "error", ", ".join(missing) if missing else "ok"))
    if not isinstance(artifacts, dict):
        return checks, artifact_payloads

    for name, record in sorted(artifacts.items()):
        if not isinstance(record, dict):
            checks.append(_check(f"artifact_{name}_shape", False, "error", "not an object"))
            continue
        relative = str(record.get("relative_path") or "")
        checks.append(_check(f"artifact_{name}_relative_path_safe", _safe_relative_path(relative), "error", relative, "Keep collection artifacts under the collection directory."))
        path = _resolve_record_path(record, output_dir)
        checks.append(_check(f"artifact_{name}_inside_output_dir", _is_within(path, output_dir), "error", str(path), "Do not reference artifacts outside the collection directory."))
        checks.append(_check(f"artifact_{name}_exists", path.exists() and path.is_file(), "error", str(path)))
        if not path.exists() or not path.is_file():
            continue
        actual_sha = sha256_file(path)
        expected_sha = str(record.get("sha256") or "").lower()
        checks.append(_check(f"artifact_{name}_sha256_matches", bool(expected_sha) and actual_sha == expected_sha, "error", actual_sha))
        try:
            payload = _read_json(path)
            artifact_payloads[str(name)] = payload
            expected_schema = TLS_PROBE_SCHEMA if name == "tls_certificate" else API_PROBE_SCHEMA
            checks.append(_check(f"artifact_{name}_schema", payload.get("schema_version") == expected_schema, "error", str(payload.get("schema_version") or "")))
            if name != "tls_certificate":
                checks.append(_check(f"artifact_{name}_path_matches", payload.get("path") == ENDPOINTS.get(str(name)), "error", str(payload.get("path") or "")))
                if bool(record.get("passed")):
                    status_code = int(payload.get("status_code") or 0)
                    checks.append(_check(f"artifact_{name}_passed_status_code", 200 <= status_code < 300, "error", str(status_code)))
            sensitive = _contains_sensitive_key(payload)
            checks.append(_check(f"artifact_{name}_redacted", not sensitive, "error", ", ".join(sensitive[:20]) if sensitive else "ok"))
        except Exception as exc:
            checks.append(_check(f"artifact_{name}_json_readable", False, "error", str(exc)))
    return checks, artifact_payloads


def _draft_checks(report: dict[str, Any], output_dir: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    draft = report.get("hosted_readiness_draft") if isinstance(report.get("hosted_readiness_draft"), dict) else {}
    raw_path = str(draft.get("path") or "").strip()
    draft_path = Path(raw_path).expanduser() if raw_path else output_dir / "hosted-readiness.draft.json"
    if not draft_path.exists():
        draft_path = output_dir / "hosted-readiness.draft.json"
    draft_path = draft_path.resolve()
    checks.append(_check("hosted_readiness_draft_inside_output_dir", _is_within(draft_path, output_dir), "error", str(draft_path), "Keep hosted readiness draft inside the collection directory."))
    checks.append(_check("hosted_readiness_draft_exists", draft_path.exists() and draft_path.is_file(), "error", str(draft_path)))
    if not draft_path.exists() or not draft_path.is_file():
        return checks
    actual_sha = sha256_file(draft_path)
    expected_sha = str(draft.get("sha256") or "").lower()
    checks.append(_check("hosted_readiness_draft_sha256_matches", bool(expected_sha) and actual_sha == expected_sha, "error", actual_sha))
    try:
        payload = _read_json(draft_path)
    except Exception as exc:
        checks.append(_check("hosted_readiness_draft_json_readable", False, "error", str(exc)))
        return checks
    checks.append(_check("hosted_readiness_draft_schema", payload.get("schema_version") == HOSTED_READINESS_SCHEMA, "error", str(payload.get("schema_version") or "")))
    statuses: list[str] = []
    evidence_missing: list[str] = []
    verified_flags: list[str] = []
    for requirement in HOSTED_READINESS_REQUIREMENTS:
        key = str(requirement["evidence_key"])
        section = payload.get(key) if isinstance(payload.get(key), dict) else {}
        status = str(section.get("status") or "")
        statuses.append(f"{key}={status or 'missing'}")
        if status != "pending":
            verified_flags.append(key)
        evidence = section.get("evidence") if isinstance(section.get("evidence"), list) else []
        if not evidence:
            evidence_missing.append(key)
        for field in requirement.get("required_true", []):
            if bool(section.get(str(field))):
                verified_flags.append(f"{key}.{field}")
    checks.append(_check("hosted_readiness_draft_pending", not verified_flags, "error", ", ".join(verified_flags) if verified_flags else ", ".join(statuses), "Collection drafts must remain pending until an operator verifies external controls."))
    checks.append(_check("hosted_readiness_draft_has_evidence_refs", not evidence_missing, "error", ", ".join(evidence_missing) if evidence_missing else "ok"))
    sensitive = _contains_sensitive_key(payload)
    checks.append(_check("hosted_readiness_draft_redacted", not sensitive, "error", ", ".join(sensitive[:20]) if sensitive else "ok"))
    return checks


def verify_hosted_evidence_collection(
    report_path: Path,
    *,
    require_collected: bool = True,
) -> dict[str, Any]:
    report_path = report_path.expanduser().resolve()
    checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {}
    try:
        report = _read_json(report_path)
        checks.append(_check("collection_report_exists", True, "error", str(report_path)))
        checks.append(_check("collection_schema", report.get("schema_version") == SCHEMA_VERSION, "error", str(report.get("schema_version") or "")))
        checks.append(_check("collection_status_collected", (not require_collected) or report.get("status") == "collected", "error", str(report.get("status") or ""), "Use --allow-attention only for rehearsal or troubleshooting reports."))
        expected_digest = str(report.get("collection_sha256") or "").lower()
        checks.append(_check("collection_sha256_matches", bool(expected_digest) and collection_digest(report) == expected_digest, "error", expected_digest))
        summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
        checks.append(_check("collection_summary_errors_clear", (not require_collected) or int(summary.get("errors") or 0) == 0, "error", str(summary.get("errors") or 0)))
        failed_error_checks = [
            str(item.get("id") or "")
            for item in report.get("checks", [])
            if isinstance(item, dict) and item.get("severity") == "error" and not item.get("passed")
        ]
        checks.append(_check("embedded_error_checks_passed", (not require_collected) or not failed_error_checks, "error", ", ".join(failed_error_checks) if failed_error_checks else "ok"))
        sensitive = _contains_sensitive_key(report)
        checks.append(_check("collection_report_redacted", not sensitive, "error", ", ".join(sensitive[:20]) if sensitive else "ok"))
    except Exception as exc:
        checks.append(_check("collection_report_readable", False, "error", str(exc)))

    output_dir = report_path.parent
    if report:
        raw_output_dir = str(report.get("output_dir") or "").strip()
        recorded_output_dir = Path(raw_output_dir).expanduser().resolve() if raw_output_dir else output_dir
        if recorded_output_dir.exists():
            output_dir = recorded_output_dir
        checks.append(_check("output_dir_exists", output_dir.exists() and output_dir.is_dir(), "error", str(output_dir)))
        checks.append(_check("report_path_inside_output_dir", _is_within(report_path, output_dir), "error", str(report_path)))
        artifact_checks, artifact_payloads = _artifact_checks(report, output_dir)
        checks.extend(artifact_checks)
        checks.extend(_draft_checks(report, output_dir))
        artifact_count = len(report.get("artifacts") if isinstance(report.get("artifacts"), dict) else {})
        summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
        checks.append(_check("summary_artifact_count_matches", int(summary.get("artifacts") or 0) == artifact_count, "error", f"summary={summary.get('artifacts')} artifacts={artifact_count}"))
        collection_sources = {
            "health_status": artifact_payloads.get("health", {}).get("payload", {}).get("status") if isinstance(artifact_payloads.get("health", {}).get("payload"), dict) else "",
            "commercial_grade": artifact_payloads.get("commercial_readiness", {}).get("payload", {}).get("commercial_grade") if isinstance(artifact_payloads.get("commercial_readiness", {}).get("payload"), dict) else "",
            "hosted_status": artifact_payloads.get("hosted_readiness", {}).get("payload", {}).get("status") if isinstance(artifact_payloads.get("hosted_readiness", {}).get("payload"), dict) else "",
        }
    else:
        collection_sources = {}

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "schema_version": "draftpaper.hosted-readiness-evidence-collection-verification/v1",
        "status": "verified" if not errors else "attention",
        "report_path": str(report_path),
        "report_sha256": sha256_file(report_path) if report_path.exists() and report_path.is_file() else "",
        "collection_sha256": str(report.get("collection_sha256") or ""),
        "base_url": str(report.get("base_url") or ""),
        "collection_sources": collection_sources,
        "summary": {"checks": len(checks), "errors": len(errors), "warnings": len(warnings)},
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Draftpaper-loop hosted evidence collection report and artifacts.")
    parser.add_argument("collection_report", help="hosted-readiness-evidence-collection.json path.")
    parser.add_argument("--allow-attention", action="store_true", help="Do not fail only because collection status is attention or embedded collection checks failed.")
    args = parser.parse_args(argv)
    result = verify_hosted_evidence_collection(Path(args.collection_report), require_collected=not args.allow_attention)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
