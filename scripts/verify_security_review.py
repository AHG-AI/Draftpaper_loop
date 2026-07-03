#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
REVIEW_SCHEMA = "draftpaper.security-review/v1"
REPORT_SCHEMA = "draftpaper.security-review-verification/v1"
ALLOWED_REVIEW_TYPES = {
    "third_party_security_review",
    "penetration_test",
    "vendor_security_assessment",
    "compliance_security_review",
    "soc2_security_review",
}
FINDING_FIELDS = [
    "critical_open",
    "high_open",
    "medium_open",
    "low_open",
    "informational_open",
]
SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
)
SENSITIVE_VALUE_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "Authorization:",
    "Bearer ",
)


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        return {"_read_error": str(exc)}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_public_mode(path: Path) -> int:
    try:
        return stat.S_IMODE(path.stat().st_mode) & 0o077
    except OSError:
        return 0o777


def _parse_time(value: Any) -> float:
    raw = str(value or "").strip()
    if not raw:
        return 0.0
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return time.mktime(time.strptime(raw, fmt))
        except ValueError:
            continue
    return 0.0


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _evidence_refs(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    refs: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            refs.append(item.strip())
        elif isinstance(item, dict):
            ref = str(item.get("id") or item.get("ref") or item.get("uri") or item.get("path") or "").strip()
            if ref:
                refs.append(ref)
    return refs


def _find_sensitive_paths(value: Any, *, prefix: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{prefix}.{key_text}"
            if any(part in key_text.lower() for part in SENSITIVE_KEY_PARTS):
                findings.append(child_path)
            findings.extend(_find_sensitive_paths(child, prefix=child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_find_sensitive_paths(child, prefix=f"{prefix}[{index}]"))
    elif isinstance(value, str):
        if any(marker in value for marker in SENSITIVE_VALUE_MARKERS):
            findings.append(prefix)
    return findings


def _optional_int(value: Any) -> int | None:
    try:
        if value is None or str(value).strip() == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _path_from_env_or_arg(value: Path | None, env_key: str) -> Path | None:
    if value is not None:
        return value.expanduser().resolve()
    raw = os.environ.get(env_key, "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _artifact_path(raw_path: str, *, base_dir: Path) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _public_review_payload(payload: dict[str, Any]) -> dict[str, Any]:
    fields = [
        "schema_version",
        "status",
        "review_type",
        "review_authority",
        "review_reference",
        "reviewed_by",
        "reviewed_at",
        "target",
        "scope",
        "findings_summary",
        "security_audit_sha256",
    ]
    return {field: payload.get(field) for field in fields if field in payload}


def verify_security_review(
    *,
    review_file: Path | None = None,
    security_audit_file: Path | None = None,
    output: Path | None = None,
) -> dict[str, Any]:
    review_file = _path_from_env_or_arg(review_file, "DRAFTPAPER_SECURITY_REVIEW_FILE")
    security_audit_file = _path_from_env_or_arg(security_audit_file, "DRAFTPAPER_SECURITY_AUDIT_FILE")
    checks: list[dict[str, Any]] = []
    payload: dict[str, Any] = {}
    observed: dict[str, Any] = {}

    checks.append(_check("security_review_file_configured", review_file is not None, "error", "Security review evidence file is configured.", "Set DRAFTPAPER_SECURITY_REVIEW_FILE or pass --review-file."))
    if review_file is not None:
        checks.append(_check("security_review_file_exists", review_file.exists(), "error", str(review_file), "Create the security review evidence file or fix the configured path."))
        if review_file.exists():
            checks.append(_check("security_review_file_permissions", _file_public_mode(review_file) == 0, "warning", f"public permission bits={oct(_file_public_mode(review_file))}", "Restrict the security review evidence file to owner-only permissions, for example chmod 600."))
            loaded = _read_json(review_file)
            if isinstance(loaded, dict) and "_read_error" not in loaded:
                payload = loaded
                checks.append(_check("security_review_file_shape", True, "error", "Security review evidence file contains a JSON object."))
            else:
                checks.append(_check("security_review_file_shape", False, "error", str(loaded.get("_read_error") if isinstance(loaded, dict) else type(loaded).__name__), f"Use a JSON object with schema_version {REVIEW_SCHEMA}."))

    if payload:
        checks.append(_check("security_review_schema", payload.get("schema_version") == REVIEW_SCHEMA, "error", f"schema_version={payload.get('schema_version') or 'missing'}", f"Set schema_version to {REVIEW_SCHEMA}."))
        checks.append(_check("security_review_status", str(payload.get("status") or "").strip().lower() == "verified", "error", f"status={payload.get('status') or 'missing'}", "Set status to verified only after the external review record is complete."))
        review_type = str(payload.get("review_type") or "").strip()
        checks.append(_check("security_review_type", review_type in ALLOWED_REVIEW_TYPES, "error", review_type or "missing", f"Use one of: {', '.join(sorted(ALLOWED_REVIEW_TYPES))}."))
        required_fields = ["review_authority", "review_reference", "reviewed_by", "reviewed_at", "target"]
        missing = [field for field in required_fields if not str(payload.get(field) or "").strip()]
        checks.append(_check("security_review_required_fields", not missing, "error", "Security review evidence includes required audit fields.", f"Missing fields: {', '.join(missing)}" if missing else ""))
        reviewed_epoch = _parse_time(payload.get("reviewed_at"))
        checks.append(_check("security_review_time_parseable", reviewed_epoch > 0, "error", "reviewed_at is parseable as YYYY-MM-DD or UTC timestamp.", "Use reviewed_at like 2026-07-03T00:00:00Z."))
        checks.append(_check("security_review_time_not_future", reviewed_epoch == 0 or reviewed_epoch <= time.time() + 300, "error", "reviewed_at is not in the future.", "Use the actual review completion timestamp."))
        scope = _string_list(payload.get("scope"))
        checks.append(_check("security_review_scope_declared", bool(scope), "error", "Security review declares reviewed scope.", "Set scope, for example ['operator_console', 'release_package', 'deployment']."))
        refs = _evidence_refs(payload.get("evidence_refs"))
        checks.append(_check("security_review_evidence_refs", bool(refs), "error", "Security review includes at least one external report, ticket, or attestation reference.", "Add evidence_refs with the external review report, ticket, or attestation references."))
        sensitive = sorted(set(_find_sensitive_paths(payload)))
        checks.append(_check("security_review_no_secret_material", not sensitive, "error", "Security review evidence does not contain obvious token, password, cookie, or private-key material.", f"Remove sensitive fields: {', '.join(sensitive[:10])}" if sensitive else ""))

        summary = payload.get("findings_summary") if isinstance(payload.get("findings_summary"), dict) else {}
        missing_finding_fields = [field for field in FINDING_FIELDS if _optional_int(summary.get(field)) is None]
        checks.append(_check("security_review_findings_summary", not missing_finding_fields, "error", "Findings summary declares open finding counts by severity.", f"Missing or invalid fields: {', '.join(missing_finding_fields)}" if missing_finding_fields else ""))
        critical_open = _optional_int(summary.get("critical_open")) or 0
        high_open = _optional_int(summary.get("high_open")) or 0
        medium_open = _optional_int(summary.get("medium_open")) or 0
        observed["findings_summary"] = {field: _optional_int(summary.get(field)) for field in FINDING_FIELDS}
        checks.append(_check("security_review_no_open_critical", critical_open == 0, "error", f"critical_open={critical_open}", "Remediate or formally close critical findings before commercial handoff."))
        checks.append(_check("security_review_no_open_high", high_open == 0, "error", f"high_open={high_open}", "Remediate or formally close high-severity findings before commercial handoff."))
        checks.append(_check("security_review_medium_findings_tracked", medium_open == 0 or bool(_evidence_refs(payload.get("risk_acceptance_refs"))), "warning", f"medium_open={medium_open}", "Track or accept residual medium findings with explicit risk_acceptance_refs."))

        artifact_records: list[dict[str, Any]] = []
        artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), list) else []
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                checks.append(_check(f"security_review_artifact_{index}_shape", False, "error", "artifact must be a JSON object", "Use artifacts with path and sha256 fields."))
                continue
            raw_path = str(artifact.get("path") or "").strip()
            expected_sha = str(artifact.get("sha256") or "").strip().lower()
            checks.append(_check(f"security_review_artifact_{index}_fields", bool(raw_path and expected_sha), "error", raw_path or "missing", "Each review artifact must declare path and sha256."))
            if not raw_path:
                continue
            base_dir = review_file.parent if review_file is not None else REPO_ROOT
            path = _artifact_path(raw_path, base_dir=base_dir)
            checks.append(_check(f"security_review_artifact_{index}_exists", path.exists(), "error", str(path), "Keep the referenced private review artifact next to the evidence record or use an absolute path."))
            if path.exists() and expected_sha:
                actual_sha = _sha256_file(path)
                checks.append(_check(f"security_review_artifact_{index}_sha256_matches", actual_sha == expected_sha, "error", str(path.name), "Update the artifact hash only after intentional review artifact replacement."))
                artifact_records.append({"path": raw_path, "sha256": actual_sha, "bytes": path.stat().st_size})
        observed["artifacts"] = artifact_records

        expected_audit_sha = str(payload.get("security_audit_sha256") or "").strip().lower()
        if security_audit_file is not None:
            checks.append(_check("security_review_audit_file_exists", security_audit_file.exists(), "error", str(security_audit_file), "Provide the local /api/security-audit report used for review evidence."))
            if security_audit_file.exists():
                audit_sha = _sha256_file(security_audit_file)
                observed["security_audit_sha256"] = audit_sha
                audit_payload = _read_json(security_audit_file)
                checks.append(_check("security_review_audit_file_shape", isinstance(audit_payload, dict) and "_read_error" not in audit_payload, "error", "Local security audit report is readable JSON.", "Use a saved /api/security-audit JSON report."))
                if isinstance(audit_payload, dict) and "_read_error" not in audit_payload:
                    errors = int((audit_payload.get("summary") or {}).get("errors") or 0) if isinstance(audit_payload.get("summary"), dict) else 0
                    checks.append(_check("security_review_audit_errors_clear", audit_payload.get("status") == "passed" and errors == 0, "error", f"status={audit_payload.get('status')} errors={errors}", "Fix local security-audit errors before relying on third-party review evidence."))
                if expected_audit_sha:
                    checks.append(_check("security_review_audit_sha256_matches", audit_sha == expected_audit_sha, "error", "Saved local security audit SHA256 matches the review evidence.", "Update review evidence after intentional security audit report replacement."))
        elif expected_audit_sha:
            checks.append(_check("security_review_audit_file_configured", False, "error", "Review evidence records security_audit_sha256 but no audit file was supplied.", "Pass --security-audit-file or set DRAFTPAPER_SECURITY_AUDIT_FILE."))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    report = {
        "schema_version": REPORT_SCHEMA,
        "status": "verified" if not errors else ("unconfigured" if review_file is None else "attention"),
        "generated_at": _utc_timestamp(),
        "review_file": str(review_file) if review_file is not None else "",
        "security_audit_file": str(security_audit_file) if security_audit_file is not None else "",
        "review": _public_review_payload(payload) if payload else {},
        "observed": observed,
        "checks": checks,
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
            "passed": sum(1 for item in checks if item["passed"]),
        },
        "notes": [
            "This verifies a private formal security review evidence record and referenced artifacts.",
            "It does not perform a third-party review, replace penetration testing, or prove hosted SaaS readiness.",
        ],
    }
    if output is not None:
        output = output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        output.chmod(0o600)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify private third-party security review evidence for Draftpaper-loop.")
    parser.add_argument("--review-file", default="", help="Path to draftpaper.security-review/v1 evidence JSON.")
    parser.add_argument("--security-audit-file", default="", help="Optional saved /api/security-audit JSON report.")
    parser.add_argument("--output", default="", help="Optional private JSON report path.")
    args = parser.parse_args(argv)
    report = verify_security_review(
        review_file=Path(args.review_file) if args.review_file else None,
        security_audit_file=Path(args.security_audit_file) if args.security_audit_file else None,
        output=Path(args.output) if args.output else None,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
