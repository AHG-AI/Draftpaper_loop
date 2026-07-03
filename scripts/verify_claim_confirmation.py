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
CONFIRMATION_SCHEMA = "draftpaper.claim-confirmation/v1"
REPORT_SCHEMA = "draftpaper.claim-confirmation-verification/v1"
ACCEPTED_CLAIM_STATUSES = {"confirmed", "approved", "accepted"}
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


def _path_from_env_or_arg(value: Path | None, env_key: str) -> Path | None:
    if value is not None:
        return value.expanduser().resolve()
    raw = os.environ.get(env_key, "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _project_from_payload(payload: dict[str, Any], *, project: Path | None) -> Path | None:
    if project is not None:
        return project.expanduser().resolve()
    raw = os.environ.get("DRAFTPAPER_CLAIM_CONFIRMATION_PROJECT", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    payload_path = str(payload.get("project_path") or "").strip()
    if payload_path:
        return Path(payload_path).expanduser().resolve()
    project_slug = str(payload.get("project_slug") or "").strip()
    projects_root = Path(os.environ.get("DRAFTPAPER_PROJECTS_DIR", REPO_ROOT / "projects")).expanduser().resolve()
    return (projects_root / project_slug).resolve() if project_slug else None


def _artifact_path(raw_path: str, *, confirmation_dir: Path, project_path: Path | None) -> Path:
    path = Path(raw_path).expanduser()
    if path.is_absolute():
        return path.resolve()
    if project_path is not None and (project_path / path).exists():
        return (project_path / path).resolve()
    return (confirmation_dir / path).resolve()


def _public_confirmation_payload(payload: dict[str, Any]) -> dict[str, Any]:
    fields = [
        "schema_version",
        "status",
        "project_id",
        "project_slug",
        "confirmation_reference",
        "confirmed_by",
        "confirmed_at",
        "scope",
        "claims_count",
    ]
    result = {field: payload.get(field) for field in fields if field in payload}
    if "claims_count" not in result and isinstance(payload.get("claims"), list):
        result["claims_count"] = len(payload["claims"])
    return result


def verify_claim_confirmation(
    *,
    confirmation_file: Path | None = None,
    project: Path | None = None,
    output: Path | None = None,
) -> dict[str, Any]:
    confirmation_file = _path_from_env_or_arg(confirmation_file, "DRAFTPAPER_CLAIM_CONFIRMATION_FILE")
    checks: list[dict[str, Any]] = []
    payload: dict[str, Any] = {}
    observed: dict[str, Any] = {}

    checks.append(_check("claim_confirmation_file_configured", confirmation_file is not None, "error", "Claim confirmation evidence file is configured.", "Set DRAFTPAPER_CLAIM_CONFIRMATION_FILE or pass --confirmation-file."))
    if confirmation_file is not None:
        checks.append(_check("claim_confirmation_file_exists", confirmation_file.exists(), "error", str(confirmation_file), "Create the claim confirmation evidence file or fix the configured path."))
        if confirmation_file.exists():
            checks.append(_check("claim_confirmation_file_permissions", _file_public_mode(confirmation_file) == 0, "warning", f"public permission bits={oct(_file_public_mode(confirmation_file))}", "Restrict the confirmation evidence file to owner-only permissions, for example chmod 600."))
            loaded = _read_json(confirmation_file)
            if isinstance(loaded, dict) and "_read_error" not in loaded:
                payload = loaded
                checks.append(_check("claim_confirmation_file_shape", True, "error", "Claim confirmation evidence file contains a JSON object."))
            else:
                checks.append(_check("claim_confirmation_file_shape", False, "error", str(loaded.get("_read_error") if isinstance(loaded, dict) else type(loaded).__name__), f"Use a JSON object with schema_version {CONFIRMATION_SCHEMA}."))

    project_path = _project_from_payload(payload, project=project) if payload else (project.expanduser().resolve() if project is not None else None)
    if payload:
        checks.append(_check("claim_confirmation_schema", payload.get("schema_version") == CONFIRMATION_SCHEMA, "error", f"schema_version={payload.get('schema_version') or 'missing'}", f"Set schema_version to {CONFIRMATION_SCHEMA}."))
        checks.append(_check("claim_confirmation_status", str(payload.get("status") or "").strip().lower() == "confirmed", "error", f"status={payload.get('status') or 'missing'}", "Set status to confirmed only after the domain/user review is complete."))
        required_fields = ["confirmation_reference", "confirmed_by", "confirmed_at"]
        missing = [field for field in required_fields if not str(payload.get(field) or "").strip()]
        checks.append(_check("claim_confirmation_required_fields", not missing, "error", "Claim confirmation includes required audit fields.", f"Missing fields: {', '.join(missing)}" if missing else ""))
        confirmed_epoch = _parse_time(payload.get("confirmed_at"))
        checks.append(_check("claim_confirmation_time_parseable", confirmed_epoch > 0, "error", "confirmed_at is parseable as YYYY-MM-DD or UTC timestamp.", "Use confirmed_at like 2026-07-03T00:00:00Z."))
        checks.append(_check("claim_confirmation_time_not_future", confirmed_epoch == 0 or confirmed_epoch <= time.time() + 300, "error", "confirmed_at is not in the future.", "Use the actual confirmation timestamp."))
        scope = _string_list(payload.get("scope"))
        checks.append(_check("claim_confirmation_scope_declared", bool(scope), "error", "Confirmation declares reviewed scope.", "Set scope, for example ['result_claims', 'domain_data', 'figures']."))
        sensitive = sorted(set(_find_sensitive_paths(payload)))
        checks.append(_check("claim_confirmation_no_secret_material", not sensitive, "error", "Claim confirmation evidence does not contain obvious token, password, cookie, or private-key material.", f"Remove sensitive fields: {', '.join(sensitive[:10])}" if sensitive else ""))

        checks.append(_check("claim_confirmation_project_configured", project_path is not None, "error", "A project path or slug is available for claim confirmation.", "Set project_slug/project_path in the evidence or pass --project."))
        if project_path is not None:
            checks.append(_check("claim_confirmation_project_exists", project_path.exists(), "error", str(project_path), "Use a valid Draftpaper-loop project directory."))
            project_json = project_path / "project.json"
            checks.append(_check("claim_confirmation_project_json", project_json.exists(), "error", str(project_json), "Use a project directory containing project.json."))
            if project_json.exists():
                project_payload = _read_json(project_json)
                if isinstance(project_payload, dict) and "_read_error" not in project_payload:
                    expected_id = str(payload.get("project_id") or "").strip()
                    expected_slug = str(payload.get("project_slug") or "").strip()
                    if expected_id:
                        checks.append(_check("claim_confirmation_project_id_matches", str(project_payload.get("project_id") or "") == expected_id, "error", "project_id matches confirmation evidence.", "Use confirmation evidence for the exact project."))
                    if expected_slug:
                        checks.append(_check("claim_confirmation_project_slug_matches", project_path.name == expected_slug, "error", "project_slug matches confirmation evidence.", "Use confirmation evidence for the exact project slug."))
                else:
                    checks.append(_check("claim_confirmation_project_json_readable", False, "error", str(project_payload.get("_read_error") if isinstance(project_payload, dict) else type(project_payload).__name__), "Use a readable project.json."))

        claims = payload.get("claims") if isinstance(payload.get("claims"), list) else []
        checks.append(_check("claim_confirmation_claims_present", bool(claims), "error", "At least one claim is recorded for confirmation.", "Add claims with id, claim, status, reviewer, and evidence_refs."))
        bad_claims: list[str] = []
        unconfirmed_claims: list[str] = []
        missing_evidence_claims: list[str] = []
        for index, claim in enumerate(claims):
            if not isinstance(claim, dict):
                bad_claims.append(str(index))
                continue
            claim_id = str(claim.get("id") or index)
            if not str(claim.get("claim") or "").strip() or not str(claim.get("reviewer") or "").strip():
                bad_claims.append(claim_id)
            if str(claim.get("status") or "").strip().lower() not in ACCEPTED_CLAIM_STATUSES:
                unconfirmed_claims.append(claim_id)
            if not _string_list(claim.get("evidence_refs")):
                missing_evidence_claims.append(claim_id)
        observed["claims_count"] = len(claims)
        checks.append(_check("claim_confirmation_claim_shape", not bad_claims, "error", "Every claim includes claim text and reviewer.", f"Invalid claims: {', '.join(bad_claims[:20])}" if bad_claims else ""))
        checks.append(_check("claim_confirmation_all_claims_confirmed", not unconfirmed_claims, "error", "Every claim status is confirmed/approved/accepted.", f"Unconfirmed claims: {', '.join(unconfirmed_claims[:20])}" if unconfirmed_claims else ""))
        checks.append(_check("claim_confirmation_claim_evidence_refs", not missing_evidence_claims, "error", "Every claim includes evidence_refs.", f"Claims missing evidence refs: {', '.join(missing_evidence_claims[:20])}" if missing_evidence_claims else ""))

        artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), list) else []
        checks.append(_check("claim_confirmation_artifacts_present", bool(artifacts), "warning", "Confirmation references hashed project or review artifacts.", "Add artifacts for result_manifest, result_validity_report, core_evidence_report, or reviewer notes."))
        artifact_records: list[dict[str, Any]] = []
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                checks.append(_check(f"claim_confirmation_artifact_{index}_shape", False, "error", "artifact must be a JSON object", "Use artifacts with path and sha256 fields."))
                continue
            raw_path = str(artifact.get("path") or "").strip()
            expected_sha = str(artifact.get("sha256") or "").strip().lower()
            checks.append(_check(f"claim_confirmation_artifact_{index}_fields", bool(raw_path and expected_sha), "error", raw_path or "missing", "Each artifact must declare path and sha256."))
            if not raw_path or confirmation_file is None:
                continue
            path = _artifact_path(raw_path, confirmation_dir=confirmation_file.parent, project_path=project_path)
            checks.append(_check(f"claim_confirmation_artifact_{index}_exists", path.exists(), "error", str(path), "Keep referenced project/review artifacts available for audit."))
            if path.exists() and expected_sha:
                actual_sha = _sha256_file(path)
                checks.append(_check(f"claim_confirmation_artifact_{index}_sha256_matches", actual_sha == expected_sha, "error", str(path.name), "Update confirmation evidence only after intentional artifact replacement and re-review."))
                artifact_records.append({"path": raw_path, "sha256": actual_sha, "bytes": path.stat().st_size})
        observed["artifacts"] = artifact_records

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    report = {
        "schema_version": REPORT_SCHEMA,
        "status": "verified" if not errors else ("unconfigured" if confirmation_file is None else "attention"),
        "generated_at": _utc_timestamp(),
        "confirmation_file": str(confirmation_file) if confirmation_file is not None else "",
        "project": str(project_path) if project_path is not None else "",
        "confirmation": _public_confirmation_payload(payload) if payload else {},
        "observed": observed,
        "checks": checks,
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
            "passed": sum(1 for item in checks if item["passed"]),
        },
        "notes": [
            "This verifies a private user/domain confirmation record for manuscript claims and referenced project artifacts.",
            "It does not create scientific truth, replace peer review, or prove hosted SaaS readiness.",
        ],
    }
    if output is not None:
        output = output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        output.chmod(0o600)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify private domain/user confirmation evidence for Draftpaper-loop manuscript claims.")
    parser.add_argument("--confirmation-file", default="", help="Path to draftpaper.claim-confirmation/v1 evidence JSON.")
    parser.add_argument("--project", default="", help="Optional project directory. Defaults to evidence project_path/project_slug.")
    parser.add_argument("--output", default="", help="Optional private JSON report path.")
    args = parser.parse_args(argv)
    report = verify_claim_confirmation(
        confirmation_file=Path(args.confirmation_file) if args.confirmation_file else None,
        project=Path(args.project) if args.project else None,
        output=Path(args.output) if args.output else None,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
