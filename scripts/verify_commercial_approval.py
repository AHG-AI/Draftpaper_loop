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
APPROVAL_SCHEMA = "draftpaper.commercial-approval/v1"
REPORT_SCHEMA = "draftpaper.commercial-approval-verification/v1"
REQUIRED_DOCUMENT_HASHES = [
    "LICENSE",
    "NOTICE",
    "COMMERCIAL_LICENSE.md",
    "COMPLIANCE.md",
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


def _license_canonical_bytes(payload: dict[str, Any]) -> bytes:
    unsigned = {
        key: value
        for key, value in payload.items()
        if key not in {"grant_sha256", "sha256", "signature", "signed_at"}
    }
    return json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def license_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_license_canonical_bytes(payload)).hexdigest()


def _file_public_mode(path: Path) -> int:
    try:
        return stat.S_IMODE(path.stat().st_mode) & 0o077
    except OSError:
        return 0o777


def _parse_approval_time(value: Any) -> float:
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


def _document_hashes(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(val).strip().lower() for key, val in value.items() if str(val).strip()}
    if isinstance(value, list):
        hashes: dict[str, str] = {}
        for item in value:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or "").strip()
            digest = str(item.get("sha256") or "").strip().lower()
            if path and digest:
                hashes[path] = digest
        return hashes
    return {}


def _find_sensitive_paths(value: Any, *, prefix: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            child_path = f"{prefix}.{key_text}"
            if any(part in key_lower for part in SENSITIVE_KEY_PARTS):
                findings.append(child_path)
            findings.extend(_find_sensitive_paths(child, prefix=child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_find_sensitive_paths(child, prefix=f"{prefix}[{index}]"))
    elif isinstance(value, str):
        if any(marker in value for marker in SENSITIVE_VALUE_MARKERS):
            findings.append(prefix)
    return findings


def _public_approval_payload(payload: dict[str, Any]) -> dict[str, Any]:
    fields = [
        "schema_version",
        "status",
        "approval_reference",
        "approval_authority",
        "approved_by",
        "approved_at",
        "customer_id",
        "customer_name",
        "license_id",
        "scope",
        "license_grant_sha256",
        "license_file_sha256",
    ]
    return {field: payload.get(field) for field in fields if field in payload}


def verify_commercial_approval(
    *,
    approval_file: Path | None = None,
    license_file: Path | None = None,
    root: Path = REPO_ROOT,
    output: Path | None = None,
) -> dict[str, Any]:
    root = root.expanduser().resolve()
    env_approval = os.environ.get("DRAFTPAPER_COMMERCIAL_APPROVAL_FILE", "").strip()
    env_license = os.environ.get("DRAFTPAPER_LICENSE_FILE", "").strip()
    approval_file = approval_file.expanduser().resolve() if approval_file is not None else (Path(env_approval).expanduser().resolve() if env_approval else None)
    license_file = license_file.expanduser().resolve() if license_file is not None else (Path(env_license).expanduser().resolve() if env_license else None)
    checks: list[dict[str, Any]] = []
    payload: dict[str, Any] = {}
    license_payload: dict[str, Any] = {}
    computed_license_digest = ""
    license_file_sha256 = ""

    checks.append(_check("approval_file_configured", approval_file is not None, "error", "Commercial approval evidence file is configured.", "Set DRAFTPAPER_COMMERCIAL_APPROVAL_FILE or pass --approval-file."))
    checks.append(_check("license_file_configured", license_file is not None, "error", "Commercial license grant file is configured for approval comparison.", "Set DRAFTPAPER_LICENSE_FILE or pass --license-file."))

    if approval_file is not None:
        checks.append(_check("approval_file_exists", approval_file.exists(), "error", str(approval_file), "Create the approval evidence file or fix the configured path."))
        if approval_file.exists():
            checks.append(_check("approval_file_permissions", _file_public_mode(approval_file) == 0, "warning", f"public permission bits={oct(_file_public_mode(approval_file))}", "Restrict the approval evidence file to owner-only permissions, for example chmod 600."))
            loaded = _read_json(approval_file)
            if isinstance(loaded, dict) and "_read_error" not in loaded:
                payload = loaded
                checks.append(_check("approval_file_shape", True, "error", "Approval evidence file contains a JSON object."))
            else:
                checks.append(_check("approval_file_shape", False, "error", str(loaded.get("_read_error") if isinstance(loaded, dict) else type(loaded).__name__), "Use a JSON object with schema_version draftpaper.commercial-approval/v1."))

    if license_file is not None:
        checks.append(_check("license_file_exists", license_file.exists(), "error", str(license_file), "Create the license grant file or fix the configured path."))
        if license_file.exists():
            license_file_sha256 = _sha256_file(license_file)
            loaded_license = _read_json(license_file)
            if isinstance(loaded_license, dict) and "_read_error" not in loaded_license:
                license_payload = loaded_license
                computed_license_digest = license_digest(license_payload)
                checks.append(_check("license_file_shape", True, "error", "License grant file contains a JSON object."))
            else:
                checks.append(_check("license_file_shape", False, "error", str(loaded_license.get("_read_error") if isinstance(loaded_license, dict) else type(loaded_license).__name__), "Use a valid commercial license grant JSON object."))

    if payload:
        checks.append(_check("approval_schema", payload.get("schema_version") == APPROVAL_SCHEMA, "error", f"schema_version={payload.get('schema_version') or 'missing'}", f"Set schema_version to {APPROVAL_SCHEMA}."))
        checks.append(_check("approval_status", str(payload.get("status") or "").strip().lower() == "approved", "error", f"status={payload.get('status') or 'missing'}", "Set status to approved only after external approval is complete."))
        required_fields = ["approval_reference", "approval_authority", "approved_by", "approved_at", "customer_id", "customer_name", "license_id"]
        missing = [field for field in required_fields if not str(payload.get(field) or "").strip()]
        checks.append(_check("approval_required_fields", not missing, "error", "Approval evidence includes required audit fields.", f"Missing fields: {', '.join(missing)}" if missing else ""))
        approval_epoch = _parse_approval_time(payload.get("approved_at"))
        checks.append(_check("approval_time_parseable", approval_epoch > 0, "error", "approved_at is parseable as YYYY-MM-DD or UTC timestamp.", "Use approved_at like 2026-07-03T00:00:00Z."))
        checks.append(_check("approval_time_not_future", approval_epoch == 0 or approval_epoch <= time.time() + 300, "error", "approved_at is not in the future.", "Use the actual approval timestamp."))
        scope = _string_list(payload.get("scope"))
        checks.append(_check("approval_scope_declared", bool(scope), "error", "Approval declares the allowed commercial scope.", "Set scope, for example ['paid_local_handoff']."))
        refs = _evidence_refs(payload.get("evidence_refs"))
        checks.append(_check("approval_evidence_refs", bool(refs), "error", "Approval includes at least one external approval or contract evidence reference.", "Add evidence_refs with contract, ticket, signature, or approval-system references."))
        sensitive = sorted(set(_find_sensitive_paths(payload)))
        checks.append(_check("approval_no_secret_material", not sensitive, "error", "Approval evidence does not contain obvious token, password, cookie, or private-key material.", f"Remove sensitive fields: {', '.join(sensitive[:10])}" if sensitive else ""))

        if license_payload:
            checks.append(_check("approval_license_id_matches", str(payload.get("license_id") or "").strip() == str(license_payload.get("license_id") or "").strip(), "error", "Approval license_id matches the configured license grant.", "Point approval evidence at the exact approved license grant."))
            checks.append(_check("approval_customer_id_matches", str(payload.get("customer_id") or "").strip() == str(license_payload.get("customer_id") or "").strip(), "error", "Approval customer_id matches the configured license grant.", "Use the approval record for the same customer_id as the license grant."))
            checks.append(_check("approval_customer_name_matches", str(payload.get("customer_name") or "").strip() == str(license_payload.get("customer_name") or "").strip(), "warning", "Approval customer_name matches the configured license grant.", "Keep the customer display name aligned with the approved license grant."))
            expected_grant_sha = str(payload.get("license_grant_sha256") or "").strip().lower()
            checks.append(_check("approval_license_grant_sha256_present", bool(expected_grant_sha), "error", "Approval records the canonical license grant SHA256.", "Set license_grant_sha256 to the current computed license grant digest."))
            if expected_grant_sha:
                checks.append(_check("approval_license_grant_sha256_matches", expected_grant_sha == computed_license_digest, "error", "Approval license_grant_sha256 matches the configured license grant.", "Reapprove or update approval evidence after intentional license edits."))
            expected_file_sha = str(payload.get("license_file_sha256") or "").strip().lower()
            if expected_file_sha:
                checks.append(_check("approval_license_file_sha256_matches", expected_file_sha == license_file_sha256, "error", "Approval license_file_sha256 matches the configured license grant file.", "Regenerate approval evidence after intentional license file edits."))

        doc_hashes = _document_hashes(payload.get("document_hashes"))
        missing_docs = [relative for relative in REQUIRED_DOCUMENT_HASHES if relative not in doc_hashes]
        checks.append(_check("approval_document_hashes_present", not missing_docs, "error", "Approval records hashes for commercial boundary documents.", f"Missing document hashes: {', '.join(missing_docs)}" if missing_docs else ""))
        for relative in REQUIRED_DOCUMENT_HASHES:
            path = root / relative
            expected = doc_hashes.get(relative, "")
            checks.append(_check(f"approval_document_exists_{relative.replace('/', '_')}", path.exists(), "error", relative, "Keep required commercial boundary documents in the release."))
            if path.exists() and expected:
                checks.append(_check(f"approval_document_hash_matches_{relative.replace('/', '_')}", _sha256_file(path) == expected, "error", f"{relative} sha256", "Reapprove or update document_hashes after intentional legal/compliance document edits."))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    report = {
        "schema_version": REPORT_SCHEMA,
        "status": "verified" if not errors else ("unconfigured" if approval_file is None else "attention"),
        "generated_at": _utc_timestamp(),
        "approval_file": str(approval_file) if approval_file is not None else "",
        "license_file": str(license_file) if license_file is not None else "",
        "approval": _public_approval_payload(payload) if payload else {},
        "computed_license_grant_sha256": computed_license_digest,
        "license_file_sha256": license_file_sha256,
        "checks": checks,
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
            "passed": sum(1 for item in checks if item["passed"]),
        },
        "notes": [
            "This verifies a private commercial approval evidence record against the local license grant and boundary-document hashes.",
            "It does not create legal approval, sign contracts, collect payment, or prove hosted SaaS readiness.",
        ],
    }
    if output is not None:
        output = output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        output.chmod(0o600)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a private Draftpaper-loop commercial approval evidence record.")
    parser.add_argument("--approval-file", default="", help="Path to draftpaper.commercial-approval/v1 approval evidence JSON.")
    parser.add_argument("--license-file", default="", help="Path to the approved commercial license grant JSON.")
    parser.add_argument("--root", default=str(REPO_ROOT), help="Repository/release root used for legal/compliance document hash checks.")
    parser.add_argument("--output", default="", help="Optional private JSON report path.")
    args = parser.parse_args(argv)
    report = verify_commercial_approval(
        approval_file=Path(args.approval_file) if args.approval_file else None,
        license_file=Path(args.license_file) if args.license_file else None,
        root=Path(args.root),
        output=Path(args.output) if args.output else None,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
