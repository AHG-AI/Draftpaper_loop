#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any


REDACTED_VALUE = "[redacted]"
SENSITIVE_KEY_PARTS = (
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "password",
    "secret",
    "token",
)
FORBIDDEN_FILENAMES = {
    "active-handoff.env",
    "billing-rates.json",
    "claim-confirmation.json",
    "claim-confirmation-verification.json",
    "commercial-approval.json",
    "commercial-approval-verification.json",
    "commercial-license-grant.json",
    "console-users.json",
    "hosted-acceptance.json",
    "hosted-readiness.json",
    "license-grant.json",
    "operator-token.txt",
    "release-trust.json",
    "release-trust-verification.json",
    "security-review.json",
    "security-review-verification.json",
}
FORBIDDEN_SUFFIXES = {".env", ".key", ".pem", ".sig", ".zip"}
REQUIRED_JSON_FILES = {
    "support_manifest.json",
    "health.json",
    "commercial_readiness.json",
    "handoff_readiness.json",
    "hosted_readiness.json",
    "security_audit.json",
    "license.json",
    "license_entitlements.json",
    "claim_confirmation.json",
    "license_approval.json",
    "release_trust.json",
    "security_review.json",
    "access_policy.json",
    "usage.json",
    "quota.json",
    "billing.json",
    "backup_verification.json",
    "backup_rehearsals.json",
    "projects.json",
    "jobs.json",
    "audit.json",
    "service_console_manifest.json",
}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _safe_member_name(name: str) -> bool:
    return bool(name) and not name.startswith("/") and "\\" not in name and all(part not in {"", ".", ".."} for part in name.split("/"))


def _member_basename(name: str) -> str:
    return Path(name).name


def _forbidden_member(name: str) -> bool:
    if not _safe_member_name(name):
        return True
    path = Path(name)
    basename = path.name
    lowered = basename.lower()
    if lowered.startswith(".env") or basename in FORBIDDEN_FILENAMES:
        return True
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        return True
    parts = {part.lower() for part in path.parts}
    if "raw" in parts or "processed" in parts:
        return True
    if any(part in lowered for part in ("private-key", "client-secret", "access-token")):
        return True
    return False


def _read_json_member(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    payload = json.loads(archive.read(name).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return payload


def _prefix_for_members(names: set[str]) -> str:
    roots = {name.split("/", 1)[0] for name in names if "/" in name}
    if len(roots) != 1:
        return ""
    return next(iter(roots))


def _sensitive_key_findings(value: Any, *, path: str = "") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            child_path = f"{path}.{key_text}" if path else key_text
            if any(part in lowered for part in SENSITIVE_KEY_PARTS):
                if item != REDACTED_VALUE:
                    findings.append(child_path)
                continue
            findings.extend(_sensitive_key_findings(item, path=child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_sensitive_key_findings(item, path=f"{path}[{index}]"))
    return findings


def _suspicious_text_findings(name: str, text: str) -> list[str]:
    patterns = [
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"DRAFTPAPER_CONSOLE_TOKEN\s*=",
        r"DRAFTPAPER_[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY)\s*=",
        r"/Users/[^\"\\\s]+",
        r"/private/tmp/[^\"\\\s]+",
        r"/var/folders/[^\"\\\s]+",
        r"raw-secret-value",
        r"plain-token",
        r"plain-secret",
    ]
    return [f"{name}:{pattern}" for pattern in patterns if re.search(pattern, text)]


def verify_support_bundle_bytes(data: bytes, *, source: str = "<bytes>") -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    bundle_sha = _sha256_bytes(data)
    manifest: dict[str, Any] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = {name for name in archive.namelist() if name and not name.endswith("/")}
            bad_member = archive.testzip()
            checks.append(_check("support_bundle_zip_readable", bad_member is None, "error", bad_member or "ok"))
            unsafe = sorted(name for name in names if not _safe_member_name(name))
            checks.append(_check("support_bundle_member_paths_safe", not unsafe, "error", ", ".join(unsafe[:20]) if unsafe else "ok"))
            prefix = _prefix_for_members(names)
            checks.append(_check("support_bundle_single_root", bool(prefix), "error", prefix or "missing"))
            basenames = {_member_basename(name) for name in names}
            missing_required = sorted(REQUIRED_JSON_FILES - basenames)
            checks.append(_check("support_bundle_required_json_present", not missing_required, "error", ", ".join(missing_required) if missing_required else "ok"))
            non_json = sorted(name for name in names if not name.endswith(".json"))
            checks.append(_check("support_bundle_json_only", not non_json, "error", ", ".join(non_json[:20]) if non_json else "ok"))
            forbidden = sorted(name for name in names if _forbidden_member(name))
            checks.append(_check("support_bundle_private_members_excluded", not forbidden, "error", ", ".join(forbidden[:20]) if forbidden else "ok"))

            json_payloads: dict[str, dict[str, Any]] = {}
            json_errors: list[str] = []
            for name in sorted(names):
                if not name.endswith(".json"):
                    continue
                try:
                    payload = _read_json_member(archive, name)
                    json_payloads[_member_basename(name)] = payload
                    text = archive.read(name).decode("utf-8", errors="replace")
                    suspicious = _suspicious_text_findings(name, text)
                    if suspicious:
                        json_errors.extend(suspicious)
                    sensitive_findings = _sensitive_key_findings(payload)
                    if sensitive_findings:
                        json_errors.extend(f"{name}:{finding}" for finding in sensitive_findings)
                except Exception as exc:
                    json_errors.append(f"{name}:{exc}")
            checks.append(_check("support_bundle_json_readable_and_redacted", not json_errors, "error", ", ".join(json_errors[:20]) if json_errors else "ok"))

            manifest = json_payloads.get("support_manifest.json", {})
            checks.append(_check("support_bundle_manifest_schema", manifest.get("schema_version") == "draftpaper.support-bundle/v1", "error", str(manifest.get("schema_version") or "")))
            checks.append(_check("support_bundle_manifest_status", manifest.get("status") == "generated", "error", str(manifest.get("status") or "")))
            privacy = manifest.get("privacy") if isinstance(manifest.get("privacy"), dict) else {}
            checks.append(_check("support_bundle_project_files_excluded", privacy.get("includes_project_files") is False, "error", str(privacy.get("includes_project_files"))))
            checks.append(_check("support_bundle_raw_processed_excluded", privacy.get("includes_raw_or_processed_data") is False, "error", str(privacy.get("includes_raw_or_processed_data"))))
            checks.append(_check("support_bundle_redaction_marker", privacy.get("redacted_value") == REDACTED_VALUE, "error", str(privacy.get("redacted_value") or "")))
            checks.append(_check("support_bundle_path_roots_redacted", privacy.get("redacted_path_roots") is True, "error", str(privacy.get("redacted_path_roots"))))

            file_entries = manifest.get("files") if isinstance(manifest.get("files"), list) else []
            entry_errors: list[str] = []
            for entry in file_entries:
                if not isinstance(entry, dict):
                    entry_errors.append("entry_not_object")
                    continue
                relative = str(entry.get("path") or "")
                member = f"{prefix}/{relative}" if prefix and relative else ""
                if member not in names:
                    entry_errors.append(f"missing={relative}")
                    continue
                raw = archive.read(member)
                expected_sha = str(entry.get("sha256") or "").lower()
                expected_bytes = int(entry.get("bytes") or 0)
                if _sha256_bytes(raw) != expected_sha or len(raw) != expected_bytes:
                    entry_errors.append(f"mismatch={relative}")
            checks.append(_check("support_bundle_manifest_file_hashes", not entry_errors, "error", ", ".join(entry_errors[:20]) if entry_errors else "ok"))
    except Exception as exc:
        checks.append(_check("support_bundle_verification", False, "error", str(exc)))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "schema_version": "draftpaper.support-bundle-verification/v1",
        "status": "verified" if not errors else "attention",
        "source": source,
        "zip_sha256": bundle_sha,
        "manifest": {
            "generated_at": manifest.get("generated_at"),
            "archive_sha256": manifest.get("archive_sha256"),
            "archive_bytes": manifest.get("archive_bytes"),
        },
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "checks": checks,
    }


def verify_support_bundle(path: Path) -> dict[str, Any]:
    path = path.expanduser().resolve()
    try:
        data = path.read_bytes()
    except OSError as exc:
        checks = [_check("support_bundle_exists", False, "error", str(exc))]
        return {
            "schema_version": "draftpaper.support-bundle-verification/v1",
            "status": "attention",
            "source": str(path),
            "zip_sha256": "",
            "summary": {"checks": len(checks), "errors": 1, "warnings": 0},
            "checks": checks,
        }
    report = verify_support_bundle_bytes(data, source=str(path))
    report["path"] = str(path)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Draftpaper-loop redacted support bundle.")
    parser.add_argument("support_bundle_zip", help="draftpaper-support-bundle.zip path.")
    args = parser.parse_args(argv)
    result = verify_support_bundle(Path(args.support_bundle_zip))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
