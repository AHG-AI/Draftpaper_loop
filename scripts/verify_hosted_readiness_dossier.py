#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any


SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")
SENSITIVE_KEY_EXCEPTIONS = {"secrets_manager"}
FORBIDDEN_FILENAMES = {
    "active-handoff.env",
    "billing-rates.json",
    "commercial-license-grant.json",
    "console-users.json",
    "hosted-acceptance.json",
    "hosted-readiness.json",
    "license-grant.json",
    "operator-token.txt",
}
FORBIDDEN_SUFFIXES = {".key", ".pem", ".sig", ".zip"}


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


def _read_json_member(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    payload = json.loads(archive.read(name).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return payload


def _safe_member_name(name: str) -> bool:
    return bool(name) and not name.startswith("/") and "\\" not in name and all(part not in {"", ".", ".."} for part in name.split("/"))


def _forbidden_member(name: str) -> bool:
    if not _safe_member_name(name):
        return True
    path = Path(name)
    basename = path.name.lower()
    if basename.startswith(".env") or basename in FORBIDDEN_FILENAMES:
        return True
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        return True
    if any(part in basename for part in ("password", "token", "private-key", "client-secret")):
        return True
    return False


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered not in SENSITIVE_KEY_EXCEPTIONS and any(part in lowered for part in SENSITIVE_KEY_PARTS):
                return True
            if _contains_sensitive_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _dossier_digest(dossier: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in dossier.items() if key != "dossier_sha256"}
    return _sha256_bytes(json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def verify_hosted_readiness_dossier(dossier_zip: Path) -> dict[str, Any]:
    dossier_zip = dossier_zip.expanduser().resolve()
    checks: list[dict[str, Any]] = []
    dossier: dict[str, Any] = {}
    actual_zip_sha = ""
    try:
        actual_zip_sha = sha256_file(dossier_zip)
        checks.append(_check("dossier_zip_exists", dossier_zip.exists(), "error", str(dossier_zip)))
    except OSError as exc:
        checks.append(_check("dossier_zip_exists", False, "error", str(exc)))
        return {"status": "attention", "zip_path": str(dossier_zip), "checks": checks, "summary": {"checks": len(checks), "errors": 1, "warnings": 0}}

    try:
        with zipfile.ZipFile(dossier_zip) as archive:
            names = set(archive.namelist())
            bad_member = archive.testzip()
            checks.append(_check("dossier_zip_readable", bad_member is None, "error", bad_member or "ok"))
            checks.append(_check("dossier_member_present", "hosted-readiness-dossier.json" in names, "error", "hosted-readiness-dossier.json"))
            checks.append(_check("summary_member_present", "hosted-readiness-summary.json" in names, "error", "hosted-readiness-summary.json"))
            checks.append(_check("validation_report_member_present", "hosted-readiness-validation-report.json" in names, "error", "hosted-readiness-validation-report.json"))
            forbidden = sorted(name for name in names if _forbidden_member(name))
            checks.append(_check("private_members_excluded", not forbidden, "error", ", ".join(forbidden[:20]) if forbidden else "ok"))
            checks.append(_check("raw_hosted_evidence_file_excluded", "hosted-readiness.json" not in {Path(name).name for name in names}, "error", "raw hosted readiness JSON must not be embedded"))
            if "hosted-readiness-dossier.json" in names:
                dossier = _read_json_member(archive, "hosted-readiness-dossier.json")
                checks.append(_check("dossier_schema", dossier.get("schema_version") == "draftpaper.hosted-readiness-dossier/v1", "error", str(dossier.get("schema_version") or "")))
                checks.append(_check("dossier_status_ready", dossier.get("status") == "ready", "error", str(dossier.get("status") or "")))
                expected_digest = str(dossier.get("dossier_sha256") or "").lower()
                checks.append(_check("dossier_sha256_matches", bool(expected_digest) and _dossier_digest(dossier) == expected_digest, "error", expected_digest))
                checks.append(_check("sensitive_keys_excluded", not _contains_sensitive_key(dossier), "error", "dossier does not include sensitive key names"))
                validation = dossier.get("validation_report") if isinstance(dossier.get("validation_report"), dict) else {}
                checks.append(_check("hosted_validation_ready", validation.get("status") == "ready", "error", str(validation.get("status") or "")))
                failed_embedded = [item.get("id") for item in dossier.get("checks", []) if isinstance(item, dict) and item.get("severity") == "error" and not item.get("passed")]
                checks.append(_check("embedded_dossier_checks_passed", not failed_embedded, "error", ", ".join(str(item) for item in failed_embedded)))
                copied = dossier.get("copied_evidence_artifacts") if isinstance(dossier.get("copied_evidence_artifacts"), list) else []
                checks.append(_check("evidence_artifacts_recorded", bool(copied), "error", f"count={len(copied)}"))
                for index, item in enumerate(copied, start=1):
                    if not isinstance(item, dict):
                        checks.append(_check(f"evidence_artifact_{index}_record_shape", False, "error", "not an object"))
                        continue
                    member = str(item.get("member") or "")
                    checks.append(_check(f"evidence_artifact_{index}_included", member in names, "error", member))
                    if member in names:
                        data = archive.read(member)
                        expected_sha = str(item.get("sha256") or "").lower()
                        expected_bytes = int(item.get("bytes") or 0)
                        checks.append(_check(f"evidence_artifact_{index}_sha256_matches", _sha256_bytes(data) == expected_sha and len(data) == expected_bytes, "error", member))
            if "hosted-readiness-dossier.json" in names and "hosted-readiness-summary.json" in names:
                summary = _read_json_member(archive, "hosted-readiness-summary.json")
                checks.append(_check("summary_matches_dossier", summary == dossier.get("hosted_readiness"), "error", "hosted-readiness-summary.json"))
            if "hosted-readiness-dossier.json" in names and "hosted-readiness-validation-report.json" in names:
                report = _read_json_member(archive, "hosted-readiness-validation-report.json")
                checks.append(_check("validation_report_matches_dossier", report == dossier.get("validation_report"), "error", "hosted-readiness-validation-report.json"))
    except Exception as exc:
        checks.append(_check("dossier_verification", False, "error", str(exc)))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "status": "verified" if not errors else "attention",
        "zip_path": str(dossier_zip),
        "zip_sha256": actual_zip_sha,
        "dossier_sha256": str(dossier.get("dossier_sha256") or ""),
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Draftpaper-loop hosted readiness evidence dossier.")
    parser.add_argument("dossier_zip", help="hosted-readiness-dossier.zip path.")
    args = parser.parse_args(argv)
    result = verify_hosted_readiness_dossier(Path(args.dossier_zip))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
