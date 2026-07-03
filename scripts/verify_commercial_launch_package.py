#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from build_commercial_launch_package import LAUNCH_PACKAGE_SCHEMA  # noqa: E402
from build_commercial_launch_package import _launch_digest  # noqa: E402
from verify_handoff_dossier import verify_handoff_dossier  # noqa: E402
from verify_hosted_readiness_dossier import verify_hosted_readiness_dossier  # noqa: E402
from verify_release_package import verify_release_package  # noqa: E402
from verify_support_bundle import verify_support_bundle  # noqa: E402


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
SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")


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


def _allowed_zip_member(name: str) -> bool:
    if not _safe_member_name(name):
        return False
    path = Path(name)
    basename = path.name.lower()
    if basename.startswith(".env") or basename in FORBIDDEN_FILENAMES:
        return False
    suffix = path.suffix.lower()
    if suffix in {".key"}:
        return False
    if suffix == ".pem" and not (name.startswith("release/") and basename.endswith(".public.pem")):
        return False
    if suffix == ".sig" and not (name.startswith("release/") and basename.endswith(".zip.sig")):
        return False
    if suffix == ".zip" and not (name.startswith("release/") or name.startswith("dossiers/") or name.startswith("support/")):
        return False
    return True


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in SENSITIVE_KEY_PARTS):
                return True
            if _contains_sensitive_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _artifact_path(tmpdir: Path, role: str, artifact: dict[str, Any]) -> Path:
    filename = str(artifact.get("filename") or Path(str(artifact.get("member") or role)).name)
    return tmpdir / role / filename


def _extract_artifacts(archive: zipfile.ZipFile, tmpdir: Path, package: dict[str, Any], names: set[str]) -> tuple[dict[str, Path], list[dict[str, Any]]]:
    extracted: dict[str, Path] = {}
    checks: list[dict[str, Any]] = []
    artifacts = package.get("artifacts") if isinstance(package.get("artifacts"), dict) else {}
    for role, artifact in sorted(artifacts.items()):
        if not isinstance(artifact, dict):
            checks.append(_check(f"{role}_artifact_record_shape", False, "error", "not an object"))
            continue
        member = str(artifact.get("member") or "")
        checks.append(_check(f"{role}_member_included", member in names, "error", member))
        if member not in names:
            continue
        data = archive.read(member)
        expected_sha = str(artifact.get("sha256") or "").lower()
        expected_bytes = int(artifact.get("bytes") or 0)
        checks.append(_check(f"{role}_member_hash_matches", _sha256_bytes(data) == expected_sha and len(data) == expected_bytes, "error", member))
        target = _artifact_path(tmpdir, str(role), artifact)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        extracted[str(role)] = target
    return extracted, checks


def _report_status_check(report: dict[str, Any] | None, item_id: str, expected: str) -> dict[str, Any]:
    status = report.get("status") if isinstance(report, dict) else ""
    return _check(item_id, status == expected, "error", str(status or ""))


def verify_commercial_launch_package(package_zip: Path) -> dict[str, Any]:
    package_zip = package_zip.expanduser().resolve()
    checks: list[dict[str, Any]] = []
    package: dict[str, Any] = {}
    reports: dict[str, Any] = {}
    actual_zip_sha = ""
    try:
        actual_zip_sha = sha256_file(package_zip)
        checks.append(_check("launch_zip_exists", package_zip.exists(), "error", str(package_zip)))
    except OSError as exc:
        checks.append(_check("launch_zip_exists", False, "error", str(exc)))
        return {"status": "attention", "zip_path": str(package_zip), "checks": checks, "summary": {"checks": len(checks), "errors": 1, "warnings": 0}}

    try:
        with zipfile.ZipFile(package_zip) as archive, tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            names = {name for name in archive.namelist() if name and not name.endswith("/")}
            bad_member = archive.testzip()
            checks.append(_check("launch_zip_readable", bad_member is None, "error", bad_member or "ok"))
            checks.append(_check("launch_package_member_present", "commercial-launch-package.json" in names, "error", "commercial-launch-package.json"))
            checks.append(_check("launch_summary_member_present", "commercial-launch-summary.json" in names, "warning", "commercial-launch-summary.json"))
            forbidden = sorted(name for name in names if not _allowed_zip_member(name))
            checks.append(_check("private_members_excluded", not forbidden, "error", ", ".join(forbidden[:20]) if forbidden else "ok"))
            if "commercial-launch-package.json" in names:
                package = _read_json_member(archive, "commercial-launch-package.json")
                checks.append(_check("launch_package_schema", package.get("schema_version") == LAUNCH_PACKAGE_SCHEMA, "error", str(package.get("schema_version") or "")))
                checks.append(_check("launch_package_status_ready", package.get("status") == "ready", "error", str(package.get("status") or "")))
                expected_digest = str(package.get("package_sha256") or "").lower()
                checks.append(_check("launch_package_sha256_matches", bool(expected_digest) and _launch_digest(package) == expected_digest, "error", expected_digest))
                checks.append(_check("raw_acceptance_payloads_excluded", "payloads" not in (package.get("acceptance") if isinstance(package.get("acceptance"), dict) else {}), "error", "raw acceptance payloads excluded"))
                checks.append(_check("sensitive_keys_excluded", not _contains_sensitive_key(package.get("acceptance")), "error", "acceptance summary has no sensitive key names"))
                embedded_failures = [item.get("id") for item in package.get("checks", []) if isinstance(item, dict) and item.get("severity") == "error" and not item.get("passed")]
                checks.append(_check("embedded_launch_checks_passed", not embedded_failures, "error", ", ".join(str(item) for item in embedded_failures)))
                extracted, artifact_checks = _extract_artifacts(archive, tmpdir, package, names)
                checks.extend(artifact_checks)

                required_roles = ["release_zip", "release_manifest", "release_sha256_file", "release_signature", "release_public_key", "handoff_dossier", "support_bundle"]
                target_track = str(package.get("target_track") or "")
                if target_track == "hosted_saas":
                    required_roles.append("hosted_readiness_dossier")
                for role in required_roles:
                    checks.append(_check(f"{role}_artifact_available", role in extracted, "error", role))

                if all(role in extracted for role in ["release_zip", "release_manifest", "release_sha256_file", "release_signature", "release_public_key"]):
                    reports["release_package"] = verify_release_package(
                        extracted["release_zip"],
                        manifest_path=extracted["release_manifest"],
                        sha256_path=extracted["release_sha256_file"],
                        signature_path=extracted["release_signature"],
                        public_key_path=extracted["release_public_key"],
                        require_signature=True,
                    )
                    checks.append(_report_status_check(reports["release_package"], "release_package_reverified", "verified"))
                if "handoff_dossier" in extracted and "release_zip" in extracted:
                    reports["handoff_dossier"] = verify_handoff_dossier(extracted["handoff_dossier"], release_zip=extracted["release_zip"], require_release_zip=True)
                    checks.append(_report_status_check(reports["handoff_dossier"], "handoff_dossier_reverified", "verified"))
                if "support_bundle" in extracted:
                    reports["support_bundle"] = verify_support_bundle(extracted["support_bundle"])
                    checks.append(_report_status_check(reports["support_bundle"], "support_bundle_reverified", "verified"))
                if "hosted_readiness_dossier" in extracted:
                    reports["hosted_readiness_dossier"] = verify_hosted_readiness_dossier(extracted["hosted_readiness_dossier"])
                    checks.append(_report_status_check(reports["hosted_readiness_dossier"], "hosted_readiness_dossier_reverified", "verified"))
                elif target_track == "hosted_saas":
                    checks.append(_check("hosted_readiness_dossier_reverified", False, "error", "missing"))
            if "commercial-launch-package.json" in names and "commercial-launch-summary.json" in names:
                summary = _read_json_member(archive, "commercial-launch-summary.json")
                checks.append(_check("launch_summary_matches_package", summary.get("status") == package.get("status") and summary.get("target_track") == package.get("target_track"), "warning", "commercial-launch-summary.json"))
    except Exception as exc:
        checks.append(_check("launch_package_verification", False, "error", str(exc)))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "schema_version": "draftpaper.commercial-launch-package-verification/v1",
        "status": "verified" if not errors else "attention",
        "zip_path": str(package_zip),
        "zip_sha256": actual_zip_sha,
        "package_sha256": str(package.get("package_sha256") or ""),
        "target_track": str(package.get("target_track") or ""),
        "reports": {
            key: {
                "status": value.get("status"),
                "summary": value.get("summary") or {},
                "zip_sha256": value.get("zip_sha256") or "",
                "dossier_sha256": value.get("dossier_sha256") or "",
            }
            for key, value in reports.items()
            if isinstance(value, dict)
        },
        "summary": {"checks": len(checks), "errors": len(errors), "warnings": len(warnings)},
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Draftpaper-loop commercial launch evidence package.")
    parser.add_argument("package_zip", help="commercial-launch-package.zip path.")
    args = parser.parse_args(argv)
    result = verify_commercial_launch_package(Path(args.package_zip))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
