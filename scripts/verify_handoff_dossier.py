#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any

try:
    from verify_release_package import verify_release_package
except ImportError:  # pragma: no cover - direct import fallback for tests.
    import importlib.util

    spec = importlib.util.spec_from_file_location("draftpaper_verify_release_package", Path(__file__).resolve().parent / "verify_release_package.py")
    if spec is None or spec.loader is None:
        verify_release_package = None  # type: ignore[assignment]
    else:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        verify_release_package = module.verify_release_package  # type: ignore[assignment]


SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")
FORBIDDEN_FILES = {
    "active-handoff.env",
    "billing-rates.json",
    "commercial-license-grant.json",
    "console-users.json",
    "hosted-acceptance.json",
    "hosted-readiness.json",
    "license-grant.json",
    "operator-token.txt",
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


def _read_json_member(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    payload = json.loads(archive.read(name).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return payload


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


def _safe_member_name(name: str) -> bool:
    return bool(name) and not name.startswith("/") and "\\" not in name and all(part not in {"", ".", ".."} for part in name.split("/"))


def _forbidden_member(name: str) -> bool:
    if not _safe_member_name(name):
        return True
    path = Path(name)
    basename = path.name
    if basename.startswith(".env") or basename in FORBIDDEN_FILES:
        return True
    suffix = path.suffix
    if suffix in {".key", ".zip"}:
        return True
    if suffix == ".pem" and not (name.startswith("release-artifacts/") and basename.endswith(".public.pem")):
        return True
    if suffix == ".sig" and not (name.startswith("release-artifacts/") and basename.endswith(".zip.sig")):
        return True
    return False


def _dossier_digest(dossier: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in dossier.items() if key != "dossier_sha256"}
    return _sha256_bytes(json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _parse_sha256_sidecar(raw: bytes) -> tuple[str, str]:
    line = raw.decode("utf-8").strip().splitlines()[0]
    parts = line.split()
    if len(parts) < 2:
        raise ValueError("sha256 sidecar must contain '<sha256>  <filename>'")
    return parts[0].lower(), parts[-1]


def _expected_sidecar_member(dossier: dict[str, Any], role: str) -> str:
    artifact = dossier.get("release_artifacts", {}).get(role) if isinstance(dossier.get("release_artifacts"), dict) else None
    if not isinstance(artifact, dict):
        return ""
    filename = str(artifact.get("filename") or "")
    return f"release-artifacts/{filename}" if filename else ""


def _verify_release_sidecars(archive: zipfile.ZipFile, names: set[str], dossier: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    artifacts = dossier.get("release_artifacts") if isinstance(dossier.get("release_artifacts"), dict) else {}
    for role in ["release_manifest", "release_sha256_file", "release_signature", "release_public_key"]:
        artifact = artifacts.get(role) if isinstance(artifacts, dict) else None
        if not isinstance(artifact, dict):
            checks.append(_check(f"{role}_recorded", role in {"release_signature", "release_public_key"}, "warning", "not recorded"))
            continue
        member = _expected_sidecar_member(dossier, role)
        checks.append(_check(f"{role}_included", member in names, "error", member, f"Include {artifact.get('filename')} in release-artifacts/."))
        if member not in names:
            continue
        data = archive.read(member)
        expected_sha = str(artifact.get("sha256") or "").lower()
        expected_bytes = int(artifact.get("bytes") or 0)
        checks.append(_check(f"{role}_sha256_matches", _sha256_bytes(data) == expected_sha and len(data) == expected_bytes, "error", member))
    zip_artifact = artifacts.get("zip") if isinstance(artifacts, dict) else None
    sha_member = _expected_sidecar_member(dossier, "release_sha256_file")
    if isinstance(zip_artifact, dict) and sha_member in names:
        try:
            sidecar_sha, sidecar_name = _parse_sha256_sidecar(archive.read(sha_member))
            checks.append(_check("release_sha256_sidecar_matches_zip_record", sidecar_sha == str(zip_artifact.get("sha256") or "").lower() and sidecar_name == str(zip_artifact.get("filename") or ""), "error", f"{sidecar_sha}  {sidecar_name}"))
        except Exception as exc:
            checks.append(_check("release_sha256_sidecar_matches_zip_record", False, "error", str(exc)))
    manifest_member = _expected_sidecar_member(dossier, "release_manifest")
    if isinstance(zip_artifact, dict) and manifest_member in names:
        try:
            manifest = _read_json_member(archive, manifest_member)
            checks.append(_check("release_manifest_zip_sha256_matches_zip_record", manifest.get("zip_sha256") == zip_artifact.get("sha256"), "error", str(manifest.get("zip_sha256") or "")))
            checks.append(_check("release_manifest_filename_matches_zip_record", Path(str(manifest.get("zip_path") or "")).name == zip_artifact.get("filename"), "warning", Path(str(manifest.get("zip_path") or "")).name))
        except Exception as exc:
            checks.append(_check("release_manifest_sidecar_readable", False, "error", str(exc)))
    return checks


def verify_handoff_dossier(
    dossier_zip: Path,
    *,
    release_zip: Path | None = None,
    require_release_zip: bool = False,
) -> dict[str, Any]:
    dossier_zip = dossier_zip.expanduser().resolve()
    checks: list[dict[str, Any]] = []
    release_report: dict[str, Any] | None = None
    dossier: dict[str, Any] = {}
    actual_zip_sha = ""
    try:
        actual_zip_sha = sha256_file(dossier_zip)
        checks.append(_check("dossier_zip_exists", dossier_zip.exists(), "error", str(dossier_zip)))
    except OSError as exc:
        checks.append(_check("dossier_zip_exists", False, "error", str(exc)))
        return {"status": "attention", "zip_path": str(dossier_zip), "checks": checks, "summary": {"errors": 1, "warnings": 0}}

    try:
        with zipfile.ZipFile(dossier_zip) as archive:
            names = set(archive.namelist())
            bad_member = archive.testzip()
            checks.append(_check("dossier_zip_readable", bad_member is None, "error", bad_member or "ok"))
            checks.append(_check("dossier_member_present", "handoff-dossier.json" in names, "error", "handoff-dossier.json"))
            checks.append(_check("acceptance_summary_member_present", "handoff-acceptance-summary.json" in names, "error", "handoff-acceptance-summary.json"))
            forbidden = sorted(name for name in names if _forbidden_member(name))
            checks.append(_check("private_members_excluded", not forbidden, "error", ", ".join(forbidden[:20]) if forbidden else "ok"))
            checks.append(_check("release_zip_not_embedded", not any(name.endswith(".zip") for name in names), "error", "release zip must be sent separately"))
            if "handoff-dossier.json" in names:
                dossier = _read_json_member(archive, "handoff-dossier.json")
                checks.append(_check("dossier_schema", dossier.get("schema_version") == "draftpaper.customer-handoff-dossier/v1", "error", str(dossier.get("schema_version") or "")))
                checks.append(_check("dossier_status_ready", dossier.get("status") == "ready", "error", str(dossier.get("status") or "")))
                expected_digest = str(dossier.get("dossier_sha256") or "").lower()
                checks.append(_check("dossier_sha256_matches", bool(expected_digest) and _dossier_digest(dossier) == expected_digest, "error", expected_digest))
                checks.append(_check("full_payloads_excluded", "payloads" not in dossier.get("acceptance", {}), "error", "dossier acceptance summary excludes full payloads"))
                checks.append(_check("sensitive_keys_excluded", not _contains_sensitive_key(dossier), "error", "dossier does not include sensitive key names"))
                failed_embedded = [item.get("id") for item in dossier.get("checks", []) if isinstance(item, dict) and item.get("severity") == "error" and not item.get("passed")]
                checks.append(_check("embedded_dossier_checks_passed", not failed_embedded, "error", ", ".join(str(item) for item in failed_embedded)))
                acceptance = dossier.get("acceptance") if isinstance(dossier.get("acceptance"), dict) else {}
                evidence = acceptance.get("evidence_summary") if isinstance(acceptance.get("evidence_summary"), dict) else {}
                checks.append(_check("acceptance_passed", acceptance.get("status") == "passed", "error", str(acceptance.get("status") or "")))
                checks.append(_check("target_track_ready", (evidence.get("target_track") or {}).get("status") == "ready" if isinstance(evidence.get("target_track"), dict) else False, "error", str((evidence.get("target_track") or {}).get("status") if isinstance(evidence.get("target_track"), dict) else "")))
                license_summary = evidence.get("license") if isinstance(evidence.get("license"), dict) else {}
                checks.append(_check("license_public_key_pin_matched", bool(license_summary.get("public_key_pin_matched")), "error", str(bool(license_summary.get("public_key_pin_matched")))))
                checks.append(_check("license_signature_verified", bool(license_summary.get("signature_verified")), "error", str(bool(license_summary.get("signature_verified")))))
                security = evidence.get("security_audit") if isinstance(evidence.get("security_audit"), dict) else {}
                checks.append(_check("security_audit_clean", security.get("status") == "passed" and int(security.get("errors") or 0) == 0 and int(security.get("warnings") or 0) == 0, "error", f"errors={security.get('errors')} warnings={security.get('warnings')}"))
                release_summary = evidence.get("release_package") if isinstance(evidence.get("release_package"), dict) else {}
                checks.append(_check("release_package_verified", release_summary.get("status") == "verified", "error", str(release_summary.get("status") or "")))
                checks.append(_check("release_signature_verified", bool(release_summary.get("signature_verified")), "error", str(bool(release_summary.get("signature_verified")))))
                checks.extend(_verify_release_sidecars(archive, names, dossier))
            if "handoff-dossier.json" in names and "handoff-acceptance-summary.json" in names:
                summary = _read_json_member(archive, "handoff-acceptance-summary.json")
                checks.append(_check("acceptance_summary_matches_dossier", summary == dossier.get("acceptance"), "error", "handoff-acceptance-summary.json"))
    except Exception as exc:
        checks.append(_check("dossier_verification", False, "error", str(exc)))

    if release_zip is not None:
        release_zip = release_zip.expanduser().resolve()
        zip_record = dossier.get("release_artifacts", {}).get("zip") if isinstance(dossier.get("release_artifacts"), dict) else {}
        if isinstance(zip_record, dict):
            checks.append(_check("separate_release_zip_matches_dossier", release_zip.exists() and sha256_file(release_zip) == str(zip_record.get("sha256") or "").lower() and release_zip.name == str(zip_record.get("filename") or ""), "error", str(release_zip)))
        manifest_member = _expected_sidecar_member(dossier, "release_manifest")
        sha_member = _expected_sidecar_member(dossier, "release_sha256_file")
        sig_member = _expected_sidecar_member(dossier, "release_signature")
        public_member = _expected_sidecar_member(dossier, "release_public_key")
        try:
            with zipfile.ZipFile(dossier_zip) as archive, tempfile.TemporaryDirectory() as tmp:
                tmpdir = Path(tmp)
                paths: dict[str, Path] = {}
                for role, member in [("manifest", manifest_member), ("sha", sha_member), ("signature", sig_member), ("public_key", public_member)]:
                    if member:
                        path = tmpdir / Path(member).name
                        path.write_bytes(archive.read(member))
                        paths[role] = path
                if verify_release_package is None:
                    checks.append(_check("release_package_reverified", False, "error", "verify_release_package.py is unavailable"))
                else:
                    release_report = verify_release_package(
                        release_zip,
                        manifest_path=paths.get("manifest"),
                        sha256_path=paths.get("sha"),
                        signature_path=paths.get("signature"),
                        public_key_path=paths.get("public_key"),
                        require_signature=True,
                    )
                    checks.append(_check("release_package_reverified", release_report.get("status") == "verified", "error", str(release_report.get("status") or "")))
        except Exception as exc:
            checks.append(_check("release_package_reverified", False, "error", str(exc)))
    elif require_release_zip:
        checks.append(_check("separate_release_zip_required", False, "error", "release zip not supplied"))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "status": "verified" if not errors else "attention",
        "zip_path": str(dossier_zip),
        "zip_sha256": actual_zip_sha,
        "dossier_sha256": str(dossier.get("dossier_sha256") or ""),
        "release_verification": release_report,
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Draftpaper-loop customer handoff dossier.")
    parser.add_argument("dossier_zip", help="handoff-dossier.zip path.")
    parser.add_argument("--release-zip", default="", help="Optional separate release zip to cross-check and reverify.")
    parser.add_argument("--require-release-zip", action="store_true", help="Fail when the separate release zip is not supplied.")
    args = parser.parse_args(argv)
    result = verify_handoff_dossier(
        Path(args.dossier_zip),
        release_zip=Path(args.release_zip).expanduser() if args.release_zip else None,
        require_release_zip=args.require_release_zip,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
