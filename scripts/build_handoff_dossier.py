#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import time
import zipfile
from pathlib import Path
from typing import Any


SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _write_public_release_manifest(source: Path, target: Path) -> Path:
    payload = _read_json(source)
    signature = payload.get("signature") if isinstance(payload.get("signature"), dict) else {}
    public_payload: dict[str, Any] = {
        "status": payload.get("status"),
        "package": payload.get("package"),
        "zip_path": Path(str(payload.get("zip_path") or "")).name,
        "zip_sha256": payload.get("zip_sha256"),
        "zip_bytes": payload.get("zip_bytes"),
        "file_count": payload.get("file_count"),
        "missing_required_files": payload.get("missing_required_files") or [],
        "generated_at": payload.get("generated_at"),
    }
    if signature:
        public_payload["signature"] = {
            "signature_algorithm": signature.get("signature_algorithm"),
            "signature_sha256": signature.get("signature_sha256"),
            "public_key_sha256": signature.get("public_key_sha256"),
            "signed_at": signature.get("signed_at"),
        }
    _write_json(target, public_payload)
    return target


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _public_checks(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    public: list[dict[str, Any]] = []
    for item in checks:
        copied = dict(item)
        note = str(copied.get("note") or "")
        if note.startswith("/") or note.startswith("~"):
            copied["note"] = Path(note).name or "provided"
        public.append(copied)
    return public


def _artifact_summary(path: Path | None, *, role: str, required: bool = False) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    if path is None:
        return None, [_check(f"{role}_provided", not required, "error" if required else "info", "not supplied")]
    path = path.expanduser().resolve()
    checks = [_check(f"{role}_exists", path.exists() and path.is_file(), "error", str(path), f"Provide a readable {role} file.")]
    if not path.exists() or not path.is_file():
        return {"role": role, "filename": path.name, "exists": False}, checks
    return {
        "role": role,
        "filename": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }, checks


def _safe_release_artifacts(
    *,
    release_zip: Path | None,
    release_manifest: Path | None,
    release_sha256_file: Path | None,
    release_signature: Path | None,
    release_public_key: Path | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[Path]]:
    checks: list[dict[str, Any]] = []
    copied: list[Path] = []
    release: dict[str, Any] = {}
    zip_summary, zip_checks = _artifact_summary(release_zip, role="release_zip", required=False)
    checks.extend(zip_checks)
    if zip_summary:
        release["zip"] = zip_summary
    for role, path in [
        ("release_manifest", release_manifest),
        ("release_sha256_file", release_sha256_file),
        ("release_signature", release_signature),
        ("release_public_key", release_public_key),
    ]:
        summary, role_checks = _artifact_summary(path, role=role, required=False)
        checks.extend(role_checks)
        if summary:
            release[role] = summary
        if path is not None and path.exists() and path.is_file():
            copied.append(path.expanduser().resolve())
    return release, checks, copied


def _acceptance_summary(acceptance: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": acceptance.get("schema_version"),
        "status": acceptance.get("status"),
        "generated_at": acceptance.get("generated_at"),
        "base_url": acceptance.get("base_url"),
        "target_track": acceptance.get("target_track"),
        "commercial_grade": acceptance.get("commercial_grade"),
        "summary": acceptance.get("summary"),
        "evidence_summary": acceptance.get("evidence_summary"),
        "release_verification": {
            "status": (acceptance.get("release_verification") or {}).get("status") if isinstance(acceptance.get("release_verification"), dict) else "",
            "summary": (acceptance.get("release_verification") or {}).get("summary") if isinstance(acceptance.get("release_verification"), dict) else {},
            "zip_sha256": (acceptance.get("release_verification") or {}).get("zip_sha256") if isinstance(acceptance.get("release_verification"), dict) else "",
        },
        "hosted_readiness": {
            "status": (acceptance.get("hosted_readiness") or {}).get("status") if isinstance(acceptance.get("hosted_readiness"), dict) else "",
            "summary": (acceptance.get("hosted_readiness") or {}).get("summary") if isinstance(acceptance.get("hosted_readiness"), dict) else {},
        },
        "support_bundle": acceptance.get("support_bundle"),
        "next_required_actions": acceptance.get("next_required_actions") or [],
        "report_sha256": acceptance.get("report_sha256"),
    }


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


def _dossier_checks(acceptance_summary: dict[str, Any], release: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = acceptance_summary.get("evidence_summary") if isinstance(acceptance_summary.get("evidence_summary"), dict) else {}
    license_summary = evidence.get("license") if isinstance(evidence.get("license"), dict) else {}
    security = evidence.get("security_audit") if isinstance(evidence.get("security_audit"), dict) else {}
    release_package = evidence.get("release_package") if isinstance(evidence.get("release_package"), dict) else {}
    backup = evidence.get("backup_recovery") if isinstance(evidence.get("backup_recovery"), dict) else {}
    target = evidence.get("target_track") if isinstance(evidence.get("target_track"), dict) else {}
    support = evidence.get("support_bundle") if isinstance(evidence.get("support_bundle"), dict) else {}
    return [
        _check("acceptance_passed", acceptance_summary.get("status") == "passed", "error", str(acceptance_summary.get("status") or "")),
        _check("target_track_ready", target.get("status") == "ready", "error", str(target.get("status") or "")),
        _check("license_valid", license_summary.get("status") == "valid", "error", str(license_summary.get("status") or "")),
        _check("license_signature_verified", bool(license_summary.get("signature_verified")), "error", str(bool(license_summary.get("signature_verified")))),
        _check("license_public_key_pin_matched", bool(license_summary.get("public_key_pin_matched")), "error", str(bool(license_summary.get("public_key_pin_matched"))), "Regenerate the signed handoff config with a pinned public key SHA256."),
        _check("security_audit_clean", security.get("status") == "passed" and int(security.get("errors") or 0) == 0 and int(security.get("warnings") or 0) == 0, "error", f"errors={security.get('errors')} warnings={security.get('warnings')}"),
        _check("release_package_verified", release_package.get("status") == "verified", "error", str(release_package.get("status") or "")),
        _check("release_signature_verified", bool(release_package.get("signature_verified")), "error", str(bool(release_package.get("signature_verified")))),
        _check("backup_recovery_verified", backup.get("verification_status") == "verified" and backup.get("rehearsal_status") == "passed", "error", f"verify={backup.get('verification_status')} rehearse={backup.get('rehearsal_status')}"),
        _check("support_bundle_recorded", bool(support.get("sha256")), "warning", str(support.get("sha256") or ""), "Download a support bundle during acceptance."),
        _check("release_sidecars_recorded", bool(release.get("release_manifest")) and bool(release.get("release_sha256_file")), "warning", ", ".join(sorted(release.keys())), "Provide release manifest and sha256 sidecar paths."),
    ]


def build_handoff_dossier(
    *,
    acceptance_report: Path,
    output_dir: Path,
    output_zip: Path | None = None,
    customer_id: str = "",
    customer_name: str = "",
    release_zip: Path | None = None,
    release_manifest: Path | None = None,
    release_sha256_file: Path | None = None,
    release_signature: Path | None = None,
    release_public_key: Path | None = None,
) -> dict[str, Any]:
    acceptance_report = acceptance_report.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o700)

    acceptance = _read_json(acceptance_report)
    summary = _acceptance_summary(acceptance)
    if release_manifest is not None and release_manifest.expanduser().exists():
        release_manifest = _write_public_release_manifest(
            release_manifest.expanduser().resolve(),
            output_dir / "_public-release-artifacts" / release_manifest.expanduser().name,
        )
    release, artifact_checks, copied_artifacts = _safe_release_artifacts(
        release_zip=release_zip,
        release_manifest=release_manifest,
        release_sha256_file=release_sha256_file,
        release_signature=release_signature,
        release_public_key=release_public_key,
    )
    checks = [*artifact_checks, *_dossier_checks(summary, release)]
    checks.append(_check("full_payloads_excluded", "payloads" not in summary, "error", "acceptance summary excludes full runtime payloads."))
    checks.append(_check("sensitive_keys_excluded", not _contains_sensitive_key(summary), "error", "customer dossier summary does not include sensitive key names."))
    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    dossier = {
        "schema_version": "draftpaper.customer-handoff-dossier/v1",
        "status": "ready" if not errors else "attention",
        "generated_at": _utc_timestamp(),
        "customer": {
            "id": customer_id,
            "name": customer_name,
        },
        "acceptance": summary,
        "release_artifacts": release,
        "checks": _public_checks(checks),
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "notes": [
            "This dossier is a customer-facing evidence summary and intentionally excludes full runtime payloads, private license files, token files, project data, and the release zip body.",
            "Provide the release zip as a separate artifact and compare it against the zip_sha256 recorded here.",
        ],
    }
    unsigned = json.dumps(dossier, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    dossier["dossier_sha256"] = _sha256_bytes(unsigned)

    dossier_path = output_dir / "handoff-dossier.json"
    summary_path = output_dir / "handoff-acceptance-summary.json"
    _write_json(dossier_path, dossier)
    _write_json(summary_path, summary)

    copied: list[dict[str, Any]] = []
    release_dir = output_dir / "release-artifacts"
    release_dir.mkdir(parents=True, exist_ok=True)
    release_dir.chmod(0o700)
    for path in copied_artifacts:
        target = release_dir / path.name
        target.write_bytes(path.read_bytes())
        target.chmod(0o600)
        copied.append({"path": str(target), "filename": target.name, "bytes": target.stat().st_size, "sha256": sha256_file(target)})

    zip_path = output_zip.expanduser().resolve() if output_zip is not None else output_dir / "handoff-dossier.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(dossier_path, "handoff-dossier.json")
        archive.write(summary_path, "handoff-acceptance-summary.json")
        for item in copied:
            archive.write(Path(item["path"]), f"release-artifacts/{item['filename']}")
    zip_path.chmod(0o600)

    result = {
        "status": dossier["status"],
        "generated_at": dossier["generated_at"],
        "dossier_path": str(dossier_path),
        "acceptance_summary_path": str(summary_path),
        "zip_path": str(zip_path),
        "zip_sha256": sha256_file(zip_path),
        "copied_release_artifacts": copied,
        "dossier_sha256": dossier["dossier_sha256"],
        "summary": dossier["summary"],
    }
    _write_json(output_dir / "handoff-dossier-manifest.json", result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a customer-facing Draftpaper-loop handoff evidence dossier.")
    parser.add_argument("--acceptance-report", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--output-zip", default="")
    parser.add_argument("--customer-id", default="")
    parser.add_argument("--customer-name", default="")
    parser.add_argument("--release-zip", default="")
    parser.add_argument("--release-manifest", default="")
    parser.add_argument("--release-sha256-file", default="")
    parser.add_argument("--release-signature", default="")
    parser.add_argument("--release-public-key", default="")
    args = parser.parse_args(argv)
    result = build_handoff_dossier(
        acceptance_report=Path(args.acceptance_report),
        output_dir=Path(args.output_dir),
        output_zip=Path(args.output_zip) if args.output_zip else None,
        customer_id=args.customer_id,
        customer_name=args.customer_name,
        release_zip=Path(args.release_zip) if args.release_zip else None,
        release_manifest=Path(args.release_manifest) if args.release_manifest else None,
        release_sha256_file=Path(args.release_sha256_file) if args.release_sha256_file else None,
        release_signature=Path(args.release_signature) if args.release_signature else None,
        release_public_key=Path(args.release_public_key) if args.release_public_key else None,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
