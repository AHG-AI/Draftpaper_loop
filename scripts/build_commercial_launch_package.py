#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import zipfile
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from verify_handoff_dossier import verify_handoff_dossier  # noqa: E402
from verify_hosted_readiness_dossier import verify_hosted_readiness_dossier  # noqa: E402
from verify_release_package import verify_release_package  # noqa: E402
from verify_support_bundle import verify_support_bundle  # noqa: E402


LAUNCH_PACKAGE_SCHEMA = "draftpaper.commercial-launch-package/v1"
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


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
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
    _write_private_json(target, public_payload)
    return target


def _safe_fragment(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip(".-") or "artifact"


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


def _artifact_record(role: str, path: Path | None, *, required: bool, member_dir: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    if path is None:
        severity = "error" if required else "info"
        return None, [_check(f"{role}_provided", not required, severity, "not supplied")]
    resolved = path.expanduser().resolve()
    checks = [_check(f"{role}_exists", resolved.exists() and resolved.is_file(), "error", str(resolved), f"Provide a readable {role} artifact.")]
    if not resolved.exists() or not resolved.is_file():
        return {
            "role": role,
            "filename": resolved.name,
            "member": f"{member_dir}/{role}-{_safe_fragment(resolved.name)}",
            "exists": False,
        }, checks
    return {
        "role": role,
        "filename": resolved.name,
        "_source_path": str(resolved),
        "member": f"{member_dir}/{role}-{_safe_fragment(resolved.name)}",
        "bytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }, checks


def _public_checks(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    public: list[dict[str, Any]] = []
    for item in checks:
        copied = dict(item)
        note = str(copied.get("note") or "")
        if note.startswith("/") or note.startswith("~"):
            copied["note"] = Path(note).name or "provided"
        public.append(copied)
    return public


def _report_summary(report: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(report, dict):
        return {"status": ""}
    return {
        "status": report.get("status"),
        "schema_version": report.get("schema_version"),
        "summary": report.get("summary") or {},
        "zip_sha256": report.get("zip_sha256") or "",
        "dossier_sha256": report.get("dossier_sha256") or "",
    }


def _acceptance_summary(acceptance: dict[str, Any]) -> dict[str, Any]:
    evidence = acceptance.get("evidence_summary") if isinstance(acceptance.get("evidence_summary"), dict) else {}
    return {
        "schema_version": acceptance.get("schema_version"),
        "status": acceptance.get("status"),
        "generated_at": acceptance.get("generated_at"),
        "base_url": acceptance.get("base_url"),
        "target_track": acceptance.get("target_track"),
        "commercial_grade": acceptance.get("commercial_grade"),
        "summary": acceptance.get("summary") or {},
        "evidence_summary": {
            "target_track": evidence.get("target_track") if isinstance(evidence.get("target_track"), dict) else {},
            "license": evidence.get("license") if isinstance(evidence.get("license"), dict) else {},
            "security_audit": evidence.get("security_audit") if isinstance(evidence.get("security_audit"), dict) else {},
            "release_package": evidence.get("release_package") if isinstance(evidence.get("release_package"), dict) else {},
            "backup_recovery": evidence.get("backup_recovery") if isinstance(evidence.get("backup_recovery"), dict) else {},
            "hosted_readiness": evidence.get("hosted_readiness") if isinstance(evidence.get("hosted_readiness"), dict) else {},
            "hosted_readiness_dossier": evidence.get("hosted_readiness_dossier") if isinstance(evidence.get("hosted_readiness_dossier"), dict) else {},
            "support_bundle": evidence.get("support_bundle") if isinstance(evidence.get("support_bundle"), dict) else {},
        },
        "release_verification": _report_summary(acceptance.get("release_verification") if isinstance(acceptance.get("release_verification"), dict) else None),
        "hosted_dossier_verification": _report_summary(acceptance.get("hosted_dossier_verification") if isinstance(acceptance.get("hosted_dossier_verification"), dict) else None),
        "support_bundle_verification": _report_summary(acceptance.get("support_bundle_verification") if isinstance(acceptance.get("support_bundle_verification"), dict) else None),
        "next_required_actions": acceptance.get("next_required_actions") or [],
        "report_sha256": acceptance.get("report_sha256") or "",
    }


def _launch_digest(payload: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "package_sha256"}
    return _sha256_bytes(json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _status_check(report: dict[str, Any] | None, item_id: str, expected: str, remediation: str) -> dict[str, Any]:
    status = report.get("status") if isinstance(report, dict) else ""
    return _check(item_id, status == expected, "error", str(status or ""), remediation)


def build_commercial_launch_package(
    *,
    acceptance_report: Path,
    output_dir: Path,
    output_zip: Path | None = None,
    target_track: str = "",
    customer_id: str = "",
    customer_name: str = "",
    release_zip: Path,
    release_manifest: Path,
    release_sha256_file: Path,
    release_signature: Path,
    release_public_key: Path,
    handoff_dossier: Path,
    support_bundle: Path,
    hosted_readiness_dossier: Path | None = None,
) -> dict[str, Any]:
    acceptance_report = acceptance_report.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o700)
    public_release_manifest = _write_public_release_manifest(
        release_manifest.expanduser().resolve(),
        output_dir / "_public-release-artifacts" / release_manifest.expanduser().name,
    )

    acceptance = _read_json(acceptance_report)
    acceptance_safe = _acceptance_summary(acceptance)
    effective_track = target_track.strip() or str(acceptance_safe.get("target_track") or "paid_local_handoff")
    hosted_required = effective_track == "hosted_saas"

    artifact_inputs = [
        ("release_zip", release_zip, True, "release"),
        ("release_manifest", public_release_manifest, True, "release"),
        ("release_sha256_file", release_sha256_file, True, "release"),
        ("release_signature", release_signature, True, "release"),
        ("release_public_key", release_public_key, True, "release"),
        ("handoff_dossier", handoff_dossier, True, "dossiers"),
        ("support_bundle", support_bundle, True, "support"),
        ("hosted_readiness_dossier", hosted_readiness_dossier, hosted_required, "dossiers"),
    ]
    artifacts: dict[str, dict[str, Any]] = {}
    checks: list[dict[str, Any]] = []
    for role, path, required, member_dir in artifact_inputs:
        record, record_checks = _artifact_record(role, path, required=required, member_dir=member_dir)
        checks.extend(record_checks)
        if record is not None:
            artifacts[role] = record
    public_artifacts = {
        role: {key: value for key, value in record.items() if not str(key).startswith("_")}
        for role, record in artifacts.items()
    }

    release_report: dict[str, Any] | None = None
    handoff_report: dict[str, Any] | None = None
    support_report: dict[str, Any] | None = None
    hosted_report: dict[str, Any] | None = None

    try:
        release_report = verify_release_package(
            release_zip.expanduser().resolve(),
            manifest_path=public_release_manifest.expanduser().resolve(),
            sha256_path=release_sha256_file.expanduser().resolve(),
            signature_path=release_signature.expanduser().resolve(),
            public_key_path=release_public_key.expanduser().resolve(),
            require_signature=True,
        )
    except Exception as exc:
        release_report = {"status": "attention", "summary": {"errors": 1, "warnings": 0}, "error": str(exc)}
    checks.append(_status_check(release_report, "release_package_verified", "verified", "Rebuild and sign the release package, then verify it with scripts/verify_release_package.py."))

    try:
        handoff_report = verify_handoff_dossier(handoff_dossier.expanduser().resolve(), release_zip=release_zip.expanduser().resolve(), require_release_zip=True)
    except Exception as exc:
        handoff_report = {"status": "attention", "summary": {"errors": 1, "warnings": 0}, "error": str(exc)}
    checks.append(_status_check(handoff_report, "handoff_dossier_verified", "verified", "Build and verify a customer handoff dossier before launch packaging."))

    try:
        support_report = verify_support_bundle(support_bundle.expanduser().resolve())
    except Exception as exc:
        support_report = {"status": "attention", "summary": {"errors": 1, "warnings": 0}, "error": str(exc)}
    checks.append(_status_check(support_report, "support_bundle_verified", "verified", "Download a redacted support bundle and verify it with scripts/verify_support_bundle.py."))

    if hosted_readiness_dossier is not None:
        try:
            hosted_report = verify_hosted_readiness_dossier(hosted_readiness_dossier.expanduser().resolve())
        except Exception as exc:
            hosted_report = {"status": "attention", "summary": {"errors": 1, "warnings": 0}, "error": str(exc)}
        checks.append(_status_check(hosted_report, "hosted_readiness_dossier_verified", "verified", "Build and verify a hosted readiness dossier before a hosted SaaS launch."))
    elif hosted_required:
        checks.append(_check("hosted_readiness_dossier_verified", False, "error", "not supplied", "Hosted SaaS launch packages require a verified hosted readiness dossier."))

    release_sha = artifacts.get("release_zip", {}).get("sha256", "")
    support_sha = artifacts.get("support_bundle", {}).get("sha256", "")
    evidence = acceptance_safe.get("evidence_summary") if isinstance(acceptance_safe.get("evidence_summary"), dict) else {}
    acceptance_release = evidence.get("release_package") if isinstance(evidence.get("release_package"), dict) else {}
    acceptance_support = evidence.get("support_bundle") if isinstance(evidence.get("support_bundle"), dict) else {}
    checks.extend(
        [
            _check("acceptance_report_passed", acceptance_safe.get("status") == "passed", "error", str(acceptance_safe.get("status") or ""), "Run scripts/run_handoff_acceptance.py until it passes."),
            _check("acceptance_target_track_matches", acceptance_safe.get("target_track") == effective_track, "error", f"{acceptance_safe.get('target_track')} != {effective_track}", "Use a launch package target matching the acceptance report target track."),
            _check("acceptance_release_sha_matches", bool(release_sha) and str(acceptance_release.get("zip_sha256") or acceptance_safe.get("release_verification", {}).get("zip_sha256") or "").lower() == str(release_sha).lower(), "error", str(acceptance_release.get("zip_sha256") or ""), "Run acceptance against the exact release zip included in the launch package."),
            _check("acceptance_support_bundle_sha_matches", bool(support_sha) and str(acceptance_support.get("sha256") or "").lower() == str(support_sha).lower(), "error", str(acceptance_support.get("sha256") or ""), "Run acceptance with the exact support bundle included in the launch package."),
            _check("raw_acceptance_payloads_excluded", "payloads" not in acceptance_safe, "error", "acceptance summary excludes raw payloads"),
            _check("sensitive_keys_excluded", not _contains_sensitive_key(acceptance_safe), "error", "launch acceptance summary excludes sensitive key names"),
        ]
    )

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    launch = {
        "schema_version": LAUNCH_PACKAGE_SCHEMA,
        "status": "ready" if not errors else "attention",
        "generated_at": _utc_timestamp(),
        "target_track": effective_track,
        "customer": {"id": customer_id, "name": customer_name},
        "acceptance": acceptance_safe,
        "artifacts": public_artifacts,
        "verification": {
            "release_package": _report_summary(release_report),
            "handoff_dossier": _report_summary(handoff_report),
            "support_bundle": _report_summary(support_report),
            "hosted_readiness_dossier": _report_summary(hosted_report),
        },
        "checks": _public_checks(checks),
        "summary": {"checks": len(checks), "errors": len(errors), "warnings": len(warnings)},
        "notes": [
            "This launch package is a customer and operator evidence bundle for a commercial Draftpaper-loop handoff.",
            "It embeds verified distributable artifacts and redacted diagnostics, but excludes raw acceptance payloads, private license files, env files, tokens, customer project data, and unredacted runtime state.",
        ],
    }
    launch["package_sha256"] = _launch_digest(launch)

    package_json = output_dir / "commercial-launch-package.json"
    summary_json = output_dir / "commercial-launch-summary.json"
    _write_private_json(package_json, launch)
    _write_private_json(summary_json, {"status": launch["status"], "target_track": effective_track, "customer": launch["customer"], "summary": launch["summary"], "artifacts": public_artifacts})

    zip_path = output_zip.expanduser().resolve() if output_zip is not None else output_dir / "commercial-launch-package.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(package_json, "commercial-launch-package.json")
        archive.write(summary_json, "commercial-launch-summary.json")
        for record in artifacts.values():
            source = Path(str(record.get("_source_path") or ""))
            member = str(record.get("member") or "")
            if source.exists() and source.is_file() and member:
                archive.write(source, member)
    zip_path.chmod(0o600)

    result = {
        "status": launch["status"],
        "generated_at": launch["generated_at"],
        "target_track": effective_track,
        "package_path": str(package_json),
        "summary_path": str(summary_json),
        "zip_path": str(zip_path),
        "zip_sha256": sha256_file(zip_path),
        "package_sha256": launch["package_sha256"],
        "summary": launch["summary"],
        "artifacts": public_artifacts,
    }
    _write_private_json(output_dir / "commercial-launch-package-manifest.json", result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a customer/operator Draftpaper-loop commercial launch evidence package.")
    parser.add_argument("--acceptance-report", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--output-zip", default="")
    parser.add_argument("--target-track", default="")
    parser.add_argument("--customer-id", default="")
    parser.add_argument("--customer-name", default="")
    parser.add_argument("--release-zip", required=True)
    parser.add_argument("--release-manifest", required=True)
    parser.add_argument("--release-sha256-file", required=True)
    parser.add_argument("--release-signature", required=True)
    parser.add_argument("--release-public-key", required=True)
    parser.add_argument("--handoff-dossier", required=True)
    parser.add_argument("--support-bundle", required=True)
    parser.add_argument("--hosted-readiness-dossier", default="")
    args = parser.parse_args(argv)
    result = build_commercial_launch_package(
        acceptance_report=Path(args.acceptance_report),
        output_dir=Path(args.output_dir),
        output_zip=Path(args.output_zip) if args.output_zip else None,
        target_track=args.target_track,
        customer_id=args.customer_id,
        customer_name=args.customer_name,
        release_zip=Path(args.release_zip),
        release_manifest=Path(args.release_manifest),
        release_sha256_file=Path(args.release_sha256_file),
        release_signature=Path(args.release_signature),
        release_public_key=Path(args.release_public_key),
        handoff_dossier=Path(args.handoff_dossier),
        support_bundle=Path(args.support_bundle),
        hosted_readiness_dossier=Path(args.hosted_readiness_dossier) if args.hosted_readiness_dossier else None,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
