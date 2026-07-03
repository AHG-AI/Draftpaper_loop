#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    from verify_hosted_readiness_dossier import verify_hosted_readiness_dossier
    from verify_release_package import verify_release_package
    from verify_support_bundle import verify_support_bundle_bytes
except ImportError:  # pragma: no cover - direct import fallback for tests.
    import importlib.util

    scripts_dir = Path(__file__).resolve().parent

    release_spec = importlib.util.spec_from_file_location("draftpaper_verify_release_package", scripts_dir / "verify_release_package.py")
    if release_spec is None or release_spec.loader is None:
        verify_release_package = None  # type: ignore[assignment]
    else:
        module = importlib.util.module_from_spec(release_spec)
        release_spec.loader.exec_module(module)
        verify_release_package = module.verify_release_package  # type: ignore[assignment]

    hosted_dossier_spec = importlib.util.spec_from_file_location("draftpaper_verify_hosted_readiness_dossier", scripts_dir / "verify_hosted_readiness_dossier.py")
    if hosted_dossier_spec is None or hosted_dossier_spec.loader is None:
        verify_hosted_readiness_dossier = None  # type: ignore[assignment]
    else:
        hosted_dossier_module = importlib.util.module_from_spec(hosted_dossier_spec)
        hosted_dossier_spec.loader.exec_module(hosted_dossier_module)
        verify_hosted_readiness_dossier = hosted_dossier_module.verify_hosted_readiness_dossier  # type: ignore[assignment]

    support_bundle_spec = importlib.util.spec_from_file_location("draftpaper_verify_support_bundle", scripts_dir / "verify_support_bundle.py")
    if support_bundle_spec is None or support_bundle_spec.loader is None:
        verify_support_bundle_bytes = None  # type: ignore[assignment]
    else:
        support_bundle_module = importlib.util.module_from_spec(support_bundle_spec)
        support_bundle_spec.loader.exec_module(support_bundle_module)
        verify_support_bundle_bytes = support_bundle_module.verify_support_bundle_bytes  # type: ignore[assignment]


DEFAULT_ENDPOINTS = {
    "health": "/health",
    "commercial_readiness": "/api/commercial-readiness",
    "handoff_readiness": "/api/handoff-readiness",
    "hosted_readiness": "/api/hosted-readiness",
    "security_audit": "/api/security-audit",
    "license": "/api/license",
    "license_entitlements": "/api/license-entitlements",
    "access_policy": "/api/access-policy",
    "quota": "/api/quota",
    "billing": "/api/billing",
    "backup_verification": "/api/backups/verify",
    "backup_rehearsals": "/api/backups/rehearsals",
}
TARGET_TRACKS = {"local_operator_pilot", "paid_local_handoff", "hosted_saas"}


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _request_json(base_url: str, path: str, *, token: str = "", timeout: float = 5.0) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Draftpaper-Token"] = token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-provided local URL.
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not return a JSON object")
    return payload


def _download_binary(base_url: str, path: str, *, token: str = "", timeout: float = 15.0) -> tuple[dict[str, Any], bytes]:
    url = base_url.rstrip("/") + path
    headers = {"Accept": "application/octet-stream"}
    if token:
        headers["X-Draftpaper-Token"] = token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-provided local URL.
        data = response.read()
    return {"url": url, "bytes": len(data), "sha256": _sha256_bytes(data)}, data


def _track_status(handoff: dict[str, Any], track_id: str) -> dict[str, Any] | None:
    for track in handoff.get("tracks", []):
        if isinstance(track, dict) and track.get("id") == track_id:
            return track
    return None


def _failed_check_ids(payload: dict[str, Any], severity: str) -> list[str]:
    checks = payload.get("checks") if isinstance(payload.get("checks"), list) else []
    return [
        str(item.get("id") or "")
        for item in checks
        if isinstance(item, dict) and item.get("severity") == severity and not item.get("passed") and str(item.get("id") or "")
    ]


def _readiness_track_summaries(handoff: dict[str, Any]) -> list[dict[str, Any]]:
    tracks = handoff.get("tracks") if isinstance(handoff.get("tracks"), list) else []
    summaries: list[dict[str, Any]] = []
    for track in tracks:
        if not isinstance(track, dict):
            continue
        gates = track.get("gates") if isinstance(track.get("gates"), list) else []
        summaries.append(
            {
                "id": str(track.get("id") or ""),
                "status": str(track.get("status") or ""),
                "failed_gates": [
                    str(gate.get("id") or "")
                    for gate in gates
                    if isinstance(gate, dict) and not gate.get("passed") and str(gate.get("id") or "")
                ],
            }
        )
    return summaries


def _release_signature_verified(release_report: dict[str, Any] | None) -> bool:
    if not release_report:
        return False
    checks = release_report.get("checks") if isinstance(release_report.get("checks"), list) else []
    for item in checks:
        if isinstance(item, dict) and item.get("id") == "signature_verified":
            return bool(item.get("passed"))
    signature_path = str(release_report.get("signature_path") or "")
    public_key_path = str(release_report.get("public_key_path") or "")
    return release_report.get("status") == "verified" and bool(signature_path and public_key_path)


def _acceptance_evidence_summary(
    *,
    target_track: str,
    payloads: dict[str, Any],
    release_report: dict[str, Any] | None,
    hosted_dossier_report: dict[str, Any] | None,
    support_bundle_verification: dict[str, Any] | None,
    support_bundle: dict[str, Any] | None,
) -> dict[str, Any]:
    health = payloads.get("health", {}) if isinstance(payloads.get("health"), dict) else {}
    handoff = payloads.get("handoff_readiness", {}) if isinstance(payloads.get("handoff_readiness"), dict) else {}
    hosted = payloads.get("hosted_readiness", {}) if isinstance(payloads.get("hosted_readiness"), dict) else {}
    license_payload = payloads.get("license", {}) if isinstance(payloads.get("license"), dict) else {}
    license_entitlements = payloads.get("license_entitlements", {}) if isinstance(payloads.get("license_entitlements"), dict) else {}
    security = payloads.get("security_audit", {}) if isinstance(payloads.get("security_audit"), dict) else {}
    backup_verification = payloads.get("backup_verification", {}) if isinstance(payloads.get("backup_verification"), dict) else {}
    backup_rehearsals = payloads.get("backup_rehearsals", {}) if isinstance(payloads.get("backup_rehearsals"), dict) else {}

    hosted_gates = hosted.get("gates") if isinstance(hosted.get("gates"), list) else []
    hosted_passed = sum(1 for gate in hosted_gates if isinstance(gate, dict) and gate.get("passed"))
    signature = license_payload.get("signature") if isinstance(license_payload.get("signature"), dict) else {}
    security_summary = security.get("summary") if isinstance(security.get("summary"), dict) else {}
    release_summary = release_report.get("summary") if isinstance(release_report, dict) and isinstance(release_report.get("summary"), dict) else {}
    hosted_dossier_summary = hosted_dossier_report.get("summary") if isinstance(hosted_dossier_report, dict) and isinstance(hosted_dossier_report.get("summary"), dict) else {}
    support_verification_summary = support_bundle_verification.get("summary") if isinstance(support_bundle_verification, dict) and isinstance(support_bundle_verification.get("summary"), dict) else {}
    bundle = support_bundle if isinstance(support_bundle, dict) else {}
    return {
        "health": {
            "status": str(health.get("status") or ""),
            "auth_required": bool(health.get("auth_required")),
            "cli_importable": bool(health.get("cli_importable")),
        },
        "target_track": {
            "id": target_track,
            "status": str((_track_status(handoff, target_track) or {}).get("status") or ""),
        },
        "handoff_tracks": _readiness_track_summaries(handoff),
        "license": {
            "status": str(license_payload.get("status") or ""),
            "signature_configured": bool(signature.get("configured")),
            "signature_verified": bool(signature.get("verified")),
            "public_key_pin_configured": bool(signature.get("public_key_pin_configured")),
            "public_key_pin_matched": bool(signature.get("public_key_pin_matched")),
            "failed_errors": _failed_check_ids(license_payload, "error"),
            "failed_warnings": _failed_check_ids(license_payload, "warning"),
        },
        "license_entitlements": {
            "status": str(license_entitlements.get("status") or ""),
            "seat_limit": license_entitlements.get("seat_limit"),
            "subjects_count": int(license_entitlements.get("subjects_count") or 0),
            "failed_errors": _failed_check_ids(license_entitlements, "error"),
            "failed_warnings": _failed_check_ids(license_entitlements, "warning"),
        },
        "security_audit": {
            "status": str(security.get("status") or ""),
            "errors": int(security_summary.get("errors") or 0),
            "warnings": int(security_summary.get("warnings") or 0),
            "failed_errors": _failed_check_ids(security, "error"),
            "failed_warnings": _failed_check_ids(security, "warning"),
        },
        "release_package": {
            "status": str((release_report or {}).get("status") or ""),
            "zip_sha256": str((release_report or {}).get("zip_sha256") or ""),
            "signature_verified": _release_signature_verified(release_report),
            "errors": int(release_summary.get("errors") or 0),
            "warnings": int(release_summary.get("warnings") or 0),
        },
        "backup_recovery": {
            "verification_status": str(backup_verification.get("status") or ""),
            "rehearsal_status": str(backup_rehearsals.get("status") or ""),
        },
        "hosted_readiness": {
            "status": str(hosted.get("status") or ""),
            "passed_gates": hosted_passed,
            "total_gates": len(hosted_gates),
            "failed_gates": [
                str(gate.get("id") or "")
                for gate in hosted_gates
                if isinstance(gate, dict) and not gate.get("passed") and str(gate.get("id") or "")
            ],
        },
        "hosted_readiness_dossier": {
            "status": str((hosted_dossier_report or {}).get("status") or ""),
            "zip_sha256": str((hosted_dossier_report or {}).get("zip_sha256") or ""),
            "dossier_sha256": str((hosted_dossier_report or {}).get("dossier_sha256") or ""),
            "errors": int(hosted_dossier_summary.get("errors") or 0),
            "warnings": int(hosted_dossier_summary.get("warnings") or 0),
        },
        "support_bundle": {
            "downloaded": bool(bundle.get("bytes")),
            "bytes": int(bundle.get("bytes") or 0),
            "sha256": str(bundle.get("sha256") or ""),
            "verification_status": str((support_bundle_verification or {}).get("status") or ""),
            "verification_errors": int(support_verification_summary.get("errors") or 0),
            "verification_warnings": int(support_verification_summary.get("warnings") or 0),
        },
    }


def _endpoint_payloads(base_url: str, *, token: str, timeout: float) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    payloads: dict[str, Any] = {}
    checks: list[dict[str, Any]] = []
    for name, path in DEFAULT_ENDPOINTS.items():
        try:
            payloads[name] = _request_json(base_url, path, token=token, timeout=timeout)
            checks.append(_check(f"endpoint_{name}", True, "error", path))
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError) as exc:
            payloads[name] = {"status": "error", "message": str(exc)}
            checks.append(_check(f"endpoint_{name}", False, "error", f"{path}: {exc}", "Start the local console and provide a valid token when auth is enabled."))
    return payloads, checks


def run_handoff_acceptance(
    *,
    base_url: str = "http://127.0.0.1:4888",
    token: str = "",
    target_track: str = "paid_local_handoff",
    release_zip: Path | None = None,
    release_manifest: Path | None = None,
    release_sha256_file: Path | None = None,
    release_signature: Path | None = None,
    release_public_key: Path | None = None,
    hosted_readiness_dossier: Path | None = None,
    require_release: bool = False,
    require_signature: bool = False,
    require_hosted_dossier: bool = False,
    download_support_bundle: bool = False,
    support_bundle_output: Path | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    if target_track not in TARGET_TRACKS:
        raise ValueError(f"target_track must be one of {sorted(TARGET_TRACKS)}")
    generated_at = _utc_timestamp()
    payloads, checks = _endpoint_payloads(base_url, token=token, timeout=timeout)

    health = payloads.get("health", {})
    checks.append(_check("health_ok", health.get("status") == "ok", "error", str(health.get("status") or ""), "Verify /health before handoff."))

    security = payloads.get("security_audit", {})
    security_errors = int(security.get("summary", {}).get("errors") or 0)
    checks.append(_check("security_errors_clear", security_errors == 0, "error", f"errors={security_errors}", "Run /api/security-audit and fix severity=error findings."))

    handoff = payloads.get("handoff_readiness", {})
    track = _track_status(handoff, target_track)
    checks.append(_check("target_track_present", track is not None, "error", target_track, "Use a supported readiness track."))
    track_status = str((track or {}).get("status") or "")
    checks.append(_check("target_track_ready", track_status == "ready", "error", f"{target_track}={track_status}", "Resolve /api/handoff-readiness next_required_actions before handoff."))

    hosted_readiness = payloads.get("hosted_readiness", {})
    if target_track == "hosted_saas":
        hosted_status = str(hosted_readiness.get("status") or "")
        hosted_gates = hosted_readiness.get("gates") if isinstance(hosted_readiness.get("gates"), list) else []
        hosted_gates_passed = bool(hosted_gates) and all(bool(gate.get("passed")) for gate in hosted_gates if isinstance(gate, dict))
        checks.append(_check("hosted_readiness_ready", hosted_status == "ready", "error", hosted_status, "Configure and verify DRAFTPAPER_HOSTED_READINESS_FILE before hosted SaaS acceptance."))
        checks.append(_check("hosted_readiness_gates_verified", hosted_gates_passed, "error", f"{sum(1 for gate in hosted_gates if isinstance(gate, dict) and gate.get('passed'))}/{len(hosted_gates)} gates", "Resolve every /api/hosted-readiness gate before hosted SaaS acceptance."))

    hosted_dossier_required = require_hosted_dossier or target_track == "hosted_saas"
    hosted_dossier_report: dict[str, Any] | None = None
    if hosted_readiness_dossier is not None:
        if verify_hosted_readiness_dossier is None:
            hosted_dossier_report = {"status": "attention", "message": "verify_hosted_readiness_dossier.py is unavailable"}
        else:
            hosted_dossier_report = verify_hosted_readiness_dossier(hosted_readiness_dossier)
        checks.append(_check("hosted_readiness_dossier_verified", hosted_dossier_report.get("status") == "verified", "error", str(hosted_dossier_report.get("status") or ""), "Run scripts/verify_hosted_readiness_dossier.py before hosted SaaS acceptance."))
    else:
        checks.append(_check("hosted_readiness_dossier_verified", not hosted_dossier_required, "error" if hosted_dossier_required else "info", "not supplied", "Provide --hosted-readiness-dossier for hosted SaaS acceptance."))

    license_status = str(payloads.get("license", {}).get("status") or "")
    license_required = target_track == "paid_local_handoff"
    checks.append(_check("license_valid", (not license_required) or license_status == "valid", "error" if license_required else "warning", license_status, "Set DRAFTPAPER_LICENSE_FILE for paid local handoff."))
    entitlement_status = str(payloads.get("license_entitlements", {}).get("status") or "")
    checks.append(_check("license_entitlements_valid", (not license_required) or entitlement_status == "passed", "error" if license_required else "warning", entitlement_status, "Fix /api/license-entitlements before paid local handoff."))

    backup_verification = payloads.get("backup_verification", {})
    checks.append(_check("backups_verified", backup_verification.get("status") == "verified", "error", str(backup_verification.get("status") or ""), "Run /api/backups/verify and fix attention backups."))

    backup_rehearsals = payloads.get("backup_rehearsals", {})
    rehearsed = backup_rehearsals.get("status") == "passed"
    checks.append(_check("backups_rehearsed", rehearsed, "error", str(backup_rehearsals.get("status") or ""), "Run POST /api/backups/rehearse before paid handoff."))

    release_report: dict[str, Any] | None = None
    if release_zip is not None:
        if verify_release_package is None:
            release_report = {"status": "attention", "message": "verify_release_package.py is unavailable"}
        else:
            release_report = verify_release_package(
                release_zip,
                manifest_path=release_manifest,
                sha256_path=release_sha256_file,
                signature_path=release_signature,
                public_key_path=release_public_key,
                require_signature=require_signature,
            )
        checks.append(_check("release_package_verified", release_report.get("status") == "verified", "error", str(release_report.get("status") or ""), "Run scripts/verify_release_package.py on the handoff zip."))
    else:
        checks.append(_check("release_package_verified", not require_release, "error" if require_release else "warning", "not supplied", "Provide --release-zip plus manifest and sha256 file for customer handoff acceptance."))

    support_bundle: dict[str, Any] | None = None
    support_bundle_verification: dict[str, Any] | None = None
    if download_support_bundle:
        try:
            support_bundle, support_bundle_data = _download_binary(base_url, "/api/support-bundle", token=token, timeout=max(timeout, 15.0))
            checks.append(_check("support_bundle_downloaded", support_bundle["bytes"] > 0, "error", f"{support_bundle['bytes']} bytes"))
            if support_bundle_output is not None:
                try:
                    support_output = support_bundle_output.expanduser()
                    support_output.parent.mkdir(parents=True, exist_ok=True)
                    support_output.write_bytes(support_bundle_data)
                    support_output.chmod(0o600)
                    checks.append(_check("support_bundle_saved", True, "error", support_output.name))
                except OSError as exc:
                    checks.append(_check("support_bundle_saved", False, "error", str(exc), "Write the support bundle to a private local path before launch packaging."))
            if verify_support_bundle_bytes is None:
                support_bundle_verification = {"status": "attention", "message": "verify_support_bundle.py is unavailable"}
            else:
                support_bundle_verification = verify_support_bundle_bytes(support_bundle_data, source=support_bundle["url"])
            checks.append(_check("support_bundle_verified", support_bundle_verification.get("status") == "verified", "error", str(support_bundle_verification.get("status") or ""), "Run scripts/verify_support_bundle.py and fix redaction or manifest findings."))
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            support_bundle = {"status": "error", "message": str(exc)}
            checks.append(_check("support_bundle_downloaded", False, "error", str(exc), "Download /api/support-bundle before customer support handoff."))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    report: dict[str, Any] = {
        "schema_version": "draftpaper.handoff-acceptance/v1",
        "status": "passed" if not errors else "attention",
        "generated_at": generated_at,
        "base_url": base_url.rstrip("/"),
        "target_track": target_track,
        "commercial_grade": handoff.get("commercial_grade"),
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "evidence_summary": _acceptance_evidence_summary(
            target_track=target_track,
            payloads=payloads,
            release_report=release_report,
            hosted_dossier_report=hosted_dossier_report,
            support_bundle_verification=support_bundle_verification,
            support_bundle=support_bundle,
        ),
        "checks": checks,
        "payloads": payloads,
        "release_verification": release_report,
        "hosted_dossier_verification": hosted_dossier_report,
        "hosted_readiness": payloads.get("hosted_readiness"),
        "support_bundle": support_bundle,
        "support_bundle_verification": support_bundle_verification,
        "next_required_actions": handoff.get("next_required_actions") or [],
        "notes": [
            "This report summarizes local handoff evidence; it is not legal approval or a third-party security assessment.",
            "For paid local handoff, the target track must be ready and the release package should be independently verified.",
        ],
    }
    unsigned = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report["report_sha256"] = _sha256_bytes(unsigned)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Draftpaper-loop local customer handoff acceptance checks.")
    parser.add_argument("--base-url", default="http://127.0.0.1:4888")
    parser.add_argument("--token", default="")
    parser.add_argument("--target-track", choices=sorted(TARGET_TRACKS), default="paid_local_handoff")
    parser.add_argument("--release-zip", default=None)
    parser.add_argument("--release-manifest", default=None)
    parser.add_argument("--release-sha256-file", default=None)
    parser.add_argument("--release-signature", default=None)
    parser.add_argument("--release-public-key", default=None)
    parser.add_argument("--hosted-readiness-dossier", default=None)
    parser.add_argument("--require-release", action="store_true")
    parser.add_argument("--require-signature", action="store_true")
    parser.add_argument("--require-hosted-dossier", action="store_true", help="Require a verified hosted readiness dossier. This is automatic for target-track=hosted_saas.")
    parser.add_argument("--download-support-bundle", action="store_true")
    parser.add_argument("--support-bundle-output", default="", help="Optional private output path for the exact support bundle downloaded during acceptance.")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--output", default="")
    args = parser.parse_args(argv)
    report = run_handoff_acceptance(
        base_url=args.base_url,
        token=args.token,
        target_track=args.target_track,
        release_zip=Path(args.release_zip).expanduser() if args.release_zip else None,
        release_manifest=Path(args.release_manifest).expanduser() if args.release_manifest else None,
        release_sha256_file=Path(args.release_sha256_file).expanduser() if args.release_sha256_file else None,
        release_signature=Path(args.release_signature).expanduser() if args.release_signature else None,
        release_public_key=Path(args.release_public_key).expanduser() if args.release_public_key else None,
        hosted_readiness_dossier=Path(args.hosted_readiness_dossier).expanduser() if args.hosted_readiness_dossier else None,
        require_release=args.require_release,
        require_signature=args.require_signature,
        require_hosted_dossier=args.require_hosted_dossier,
        download_support_bundle=args.download_support_bundle,
        support_bundle_output=Path(args.support_bundle_output).expanduser() if args.support_bundle_output else None,
        timeout=args.timeout,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding="utf-8")
        output_path.chmod(0o600)
    print(text, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
