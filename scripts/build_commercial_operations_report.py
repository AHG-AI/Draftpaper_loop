#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from verify_commercial_launch_package import verify_commercial_launch_package  # noqa: E402


OPERATIONS_REPORT_SCHEMA = "draftpaper.commercial-operations-report/v1"
REDACTED = "[redacted]"
SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")
LOCAL_PATH_PATTERNS = (
    re.compile(r"/Users/[^\"'\s]+"),
    re.compile(r"/private/tmp/[^\"'\s]+"),
    re.compile(r"/var/folders/[^\"'\s]+"),
)
ENDPOINTS = {
    "health": "/health",
    "commercial_readiness": "/api/commercial-readiness",
    "handoff_readiness": "/api/handoff-readiness",
    "hosted_readiness": "/api/hosted-readiness",
    "security_audit": "/api/security-audit",
    "license": "/api/license",
    "license_entitlements": "/api/license-entitlements",
    "billing": "/api/billing",
    "quota": "/api/quota",
    "backup_verification": "/api/backups/verify",
    "backup_rehearsals": "/api/backups/rehearsals",
}
READY_GRADES = {
    "local_operator_pilot": {"local_operator_pilot_ready", "paid_local_handoff_ready", "hosted_saas_ready"},
    "paid_local_handoff": {"paid_local_handoff_ready", "hosted_saas_ready"},
    "hosted_saas": {"hosted_saas_ready"},
}


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


def _request_json(base_url: str, path: str, *, token: str = "", timeout: float = 5.0) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-Draftpaper-Token"] = token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-provided local or internal URL.
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not return a JSON object")
    return payload


def _redact_text(value: str) -> str:
    redacted = value
    for pattern in LOCAL_PATH_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def redact_public(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if any(part in lowered for part in SENSITIVE_KEY_PARTS):
                result[key_text] = REDACTED
            else:
                result[key_text] = redact_public(item)
        return result
    if isinstance(value, list):
        return [redact_public(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _fetch_payloads(base_url: str, *, token: str, timeout: float) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    payloads: dict[str, dict[str, Any]] = {}
    checks: list[dict[str, Any]] = []
    for name, path in ENDPOINTS.items():
        try:
            payloads[name] = _request_json(base_url, path, token=token, timeout=timeout)
            checks.append(_check(f"endpoint_{name}", True, "error", path))
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError) as exc:
            payloads[name] = {"status": "error", "message": str(exc)}
            checks.append(_check(f"endpoint_{name}", False, "error", f"{path}: {exc}", "Start the console and provide a valid operator token."))
    return payloads, checks


def _track_summary(track: dict[str, Any]) -> dict[str, Any]:
    summary = track.get("summary") if isinstance(track.get("summary"), dict) else {}
    return {
        "id": str(track.get("id") or ""),
        "label": str(track.get("label") or ""),
        "status": str(track.get("status") or ""),
        "summary": summary,
        "failed_gates": [
            str(gate.get("id") or "")
            for gate in track.get("gates", [])
            if isinstance(gate, dict) and not gate.get("passed") and str(gate.get("id") or "")
        ],
    }


def _find_track(payload: dict[str, Any], target_track: str) -> dict[str, Any]:
    for track in payload.get("tracks") or payload.get("readiness_tracks") or []:
        if isinstance(track, dict) and track.get("id") == target_track:
            return track
    return {}


def _license_summary(payload: dict[str, Any]) -> dict[str, Any]:
    signature = payload.get("signature") if isinstance(payload.get("signature"), dict) else {}
    grant = payload.get("grant") if isinstance(payload.get("grant"), dict) else {}
    public_grant = {
        key: grant.get(key)
        for key in ["license_id", "customer_id", "customer_name", "grant_type", "issued_at", "expires_at", "seats", "features", "workspaces", "terms"]
        if key in grant
    }
    return {
        "status": str(payload.get("status") or ""),
        "configured": bool(payload.get("configured", bool(public_grant))),
        "grant": redact_public(public_grant),
        "summary": payload.get("summary") if isinstance(payload.get("summary"), dict) else {},
        "signature": {
            "configured": bool(signature.get("configured")),
            "verified": bool(signature.get("verified")),
            "public_key_pin_configured": bool(signature.get("public_key_pin_configured")),
            "public_key_pin_matched": bool(signature.get("public_key_pin_matched")),
            "signature_sha256": str(signature.get("signature_sha256") or ""),
            "public_key_sha256": str(signature.get("public_key_sha256") or ""),
            "algorithm": str(signature.get("algorithm") or ""),
        },
    }


def _license_entitlement_summary(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return {
        "status": str(payload.get("status") or ""),
        "license_status": str(payload.get("license_status") or ""),
        "license_id": str(payload.get("license_id") or ""),
        "customer_id": str(payload.get("customer_id") or ""),
        "seat_limit": payload.get("seat_limit"),
        "subjects_count": int(payload.get("subjects_count") or 0),
        "licensed_workspaces": payload.get("licensed_workspaces") if isinstance(payload.get("licensed_workspaces"), list) else [],
        "licensed_action_scope": payload.get("licensed_action_scope") if isinstance(payload.get("licensed_action_scope"), dict) else {},
        "violations": payload.get("violations") if isinstance(payload.get("violations"), dict) else {},
        "summary": {
            "total": int(summary.get("total") or 0),
            "errors": int(summary.get("errors") or 0),
            "warnings": int(summary.get("warnings") or 0),
            "passed": int(summary.get("passed") or 0),
        },
    }


def _security_summary(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return {
        "status": str(payload.get("status") or ""),
        "summary": {
            "total": int(summary.get("total") or 0),
            "errors": int(summary.get("errors") or 0),
            "warnings": int(summary.get("warnings") or 0),
            "passed": int(summary.get("passed") or 0),
        },
    }


def _billing_summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": str(payload.get("status") or ""),
        "billing_config_status": str(payload.get("billing_config_status") or ""),
        "currency": str(payload.get("currency") or ""),
        "period": payload.get("period") if isinstance(payload.get("period"), dict) else {},
        "totals": payload.get("totals") if isinstance(payload.get("totals"), dict) else {},
        "notes": payload.get("notes") if isinstance(payload.get("notes"), list) else [],
    }


def _quota_summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": str(payload.get("status") or ""),
        "limits": payload.get("limits") if isinstance(payload.get("limits"), dict) else {},
        "usage": payload.get("usage") if isinstance(payload.get("usage"), dict) else {},
        "window": payload.get("window") if isinstance(payload.get("window"), dict) else {},
    }


def _ops_digest(report: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in report.items() if key != "report_sha256"}
    return _sha256_bytes(json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _markdown_report(report: dict[str, Any]) -> str:
    evidence = report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
    launch = evidence.get("launch_package") if isinstance(evidence.get("launch_package"), dict) else {}
    lines = [
        f"# Draftpaper Commercial Operations Report",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Target track: `{report.get('target_track')}`",
        f"- Commercial grade: `{evidence.get('commercial_grade')}`",
        f"- Generated at: `{report.get('generated_at')}`",
        f"- Customer: `{(report.get('customer') or {}).get('name') or ''}`",
        "",
        "## Evidence",
        "",
        f"- License: `{(evidence.get('license') or {}).get('status')}`",
        f"- License entitlements: `{(evidence.get('license_entitlements') or {}).get('status')}`",
        f"- Security audit: `{(evidence.get('security_audit') or {}).get('status')}`",
        f"- Billing: `{(evidence.get('billing') or {}).get('billing_config_status')}`",
        f"- Backup verification: `{(evidence.get('backup_verification') or {}).get('status')}`",
        f"- Backup rehearsal: `{(evidence.get('backup_rehearsals') or {}).get('status')}`",
        f"- Launch package: `{launch.get('status') or 'not supplied'}`",
        "",
        "## Checks",
        "",
    ]
    for item in report.get("checks", []):
        if not isinstance(item, dict):
            continue
        state = "pass" if item.get("passed") else "fail"
        lines.append(f"- `{state}` `{item.get('severity')}` `{item.get('id')}` - {item.get('note') or ''}")
    return "\n".join(lines) + "\n"


def build_commercial_operations_report(
    *,
    base_url: str = "http://127.0.0.1:4888",
    token: str = "",
    target_track: str = "paid_local_handoff",
    launch_package: Path | None = None,
    require_launch_package: bool = False,
    customer_id: str = "",
    customer_name: str = "",
    output: Path | None = None,
    markdown_output: Path | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    generated_at = _utc_timestamp()
    payloads, checks = _fetch_payloads(base_url, token=token, timeout=timeout)

    commercial = payloads.get("commercial_readiness", {})
    handoff = payloads.get("handoff_readiness", {})
    hosted = payloads.get("hosted_readiness", {})
    target = _find_track(handoff, target_track)
    commercial_grade = str(commercial.get("commercial_grade") or handoff.get("commercial_grade") or "")
    security = _security_summary(payloads.get("security_audit", {}))
    license_payload = _license_summary(payloads.get("license", {}))
    license_entitlements = _license_entitlement_summary(payloads.get("license_entitlements", {}))
    billing = _billing_summary(payloads.get("billing", {}))
    quota = _quota_summary(payloads.get("quota", {}))
    backup_verification = payloads.get("backup_verification", {})
    backup_rehearsals = payloads.get("backup_rehearsals", {})

    checks.extend(
        [
            _check("target_track_ready", target.get("status") == "ready", "error", f"{target_track}={target.get('status') or 'missing'}", "Resolve /api/handoff-readiness before customer operations review."),
            _check("commercial_grade_matches_track", commercial_grade in READY_GRADES.get(target_track, set()), "error", commercial_grade, "Use a report target that matches the current commercial readiness grade."),
            _check("security_audit_clean", security["status"] == "passed" and security["summary"]["errors"] == 0, "error", f"errors={security['summary']['errors']} warnings={security['summary']['warnings']}", "Fix security audit errors before commercial operations approval."),
            _check("license_valid", license_payload["status"] == "valid" if target_track in {"paid_local_handoff", "hosted_saas"} else True, "error", license_payload["status"], "Configure a valid paid license grant for commercial operations."),
            _check("license_entitlements_valid", license_entitlements["status"] == "passed" if target_track in {"paid_local_handoff", "hosted_saas"} else True, "error", license_entitlements["status"], "Fix license seat, workspace, customer, or action-scope entitlement findings before commercial operations approval."),
            _check("license_signature_verified", bool(license_payload["signature"]["verified"]) if target_track in {"paid_local_handoff", "hosted_saas"} else True, "error", str(bool(license_payload["signature"]["verified"])), "Use a signed license grant for customer operations records."),
            _check("billing_configured", billing["billing_config_status"] == "configured", "warning", billing["billing_config_status"], "Configure local billing rates before charging by usage."),
            _check("quota_reported", quota["status"] == "reported", "error", quota["status"], "Quota reporting must be available for commercial operations."),
            _check("backups_verified", backup_verification.get("status") == "verified", "error", str(backup_verification.get("status") or ""), "Run /api/backups/verify and fix attention backups."),
            _check("backups_rehearsed", backup_rehearsals.get("status") == "passed", "error", str(backup_rehearsals.get("status") or ""), "Run backup restore rehearsal before customer operations review."),
        ]
    )
    if target_track == "hosted_saas":
        hosted_summary = hosted.get("summary") if isinstance(hosted.get("summary"), dict) else {}
        checks.append(_check("hosted_readiness_ready", hosted.get("status") == "ready" and int(hosted_summary.get("errors") or 0) == 0, "error", str(hosted.get("status") or ""), "Provide verified hosted readiness evidence before hosted operations approval."))

    launch_report: dict[str, Any] | None = None
    if launch_package is not None:
        try:
            launch_report = verify_commercial_launch_package(launch_package)
        except Exception as exc:
            launch_report = {"status": "attention", "summary": {"errors": 1, "warnings": 0}, "message": str(exc)}
        checks.append(_check("launch_package_verified", launch_report.get("status") == "verified", "error", str(launch_report.get("status") or ""), "Build and verify a commercial launch package for the customer record."))
        checks.append(_check("launch_package_track_matches", str(launch_report.get("target_track") or "") == target_track, "error", str(launch_report.get("target_track") or ""), "Use a launch package for the same target track as this operations report."))
    else:
        checks.append(_check("launch_package_verified", not require_launch_package, "error" if require_launch_package else "warning", "not supplied", "Attach a verified launch package when archiving a customer handoff."))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    launch_summary = {
        "status": str((launch_report or {}).get("status") or ""),
        "target_track": str((launch_report or {}).get("target_track") or ""),
        "zip_sha256": str((launch_report or {}).get("zip_sha256") or ""),
        "package_sha256": str((launch_report or {}).get("package_sha256") or ""),
        "summary": (launch_report or {}).get("summary") if isinstance((launch_report or {}).get("summary"), dict) else {},
    }
    report = {
        "schema_version": OPERATIONS_REPORT_SCHEMA,
        "status": "ready" if not errors else "attention",
        "generated_at": generated_at,
        "base_url": base_url.rstrip("/"),
        "target_track": target_track,
        "customer": {"id": customer_id, "name": customer_name},
        "evidence": redact_public(
            {
                "commercial_grade": commercial_grade,
                "commercial_readiness": {
                    "status": commercial.get("status"),
                    "score": commercial.get("score"),
                    "remaining_gaps": commercial.get("remaining_gaps") or [],
                },
                "handoff_track": _track_summary(target),
                "readiness_tracks": [_track_summary(track) for track in handoff.get("tracks", []) if isinstance(track, dict)],
                "hosted_readiness": {"status": hosted.get("status"), "summary": hosted.get("summary") if isinstance(hosted.get("summary"), dict) else {}},
                "license": license_payload,
                "license_entitlements": license_entitlements,
                "security_audit": security,
                "billing": billing,
                "quota": quota,
                "backup_verification": {"status": backup_verification.get("status"), "summary": backup_verification.get("summary") if isinstance(backup_verification.get("summary"), dict) else {}},
                "backup_rehearsals": {"status": backup_rehearsals.get("status"), "summary": backup_rehearsals.get("summary") if isinstance(backup_rehearsals.get("summary"), dict) else {}},
                "launch_package": launch_summary,
            }
        ),
        "checks": redact_public(checks),
        "summary": {"checks": len(checks), "errors": len(errors), "warnings": len(warnings)},
        "notes": [
            "This report is a customer-safe operations evidence summary; it excludes raw endpoint payloads, tokens, private license paths, env files, and machine-local path roots.",
            "Local billing amounts are estimates from configured rates and are not payment collection.",
            "Hosted SaaS readiness still requires independently verified external production evidence.",
        ],
    }
    report["report_sha256"] = _ops_digest(report)

    if output is not None:
        output = output.expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        output.chmod(0o600)
    if markdown_output is not None:
        markdown_output = markdown_output.expanduser()
        markdown_output.parent.mkdir(parents=True, exist_ok=True)
        markdown_output.write_text(_markdown_report(report), encoding="utf-8")
        markdown_output.chmod(0o600)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a customer-safe Draftpaper-loop commercial operations report.")
    parser.add_argument("--base-url", default="http://127.0.0.1:4888")
    parser.add_argument("--token", default="")
    parser.add_argument("--target-track", choices=sorted(READY_GRADES), default="paid_local_handoff")
    parser.add_argument("--launch-package", default="")
    parser.add_argument("--require-launch-package", action="store_true")
    parser.add_argument("--customer-id", default="")
    parser.add_argument("--customer-name", default="")
    parser.add_argument("--output", default="")
    parser.add_argument("--markdown-output", default="")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    report = build_commercial_operations_report(
        base_url=args.base_url,
        token=args.token,
        target_track=args.target_track,
        launch_package=Path(args.launch_package).expanduser() if args.launch_package else None,
        require_launch_package=args.require_launch_package,
        customer_id=args.customer_id,
        customer_name=args.customer_name,
        output=Path(args.output).expanduser() if args.output else None,
        markdown_output=Path(args.markdown_output).expanduser() if args.markdown_output else None,
        timeout=args.timeout,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
