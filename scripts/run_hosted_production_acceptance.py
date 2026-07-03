#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    from validate_hosted_readiness import validate_hosted_readiness
    from verify_hosted_readiness_dossier import verify_hosted_readiness_dossier
except ImportError:  # pragma: no cover - direct import fallback for isolated tests.
    import importlib.util
    import sys

    scripts_dir = Path(__file__).resolve().parent
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))

    validator_spec = importlib.util.spec_from_file_location("draftpaper_validate_hosted_readiness", scripts_dir / "validate_hosted_readiness.py")
    if validator_spec is None or validator_spec.loader is None:
        validate_hosted_readiness = None  # type: ignore[assignment]
    else:
        validator_module = importlib.util.module_from_spec(validator_spec)
        validator_spec.loader.exec_module(validator_module)
        validate_hosted_readiness = validator_module.validate_hosted_readiness  # type: ignore[assignment]

    dossier_spec = importlib.util.spec_from_file_location("draftpaper_verify_hosted_readiness_dossier", scripts_dir / "verify_hosted_readiness_dossier.py")
    if dossier_spec is None or dossier_spec.loader is None:
        verify_hosted_readiness_dossier = None  # type: ignore[assignment]
    else:
        dossier_module = importlib.util.module_from_spec(dossier_spec)
        dossier_spec.loader.exec_module(dossier_module)
        verify_hosted_readiness_dossier = dossier_module.verify_hosted_readiness_dossier  # type: ignore[assignment]


SCHEMA_VERSION = "draftpaper.hosted-production-acceptance/v1"
HOSTED_GATE_IDS = {
    "hosted_enterprise_auth",
    "hosted_payment_collection",
    "managed_storage_dr",
    "hosted_worker_isolation",
    "deployment_hardening",
}
ENDPOINTS = {
    "health": "/health",
    "commercial_readiness": "/api/commercial-readiness",
    "handoff_readiness": "/api/handoff-readiness",
    "hosted_readiness": "/api/hosted-readiness",
    "security_audit": "/api/security-audit",
    "license": "/api/license",
    "license_entitlements": "/api/license-entitlements",
    "backup_verification": "/api/backups/verify",
    "backup_rehearsals": "/api/backups/rehearsals",
}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _write_private_json(path: Path, payload: dict[str, Any], *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _request_json(base_url: str, path: str, *, token: str = "", timeout: float = 8.0) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Draftpaper-Token"] = token
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-provided acceptance URL.
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not return a JSON object")
    return payload


def _endpoint_payloads(base_url: str, *, token: str, timeout: float) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    payloads: dict[str, Any] = {}
    checks: list[dict[str, Any]] = []
    for name, path in ENDPOINTS.items():
        try:
            payloads[name] = _request_json(base_url, path, token=token, timeout=timeout)
            checks.append(_check(f"endpoint_{name}", True, "error", path))
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError) as exc:
            payloads[name] = {"status": "error", "message": str(exc)}
            checks.append(_check(f"endpoint_{name}", False, "error", f"{path}: {exc}", "Expose the hosted console endpoint and provide a valid operator token."))
    return payloads, checks


def _track_status(handoff: dict[str, Any], track_id: str) -> dict[str, Any] | None:
    tracks = handoff.get("tracks") if isinstance(handoff.get("tracks"), list) else handoff.get("readiness_tracks")
    if not isinstance(tracks, list):
        return None
    for track in tracks:
        if isinstance(track, dict) and track.get("id") == track_id:
            return track
    return None


def _summary_errors(payload: dict[str, Any]) -> int:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return int(summary.get("errors") or 0)


def _hosted_gate_summary(hosted: dict[str, Any]) -> dict[str, Any]:
    gates = hosted.get("gates") if isinstance(hosted.get("gates"), list) else []
    passed_ids = {
        str(gate.get("id") or "")
        for gate in gates
        if isinstance(gate, dict) and gate.get("passed") and str(gate.get("id") or "")
    }
    failed_ids = [
        str(gate.get("id") or "")
        for gate in gates
        if isinstance(gate, dict) and not gate.get("passed") and str(gate.get("id") or "")
    ]
    return {
        "status": str(hosted.get("status") or ""),
        "passed_gates": len(passed_ids),
        "total_gates": len(gates),
        "missing_required_gates": sorted(HOSTED_GATE_IDS - passed_ids),
        "failed_gates": failed_ids,
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


def _base_url_checks(base_url: str, *, allow_localhost: bool, allow_insecure_http: bool) -> list[dict[str, Any]]:
    parsed = urllib.parse.urlparse(base_url)
    hostname = (parsed.hostname or "").lower()
    is_local = hostname in LOCAL_HOSTS
    return [
        _check("base_url_present", bool(parsed.scheme and parsed.netloc), "error", base_url, "Provide --base-url such as https://draftpaper.example.com."),
        _check("base_url_not_localhost", allow_localhost or not is_local, "error", hostname or "missing", "Hosted production acceptance requires an external hostname. Use --allow-localhost only for local rehearsal."),
        _check("base_url_https", allow_insecure_http or parsed.scheme == "https", "error", parsed.scheme or "missing", "Hosted production acceptance requires HTTPS. Use --allow-insecure-http only for local rehearsal."),
    ]


def run_hosted_production_acceptance(
    *,
    base_url: str,
    token: str = "",
    evidence_file: Path | None = None,
    hosted_readiness_dossier: Path | None = None,
    allow_localhost: bool = False,
    allow_insecure_http: bool = False,
    timeout: float = 8.0,
) -> dict[str, Any]:
    generated_at = _utc_timestamp()
    checks = _base_url_checks(base_url, allow_localhost=allow_localhost, allow_insecure_http=allow_insecure_http)
    payloads, endpoint_checks = _endpoint_payloads(base_url, token=token, timeout=timeout)
    checks.extend(endpoint_checks)

    local_validation: dict[str, Any] = {}
    if evidence_file is not None:
        if validate_hosted_readiness is None:
            local_validation = {"status": "attention", "message": "validate_hosted_readiness.py is unavailable"}
        else:
            local_validation = validate_hosted_readiness(evidence_file)
        checks.append(_check("local_hosted_evidence_ready", local_validation.get("status") == "ready", "error", str(local_validation.get("status") or ""), "Validate the private hosted readiness evidence file with --require-ready."))
    else:
        checks.append(_check("local_hosted_evidence_ready", False, "error", "not supplied", "Provide --evidence-file so production acceptance has a local private evidence source to compare."))

    dossier_report: dict[str, Any] = {}
    if hosted_readiness_dossier is not None:
        if verify_hosted_readiness_dossier is None:
            dossier_report = {"status": "attention", "message": "verify_hosted_readiness_dossier.py is unavailable"}
        else:
            dossier_report = verify_hosted_readiness_dossier(hosted_readiness_dossier.expanduser())
        checks.append(_check("hosted_readiness_dossier_verified", dossier_report.get("status") == "verified", "error", str(dossier_report.get("status") or ""), "Build and verify a hosted readiness dossier before hosted production acceptance."))
    else:
        checks.append(_check("hosted_readiness_dossier_verified", False, "error", "not supplied", "Provide --hosted-readiness-dossier."))

    health = payloads.get("health", {}) if isinstance(payloads.get("health"), dict) else {}
    commercial = payloads.get("commercial_readiness", {}) if isinstance(payloads.get("commercial_readiness"), dict) else {}
    handoff = payloads.get("handoff_readiness", {}) if isinstance(payloads.get("handoff_readiness"), dict) else {}
    hosted = payloads.get("hosted_readiness", {}) if isinstance(payloads.get("hosted_readiness"), dict) else {}
    security = payloads.get("security_audit", {}) if isinstance(payloads.get("security_audit"), dict) else {}
    license_payload = payloads.get("license", {}) if isinstance(payloads.get("license"), dict) else {}
    entitlements = payloads.get("license_entitlements", {}) if isinstance(payloads.get("license_entitlements"), dict) else {}
    backup_verification = payloads.get("backup_verification", {}) if isinstance(payloads.get("backup_verification"), dict) else {}
    backup_rehearsals = payloads.get("backup_rehearsals", {}) if isinstance(payloads.get("backup_rehearsals"), dict) else {}

    hosted_gate_summary = _hosted_gate_summary(hosted)
    hosted_track = _track_status(handoff, "hosted_saas") or {}
    checks.extend(
        [
            _check("health_ok", health.get("status") == "ok", "error", str(health.get("status") or ""), "Verify the hosted service health endpoint."),
            _check("commercial_grade_hosted", commercial.get("commercial_grade") == "hosted_saas_ready", "error", str(commercial.get("commercial_grade") or ""), "Hosted production acceptance requires commercial_grade=hosted_saas_ready."),
            _check("hosted_track_ready", hosted_track.get("status") == "ready", "error", str(hosted_track.get("status") or "missing"), "Resolve the hosted_saas track in /api/handoff-readiness."),
            _check("hosted_readiness_ready", hosted.get("status") == "ready", "error", str(hosted.get("status") or ""), "Configure DRAFTPAPER_HOSTED_READINESS_FILE on the hosted service."),
            _check("hosted_required_gates_passed", not hosted_gate_summary["missing_required_gates"] and not hosted_gate_summary["failed_gates"], "error", json.dumps(hosted_gate_summary, sort_keys=True), "Every hosted readiness gate must pass."),
            _check("security_audit_clean", security.get("status") == "passed" and _summary_errors(security) == 0, "error", f"{security.get('status') or ''} errors={_summary_errors(security)}", "Fix hosted security audit errors."),
            _check("license_valid", license_payload.get("status") == "valid", "error", str(license_payload.get("status") or ""), "Configure a valid hosted/paid license record."),
            _check("license_entitlements_valid", entitlements.get("status") == "passed", "error", str(entitlements.get("status") or ""), "Resolve hosted license entitlement findings."),
            _check("backups_verified", backup_verification.get("status") == "verified", "error", str(backup_verification.get("status") or ""), "Verify hosted backups."),
            _check("backups_rehearsed", backup_rehearsals.get("status") == "passed", "error", str(backup_rehearsals.get("status") or ""), "Run a hosted restore rehearsal."),
        ]
    )

    evidence_summary = {
        "base_url": base_url.rstrip("/"),
        "commercial_grade": str(commercial.get("commercial_grade") or ""),
        "hosted_track": {"status": str(hosted_track.get("status") or ""), "summary": hosted_track.get("summary") if isinstance(hosted_track.get("summary"), dict) else {}},
        "hosted_readiness": hosted_gate_summary,
        "local_validation": {
            "status": str(local_validation.get("status") or ""),
            "summary": local_validation.get("summary") if isinstance(local_validation.get("summary"), dict) else {},
        },
        "hosted_readiness_dossier": {
            "status": str(dossier_report.get("status") or ""),
            "zip_sha256": str(dossier_report.get("zip_sha256") or ""),
            "dossier_sha256": str(dossier_report.get("dossier_sha256") or ""),
            "summary": dossier_report.get("summary") if isinstance(dossier_report.get("summary"), dict) else {},
        },
        "security_audit": {"status": str(security.get("status") or ""), "summary": security.get("summary") if isinstance(security.get("summary"), dict) else {}},
        "backup_recovery": {"verification_status": str(backup_verification.get("status") or ""), "rehearsal_status": str(backup_rehearsals.get("status") or "")},
    }
    checks.append(_check("acceptance_report_redacted", not _contains_sensitive_key(evidence_summary), "error", "customer-safe summary", "Do not include tokens, cookies, secrets, or authorization values in the acceptance report."))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed" if not errors else "attention",
        "generated_at": generated_at,
        "base_url": base_url.rstrip("/"),
        "summary": {"checks": len(checks), "errors": len(errors), "warnings": len(warnings)},
        "checks": checks,
        "evidence_summary": evidence_summary,
        "notes": [
            "This report verifies that a hosted URL, hosted readiness evidence, and hosted readiness dossier agree.",
            "It does not embed raw hosted readiness JSON, private evidence files, tokens, cookies, or customer project data.",
            "Localhost and plain HTTP are rejected by default so local paid handoff evidence cannot be mistaken for hosted SaaS production acceptance.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Draftpaper-loop hosted SaaS production acceptance checks.")
    parser.add_argument("--base-url", required=True, help="Hosted console base URL, for example https://draftpaper.example.com.")
    parser.add_argument("--token", default=os.environ.get("DRAFTPAPER_CONSOLE_TOKEN", ""), help="Operator token. Prefer DRAFTPAPER_CONSOLE_TOKEN instead of shell history.")
    parser.add_argument("--evidence-file", default="", help="Private hosted-readiness.json file to validate and compare.")
    parser.add_argument("--hosted-readiness-dossier", default="", help="Verified hosted-readiness-dossier.zip path.")
    parser.add_argument("--output", default="", help="Optional private JSON report output path.")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--require-passed", action="store_true", help="Exit non-zero unless all production acceptance checks pass.")
    parser.add_argument("--allow-localhost", action="store_true", help="Allow localhost base URLs for rehearsal only.")
    parser.add_argument("--allow-insecure-http", action="store_true", help="Allow http:// base URLs for rehearsal only.")
    parser.add_argument("--force", action="store_true", help="Overwrite --output if it already exists.")
    args = parser.parse_args(argv)

    report = run_hosted_production_acceptance(
        base_url=args.base_url,
        token=args.token,
        evidence_file=Path(args.evidence_file).expanduser() if args.evidence_file else None,
        hosted_readiness_dossier=Path(args.hosted_readiness_dossier).expanduser() if args.hosted_readiness_dossier else None,
        allow_localhost=args.allow_localhost,
        allow_insecure_http=args.allow_insecure_http,
        timeout=args.timeout,
    )
    if args.output:
        _write_private_json(Path(args.output).expanduser(), report, force=args.force)
    print(json.dumps(report, ensure_ascii=False, indent=2) + "\n", end="")
    if args.require_passed and report.get("status") != "passed":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
