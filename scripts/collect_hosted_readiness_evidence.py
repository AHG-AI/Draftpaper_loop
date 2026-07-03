#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    from serviceconsole_app import HOSTED_READINESS_REQUIREMENTS, HOSTED_READINESS_SCHEMA
except ImportError:  # pragma: no cover - direct import fallback for isolated packaging checks.
    import importlib.util
    import sys

    scripts_dir = Path(__file__).resolve().parent
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    spec = importlib.util.spec_from_file_location("draftpaper_serviceconsole_app", scripts_dir / "serviceconsole_app.py")
    if spec is None or spec.loader is None:
        raise
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    HOSTED_READINESS_REQUIREMENTS = module.HOSTED_READINESS_REQUIREMENTS
    HOSTED_READINESS_SCHEMA = module.HOSTED_READINESS_SCHEMA


SCHEMA_VERSION = "draftpaper.hosted-readiness-evidence-collection/v1"
API_PROBE_SCHEMA = "draftpaper.hosted-api-probe/v1"
TLS_PROBE_SCHEMA = "draftpaper.hosted-tls-probe/v1"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")
REDACTED = "[redacted]"

ENDPOINTS = {
    "health": "/health",
    "commercial_readiness": "/api/commercial-readiness",
    "handoff_readiness": "/api/handoff-readiness",
    "hosted_readiness": "/api/hosted-readiness",
    "security_audit": "/api/security-audit",
    "access_policy": "/api/access-policy",
    "quota": "/api/quota",
    "billing": "/api/billing",
    "license": "/api/license",
    "license_entitlements": "/api/license-entitlements",
    "backup_verification": "/api/backups/verify",
    "backup_rehearsals": "/api/backups/rehearsals",
}

SECTION_ARTIFACTS = {
    "enterprise_auth": ["security_audit", "access_policy", "handoff_readiness"],
    "payment_collection": ["billing", "license", "license_entitlements"],
    "managed_storage_dr": ["backup_verification", "backup_rehearsals"],
    "worker_isolation": ["handoff_readiness", "hosted_readiness"],
    "deployment_hardening": ["tls_certificate", "health", "security_audit", "commercial_readiness"],
}


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collection_digest(report: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in report.items() if key != "collection_sha256"}
    raw = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def _safe_key(key: str, index: int) -> str:
    if _is_sensitive_key(key):
        return f"redacted_field_{index}"
    return key


def _redact(value: Any, *, token: str = "") -> Any:
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            safe[_safe_key(str(key), index)] = REDACTED if _is_sensitive_key(str(key)) else _redact(item, token=token)
        return safe
    if isinstance(value, list):
        return [_redact(item, token=token) for item in value]
    if isinstance(value, str):
        return value.replace(token, REDACTED) if token else value
    return value


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if _is_sensitive_key(str(key)):
                return True
            if _contains_sensitive_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _write_private_json(path: Path, payload: dict[str, Any], *, force: bool = False) -> Path:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _prepare_output_dir(output_dir: Path, *, force: bool = False) -> Path:
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not force:
        raise FileExistsError(f"{output_dir} is not empty; pass --force to add or overwrite collection files")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o700)
    return output_dir


def _base_url_checks(base_url: str, *, allow_localhost: bool, allow_insecure_http: bool) -> list[dict[str, Any]]:
    parsed = urllib.parse.urlparse(base_url)
    hostname = (parsed.hostname or "").lower()
    is_local = hostname in LOCAL_HOSTS
    return [
        _check("base_url_present", bool(parsed.scheme and parsed.netloc), "error", base_url, "Provide --base-url such as https://draftpaper.example.com."),
        _check("base_url_not_localhost", allow_localhost or not is_local, "error", hostname or "missing", "Hosted evidence collection for production requires an external hostname. Use --allow-localhost only for rehearsal."),
        _check("base_url_https", allow_insecure_http or parsed.scheme == "https", "error", parsed.scheme or "missing", "Hosted evidence collection for production requires HTTPS. Use --allow-insecure-http only for rehearsal."),
    ]


def _request_endpoint(base_url: str, path: str, *, token: str, timeout: float) -> tuple[dict[str, Any], bool, str]:
    url = base_url.rstrip("/") + path
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Draftpaper-Token"] = token
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-provided hosted URL.
            raw = response.read().decode("utf-8")
            payload = json.loads(raw) if raw else {}
            artifact = {
                "schema_version": API_PROBE_SCHEMA,
                "generated_at": _utc_timestamp(),
                "url": url,
                "path": path,
                "status_code": response.status,
                "content_type": response.headers.get("Content-Type", ""),
                "response_headers": _redact(dict(response.headers), token=token),
                "payload": _redact(payload, token=token),
            }
            return artifact, isinstance(payload, dict) and 200 <= response.status < 300, ""
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            payload: Any = json.loads(body) if body else {}
        except json.JSONDecodeError:
            payload = {"body": body[:1000]}
        artifact = {
            "schema_version": API_PROBE_SCHEMA,
            "generated_at": _utc_timestamp(),
            "url": url,
            "path": path,
            "status_code": exc.code,
            "content_type": exc.headers.get("Content-Type", "") if exc.headers else "",
            "response_headers": _redact(dict(exc.headers or {}), token=token),
            "payload": _redact(payload, token=token),
        }
        return artifact, False, str(exc)
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
        artifact = {
            "schema_version": API_PROBE_SCHEMA,
            "generated_at": _utc_timestamp(),
            "url": url,
            "path": path,
            "status": "error",
            "message": str(exc),
        }
        return artifact, False, str(exc)


def _name_to_filename(name: str) -> str:
    return name.replace("/", "_").replace(" ", "_").replace("-", "_") + ".json"


def _collect_api_artifacts(
    *,
    base_url: str,
    token: str,
    timeout: float,
    output_dir: Path,
    force: bool,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    records: dict[str, dict[str, Any]] = {}
    checks: list[dict[str, Any]] = []
    api_dir = output_dir / "artifacts" / "api"
    for name, path in ENDPOINTS.items():
        artifact, ok, message = _request_endpoint(base_url, path, token=token, timeout=timeout)
        artifact_path = _write_private_json(api_dir / _name_to_filename(name), artifact, force=force)
        sha = _sha256_file(artifact_path)
        records[name] = {
            "path": artifact_path,
            "relative_path": artifact_path.relative_to(output_dir).as_posix(),
            "sha256": sha,
            "description": f"Hosted API probe for {path}",
            "passed": ok,
        }
        checks.append(_check(f"endpoint_{name}", ok, "error", path if ok else f"{path}: {message}", "Expose the hosted console endpoint and provide a valid operator token."))
    return records, checks


def _format_cert_name(name: tuple[tuple[tuple[str, str], ...], ...] | tuple[Any, ...]) -> str:
    parts: list[str] = []
    for group in name:
        if not isinstance(group, tuple):
            continue
        for pair in group:
            if isinstance(pair, tuple) and len(pair) == 2:
                parts.append(f"{pair[0]}={pair[1]}")
    return ", ".join(parts)


def _collect_tls_artifact(
    *,
    base_url: str,
    timeout: float,
    output_dir: Path,
    force: bool,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    parsed = urllib.parse.urlparse(base_url)
    checks: list[dict[str, Any]] = []
    if parsed.scheme != "https":
        checks.append(_check("tls_certificate_collected", False, "warning", "skipped for non-HTTPS URL", "Collect TLS evidence from the real HTTPS hosted URL."))
        return None, checks
    hostname = parsed.hostname
    if not hostname:
        checks.append(_check("tls_certificate_collected", False, "error", "hostname missing", "Use a valid HTTPS hosted URL."))
        return None, checks
    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                cert = tls_sock.getpeercert()
                artifact = {
                    "schema_version": TLS_PROBE_SCHEMA,
                    "generated_at": _utc_timestamp(),
                    "hostname": hostname,
                    "port": port,
                    "tls_version": tls_sock.version(),
                    "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else "",
                    "certificate": {
                        "sha256": hashlib.sha256(der or b"").hexdigest(),
                        "subject": _format_cert_name(cert.get("subject", ())) if isinstance(cert, dict) else "",
                        "issuer": _format_cert_name(cert.get("issuer", ())) if isinstance(cert, dict) else "",
                        "not_before": cert.get("notBefore", "") if isinstance(cert, dict) else "",
                        "not_after": cert.get("notAfter", "") if isinstance(cert, dict) else "",
                        "serial_number": cert.get("serialNumber", "") if isinstance(cert, dict) else "",
                        "subject_alt_names": cert.get("subjectAltName", []) if isinstance(cert, dict) else [],
                    },
                }
        artifact_path = _write_private_json(output_dir / "artifacts" / "tls_certificate.json", artifact, force=force)
        record = {
            "path": artifact_path,
            "relative_path": artifact_path.relative_to(output_dir).as_posix(),
            "sha256": _sha256_file(artifact_path),
            "description": "Hosted TLS certificate and cipher probe",
            "passed": True,
        }
        checks.append(_check("tls_certificate_collected", True, "error", hostname))
        return record, checks
    except Exception as exc:  # pragma: no cover - exercised against real hosted endpoints.
        artifact = {
            "schema_version": TLS_PROBE_SCHEMA,
            "generated_at": _utc_timestamp(),
            "hostname": hostname,
            "port": port,
            "status": "error",
            "message": str(exc),
        }
        artifact_path = _write_private_json(output_dir / "artifacts" / "tls_certificate.json", artifact, force=force)
        record = {
            "path": artifact_path,
            "relative_path": artifact_path.relative_to(output_dir).as_posix(),
            "sha256": _sha256_file(artifact_path),
            "description": "Hosted TLS certificate probe error",
            "passed": False,
        }
        checks.append(_check("tls_certificate_collected", False, "error", str(exc), "Fix TLS and certificate validation before hosted production acceptance."))
        return record, checks


def _artifact_entry(record: dict[str, Any]) -> dict[str, str]:
    return {
        "path": str(record["relative_path"]),
        "sha256": str(record["sha256"]),
        "description": str(record.get("description") or ""),
    }


def _build_hosted_readiness_draft(
    *,
    output_dir: Path,
    environment: str,
    artifact_records: dict[str, dict[str, Any]],
    force: bool,
) -> Path:
    payload: dict[str, Any] = {
        "schema_version": HOSTED_READINESS_SCHEMA,
        "environment": environment,
        "generated_at": _utc_timestamp(),
        "status_note": "draft generated from hosted live probes; operator must verify external controls before changing sections to verified",
    }
    for requirement in HOSTED_READINESS_REQUIREMENTS:
        evidence_key = str(requirement["evidence_key"])
        section: dict[str, Any] = {"status": "pending", "evidence": []}
        for field in requirement.get("required_fields", []):
            section[str(field)] = ""
        for field in requirement.get("required_true", []):
            section[str(field)] = False
        for artifact_name in SECTION_ARTIFACTS.get(evidence_key, []):
            record = artifact_records.get(artifact_name)
            if record is not None:
                section["evidence"].append(_artifact_entry(record))
        payload[evidence_key] = section
    return _write_private_json(output_dir / "hosted-readiness.draft.json", payload, force=force)


def collect_hosted_readiness_evidence(
    *,
    base_url: str,
    output_dir: Path,
    token: str = "",
    environment: str = "production",
    timeout: float = 8.0,
    allow_localhost: bool = False,
    allow_insecure_http: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    generated_at = _utc_timestamp()
    output_dir = _prepare_output_dir(output_dir, force=force)
    checks = _base_url_checks(base_url, allow_localhost=allow_localhost, allow_insecure_http=allow_insecure_http)
    api_records, api_checks = _collect_api_artifacts(
        base_url=base_url,
        token=token,
        timeout=timeout,
        output_dir=output_dir,
        force=force,
    )
    checks.extend(api_checks)
    tls_record, tls_checks = _collect_tls_artifact(
        base_url=base_url,
        timeout=timeout,
        output_dir=output_dir,
        force=force,
    )
    checks.extend(tls_checks)
    artifact_records = dict(api_records)
    if tls_record is not None:
        artifact_records["tls_certificate"] = tls_record

    draft_path = _build_hosted_readiness_draft(
        output_dir=output_dir,
        environment=environment,
        artifact_records=artifact_records,
        force=force,
    )
    report_path = output_dir / "hosted-readiness-evidence-collection.json"
    artifacts = {
        name: {
            "path": str(record["path"]),
            "relative_path": str(record["relative_path"]),
            "sha256": str(record["sha256"]),
            "description": str(record.get("description") or ""),
            "passed": bool(record.get("passed")),
        }
        for name, record in sorted(artifact_records.items())
    }
    checks.extend(
        [
            _check("hosted_readiness_draft_written", draft_path.exists(), "error", str(draft_path), "Write the hosted readiness draft evidence file."),
            _check("artifact_hashes_recorded", all(str(item.get("sha256") or "") for item in artifacts.values()), "error", f"{len(artifacts)} artifacts", "Every evidence artifact must have a SHA256 digest."),
            _check("collected_artifacts_redacted", not _contains_sensitive_key(artifacts), "error", "artifact manifest is key-redacted", "Do not store tokens, cookies, secrets, or authorization fields in hosted evidence artifacts."),
        ]
    )
    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "collected" if not errors else "attention",
        "generated_at": generated_at,
        "base_url": base_url.rstrip("/"),
        "environment": environment,
        "output_dir": str(output_dir),
        "hosted_readiness_draft": {
            "path": str(draft_path),
            "sha256": _sha256_file(draft_path),
        },
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
            "artifacts": len(artifacts),
        },
        "checks": checks,
        "artifacts": artifacts,
        "notes": [
            "This collection captures live hosted API, security, backup, license, and TLS evidence for operator review.",
            "The generated hosted-readiness.draft.json remains pending until the operator verifies external identity, billing, storage/DR, worker isolation, and deployment controls.",
            "Passing this collector is not the same as hosted_saas readiness; run validate_hosted_readiness.py, build_hosted_readiness_dossier.py, and run_hosted_production_acceptance.py after the evidence is complete.",
        ],
    }
    report["collection_sha256"] = collection_digest(report)
    _write_private_json(report_path, report, force=force)
    report["report_path"] = str(report_path)
    report["report_sha256"] = _sha256_file(report_path)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect private hosted SaaS readiness evidence from a real Draftpaper-loop hosted URL.")
    parser.add_argument("--base-url", required=True, help="Hosted console base URL, for example https://draftpaper.example.com.")
    parser.add_argument("--output-dir", required=True, help="Private directory for collected artifacts and hosted-readiness.draft.json.")
    parser.add_argument("--token", default=os.environ.get("DRAFTPAPER_CONSOLE_TOKEN", ""), help="Operator token. Prefer DRAFTPAPER_CONSOLE_TOKEN instead of shell history.")
    parser.add_argument("--environment", default="production")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--allow-localhost", action="store_true", help="Allow localhost base URLs for rehearsal only.")
    parser.add_argument("--allow-insecure-http", action="store_true", help="Allow http:// base URLs for rehearsal only.")
    parser.add_argument("--force", action="store_true", help="Allow writing into a non-empty output directory and overwriting known collection files.")
    parser.add_argument("--require-collected", action="store_true", help="Exit non-zero unless the evidence collection has no error findings.")
    args = parser.parse_args(argv)
    report = collect_hosted_readiness_evidence(
        base_url=args.base_url,
        output_dir=Path(args.output_dir),
        token=args.token,
        environment=args.environment,
        timeout=args.timeout,
        allow_localhost=args.allow_localhost,
        allow_insecure_http=args.allow_insecure_http,
        force=args.force,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", end="")
    if args.require_collected and report.get("status") != "collected":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
