#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
TRUST_SCHEMA = "draftpaper.release-trust/v1"
REPORT_SCHEMA = "draftpaper.release-trust-verification/v1"
ALLOWED_TRUST_TYPES = {
    "certificate_code_signing",
    "notarization",
    "third_party_release_trust",
    "enterprise_allowlist",
}
SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
)
SENSITIVE_VALUE_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "Authorization:",
    "Bearer ",
)


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        return {"_read_error": str(exc)}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_public_mode(path: Path) -> int:
    try:
        return stat.S_IMODE(path.stat().st_mode) & 0o077
    except OSError:
        return 0o777


def _parse_time(value: Any) -> float:
    raw = str(value or "").strip()
    if not raw:
        return 0.0
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return time.mktime(time.strptime(raw, fmt))
        except ValueError:
            continue
    return 0.0


def _evidence_refs(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    refs: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            refs.append(item.strip())
        elif isinstance(item, dict):
            ref = str(item.get("id") or item.get("ref") or item.get("uri") or item.get("path") or "").strip()
            if ref:
                refs.append(ref)
    return refs


def _find_sensitive_paths(value: Any, *, prefix: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{prefix}.{key_text}"
            if any(part in key_text.lower() for part in SENSITIVE_KEY_PARTS):
                findings.append(child_path)
            findings.extend(_find_sensitive_paths(child, prefix=child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_find_sensitive_paths(child, prefix=f"{prefix}[{index}]"))
    elif isinstance(value, str):
        if any(marker in value for marker in SENSITIVE_VALUE_MARKERS):
            findings.append(prefix)
    return findings


def _public_trust_payload(payload: dict[str, Any]) -> dict[str, Any]:
    fields = [
        "schema_version",
        "status",
        "trust_type",
        "trust_authority",
        "trust_reference",
        "verified_by",
        "verified_at",
        "package",
        "release_zip_sha256",
        "release_manifest_sha256",
        "release_signature_sha256",
        "release_public_key_sha256",
    ]
    return {field: payload.get(field) for field in fields if field in payload}


def _release_verifier_module() -> Any:
    verifier_path = REPO_ROOT / "scripts" / "verify_release_package.py"
    spec = importlib.util.spec_from_file_location("draftpaper_verify_release_package", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/verify_release_package.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _path_from_env_or_arg(value: Path | None, env_key: str) -> Path | None:
    if value is not None:
        return value.expanduser().resolve()
    raw = os.environ.get(env_key, "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _artifact_hash_check(checks: list[dict[str, Any]], *, path: Path | None, field_name: str, payload: dict[str, Any], label: str, required: bool = False) -> str:
    expected = str(payload.get(field_name) or "").strip().lower()
    if path is None:
        checks.append(_check(f"{label}_configured", not required, "error" if required else "warning", f"No {label} path is configured.", f"Pass --{label.replace('_', '-')} or set the matching DRAFTPAPER_RELEASE_* env var."))
        return ""
    checks.append(_check(f"{label}_exists", path.exists(), "error", str(path), f"Fix the configured {label} path."))
    if not path.exists():
        return ""
    actual = _sha256_file(path)
    checks.append(_check(f"{label}_sha256_present", bool(expected), "warning", f"{field_name} {'present' if expected else 'missing'}.", f"Record {field_name} in the trust evidence file."))
    if expected:
        checks.append(_check(f"{label}_sha256_matches", actual == expected, "error", f"{field_name} matches {path.name}.", f"Update or reissue trust evidence after intentional {label} changes."))
    return actual


def verify_release_trust(
    *,
    trust_file: Path | None = None,
    release_zip: Path | None = None,
    release_manifest: Path | None = None,
    release_sha256_file: Path | None = None,
    release_signature: Path | None = None,
    release_public_key: Path | None = None,
    output: Path | None = None,
) -> dict[str, Any]:
    trust_file = _path_from_env_or_arg(trust_file, "DRAFTPAPER_RELEASE_TRUST_FILE")
    release_zip = _path_from_env_or_arg(release_zip, "DRAFTPAPER_RELEASE_ZIP")
    release_manifest = _path_from_env_or_arg(release_manifest, "DRAFTPAPER_RELEASE_MANIFEST_FILE")
    release_sha256_file = _path_from_env_or_arg(release_sha256_file, "DRAFTPAPER_RELEASE_SHA256_FILE")
    release_signature = _path_from_env_or_arg(release_signature, "DRAFTPAPER_RELEASE_SIGNATURE_FILE")
    release_public_key = _path_from_env_or_arg(release_public_key, "DRAFTPAPER_RELEASE_PUBLIC_KEY_FILE")
    checks: list[dict[str, Any]] = []
    payload: dict[str, Any] = {}
    observed: dict[str, str] = {}

    checks.append(_check("release_trust_file_configured", trust_file is not None, "error", "Release trust evidence file is configured.", "Set DRAFTPAPER_RELEASE_TRUST_FILE or pass --trust-file."))
    if trust_file is not None:
        checks.append(_check("release_trust_file_exists", trust_file.exists(), "error", str(trust_file), "Create the release trust evidence file or fix the configured path."))
        if trust_file.exists():
            checks.append(_check("release_trust_file_permissions", _file_public_mode(trust_file) == 0, "warning", f"public permission bits={oct(_file_public_mode(trust_file))}", "Restrict the release trust evidence file to owner-only permissions, for example chmod 600."))
            loaded = _read_json(trust_file)
            if isinstance(loaded, dict) and "_read_error" not in loaded:
                payload = loaded
                checks.append(_check("release_trust_file_shape", True, "error", "Release trust evidence file contains a JSON object."))
            else:
                checks.append(_check("release_trust_file_shape", False, "error", str(loaded.get("_read_error") if isinstance(loaded, dict) else type(loaded).__name__), f"Use a JSON object with schema_version {TRUST_SCHEMA}."))

    if payload:
        checks.append(_check("release_trust_schema", payload.get("schema_version") == TRUST_SCHEMA, "error", f"schema_version={payload.get('schema_version') or 'missing'}", f"Set schema_version to {TRUST_SCHEMA}."))
        checks.append(_check("release_trust_status", str(payload.get("status") or "").strip().lower() == "verified", "error", f"status={payload.get('status') or 'missing'}", "Set status to verified only after external release trust evidence is complete."))
        trust_type = str(payload.get("trust_type") or "").strip()
        checks.append(_check("release_trust_type", trust_type in ALLOWED_TRUST_TYPES, "error", trust_type or "missing", f"Use one of: {', '.join(sorted(ALLOWED_TRUST_TYPES))}."))
        required_fields = ["trust_authority", "trust_reference", "verified_by", "verified_at", "release_zip_sha256"]
        missing = [field for field in required_fields if not str(payload.get(field) or "").strip()]
        checks.append(_check("release_trust_required_fields", not missing, "error", "Release trust evidence includes required audit fields.", f"Missing fields: {', '.join(missing)}" if missing else ""))
        verified_epoch = _parse_time(payload.get("verified_at"))
        checks.append(_check("release_trust_time_parseable", verified_epoch > 0, "error", "verified_at is parseable as YYYY-MM-DD or UTC timestamp.", "Use verified_at like 2026-07-03T00:00:00Z."))
        checks.append(_check("release_trust_time_not_future", verified_epoch == 0 or verified_epoch <= time.time() + 300, "error", "verified_at is not in the future.", "Use the actual release trust verification timestamp."))
        refs = _evidence_refs(payload.get("evidence_refs"))
        checks.append(_check("release_trust_evidence_refs", bool(refs), "error", "Release trust evidence includes at least one external certificate, notarization, allowlist, or third-party trust reference.", "Add evidence_refs with certificate, notarization, MDM, or third-party review references."))
        sensitive = sorted(set(_find_sensitive_paths(payload)))
        checks.append(_check("release_trust_no_secret_material", not sensitive, "error", "Release trust evidence does not contain obvious token, password, cookie, or private-key material.", f"Remove sensitive fields: {', '.join(sensitive[:10])}" if sensitive else ""))

        observed["release_zip_sha256"] = _artifact_hash_check(checks, path=release_zip, field_name="release_zip_sha256", payload=payload, label="release_zip", required=True)
        observed["release_manifest_sha256"] = _artifact_hash_check(checks, path=release_manifest, field_name="release_manifest_sha256", payload=payload, label="release_manifest")
        observed["release_sha256_file_sha256"] = _artifact_hash_check(checks, path=release_sha256_file, field_name="release_sha256_file_sha256", payload=payload, label="release_sha256_file")
        observed["release_signature_sha256"] = _artifact_hash_check(checks, path=release_signature, field_name="release_signature_sha256", payload=payload, label="release_signature")
        observed["release_public_key_sha256"] = _artifact_hash_check(checks, path=release_public_key, field_name="release_public_key_sha256", payload=payload, label="release_public_key")

        if release_manifest is not None and release_manifest.exists():
            manifest = _read_json(release_manifest)
            if isinstance(manifest, dict) and "_read_error" not in manifest:
                checks.append(_check("release_trust_manifest_zip_sha256_matches", str(manifest.get("zip_sha256") or "").strip().lower() == str(payload.get("release_zip_sha256") or "").strip().lower(), "error", "External release manifest zip_sha256 matches trust evidence.", "Use trust evidence for the exact release manifest."))
                if str(payload.get("package") or "").strip():
                    checks.append(_check("release_trust_package_matches", str(manifest.get("package") or "").strip() == str(payload.get("package") or "").strip(), "error", "External release manifest package matches trust evidence.", "Use trust evidence for the exact package name."))
            else:
                checks.append(_check("release_trust_manifest_readable", False, "error", str(manifest.get("_read_error") if isinstance(manifest, dict) else type(manifest).__name__), "Use a readable external release manifest JSON file."))
        if release_sha256_file is not None and release_sha256_file.exists():
            first_line = release_sha256_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()[0]
            checks.append(_check("release_trust_sha256_file_points_to_zip", str(payload.get("release_zip_sha256") or "").strip().lower() in first_line.lower(), "error", "External .zip.sha256 file records the trusted zip hash.", "Use the .zip.sha256 sidecar generated for the trusted release zip."))

        if release_zip is not None and release_zip.exists() and release_signature is not None and release_public_key is not None:
            try:
                verifier = _release_verifier_module()
                release_report = verifier.verify_release_package(
                    release_zip,
                    manifest_path=release_manifest,
                    sha256_path=release_sha256_file,
                    signature_path=release_signature,
                    public_key_path=release_public_key,
                    require_signature=True,
                )
                checks.append(_check("release_trust_release_package_verified", release_report.get("status") == "verified", "error", f"release verifier status={release_report.get('status')}", "Fix release package verification before relying on external release trust evidence."))
                signature_ok = any(item.get("id") == "signature_verified" and item.get("passed") for item in release_report.get("checks", []))
                checks.append(_check("release_trust_release_signature_verified", signature_ok, "error", "Release package detached signature verifies against the configured public key.", "Provide the trusted release signature and public key."))
            except Exception as exc:
                checks.append(_check("release_trust_release_verifier_ran", False, "error", str(exc), "Restore scripts/verify_release_package.py and valid release sidecars."))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    report = {
        "schema_version": REPORT_SCHEMA,
        "status": "verified" if not errors else ("unconfigured" if trust_file is None else "attention"),
        "generated_at": _utc_timestamp(),
        "trust_file": str(trust_file) if trust_file is not None else "",
        "release_zip": str(release_zip) if release_zip is not None else "",
        "release_manifest": str(release_manifest) if release_manifest is not None else "",
        "release_sha256_file": str(release_sha256_file) if release_sha256_file is not None else "",
        "release_signature": str(release_signature) if release_signature is not None else "",
        "release_public_key": str(release_public_key) if release_public_key is not None else "",
        "trust": _public_trust_payload(payload) if payload else {},
        "observed": observed,
        "checks": checks,
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
            "passed": sum(1 for item in checks if item["passed"]),
        },
        "notes": [
            "This verifies a private release trust evidence record against a specific release package and sidecars.",
            "It does not obtain a certificate, notarize software, perform MDM allowlisting, or replace a third-party release trust program.",
        ],
    }
    if output is not None:
        output = output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        output.chmod(0o600)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify private release trust evidence for a Draftpaper-loop release package.")
    parser.add_argument("--trust-file", default="", help="Path to draftpaper.release-trust/v1 evidence JSON.")
    parser.add_argument("--release-zip", default="")
    parser.add_argument("--release-manifest", default="")
    parser.add_argument("--release-sha256-file", default="")
    parser.add_argument("--release-signature", default="")
    parser.add_argument("--release-public-key", default="")
    parser.add_argument("--output", default="", help="Optional private JSON report path.")
    args = parser.parse_args(argv)
    report = verify_release_trust(
        trust_file=Path(args.trust_file) if args.trust_file else None,
        release_zip=Path(args.release_zip) if args.release_zip else None,
        release_manifest=Path(args.release_manifest) if args.release_manifest else None,
        release_sha256_file=Path(args.release_sha256_file) if args.release_sha256_file else None,
        release_signature=Path(args.release_signature) if args.release_signature else None,
        release_public_key=Path(args.release_public_key) if args.release_public_key else None,
        output=Path(args.output) if args.output else None,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
