#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FEATURES = ["local_console", "paper_loop", "project_export", "backup_restore"]
DEFAULT_ACTIVE_ENV_PATH = REPO_ROOT / "var" / "private" / "active-handoff.env"


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _date_days_from_now(days: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() + days * 86400))


def _slug(value: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in value.strip())
    return safe.strip("-._").lower() or "customer"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def license_digest(payload: dict[str, Any]) -> str:
    raw = _license_canonical_bytes(payload)
    return hashlib.sha256(raw).hexdigest()


def _license_canonical_bytes(payload: dict[str, Any]) -> bytes:
    unsigned = {
        key: value
        for key, value in payload.items()
        if key not in {"grant_sha256", "sha256", "signature", "signed_at"}
    }
    return json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _openssl_bin() -> str:
    found = shutil.which("openssl")
    if not found:
        raise RuntimeError("openssl is required for license grant signing")
    return found


def _run_openssl(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([_openssl_bin(), *args], check=True, text=True, capture_output=True)


def _copy_or_derive_public_key(private_key: Path, public_key: Path | None, output_path: Path, *, force: bool) -> Path:
    if output_path.exists() and not force:
        raise FileExistsError(f"{output_path} already exists; pass --force to overwrite")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if public_key is not None:
        shutil.copyfile(public_key, output_path)
    else:
        _run_openssl(["pkey", "-in", str(private_key), "-pubout", "-out", str(output_path)])
    output_path.chmod(0o600)
    return output_path


def sign_license_grant(
    payload: dict[str, Any],
    *,
    private_key: Path,
    signature_path: Path,
    public_key_path: Path,
    public_key: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    if signature_path.exists() and not force:
        raise FileExistsError(f"{signature_path} already exists; pass --force to overwrite")
    _copy_or_derive_public_key(private_key, public_key, public_key_path, force=force)
    with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
        canonical_path = Path(handle.name)
        handle.write(_license_canonical_bytes(payload))
    try:
        signature_path.parent.mkdir(parents=True, exist_ok=True)
        _run_openssl(["dgst", "-sha256", "-sign", str(private_key), "-out", str(signature_path), str(canonical_path)])
    finally:
        canonical_path.unlink(missing_ok=True)
    signature_path.chmod(0o600)
    return {
        "signature_algorithm": "openssl-dgst-sha256",
        "signature_path": signature_path.name,
        "signature_sha256": hashlib.sha256(signature_path.read_bytes()).hexdigest(),
        "public_key_path": public_key_path.name,
        "public_key_sha256": hashlib.sha256(public_key_path.read_bytes()).hexdigest(),
        "license_sha256": license_digest(payload),
        "signed_at": _utc_timestamp(),
    }


def _write_private_json(path: Path, payload: dict[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _write_private_text(path: Path, content: str, *, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def generate_handoff_config(
    *,
    output_dir: Path,
    customer_id: str,
    customer_name: str,
    expires_at: str,
    seats: int = 1,
    license_id: str = "",
    grant_type: str = "paid-local-pilot",
    issued_at: str = "",
    workspace: str = "",
    billing_plan: str = "pilot-paid",
    features: list[str] | None = None,
    operator_id: str = "customer-admin",
    operator_role: str = "admin",
    operator_token: str = "",
    can_export_data: bool = False,
    currency: str = "USD",
    job_rate: float = 0.0,
    backup_rate: float = 0.0,
    storage_gb_month_rate: float = 0.0,
    write_token_file: bool = True,
    activate: bool = False,
    active_env_path: Path | None = None,
    license_signing_key: Path | None = None,
    license_public_key: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    if seats < 1:
        raise ValueError("seats must be positive")
    if operator_role not in {"admin", "operator", "viewer"}:
        raise ValueError("operator_role must be admin, operator, or viewer")
    customer_slug = _slug(customer_id or customer_name)
    output_dir = output_dir.expanduser().resolve()
    workspace = workspace or customer_slug
    issued_at = issued_at or time.strftime("%Y-%m-%d", time.gmtime())
    license_id = license_id or f"DPL-COMM-{time.strftime('%Y%m%d', time.gmtime())}-{customer_slug.upper()}"
    token = operator_token or secrets.token_urlsafe(32)
    token_hash = _sha256_text(token)

    license_payload: dict[str, Any] = {
        "schema_version": "draftpaper.commercial-license/v1",
        "license_id": license_id,
        "customer_id": customer_id,
        "customer_name": customer_name,
        "grant_type": grant_type,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "seats": seats,
        "features": features or list(DEFAULT_FEATURES),
        "workspaces": [workspace],
        "terms": "Local paid pilot handoff; does not grant SaaS, resale, or hosted multi-tenant rights.",
    }
    license_payload["grant_sha256"] = license_digest(license_payload)

    users_payload = {
        "schema_version": "draftpaper.console-users/v1",
        "generated_at": _utc_timestamp(),
        "users": [
            {
                "id": operator_id,
                "role": operator_role,
                "workspace": workspace,
                "billing_customer_id": customer_id,
                "billing_plan": billing_plan,
                "token_sha256": token_hash,
                "allowed_actions": ["*"],
                "blocked_actions": [],
                "can_export_data": can_export_data,
            }
        ],
    }
    billing_payload = {
        "schema_version": "draftpaper.billing-rates/v1",
        "currency": currency,
        "rates": {
            "job": job_rate,
            "backup": backup_rate,
            "storage_gb_month": storage_gb_month_rate,
        },
    }

    license_path = output_dir / "commercial-license-grant.json"
    license_signature_path = output_dir / "commercial-license-grant.json.sig"
    license_public_key_path = output_dir / "commercial-license-grant.public.pem"
    users_path = output_dir / "console-users.json"
    billing_path = output_dir / "billing-rates.json"
    env_path = output_dir / "handoff-env.sh"
    manifest_path = output_dir / "handoff-manifest.json"
    token_path = output_dir / "operator-token.txt"

    license_signed = False
    if license_signing_key is not None:
        license_payload["signature"] = sign_license_grant(
            license_payload,
            private_key=license_signing_key.expanduser().resolve(),
            public_key=license_public_key.expanduser().resolve() if license_public_key is not None else None,
            signature_path=license_signature_path,
            public_key_path=license_public_key_path,
            force=force,
        )
        license_signed = True

    _write_private_json(license_path, license_payload, force=force)
    _write_private_json(users_path, users_payload, force=force)
    _write_private_json(billing_path, billing_payload, force=force)
    env_text = "\n".join(
        [
            "# Source this file before starting Draftpaper-loop for this handoff.",
            f"export DRAFTPAPER_LICENSE_FILE={shlex.quote(str(license_path))}",
            f"export DRAFTPAPER_CONSOLE_USERS_FILE={shlex.quote(str(users_path))}",
            f"export DRAFTPAPER_BILLING_RATES_FILE={shlex.quote(str(billing_path))}",
            *([f"export DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256={shlex.quote(str(license_payload['signature']['public_key_sha256']))}"] if license_signed else []),
            "",
        ]
    )
    _write_private_text(env_path, env_text, force=force)
    token_written = False
    if write_token_file:
        _write_private_text(token_path, token + "\n", force=force)
        token_written = True

    active_env_written = False
    if activate:
        active_path = (active_env_path or DEFAULT_ACTIVE_ENV_PATH).expanduser().resolve()
        _write_private_text(
            active_path,
            "\n".join(
                [
                    "# Active private handoff environment loaded by scripts/serviceconsole_app.py.",
                    f"export DRAFTPAPER_LICENSE_FILE={shlex.quote(str(license_path))}",
                    f"export DRAFTPAPER_CONSOLE_USERS_FILE={shlex.quote(str(users_path))}",
                    f"export DRAFTPAPER_BILLING_RATES_FILE={shlex.quote(str(billing_path))}",
                    *([f"export DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256={shlex.quote(str(license_payload['signature']['public_key_sha256']))}"] if license_signed else []),
                    "",
                ]
            ),
            force=force,
        )
        active_env_written = True
    else:
        active_path = active_env_path.expanduser().resolve() if active_env_path else None

    manifest = {
        "schema_version": "draftpaper.handoff-config/v1",
        "status": "generated",
        "generated_at": _utc_timestamp(),
        "output_dir": str(output_dir),
        "customer_id": customer_id,
        "customer_name": customer_name,
        "license_id": license_id,
        "workspace": workspace,
        "operator_id": operator_id,
        "operator_role": operator_role,
        "token_sha256": token_hash,
        "grant_sha256": license_payload["grant_sha256"],
        "files": {
            "license": str(license_path),
            "license_signature": str(license_signature_path) if license_signed else "",
            "license_public_key": str(license_public_key_path) if license_signed else "",
            "license_public_key_sha256": str(license_payload.get("signature", {}).get("public_key_sha256") or "") if license_signed else "",
            "users": str(users_path),
            "billing": str(billing_path),
            "env": str(env_path),
            "manifest": str(manifest_path),
            "token": str(token_path) if token_written else "",
            "active_env": str(active_path) if active_env_written and active_path else "",
        },
        "activated": active_env_written,
        "license_signed": license_signed,
        "notes": [
            "Private files are written with owner-only permissions.",
            "The users file stores only token_sha256; the plaintext operator token is stored separately only when token file output is enabled.",
            "Use --license-signing-key to generate a detached OpenSSL signature for commercial license grant evidence.",
            "Signed handoff env files include DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256 so the console can pin the expected license verification key.",
            "Use --activate to write var/private/active-handoff.env for the standard Service Console startup path.",
            "These files are private runtime handoff material and are excluded from release packages by name or var/ directory scope.",
        ],
    }
    _write_private_json(manifest_path, manifest, force=force)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate private Draftpaper-loop paid local handoff config files.")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "var" / "private" / "handoff"), help="Private output directory.")
    parser.add_argument("--customer-id", required=True)
    parser.add_argument("--customer-name", required=True)
    parser.add_argument("--license-id", default="")
    parser.add_argument("--grant-type", default="paid-local-pilot")
    parser.add_argument("--issued-at", default="")
    parser.add_argument("--expires-at", default=_date_days_from_now(365))
    parser.add_argument("--seats", type=int, default=1)
    parser.add_argument("--workspace", default="")
    parser.add_argument("--billing-plan", default="pilot-paid")
    parser.add_argument("--features", nargs="*", default=list(DEFAULT_FEATURES))
    parser.add_argument("--operator-id", default="customer-admin")
    parser.add_argument("--operator-role", choices=["admin", "operator", "viewer"], default="admin")
    parser.add_argument("--operator-token", default="", help="Optional preselected operator token. If omitted, a random token is generated.")
    parser.add_argument("--can-export-data", action="store_true", help="Allow this operator to export raw/processed project data.")
    parser.add_argument("--currency", default="USD")
    parser.add_argument("--job-rate", type=float, default=0.0)
    parser.add_argument("--backup-rate", type=float, default=0.0)
    parser.add_argument("--storage-gb-month-rate", type=float, default=0.0)
    parser.add_argument("--no-token-file", action="store_true", help="Do not write operator-token.txt.")
    parser.add_argument("--activate", action="store_true", help="Write var/private/active-handoff.env so the standard local console startup loads this handoff config.")
    parser.add_argument("--active-env-path", default=str(DEFAULT_ACTIVE_ENV_PATH), help="Path for the active handoff env pointer written with --activate.")
    parser.add_argument("--license-signing-key", default="", help="Optional PEM private key used to create a detached signature for commercial-license-grant.json.")
    parser.add_argument("--license-public-key", default="", help="Optional PEM public key to copy into the handoff directory; derived from --license-signing-key when omitted.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing generated files.")
    args = parser.parse_args(argv)

    result = generate_handoff_config(
        output_dir=Path(args.output_dir),
        customer_id=args.customer_id,
        customer_name=args.customer_name,
        expires_at=args.expires_at,
        seats=args.seats,
        license_id=args.license_id,
        grant_type=args.grant_type,
        issued_at=args.issued_at,
        workspace=args.workspace,
        billing_plan=args.billing_plan,
        features=args.features,
        operator_id=args.operator_id,
        operator_role=args.operator_role,
        operator_token=args.operator_token,
        can_export_data=args.can_export_data,
        currency=args.currency,
        job_rate=args.job_rate,
        backup_rate=args.backup_rate,
        storage_gb_month_rate=args.storage_gb_month_rate,
        write_token_file=not args.no_token_file,
        activate=args.activate,
        active_env_path=Path(args.active_env_path),
        license_signing_key=Path(args.license_signing_key) if args.license_signing_key else None,
        license_public_key=Path(args.license_public_key) if args.license_public_key else None,
        force=args.force,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
