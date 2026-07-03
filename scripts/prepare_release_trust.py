#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "draftpaper.release-trust-preparation/v1"
TRUST_SCHEMA = "draftpaper.release-trust/v1"
ALLOWED_TRUST_TYPES = {
    "certificate_code_signing",
    "notarization",
    "third_party_release_trust",
    "enterprise_allowlist",
}


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _path_from_arg_or_env(path: Path | None, env_key: str, *, required: bool = False) -> Path | None:
    if path is not None:
        resolved = path.expanduser().resolve()
    else:
        raw = os.environ.get(env_key, "").strip()
        resolved = Path(raw).expanduser().resolve() if raw else None
    if required and resolved is None:
        raise ValueError(f"{env_key} is required or pass the matching CLI argument")
    return resolved


def _default_sidecar(release_zip: Path, suffix: str) -> Path | None:
    candidate = release_zip.with_suffix(suffix)
    return candidate if candidate.exists() else None


def _release_sidecars(
    *,
    release_zip: Path,
    release_manifest: Path | None,
    release_sha256_file: Path | None,
    release_signature: Path | None,
    release_public_key: Path | None,
) -> dict[str, Path | None]:
    stem = release_zip.with_suffix("")
    return {
        "release_manifest": release_manifest or _default_sidecar(release_zip, ".manifest.json"),
        "release_sha256_file": release_sha256_file or Path(f"{release_zip}.sha256") if Path(f"{release_zip}.sha256").exists() else release_sha256_file,
        "release_signature": release_signature or Path(f"{release_zip}.sig") if Path(f"{release_zip}.sig").exists() else release_signature,
        "release_public_key": release_public_key or Path(f"{stem}.public.pem") if Path(f"{stem}.public.pem").exists() else release_public_key,
    }


def _hash_if_present(path: Path | None) -> str:
    return _sha256_file(path) if path is not None and path.exists() and path.is_file() else ""


def _load_verifier_module() -> Any:
    verifier_path = REPO_ROOT / "scripts" / "verify_release_trust.py"
    spec = importlib.util.spec_from_file_location("draftpaper_verify_release_trust", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/verify_release_trust.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_release_trust(
    *,
    output: Path,
    release_zip: Path | None = None,
    release_manifest: Path | None = None,
    release_sha256_file: Path | None = None,
    release_signature: Path | None = None,
    release_public_key: Path | None = None,
    status: str = "draft",
    trust_type: str = "third_party_release_trust",
    trust_authority: str = "",
    trust_reference: str = "",
    verified_by: str = "",
    verified_at: str = "",
    evidence_refs: list[str] | None = None,
    verify: bool = True,
) -> dict[str, Any]:
    release_zip = _path_from_arg_or_env(release_zip, "DRAFTPAPER_RELEASE_ZIP", required=True)
    assert release_zip is not None
    if not release_zip.exists() or not release_zip.is_file():
        raise FileNotFoundError(f"release zip not found: {release_zip}")
    release_manifest = _path_from_arg_or_env(release_manifest, "DRAFTPAPER_RELEASE_MANIFEST_FILE")
    release_sha256_file = _path_from_arg_or_env(release_sha256_file, "DRAFTPAPER_RELEASE_SHA256_FILE")
    release_signature = _path_from_arg_or_env(release_signature, "DRAFTPAPER_RELEASE_SIGNATURE_FILE")
    release_public_key = _path_from_arg_or_env(release_public_key, "DRAFTPAPER_RELEASE_PUBLIC_KEY_FILE")
    sidecars = _release_sidecars(
        release_zip=release_zip,
        release_manifest=release_manifest,
        release_sha256_file=release_sha256_file,
        release_signature=release_signature,
        release_public_key=release_public_key,
    )
    release_manifest = sidecars["release_manifest"]
    release_sha256_file = sidecars["release_sha256_file"]
    release_signature = sidecars["release_signature"]
    release_public_key = sidecars["release_public_key"]

    status = str(status or "draft").strip().lower()
    if status not in {"draft", "verified"}:
        raise ValueError("status must be draft or verified")
    trust_type = str(trust_type or "").strip()
    if trust_type not in ALLOWED_TRUST_TYPES:
        raise ValueError(f"trust_type must be one of: {', '.join(sorted(ALLOWED_TRUST_TYPES))}")
    refs = [str(item).strip() for item in (evidence_refs or []) if str(item).strip()]
    if status == "verified":
        missing = [
            name
            for name, value in {
                "trust_authority": trust_authority,
                "trust_reference": trust_reference,
                "verified_by": verified_by,
            }.items()
            if not str(value or "").strip()
        ]
        if missing or not refs:
            raise ValueError("--status verified requires trust authority, reference, verified-by, and at least one --evidence-ref")
        missing_sidecars = [
            name
            for name, path in {
                "release_manifest": release_manifest,
                "release_sha256_file": release_sha256_file,
                "release_signature": release_signature,
                "release_public_key": release_public_key,
            }.items()
            if path is None or not path.exists() or not path.is_file()
        ]
        if missing_sidecars:
            raise ValueError(f"--status verified requires signed release sidecars: {', '.join(missing_sidecars)}")

    manifest_payload = _read_json(release_manifest) if release_manifest is not None and release_manifest.exists() else {}
    now = _utc_timestamp()
    trust = {
        "schema_version": TRUST_SCHEMA,
        "status": status,
        "trust_type": trust_type,
        "trust_authority": trust_authority.strip(),
        "trust_reference": trust_reference.strip() or (f"DRAFT-{release_zip.stem}-{now[:10]}" if status == "draft" else ""),
        "verified_by": verified_by.strip(),
        "verified_at": verified_at.strip() or (now if status == "verified" else ""),
        "prepared_at": now,
        "prepared_by": "prepare_release_trust.py",
        "package": str(manifest_payload.get("package") or release_zip.stem),
        "evidence_refs": refs,
        "release_zip_sha256": _sha256_file(release_zip),
        "release_manifest_sha256": _hash_if_present(release_manifest),
        "release_sha256_file_sha256": _hash_if_present(release_sha256_file),
        "release_signature_sha256": _hash_if_present(release_signature),
        "release_public_key_sha256": _hash_if_present(release_public_key),
        "review_instructions": [
            "Review the exact release package, manifest, checksum, signature, public key, and external trust evidence before setting status to verified.",
            "Keep certificate, notarization, MDM, or third-party review identifiers in evidence_refs rather than embedding private reports.",
            "Do not add tokens, passwords, cookies, private keys, or other secrets to this file.",
        ],
    }

    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(trust, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.chmod(0o600)

    verification: dict[str, Any] | None = None
    if verify:
        module = _load_verifier_module()
        verification = module.verify_release_trust(
            trust_file=output,
            release_zip=release_zip,
            release_manifest=release_manifest,
            release_sha256_file=release_sha256_file,
            release_signature=release_signature,
            release_public_key=release_public_key,
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "prepared",
        "generated_at": now,
        "output": str(output),
        "trust_status": status,
        "trust_type": trust_type,
        "release_zip": str(release_zip),
        "release_manifest": str(release_manifest or ""),
        "release_sha256_file": str(release_sha256_file or ""),
        "release_signature": str(release_signature or ""),
        "release_public_key": str(release_public_key or ""),
        "package": trust["package"],
        "evidence_refs_count": len(refs),
        "verification_status": verification.get("status") if isinstance(verification, dict) else "",
        "verification_summary": verification.get("summary") if isinstance(verification, dict) else {},
        "notes": [
            "Draft release trust evidence is private runtime material.",
            "A draft or unverified record must not be treated as certificate, notarization, allowlist, or third-party release trust.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare private Draftpaper-loop release trust evidence.")
    parser.add_argument("--output", required=True, help="Private release trust JSON output path.")
    parser.add_argument("--release-zip", default="", help="Release zip. Defaults to DRAFTPAPER_RELEASE_ZIP.")
    parser.add_argument("--release-manifest", default="", help="External release manifest JSON.")
    parser.add_argument("--release-sha256-file", default="", help="External .zip.sha256 sidecar.")
    parser.add_argument("--release-signature", default="", help="Detached release signature sidecar.")
    parser.add_argument("--release-public-key", default="", help="Release signature public key.")
    parser.add_argument("--status", choices=["draft", "verified"], default="draft", help="Write a draft template or verified trust evidence.")
    parser.add_argument("--trust-type", choices=sorted(ALLOWED_TRUST_TYPES), default="third_party_release_trust")
    parser.add_argument("--trust-authority", default="", help="External certificate, notarization, MDM, or trust authority.")
    parser.add_argument("--trust-reference", default="", help="External trust reference id.")
    parser.add_argument("--verified-by", default="", help="Verifier identity required when --status verified.")
    parser.add_argument("--verified-at", default="", help="Verification timestamp. Defaults to now only for --status verified.")
    parser.add_argument("--evidence-ref", action="append", default=[], help="External trust evidence reference. Repeat for multiple refs.")
    parser.add_argument("--no-verify", action="store_true", help="Skip running verify_release_trust.py after writing the file.")
    args = parser.parse_args(argv)
    report = prepare_release_trust(
        output=Path(args.output),
        release_zip=Path(args.release_zip) if args.release_zip else None,
        release_manifest=Path(args.release_manifest) if args.release_manifest else None,
        release_sha256_file=Path(args.release_sha256_file) if args.release_sha256_file else None,
        release_signature=Path(args.release_signature) if args.release_signature else None,
        release_public_key=Path(args.release_public_key) if args.release_public_key else None,
        status=args.status,
        trust_type=args.trust_type,
        trust_authority=args.trust_authority,
        trust_reference=args.trust_reference,
        verified_by=args.verified_by,
        verified_at=args.verified_at,
        evidence_refs=list(args.evidence_ref or []),
        verify=not args.no_verify,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
