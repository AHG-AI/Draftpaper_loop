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
SCHEMA_VERSION = "draftpaper.commercial-approval-preparation/v1"
APPROVAL_SCHEMA = "draftpaper.commercial-approval/v1"
REQUIRED_DOCUMENT_HASHES = [
    "LICENSE",
    "NOTICE",
    "COMMERCIAL_LICENSE.md",
    "COMPLIANCE.md",
]


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


def _license_canonical_bytes(payload: dict[str, Any]) -> bytes:
    unsigned = {
        key: value
        for key, value in payload.items()
        if key not in {"grant_sha256", "sha256", "signature", "signed_at"}
    }
    return json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def license_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_license_canonical_bytes(payload)).hexdigest()


def _load_verifier_module() -> Any:
    verifier_path = REPO_ROOT / "scripts" / "verify_commercial_approval.py"
    spec = importlib.util.spec_from_file_location("draftpaper_verify_commercial_approval", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/verify_commercial_approval.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _license_file_from_arg_or_env(license_file: Path | None) -> Path:
    if license_file is not None:
        return license_file.expanduser().resolve()
    raw = os.environ.get("DRAFTPAPER_LICENSE_FILE", "").strip()
    if not raw:
        raise ValueError("license file is required; pass --license-file or set DRAFTPAPER_LICENSE_FILE")
    return Path(raw).expanduser().resolve()


def _document_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    missing: list[str] = []
    for relative in REQUIRED_DOCUMENT_HASHES:
        path = root / relative
        if path.exists() and path.is_file():
            hashes[relative] = _sha256_file(path)
        else:
            missing.append(relative)
    if missing:
        raise FileNotFoundError(f"required commercial boundary documents missing: {', '.join(missing)}")
    return hashes


def prepare_commercial_approval(
    *,
    output: Path,
    license_file: Path | None = None,
    root: Path = REPO_ROOT,
    status: str = "draft",
    approval_authority: str = "",
    approval_reference: str = "",
    approved_by: str = "",
    approved_at: str = "",
    evidence_refs: list[str] | None = None,
    scope: list[str] | None = None,
    verify: bool = True,
) -> dict[str, Any]:
    root = root.expanduser().resolve()
    license_file = _license_file_from_arg_or_env(license_file)
    if not license_file.exists() or not license_file.is_file():
        raise FileNotFoundError(f"license file not found: {license_file}")
    license_payload = _read_json(license_file)
    if not license_payload:
        raise ValueError(f"license file is not a JSON object: {license_file}")

    status = str(status or "draft").strip().lower()
    if status not in {"draft", "approved"}:
        raise ValueError("status must be draft or approved")
    refs = [str(item).strip() for item in (evidence_refs or []) if str(item).strip()]
    if status == "approved":
        missing = [
            name
            for name, value in {
                "approval_authority": approval_authority,
                "approval_reference": approval_reference,
                "approved_by": approved_by,
            }.items()
            if not str(value or "").strip()
        ]
        if missing or not refs:
            raise ValueError("--status approved requires approval authority, reference, approved-by, and at least one --evidence-ref")

    now = _utc_timestamp()
    approval = {
        "schema_version": APPROVAL_SCHEMA,
        "status": status,
        "approval_reference": approval_reference.strip() or (f"DRAFT-{license_payload.get('license_id') or license_file.stem}-{now[:10]}" if status == "draft" else ""),
        "approval_authority": approval_authority.strip(),
        "approved_by": approved_by.strip(),
        "approved_at": approved_at.strip() or (now if status == "approved" else ""),
        "prepared_at": now,
        "prepared_by": "prepare_commercial_approval.py",
        "customer_id": str(license_payload.get("customer_id") or "").strip(),
        "customer_name": str(license_payload.get("customer_name") or "").strip(),
        "license_id": str(license_payload.get("license_id") or "").strip(),
        "scope": scope or ["paid_local_handoff"],
        "evidence_refs": refs,
        "license_grant_sha256": license_digest(license_payload),
        "license_file_sha256": _sha256_file(license_file),
        "document_hashes": _document_hashes(root),
        "review_instructions": [
            "Review the license grant, commercial license, compliance boundary, and customer approval record before setting status to approved.",
            "Do not add tokens, passwords, cookies, private keys, contract contents, payment details, or other secrets to this file.",
            "Keep external contract or approval-system identifiers in evidence_refs rather than embedding private documents.",
        ],
    }

    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(approval, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.chmod(0o600)

    verification: dict[str, Any] | None = None
    if verify:
        module = _load_verifier_module()
        verification = module.verify_commercial_approval(approval_file=output, license_file=license_file, root=root)

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "prepared",
        "generated_at": now,
        "output": str(output),
        "license_file": str(license_file),
        "approval_status": status,
        "customer_id": approval["customer_id"],
        "license_id": approval["license_id"],
        "document_hashes_count": len(approval["document_hashes"]),
        "evidence_refs_count": len(refs),
        "verification_status": verification.get("status") if isinstance(verification, dict) else "",
        "verification_summary": verification.get("summary") if isinstance(verification, dict) else {},
        "notes": [
            "Draft approval evidence is private runtime material.",
            "A draft or unapproved record must not be treated as legal or commercial approval.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare private Draftpaper-loop commercial approval evidence.")
    parser.add_argument("--output", required=True, help="Private commercial approval JSON output path.")
    parser.add_argument("--license-file", default="", help="Approved commercial license grant JSON. Defaults to DRAFTPAPER_LICENSE_FILE.")
    parser.add_argument("--root", default=str(REPO_ROOT), help="Repository/release root used for boundary document hashes.")
    parser.add_argument("--status", choices=["draft", "approved"], default="draft", help="Write a draft template or approved evidence.")
    parser.add_argument("--approval-authority", default="", help="External approval system, legal authority, or customer approver source.")
    parser.add_argument("--approval-reference", default="", help="Contract, approval ticket, quote, or approval record reference.")
    parser.add_argument("--approved-by", default="", help="Approver identity required when --status approved.")
    parser.add_argument("--approved-at", default="", help="Approval timestamp. Defaults to now only for --status approved.")
    parser.add_argument("--evidence-ref", action="append", default=[], help="External approval reference. Repeat for multiple refs.")
    parser.add_argument("--scope", action="append", default=[], help="Approved commercial scope. Defaults to paid_local_handoff.")
    parser.add_argument("--no-verify", action="store_true", help="Skip running verify_commercial_approval.py after writing the file.")
    args = parser.parse_args(argv)
    report = prepare_commercial_approval(
        output=Path(args.output),
        license_file=Path(args.license_file) if args.license_file else None,
        root=Path(args.root),
        status=args.status,
        approval_authority=args.approval_authority,
        approval_reference=args.approval_reference,
        approved_by=args.approved_by,
        approved_at=args.approved_at,
        evidence_refs=list(args.evidence_ref or []),
        scope=list(args.scope or []) or None,
        verify=not args.no_verify,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
