#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "draftpaper.security-review-preparation/v1"
REVIEW_SCHEMA = "draftpaper.security-review/v1"
ALLOWED_REVIEW_TYPES = {
    "third_party_security_review",
    "penetration_test",
    "vendor_security_assessment",
    "compliance_security_review",
    "soc2_security_review",
}
FINDING_FIELDS = [
    "critical_open",
    "high_open",
    "medium_open",
    "low_open",
    "informational_open",
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


def _load_verifier_module() -> Any:
    verifier_path = REPO_ROOT / "scripts" / "verify_security_review.py"
    spec = importlib.util.spec_from_file_location("draftpaper_verify_security_review", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/verify_security_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _finding_summary(value: dict[str, Any]) -> dict[str, int]:
    summary = value.get("findings_summary") if isinstance(value.get("findings_summary"), dict) else {}
    result: dict[str, int] = {}
    for field in FINDING_FIELDS:
        try:
            result[field] = int(summary.get(field) or 0)
        except (TypeError, ValueError):
            result[field] = 0
    return result


def _artifact_records(paths: list[str], *, base_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in paths:
        text = str(raw or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        path = Path(text).expanduser()
        if not path.is_absolute():
            path = base_dir / path
        path = path.resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"review artifact not found: {path}")
        records.append({"path": str(path), "sha256": _sha256_file(path), "bytes": path.stat().st_size})
    return records


def prepare_security_review(
    *,
    output: Path,
    security_audit_file: Path,
    status: str = "draft",
    review_type: str = "third_party_security_review",
    review_authority: str = "",
    review_reference: str = "",
    reviewed_by: str = "",
    reviewed_at: str = "",
    target: str = "draftpaper-loop-local-handoff",
    scope: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    risk_acceptance_refs: list[str] | None = None,
    artifact_paths: list[str] | None = None,
    verify: bool = True,
) -> dict[str, Any]:
    security_audit_file = security_audit_file.expanduser().resolve()
    if not security_audit_file.exists() or not security_audit_file.is_file():
        raise FileNotFoundError(f"security audit file not found: {security_audit_file}")
    security_audit = _read_json(security_audit_file)
    if not security_audit:
        raise ValueError(f"security audit file is not a JSON object: {security_audit_file}")

    status = str(status or "draft").strip().lower()
    if status not in {"draft", "verified"}:
        raise ValueError("status must be draft or verified")
    review_type = str(review_type or "").strip()
    if review_type not in ALLOWED_REVIEW_TYPES:
        raise ValueError(f"review_type must be one of: {', '.join(sorted(ALLOWED_REVIEW_TYPES))}")
    refs = [str(item).strip() for item in (evidence_refs or []) if str(item).strip()]
    if status == "verified":
        missing = [
            name
            for name, value in {
                "review_authority": review_authority,
                "review_reference": review_reference,
                "reviewed_by": reviewed_by,
                "target": target,
            }.items()
            if not str(value or "").strip()
        ]
        if missing or not refs:
            raise ValueError("--status verified requires review authority, reference, reviewed-by, target, and at least one --evidence-ref")

    now = _utc_timestamp()
    findings = _finding_summary(security_audit)
    review = {
        "schema_version": REVIEW_SCHEMA,
        "status": status,
        "review_type": review_type,
        "review_authority": review_authority.strip(),
        "review_reference": review_reference.strip() or (f"DRAFT-SECURITY-REVIEW-{now[:10]}" if status == "draft" else ""),
        "reviewed_by": reviewed_by.strip(),
        "reviewed_at": reviewed_at.strip() or (now if status == "verified" else ""),
        "prepared_at": now,
        "prepared_by": "prepare_security_review.py",
        "target": target.strip(),
        "scope": scope or ["operator_console", "release_package", "deployment", "license_boundary", "support_bundle"],
        "evidence_refs": refs,
        "risk_acceptance_refs": [str(item).strip() for item in (risk_acceptance_refs or []) if str(item).strip()],
        "findings_summary": findings,
        "security_audit_sha256": _sha256_file(security_audit_file),
        "artifacts": _artifact_records(artifact_paths or [], base_dir=security_audit_file.parent),
        "review_instructions": [
            "Review the saved security audit, release package boundary, deployment hardening, support bundle redaction, and private runtime file controls.",
            "Set status to verified only after the external review, penetration test, vendor assessment, or compliance review is complete.",
            "Do not add tokens, passwords, cookies, private keys, raw security reports, or other secrets to this file.",
        ],
    }

    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(review, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.chmod(0o600)

    verification: dict[str, Any] | None = None
    if verify:
        module = _load_verifier_module()
        verification = module.verify_security_review(review_file=output, security_audit_file=security_audit_file)

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "prepared",
        "generated_at": now,
        "output": str(output),
        "review_status": status,
        "review_type": review_type,
        "security_audit_file": str(security_audit_file),
        "security_audit_status": security_audit.get("status"),
        "security_audit_summary": security_audit.get("summary") if isinstance(security_audit.get("summary"), dict) else {},
        "findings_summary": findings,
        "artifacts_count": len(review["artifacts"]),
        "evidence_refs_count": len(refs),
        "verification_status": verification.get("status") if isinstance(verification, dict) else "",
        "verification_summary": verification.get("summary") if isinstance(verification, dict) else {},
        "notes": [
            "Draft security review evidence is private runtime material.",
            "A draft or unverified record must not be treated as a formal third-party security review.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare private Draftpaper-loop formal security review evidence.")
    parser.add_argument("--output", required=True, help="Private security review JSON output path.")
    parser.add_argument("--security-audit-file", required=True, help="Saved /api/security-audit JSON report.")
    parser.add_argument("--status", choices=["draft", "verified"], default="draft", help="Write a draft template or verified review evidence.")
    parser.add_argument("--review-type", choices=sorted(ALLOWED_REVIEW_TYPES), default="third_party_security_review")
    parser.add_argument("--review-authority", default="", help="External reviewer, auditor, or assessment authority.")
    parser.add_argument("--review-reference", default="", help="External review report, ticket, or attestation reference.")
    parser.add_argument("--reviewed-by", default="", help="Reviewer identity required when --status verified.")
    parser.add_argument("--reviewed-at", default="", help="Review timestamp. Defaults to now only for --status verified.")
    parser.add_argument("--target", default="draftpaper-loop-local-handoff", help="Reviewed target or release.")
    parser.add_argument("--scope", action="append", default=[], help="Reviewed scope entry. Repeat for multiple scopes.")
    parser.add_argument("--evidence-ref", action="append", default=[], help="External review evidence reference. Repeat for multiple refs.")
    parser.add_argument("--risk-acceptance-ref", action="append", default=[], help="Residual risk acceptance reference for open medium findings.")
    parser.add_argument("--artifact", action="append", default=[], help="Optional review artifact path to hash.")
    parser.add_argument("--no-verify", action="store_true", help="Skip running verify_security_review.py after writing the file.")
    args = parser.parse_args(argv)
    report = prepare_security_review(
        output=Path(args.output),
        security_audit_file=Path(args.security_audit_file),
        status=args.status,
        review_type=args.review_type,
        review_authority=args.review_authority,
        review_reference=args.review_reference,
        reviewed_by=args.reviewed_by,
        reviewed_at=args.reviewed_at,
        target=args.target,
        scope=list(args.scope or []) or None,
        evidence_refs=list(args.evidence_ref or []),
        risk_acceptance_refs=list(args.risk_acceptance_ref or []),
        artifact_paths=list(args.artifact or []),
        verify=not args.no_verify,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
