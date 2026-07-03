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
SCHEMA_VERSION = "draftpaper.claim-confirmation-preparation/v1"
CONFIRMATION_SCHEMA = "draftpaper.claim-confirmation/v1"
DEFAULT_ARTIFACTS = [
    "project.json",
    "result_validity/result_validity_report.json",
    "core_evidence/core_evidence_report.json",
    "results/result_manifest.yaml",
    "results/results.tex",
    "results/results_summary_zh.md",
    "quality_checks/stage_manifest.json",
    "review/claim-confirmation-note.txt",
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


def _safe_relative(path: Path, root: Path) -> str:
    resolved = path.resolve()
    root = root.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"artifact escapes project root: {path}")
    return resolved.relative_to(root).as_posix()


def _load_verifier_module() -> Any:
    verifier_path = REPO_ROOT / "scripts" / "verify_claim_confirmation.py"
    spec = importlib.util.spec_from_file_location("draftpaper_verify_claim_confirmation", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/verify_claim_confirmation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _artifact_records(project: Path, requested: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    artifacts: list[dict[str, Any]] = []
    missing: list[str] = []
    seen: set[str] = set()
    for relative in requested:
        clean = str(relative).strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        path = (project / clean).resolve()
        if project.resolve() not in path.parents and path != project.resolve():
            raise ValueError(f"artifact escapes project root: {clean}")
        if not path.exists() or not path.is_file():
            missing.append(clean)
            continue
        artifacts.append(
            {
                "path": _safe_relative(path, project),
                "sha256": _sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    return artifacts, missing


def _claim_records(claims: list[str], *, status: str, reviewer: str, evidence_refs: list[str]) -> list[dict[str, Any]]:
    claim_status = "confirmed" if status == "confirmed" else "needs_review"
    return [
        {
            "id": f"C{index}",
            "claim": claim.strip(),
            "status": claim_status,
            "reviewer": reviewer if status == "confirmed" else "",
            "evidence_refs": evidence_refs,
        }
        for index, claim in enumerate(claims, start=1)
        if claim.strip()
    ]


def prepare_claim_confirmation(
    *,
    project: Path,
    output: Path,
    claims: list[str] | None = None,
    artifacts: list[str] | None = None,
    status: str = "draft",
    confirmed_by: str = "",
    confirmation_reference: str = "",
    confirmed_at: str = "",
    verify: bool = True,
) -> dict[str, Any]:
    project = project.expanduser().resolve()
    if not project.exists() or not project.is_dir():
        raise FileNotFoundError(f"project directory not found: {project}")
    project_json = project / "project.json"
    if not project_json.exists():
        raise FileNotFoundError(f"project.json not found: {project_json}")

    status = str(status or "draft").strip().lower()
    if status not in {"draft", "confirmed"}:
        raise ValueError("status must be draft or confirmed")
    claims = claims or []
    if status == "confirmed" and (not claims or not confirmed_by.strip()):
        raise ValueError("--status confirmed requires at least one --claim and --confirmed-by")

    project_payload = _read_json(project_json)
    project_slug = str(project_payload.get("project_slug") or project.name)
    project_id = str(project_payload.get("project_id") or project_slug)
    requested_artifacts = list(DEFAULT_ARTIFACTS)
    if artifacts:
        requested_artifacts.extend(artifacts)
    artifact_records, missing_artifacts = _artifact_records(project, requested_artifacts)
    evidence_refs = [item["path"] for item in artifact_records]
    now = _utc_timestamp()

    confirmation = {
        "schema_version": CONFIRMATION_SCHEMA,
        "status": status,
        "project_id": project_id,
        "project_slug": project_slug,
        "project_path": str(project),
        "confirmation_reference": confirmation_reference.strip() or (f"DRAFT-{project_slug}-{now[:10]}" if status == "draft" else ""),
        "confirmed_by": confirmed_by.strip(),
        "confirmed_at": confirmed_at.strip() or (now if status == "confirmed" else ""),
        "prepared_at": now,
        "prepared_by": "prepare_claim_confirmation.py",
        "scope": ["result_claims", "domain_data", "figures", "project_artifacts"],
        "claims": _claim_records(claims, status=status, reviewer=confirmed_by.strip(), evidence_refs=evidence_refs),
        "artifacts": artifact_records,
        "missing_artifacts": missing_artifacts,
        "review_instructions": [
            "Review each manuscript claim against domain data, result validity, core evidence, figures, and reviewer notes.",
            "Set status to confirmed only after domain/user review is complete.",
            "Do not add tokens, passwords, cookies, private keys, or other secrets to this file.",
        ],
    }

    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(confirmation, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.chmod(0o600)

    verification: dict[str, Any] | None = None
    if verify:
        module = _load_verifier_module()
        verification = module.verify_claim_confirmation(confirmation_file=output, project=project)

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "prepared",
        "generated_at": now,
        "project": str(project),
        "output": str(output),
        "confirmation_status": status,
        "claims_count": len(confirmation["claims"]),
        "artifacts_count": len(artifact_records),
        "missing_artifacts": missing_artifacts,
        "verification_status": verification.get("status") if isinstance(verification, dict) else "",
        "verification_summary": verification.get("summary") if isinstance(verification, dict) else {},
        "notes": [
            "Draft claim confirmation evidence is private runtime material.",
            "A draft or unreviewed record must not be treated as scientific confirmation.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare private Draftpaper-loop manuscript claim confirmation evidence.")
    parser.add_argument("--project", required=True, help="Draftpaper-loop project directory.")
    parser.add_argument("--output", required=True, help="Private claim-confirmation JSON output path.")
    parser.add_argument("--claim", action="append", default=[], help="Claim text to include. Repeat for multiple claims.")
    parser.add_argument("--artifact", action="append", default=[], help="Additional project-relative artifact path to hash.")
    parser.add_argument("--status", choices=["draft", "confirmed"], default="draft", help="Write a draft template or confirmed evidence.")
    parser.add_argument("--confirmed-by", default="", help="Reviewer/user name required when --status confirmed.")
    parser.add_argument("--confirmation-reference", default="", help="External or customer review reference.")
    parser.add_argument("--confirmed-at", default="", help="Confirmation timestamp. Defaults to now only for --status confirmed.")
    parser.add_argument("--no-verify", action="store_true", help="Skip running verify_claim_confirmation.py after writing the file.")
    args = parser.parse_args(argv)
    report = prepare_claim_confirmation(
        project=Path(args.project),
        output=Path(args.output),
        claims=list(args.claim or []),
        artifacts=list(args.artifact or []),
        status=args.status,
        confirmed_by=args.confirmed_by,
        confirmation_reference=args.confirmation_reference,
        confirmed_at=args.confirmed_at,
        verify=not args.no_verify,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
