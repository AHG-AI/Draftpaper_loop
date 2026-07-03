#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from serviceconsole_app import HOSTED_READINESS_REQUIREMENTS, HOSTED_READINESS_SCHEMA  # noqa: E402
from validate_hosted_readiness import validate_hosted_readiness  # noqa: E402
from verify_hosted_evidence_collection import verify_hosted_evidence_collection  # noqa: E402


SCHEMA_VERSION = "draftpaper.hosted-readiness-preparation/v1"
CONTROLS_SCHEMA = "draftpaper.hosted-readiness-controls/v1"
SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")
SENSITIVE_KEY_EXCEPTIONS = {"secrets_manager"}
FORBIDDEN_FILENAMES = {
    "active-handoff.env",
    "billing-rates.json",
    "commercial-license-grant.json",
    "console-users.json",
    "hosted-acceptance.json",
    "hosted-readiness.json",
    "license-grant.json",
    "operator-token.txt",
}
FORBIDDEN_SUFFIXES = {".key", ".pem", ".sig", ".zip"}


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _write_private_json(path: Path, payload: dict[str, Any], *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _payload_digest(payload: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "preparation_sha256"}
    raw = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _safe_member_fragment(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip(".-")
    return cleaned or "artifact"


def _forbidden_artifact_path(path: Path) -> bool:
    basename = path.name.lower()
    if basename.startswith(".env") or basename in FORBIDDEN_FILENAMES:
        return True
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        return True
    return any(part in basename for part in ("password", "token", "private-key", "client-secret"))


def _contains_sensitive_key(value: Any, *, path: str = "") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            child = f"{path}.{key_text}" if path else key_text
            if lowered not in SENSITIVE_KEY_EXCEPTIONS and any(part in lowered for part in SENSITIVE_KEY_PARTS):
                findings.append(child)
                continue
            findings.extend(_contains_sensitive_key(item, path=child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_contains_sensitive_key(item, path=f"{path}[{index}]"))
    return findings


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "verified", "passed", "complete"}
    return False


def _evidence_entries(section: dict[str, Any]) -> list[Any]:
    entries: list[Any] = []
    for key in ("evidence", "evidence_refs", "artifacts", "links"):
        raw = section.get(key)
        if isinstance(raw, list):
            entries.extend(item for item in raw if item)
        elif isinstance(raw, str) and raw.strip():
            entries.append(raw.strip())
    return entries


def _resolve_collection_output_dir(collection_report_path: Path, collection_report: dict[str, Any]) -> Path:
    raw = str(collection_report.get("output_dir") or "").strip()
    candidate = Path(raw).expanduser() if raw else collection_report_path.parent
    if not candidate.is_absolute():
        candidate = collection_report_path.parent / candidate
    return candidate.resolve()


def _resolve_collection_draft_path(collection_report_path: Path, collection_report: dict[str, Any], output_dir: Path) -> Path:
    draft_record = collection_report.get("hosted_readiness_draft") if isinstance(collection_report.get("hosted_readiness_draft"), dict) else {}
    raw = str(draft_record.get("path") or "").strip()
    candidate = Path(raw).expanduser() if raw else output_dir / "hosted-readiness.draft.json"
    if not candidate.is_absolute():
        candidate = output_dir / candidate
    if not candidate.exists():
        candidate = collection_report_path.parent / "hosted-readiness.draft.json"
    return candidate.resolve()


def _copy_evidence_entry(
    *,
    entry: Any,
    source_base_dir: Path,
    output_dir: Path,
    section_key: str,
    role: str,
    index: int,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    if not isinstance(entry, dict):
        checks.append(_check(f"{section_key}_{role}_{index}_artifact_shape", False, "error", "not an object", "Use evidence objects with path, sha256, and description."))
        return None, checks
    raw_path = str(entry.get("path") or entry.get("file") or "").strip()
    expected_sha = str(entry.get("sha256") or entry.get("sha256sum") or "").strip().lower()
    description = str(entry.get("description") or entry.get("label") or f"{section_key} {role} evidence")
    checks.append(_check(f"{section_key}_{role}_{index}_path_present", bool(raw_path), "error", raw_path or "missing"))
    if not raw_path:
        return None, checks
    source = Path(raw_path).expanduser()
    if not source.is_absolute():
        source = source_base_dir / source
    source = source.resolve()
    checks.append(_check(f"{section_key}_{role}_{index}_exists", source.exists() and source.is_file(), "error", str(source), "Provide every referenced hosted evidence artifact."))
    if not source.exists() or not source.is_file():
        return None, checks
    forbidden = _forbidden_artifact_path(source)
    checks.append(_check(f"{section_key}_{role}_{index}_filename_safe", not forbidden, "error", source.name, "Do not use private keys, tokens, env files, signatures, archives, or raw readiness files as evidence artifacts."))
    actual_sha = _sha256_file(source)
    checks.append(_check(f"{section_key}_{role}_{index}_sha256_matches", bool(expected_sha) and actual_sha == expected_sha, "error", actual_sha, "Set sha256 to the exact digest of the evidence artifact."))
    if forbidden or not expected_sha or actual_sha != expected_sha:
        return None, checks

    target_dir = output_dir / "hosted-readiness-artifacts" / role / section_key
    target_dir.mkdir(parents=True, exist_ok=True)
    target_dir.chmod(0o700)
    target = target_dir / f"{index:02d}-{_safe_member_fragment(source.name)}"
    if source != target.resolve():
        shutil.copyfile(source, target)
    target.chmod(0o600)
    copied_sha = _sha256_file(target)
    relative_path = target.relative_to(output_dir).as_posix()
    checks.append(_check(f"{section_key}_{role}_{index}_copied", copied_sha == actual_sha, "error", relative_path))
    return {"path": relative_path, "sha256": copied_sha, "description": description, "source": role}, checks


def _controls_sections(controls: dict[str, Any]) -> dict[str, Any]:
    raw = controls.get("sections") if isinstance(controls.get("sections"), dict) else controls
    return raw if isinstance(raw, dict) else {}


def write_controls_template(
    *,
    collection_report: Path,
    output_file: Path,
    force: bool = False,
) -> dict[str, Any]:
    collection_report = collection_report.expanduser().resolve()
    report_payload = _read_json(collection_report)
    output_dir = _resolve_collection_output_dir(collection_report, report_payload)
    draft_path = _resolve_collection_draft_path(collection_report, report_payload, output_dir)
    draft = _read_json(draft_path)
    template: dict[str, Any] = {
        "schema_version": CONTROLS_SCHEMA,
        "generated_at": _utc_timestamp(),
        "collection_report": collection_report.name,
        "attestation": {
            "approved_by": "",
            "approval_reference": "",
            "notes": "Fill after external identity, billing, storage/DR, worker, and deployment controls are verified.",
        },
        "sections": {},
    }
    sections = template["sections"]
    for requirement in HOSTED_READINESS_REQUIREMENTS:
        key = str(requirement["evidence_key"])
        draft_section = draft.get(key) if isinstance(draft.get(key), dict) else {}
        section: dict[str, Any] = {"status": "verified"}
        for field in requirement.get("required_fields", []):
            section[str(field)] = ""
        for field in requirement.get("required_true", []):
            section[str(field)] = True
        section["evidence"] = [{"path": "", "sha256": "", "description": f"{key} operator verification evidence"}]
        section["collected_probe_count"] = len(_evidence_entries(draft_section))
        sections[key] = section
    output_file = output_file.expanduser()
    _write_private_json(output_file, template, force=force)
    return {"status": "template_written", "schema_version": CONTROLS_SCHEMA, "path": str(output_file.resolve())}


def prepare_hosted_readiness(
    *,
    collection_report: Path,
    controls_file: Path,
    output_file: Path,
    report_output: Path | None = None,
    force: bool = False,
    write_attention_candidate: bool = False,
) -> dict[str, Any]:
    generated_at = _utc_timestamp()
    collection_report = collection_report.expanduser().resolve()
    controls_file = controls_file.expanduser().resolve()
    output_file = output_file.expanduser().resolve()
    output_dir = output_file.parent
    checks: list[dict[str, Any]] = []

    if output_file.exists() and not force:
        raise FileExistsError(f"{output_file} already exists; pass --force to overwrite")

    collection_verification = verify_hosted_evidence_collection(collection_report)
    checks.append(_check("collection_verified", collection_verification.get("status") == "verified", "error", str(collection_verification.get("status") or ""), "Run scripts/verify_hosted_evidence_collection.py and fix every finding first."))
    collection_payload = _read_json(collection_report)
    collection_output_dir = _resolve_collection_output_dir(collection_report, collection_payload)
    draft_path = _resolve_collection_draft_path(collection_report, collection_payload, collection_output_dir)
    checks.append(_check("collection_draft_exists", draft_path.exists() and draft_path.is_file(), "error", str(draft_path)))
    draft = _read_json(draft_path) if draft_path.exists() and draft_path.is_file() else {}
    checks.append(_check("collection_draft_schema", draft.get("schema_version") == HOSTED_READINESS_SCHEMA, "error", str(draft.get("schema_version") or "")))

    controls = _read_json(controls_file)
    controls_sensitive = _contains_sensitive_key(controls)
    checks.append(_check("controls_schema", controls.get("schema_version") in {"", None, CONTROLS_SCHEMA}, "error", str(controls.get("schema_version") or "")))
    checks.append(_check("controls_no_sensitive_keys", not controls_sensitive, "error", ", ".join(controls_sensitive[:20]) if controls_sensitive else "ok", "Do not store tokens, cookies, passwords, secrets, or API keys in hosted readiness controls."))
    attestation = controls.get("attestation") if isinstance(controls.get("attestation"), dict) else {}
    checks.append(_check("attestation_approved_by", bool(str(attestation.get("approved_by") or "").strip()), "error", "approved_by", "Record the responsible approver for hosted readiness controls."))
    checks.append(_check("attestation_approval_reference", bool(str(attestation.get("approval_reference") or "").strip()), "error", "approval_reference", "Record a ticket, review, change, or signed approval reference."))

    controls_sections = _controls_sections(controls)
    prepared: dict[str, Any] = {
        "schema_version": HOSTED_READINESS_SCHEMA,
        "environment": str(controls.get("environment") or draft.get("environment") or collection_payload.get("environment") or "production"),
        "generated_at": generated_at,
        "prepared_from": {
            "collection_report": collection_report.name,
            "collection_sha256": str(collection_payload.get("collection_sha256") or ""),
            "collection_verification_status": str(collection_verification.get("status") or ""),
            "draft_file": draft_path.name,
            "controls_file": controls_file.name,
        },
        "attestation": {
            "approved_by": str(attestation.get("approved_by") or ""),
            "approval_reference": str(attestation.get("approval_reference") or ""),
            "prepared_by": str(attestation.get("prepared_by") or ""),
            "notes": str(attestation.get("notes") or ""),
        },
    }
    copied_records: list[dict[str, Any]] = []
    for requirement in HOSTED_READINESS_REQUIREMENTS:
        key = str(requirement["evidence_key"])
        draft_section = draft.get(key) if isinstance(draft.get(key), dict) else {}
        control_section = controls_sections.get(key) if isinstance(controls_sections.get(key), dict) else {}
        checks.append(_check(f"{key}_controls_present", bool(control_section), "error", key, "Provide an operator controls section for every hosted readiness requirement."))
        final_section: dict[str, Any] = {"status": str(control_section.get("status") or "").strip().lower()}
        checks.append(_check(f"{key}_status_verified", final_section["status"] == "verified", "error", final_section["status"] or "missing"))
        for field in requirement.get("required_fields", []):
            value = str(control_section.get(str(field)) or "").strip()
            final_section[str(field)] = value
            checks.append(_check(f"{key}_{field}_present", bool(value), "error", field))
        for field in requirement.get("required_true", []):
            value = control_section.get(str(field))
            final_section[str(field)] = _truthy(value)
            checks.append(_check(f"{key}_{field}_verified", _truthy(value), "error", field))

        evidence: list[dict[str, Any]] = []
        collected_entries = _evidence_entries(draft_section)
        for index, entry in enumerate(collected_entries, start=1):
            copied, entry_checks = _copy_evidence_entry(
                entry=entry,
                source_base_dir=collection_output_dir,
                output_dir=output_dir,
                section_key=key,
                role="collected",
                index=index,
            )
            checks.extend(entry_checks)
            if copied is not None:
                evidence.append(copied)
                copied_records.append({"section": key, **copied})

        operator_entries = _evidence_entries(control_section)
        operator_copied = 0
        for index, entry in enumerate(operator_entries, start=1):
            copied, entry_checks = _copy_evidence_entry(
                entry=entry,
                source_base_dir=controls_file.parent,
                output_dir=output_dir,
                section_key=key,
                role="operator",
                index=index,
            )
            checks.extend(entry_checks)
            if copied is not None:
                evidence.append(copied)
                copied_records.append({"section": key, **copied})
                operator_copied += 1
        checks.append(_check(f"{key}_operator_evidence_verified", operator_copied > 0, "error", f"count={operator_copied}", "Attach at least one operator-reviewed external control evidence artifact with a matching SHA256."))
        final_section["evidence"] = evidence
        prepared[key] = final_section

    prewrite_errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    validation_report: dict[str, Any] = {}
    wrote_output = False
    if not prewrite_errors or write_attention_candidate:
        _write_private_json(output_file, prepared, force=force)
        wrote_output = True
        validation_report = validate_hosted_readiness(output_file)
        checks.append(_check("prepared_hosted_readiness_ready", validation_report.get("status") == "ready", "error", str(validation_report.get("status") or ""), "Fix hosted readiness evidence until validate_hosted_readiness.py reports ready."))
    else:
        checks.append(_check("prepared_hosted_readiness_written", False, "error", "skipped because controls are incomplete", "Fix failed checks, then rerun to write hosted-readiness.json."))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "ready" if not errors and wrote_output and validation_report.get("status") == "ready" else "attention",
        "generated_at": generated_at,
        "collection_report": str(collection_report),
        "controls_file": str(controls_file),
        "output_file": str(output_file) if wrote_output else "",
        "validation": {
            "status": str(validation_report.get("status") or ""),
            "summary": validation_report.get("summary") if isinstance(validation_report.get("summary"), dict) else {},
        },
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
            "copied_evidence_artifacts": len(copied_records),
            "operator_evidence_artifacts": sum(1 for item in copied_records if item.get("source") == "operator"),
        },
        "checks": checks,
        "copied_evidence_artifacts": copied_records,
        "notes": [
            "This helper fails closed: it writes hosted-readiness.json only after collection verification, operator attestation, required controls, and evidence hashes pass.",
            "It does not verify that external providers are contractually approved; keep legal and security review records with the private customer evidence folder.",
        ],
    }
    result["preparation_sha256"] = _payload_digest(result)
    if report_output is not None:
        _write_private_json(report_output.expanduser(), result, force=force)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare a verified hosted-readiness.json from collected probes and operator control evidence.")
    parser.add_argument("--collection-report", required=True, help="hosted-readiness-evidence-collection.json path.")
    parser.add_argument("--controls-file", default="", help="Operator hosted readiness controls JSON.")
    parser.add_argument("--output", required=True, help="Output hosted-readiness.json, or controls template path with --write-controls-template.")
    parser.add_argument("--report-output", default="", help="Optional private preparation report path.")
    parser.add_argument("--write-controls-template", action="store_true", help="Write a hosted readiness controls template instead of preparing final evidence.")
    parser.add_argument("--write-attention-candidate", action="store_true", help="Write an attention candidate even when preflight checks fail.")
    parser.add_argument("--require-ready", action="store_true", help="Exit non-zero unless final hosted readiness preparation is ready.")
    parser.add_argument("--force", action="store_true", help="Overwrite output/report files.")
    args = parser.parse_args(argv)

    if args.write_controls_template:
        result = write_controls_template(
            collection_report=Path(args.collection_report),
            output_file=Path(args.output),
            force=args.force,
        )
    else:
        if not args.controls_file:
            parser.error("--controls-file is required unless --write-controls-template is used")
        result = prepare_hosted_readiness(
            collection_report=Path(args.collection_report),
            controls_file=Path(args.controls_file),
            output_file=Path(args.output),
            report_output=Path(args.report_output) if args.report_output else None,
            force=args.force,
            write_attention_candidate=args.write_attention_candidate,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if args.require_ready and result.get("status") != "ready":
        return 1
    return 0 if result.get("status") in {"ready", "template_written"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
