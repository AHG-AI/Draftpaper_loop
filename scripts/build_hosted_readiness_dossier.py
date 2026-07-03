#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import zipfile
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from serviceconsole_app import HOSTED_READINESS_REQUIREMENTS, HOSTED_READINESS_SCHEMA  # noqa: E402
from validate_hosted_readiness import validate_hosted_readiness  # noqa: E402


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


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered not in SENSITIVE_KEY_EXCEPTIONS and any(part in lowered for part in SENSITIVE_KEY_PARTS):
                return True
            if _contains_sensitive_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _safe_member_fragment(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip(".-")
    return cleaned or "artifact"


def _forbidden_artifact_path(path: Path) -> bool:
    basename = path.name.lower()
    if basename.startswith(".env") or basename in FORBIDDEN_FILENAMES:
        return True
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        return True
    if any(part in basename for part in ("password", "token", "private-key", "client-secret")):
        return True
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


def _section_summary(requirement: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    section = payload.get(str(requirement["evidence_key"]))
    section = section if isinstance(section, dict) else {}
    summary: dict[str, Any] = {"status": str(section.get("status") or "")}
    for field in requirement.get("required_fields", []):
        summary[str(field)] = str(section.get(str(field)) or "")
    for field in requirement.get("required_true", []):
        summary[str(field)] = bool(section.get(str(field)))
    summarized_entries: list[dict[str, Any]] = []
    for entry in _evidence_entries(section):
        if isinstance(entry, dict):
            summarized_entries.append(
                {
                    "path": str(entry.get("path") or entry.get("file") or ""),
                    "sha256": str(entry.get("sha256") or entry.get("sha256sum") or ""),
                    "description": str(entry.get("description") or entry.get("label") or ""),
                }
            )
        else:
            summarized_entries.append({"ref": str(entry)})
    summary["evidence"] = summarized_entries
    return summary


def _copy_evidence_artifacts(
    *,
    payload: dict[str, Any],
    evidence_base_dir: Path,
    output_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    copied: list[dict[str, Any]] = []
    target_root = output_dir / "evidence-artifacts"
    target_root.mkdir(parents=True, exist_ok=True)
    target_root.chmod(0o700)

    for requirement in HOSTED_READINESS_REQUIREMENTS:
        key = str(requirement["evidence_key"])
        section = payload.get(key)
        section = section if isinstance(section, dict) else {}
        section_dir = target_root / key
        section_dir.mkdir(parents=True, exist_ok=True)
        section_dir.chmod(0o700)
        for index, entry in enumerate(_evidence_entries(section), start=1):
            if not isinstance(entry, dict):
                continue
            raw_path = str(entry.get("path") or entry.get("file") or "").strip()
            expected_sha = str(entry.get("sha256") or entry.get("sha256sum") or "").strip().lower()
            description = str(entry.get("description") or entry.get("label") or "")
            if not raw_path:
                checks.append(_check(f"{key}_artifact_{index}_path", False, "error", "missing path"))
                continue
            source = Path(raw_path).expanduser()
            if not source.is_absolute():
                source = evidence_base_dir / source
            source = source.resolve()
            checks.append(_check(f"{key}_artifact_{index}_exists", source.exists() and source.is_file(), "error", raw_path, "Provide every referenced hosted evidence artifact."))
            if not source.exists() or not source.is_file():
                continue
            checks.append(_check(f"{key}_artifact_{index}_filename_safe", not _forbidden_artifact_path(source), "error", source.name, "Do not embed private keys, tokens, env files, signatures, or archives in a hosted evidence dossier."))
            actual_sha = sha256_file(source)
            checks.append(_check(f"{key}_artifact_{index}_sha256", bool(expected_sha) and actual_sha == expected_sha, "error", raw_path, "Update the evidence entry sha256 to match the referenced artifact."))
            if _forbidden_artifact_path(source) or actual_sha != expected_sha:
                continue
            filename = f"{index:02d}-{_safe_member_fragment(source.name)}"
            target = section_dir / filename
            target.write_bytes(source.read_bytes())
            target.chmod(0o600)
            copied.append(
                {
                    "section": key,
                    "source_ref": raw_path,
                    "description": description,
                    "member": f"evidence-artifacts/{key}/{filename}",
                    "filename": filename,
                    "bytes": target.stat().st_size,
                    "sha256": sha256_file(target),
                }
            )
    return copied, checks


def _dossier_digest(dossier: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in dossier.items() if key != "dossier_sha256"}
    return _sha256_bytes(json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def build_hosted_readiness_dossier(
    *,
    evidence_file: Path,
    output_dir: Path,
    output_zip: Path | None = None,
    customer_id: str = "",
    customer_name: str = "",
) -> dict[str, Any]:
    evidence_file = evidence_file.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o700)

    validation_report = validate_hosted_readiness(evidence_file)
    payload = _read_json(evidence_file)
    sections = {str(requirement["evidence_key"]): _section_summary(requirement, payload) for requirement in HOSTED_READINESS_REQUIREMENTS}
    copied_artifacts, artifact_checks = _copy_evidence_artifacts(payload=payload, evidence_base_dir=evidence_file.parent, output_dir=output_dir)
    gate_errors = [
        item.get("id")
        for item in validation_report.get("gates", [])
        if isinstance(item, dict) and item.get("severity") == "error" and not item.get("passed")
    ]
    checks = [
        _check("hosted_readiness_ready", validation_report.get("status") == "ready", "error", str(validation_report.get("status") or ""), "Resolve every hosted readiness gate before building a ready dossier."),
        _check("hosted_schema", payload.get("schema_version") == HOSTED_READINESS_SCHEMA, "error", str(payload.get("schema_version") or "")),
        _check("hosted_gates_verified", not gate_errors, "error", ", ".join(str(item) for item in gate_errors) if gate_errors else "ok"),
        _check("raw_hosted_evidence_file_excluded", True, "error", "raw hosted readiness JSON is summarized, not embedded"),
        *artifact_checks,
    ]

    summary = {
        "schema_version": payload.get("schema_version"),
        "environment": payload.get("environment"),
        "generated_at": payload.get("generated_at"),
        "source_evidence_file": {
            "filename": evidence_file.name,
            "bytes": evidence_file.stat().st_size if evidence_file.exists() else 0,
            "sha256": sha256_file(evidence_file) if evidence_file.exists() else "",
        },
        "sections": sections,
        "validation": {
            "status": validation_report.get("status"),
            "summary": validation_report.get("summary"),
        },
    }
    checks.append(_check("sensitive_keys_excluded", not _contains_sensitive_key(summary), "error", "hosted dossier summary excludes sensitive key names."))
    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    dossier = {
        "schema_version": "draftpaper.hosted-readiness-dossier/v1",
        "status": "ready" if not errors else "attention",
        "generated_at": _utc_timestamp(),
        "customer": {
            "id": customer_id,
            "name": customer_name,
        },
        "hosted_readiness": summary,
        "validation_report": validation_report,
        "copied_evidence_artifacts": copied_artifacts,
        "checks": checks,
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
            "copied_evidence_artifacts": len(copied_artifacts),
        },
        "notes": [
            "This dossier summarizes hosted SaaS readiness evidence and embeds only explicitly referenced evidence artifacts with matching SHA256 values.",
            "It intentionally excludes the raw hosted readiness JSON, private keys, env files, tokens, signatures, archives, customer project data, and runtime state.",
        ],
    }
    dossier["dossier_sha256"] = _dossier_digest(dossier)

    dossier_path = output_dir / "hosted-readiness-dossier.json"
    summary_path = output_dir / "hosted-readiness-summary.json"
    report_path = output_dir / "hosted-readiness-validation-report.json"
    _write_private_json(dossier_path, dossier)
    _write_private_json(summary_path, summary)
    _write_private_json(report_path, validation_report)

    zip_path = output_zip.expanduser().resolve() if output_zip is not None else output_dir / "hosted-readiness-dossier.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(dossier_path, "hosted-readiness-dossier.json")
        archive.write(summary_path, "hosted-readiness-summary.json")
        archive.write(report_path, "hosted-readiness-validation-report.json")
        for item in copied_artifacts:
            source = output_dir / str(item["member"])
            archive.write(source, str(item["member"]))
    zip_path.chmod(0o600)

    result = {
        "status": dossier["status"],
        "generated_at": dossier["generated_at"],
        "dossier_path": str(dossier_path),
        "summary_path": str(summary_path),
        "validation_report_path": str(report_path),
        "zip_path": str(zip_path),
        "zip_sha256": sha256_file(zip_path),
        "dossier_sha256": dossier["dossier_sha256"],
        "copied_evidence_artifacts": copied_artifacts,
        "summary": dossier["summary"],
    }
    _write_private_json(output_dir / "hosted-readiness-dossier-manifest.json", result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a customer-facing hosted SaaS readiness evidence dossier.")
    parser.add_argument("--evidence-file", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--output-zip", default="")
    parser.add_argument("--customer-id", default="")
    parser.add_argument("--customer-name", default="")
    args = parser.parse_args(argv)
    result = build_hosted_readiness_dossier(
        evidence_file=Path(args.evidence_file),
        output_dir=Path(args.output_dir),
        output_zip=Path(args.output_zip) if args.output_zip else None,
        customer_id=args.customer_id,
        customer_name=args.customer_name,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
