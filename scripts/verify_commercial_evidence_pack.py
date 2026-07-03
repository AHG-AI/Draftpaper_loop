#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


EVIDENCE_PACK_SCHEMA = "draftpaper.commercial-evidence-pack/v1"
VERIFICATION_SCHEMA = "draftpaper.commercial-evidence-pack-verification/v1"
ALLOWED_TARGET_TRACKS = {"local_operator_pilot", "paid_local_handoff", "hosted_saas"}
EXPECTED_EVIDENCE_IDS = {
    "claim_confirmation",
    "commercial_approval",
    "release_trust",
    "security_review",
    "hosted_readiness",
}
PAID_REQUIRED_EVIDENCE_IDS = {
    "claim_confirmation",
    "commercial_approval",
    "release_trust",
    "security_review",
}
SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey", "private_key")
FORBIDDEN_PATH_PARTS = ("operator-token", "license-signing", "private-key")


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def commercial_evidence_pack_digest(pack: dict[str, Any]) -> str:
    excluded = {"pack_sha256", "verification", "verification_status", "verification_summary"}
    payload = {key: value for key, value in pack.items() if key not in excluded}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _owner_only(path: Path) -> bool:
    return path.exists() and (path.stat().st_mode & 0o077) == 0


def _sensitive_key_findings(value: Any, *, path: str = "") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            child = f"{path}.{key_text}" if path else key_text
            if any(part in key_text.lower() for part in SENSITIVE_KEY_PARTS):
                findings.append(child)
                continue
            findings.extend(_sensitive_key_findings(item, path=child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_sensitive_key_findings(item, path=f"{path}[{index}]"))
    return findings


def _forbidden_path_findings(value: Any, *, path: str = "") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            child = f"{path}.{key_text}" if path else key_text
            findings.extend(_forbidden_path_findings(item, path=child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_forbidden_path_findings(item, path=f"{path}[{index}]"))
    elif isinstance(value, str):
        lowered = value.lower()
        if any(part in lowered for part in FORBIDDEN_PATH_PARTS) or lowered.endswith(".key"):
            findings.append(path or value)
    return findings


def _evidence_records(pack: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = pack.get("evidence")
    if not isinstance(evidence, list):
        return []
    return [item for item in evidence if isinstance(item, dict)]


def _expected_blocking_ids(evidence: list[dict[str, Any]]) -> list[str]:
    return [str(item.get("id")) for item in evidence if item.get("required") and not item.get("passed")]


def _evidence_consistency_checks(pack: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    evidence = _evidence_records(pack)
    evidence_ids = [str(item.get("id") or "") for item in evidence]
    target_track = str(pack.get("target_track") or "")
    blocking_ids = [str(item) for item in pack.get("blocking_evidence_ids") or []]
    expected_blocking = _expected_blocking_ids(evidence)
    checks.append(_check("evidence_list_present", bool(evidence), "error", f"count={len(evidence)}"))
    checks.append(_check("expected_evidence_ids_present", EXPECTED_EVIDENCE_IDS.issubset(set(evidence_ids)), "error", ",".join(sorted(set(evidence_ids)))))
    checks.append(_check("evidence_ids_unique", len(evidence_ids) == len(set(evidence_ids)), "error", ",".join(evidence_ids)))
    checks.append(_check("blocking_ids_match_evidence", sorted(blocking_ids) == sorted(expected_blocking), "error", ",".join(blocking_ids)))
    for item in evidence:
        item_id = str(item.get("id") or "unknown")
        required = bool(item.get("required"))
        passed = bool(item.get("passed"))
        blocking = bool(item.get("blocking"))
        required_for = item.get("required_for") if isinstance(item.get("required_for"), list) else []
        checks.append(_check(f"{item_id}_status_present", bool(str(item.get("status") or "").strip()), "error", str(item.get("status") or "")))
        checks.append(_check(f"{item_id}_blocking_consistent", blocking == (required and not passed), "error", f"required={required} passed={passed} blocking={blocking}"))
        checks.append(_check(f"{item_id}_required_for_valid", all(str(track) in ALLOWED_TARGET_TRACKS for track in required_for), "error", ",".join(str(track) for track in required_for)))
    paid_required = [item for item in evidence if str(item.get("id")) in PAID_REQUIRED_EVIDENCE_IDS]
    checks.append(_check(
        "paid_external_evidence_required",
        target_track == "local_operator_pilot" or all(bool(item.get("required")) for item in paid_required),
        "error",
        target_track,
    ))
    hosted_item = next((item for item in evidence if str(item.get("id")) == "hosted_readiness"), None)
    checks.append(_check(
        "hosted_readiness_required_for_hosted_track",
        target_track != "hosted_saas" or bool(hosted_item and hosted_item.get("required")),
        "error",
        target_track,
    ))
    expected_status = "ready" if not expected_blocking else "attention"
    checks.append(_check("pack_status_matches_blocking", pack.get("status") == expected_status, "error", f"expected={expected_status} actual={pack.get('status')}"))
    return checks


def verify_commercial_evidence_pack(
    pack_path: Path,
    *,
    markdown_path: Path | None = None,
    require_ready: bool = True,
) -> dict[str, Any]:
    pack_path = pack_path.expanduser().resolve()
    checks: list[dict[str, Any]] = []
    pack: dict[str, Any] = {}
    markdown = markdown_path.expanduser().resolve() if markdown_path is not None else None
    try:
        pack = _read_json(pack_path)
        checks.append(_check("evidence_pack_exists", pack_path.exists() and pack_path.is_file(), "error", str(pack_path)))
        checks.append(_check("evidence_pack_owner_only", _owner_only(pack_path), "error", oct(pack_path.stat().st_mode & 0o077)))
        checks.append(_check("evidence_pack_schema", pack.get("schema_version") == EVIDENCE_PACK_SCHEMA, "error", str(pack.get("schema_version") or "")))
        target_track = str(pack.get("target_track") or "")
        checks.append(_check("target_track_valid", target_track in ALLOWED_TARGET_TRACKS, "error", target_track))
        status = str(pack.get("status") or "")
        checks.append(_check("evidence_pack_status_ready", (not require_ready and status in {"ready", "attention"}) or status == "ready", "error", status))
        expected_digest = str(pack.get("pack_sha256") or "").lower()
        checks.append(_check("evidence_pack_sha256_matches", bool(expected_digest) and commercial_evidence_pack_digest(pack) == expected_digest, "error", expected_digest))
        checks.extend(_evidence_consistency_checks(pack))
        sensitive = _sensitive_key_findings(pack)
        checks.append(_check("sensitive_keys_excluded", not sensitive, "error", ",".join(sensitive[:20]) if sensitive else "ok"))
        forbidden_paths = _forbidden_path_findings(pack)
        checks.append(_check("forbidden_private_key_paths_excluded", not forbidden_paths, "error", ",".join(forbidden_paths[:20]) if forbidden_paths else "ok"))
        if markdown is None:
            raw_markdown = str(pack.get("markdown_path") or "").strip()
            markdown = Path(raw_markdown).expanduser().resolve() if raw_markdown else None
        checks.append(_check("markdown_path_recorded", markdown is not None, "error", str(pack.get("markdown_path") or "")))
        if markdown is not None:
            checks.append(_check("markdown_file_exists", markdown.exists() and markdown.is_file(), "error", str(markdown)))
            if markdown.exists() and markdown.is_file():
                markdown_text = markdown.read_text(encoding="utf-8")
                checks.append(_check("markdown_owner_only", _owner_only(markdown), "error", oct(markdown.stat().st_mode & 0o077)))
                checks.append(_check("markdown_title_present", "# Draftpaper Commercial Evidence Pack" in markdown_text, "error", str(markdown)))
                checks.append(_check("markdown_target_track_matches", f"Target track: {pack.get('target_track')}" in markdown_text, "error", str(pack.get("target_track") or "")))
                checks.append(_check("markdown_status_matches", f"Status: {pack.get('status')}" in markdown_text, "error", str(pack.get("status") or "")))
                missing_labels = [str(item.get("label") or item.get("id")) for item in _evidence_records(pack) if str(item.get("label") or item.get("id")) not in markdown_text]
                checks.append(_check("markdown_lists_evidence_items", not missing_labels, "warning", ",".join(missing_labels[:20]) if missing_labels else "ok"))
    except Exception as exc:
        checks.append(_check("evidence_pack_readable", False, "error", str(exc)))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "schema_version": VERIFICATION_SCHEMA,
        "status": "verified" if not errors else "attention",
        "pack_path": str(pack_path),
        "markdown_path": str(markdown) if markdown is not None else "",
        "pack_sha256": str(pack.get("pack_sha256") or ""),
        "target_track": str(pack.get("target_track") or ""),
        "pack_status": str(pack.get("status") or ""),
        "blocking_evidence_ids": [str(item) for item in pack.get("blocking_evidence_ids") or []],
        "summary": {"checks": len(checks), "errors": len(errors), "warnings": len(warnings)},
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Draftpaper-loop commercial evidence pack.")
    parser.add_argument("pack_path", help="commercial-evidence-pack.json path.")
    parser.add_argument("--markdown-path", default="", help="Optional commercial-evidence-pack.md path.")
    parser.add_argument("--allow-attention", action="store_true", help="Accept an attention pack when blocking evidence is intentionally still missing.")
    args = parser.parse_args(argv)
    result = verify_commercial_evidence_pack(
        Path(args.pack_path),
        markdown_path=Path(args.markdown_path) if args.markdown_path else None,
        require_ready=not args.allow_attention,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
