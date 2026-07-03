#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from serviceconsole_app import HOSTED_READINESS_REQUIREMENTS, HOSTED_READINESS_SCHEMA, hosted_readiness_summary


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def hosted_readiness_template(*, environment: str = "production") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": HOSTED_READINESS_SCHEMA,
        "environment": environment,
        "generated_at": _utc_timestamp(),
    }
    for requirement in HOSTED_READINESS_REQUIREMENTS:
        section: dict[str, Any] = {"status": "pending", "evidence": [{"path": "", "sha256": "", "description": ""}]}
        for field in requirement.get("required_fields", []):
            section[str(field)] = ""
        for field in requirement.get("required_true", []):
            section[str(field)] = False
        payload[str(requirement["evidence_key"])] = section
    return payload


def _write_private_json(path: Path, payload: dict[str, Any], *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def validate_hosted_readiness(evidence_file: Path | None = None) -> dict[str, Any]:
    previous = os.environ.get("DRAFTPAPER_HOSTED_READINESS_FILE")
    try:
        if evidence_file is not None:
            os.environ["DRAFTPAPER_HOSTED_READINESS_FILE"] = str(evidence_file.expanduser().resolve())
        return hosted_readiness_summary()
    finally:
        if evidence_file is not None:
            if previous is None:
                os.environ.pop("DRAFTPAPER_HOSTED_READINESS_FILE", None)
            else:
                os.environ["DRAFTPAPER_HOSTED_READINESS_FILE"] = previous


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Draftpaper-loop hosted SaaS readiness evidence.")
    parser.add_argument("--evidence-file", default="", help="Hosted readiness evidence JSON. Defaults to DRAFTPAPER_HOSTED_READINESS_FILE.")
    parser.add_argument("--write-template", default="", help="Write a private draftpaper.hosted-readiness/v1 template JSON and exit.")
    parser.add_argument("--environment", default="production", help="Environment label used in generated templates.")
    parser.add_argument("--output", default="", help="Optional private JSON report output path.")
    parser.add_argument("--require-ready", action="store_true", help="Exit non-zero unless hosted readiness status is ready.")
    parser.add_argument("--force", action="store_true", help="Overwrite --write-template or --output targets.")
    args = parser.parse_args(argv)

    if args.write_template:
        template_path = Path(args.write_template).expanduser()
        payload = hosted_readiness_template(environment=args.environment)
        _write_private_json(template_path, payload, force=args.force)
        result = {
            "status": "template_written",
            "schema_version": HOSTED_READINESS_SCHEMA,
            "path": str(template_path.resolve()),
            "mode": oct(template_path.stat().st_mode & 0o777),
            "next": "Fill every section with status=verified, required fields, true controls, and evidence references; then run this script with --require-ready.",
        }
    else:
        evidence = Path(args.evidence_file).expanduser() if args.evidence_file else None
        result = validate_hosted_readiness(evidence)

    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        output_path = Path(args.output).expanduser()
        _write_private_json(output_path, result, force=args.force)
    print(text, end="")
    if args.require_ready and result.get("status") != "ready":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
