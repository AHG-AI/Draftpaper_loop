#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

try:
    from build_commercial_launch_package import build_commercial_launch_package
    from build_commercial_operations_report import build_commercial_operations_report
    from build_handoff_dossier import build_handoff_dossier
    from package_release import build_release_package
    from run_handoff_acceptance import run_handoff_acceptance
    from verify_commercial_launch_package import verify_commercial_launch_package
    from verify_commercial_operations_report import verify_commercial_operations_report
    from verify_handoff_dossier import verify_handoff_dossier
    from verify_release_package import verify_release_package
except ImportError:  # pragma: no cover - direct import fallback for isolated tests.
    import importlib.util
    import sys

    scripts_dir = Path(__file__).resolve().parent
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))

    def _load_function(module_name: str, function_name: str):
        spec = importlib.util.spec_from_file_location(f"draftpaper_{module_name}", scripts_dir / f"{module_name}.py")
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load {module_name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return getattr(module, function_name)

    build_commercial_launch_package = _load_function("build_commercial_launch_package", "build_commercial_launch_package")  # type: ignore[assignment]
    build_commercial_operations_report = _load_function("build_commercial_operations_report", "build_commercial_operations_report")  # type: ignore[assignment]
    build_handoff_dossier = _load_function("build_handoff_dossier", "build_handoff_dossier")  # type: ignore[assignment]
    build_release_package = _load_function("package_release", "build_release_package")  # type: ignore[assignment]
    run_handoff_acceptance = _load_function("run_handoff_acceptance", "run_handoff_acceptance")  # type: ignore[assignment]
    verify_commercial_launch_package = _load_function("verify_commercial_launch_package", "verify_commercial_launch_package")  # type: ignore[assignment]
    verify_commercial_operations_report = _load_function("verify_commercial_operations_report", "verify_commercial_operations_report")  # type: ignore[assignment]
    verify_handoff_dossier = _load_function("verify_handoff_dossier", "verify_handoff_dossier")  # type: ignore[assignment]
    verify_release_package = _load_function("verify_release_package", "verify_release_package")  # type: ignore[assignment]


SUITE_SCHEMA = "draftpaper.commercial-acceptance-suite/v1"
TARGET_TRACKS = {"paid_local_handoff", "hosted_saas"}


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(payload: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "suite_sha256"}
    return _sha256_bytes(json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _write_private_json(path: Path, payload: dict[str, Any], *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _file_record(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    path = path.expanduser().resolve()
    if not path.exists() or not path.is_file():
        return {"path": str(path), "exists": False}
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "exists": True, "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def _status_summary(report: dict[str, Any] | None, *, path: Path | None = None) -> dict[str, Any]:
    if not isinstance(report, dict):
        summary: dict[str, Any] = {"status": "", "summary": {}}
    else:
        summary = {
            "status": str(report.get("status") or ""),
            "summary": report.get("summary") if isinstance(report.get("summary"), dict) else {},
        }
        for key in ("zip_sha256", "package_sha256", "dossier_sha256", "report_sha256", "target_track", "commercial_grade"):
            if report.get(key):
                summary[key] = report.get(key)
    if path is not None:
        summary["artifact"] = _file_record(path)
    return summary


def _step(step_id: str, expected_status: str, report: dict[str, Any] | None, *, artifact: Path | None = None) -> dict[str, Any]:
    status = str((report or {}).get("status") or "")
    return {
        "id": step_id,
        "passed": status == expected_status,
        "expected_status": expected_status,
        "status": status,
        "artifact": _file_record(artifact) if artifact is not None else {},
        "summary": (report or {}).get("summary") if isinstance((report or {}).get("summary"), dict) else {},
    }


def _require_signature_paths(release: dict[str, Any]) -> tuple[Path, Path]:
    signature = release.get("signature") if isinstance(release.get("signature"), dict) else {}
    signature_path = str(signature.get("signature_path") or "")
    public_key_path = str(signature.get("public_key_path") or "")
    if not signature_path or not public_key_path:
        raise RuntimeError("Commercial acceptance suite requires a signed release; pass --signing-key.")
    return Path(signature_path), Path(public_key_path)


def run_commercial_acceptance_suite(
    *,
    output_dir: Path,
    base_url: str = "http://127.0.0.1:4888",
    token: str = "",
    target_track: str = "paid_local_handoff",
    customer_id: str,
    customer_name: str,
    signing_key: Path,
    signing_public_key: Path | None = None,
    version_label: str = "",
    hosted_readiness_dossier: Path | None = None,
    timeout: float = 5.0,
    force: bool = False,
) -> dict[str, Any]:
    if target_track not in TARGET_TRACKS:
        raise ValueError(f"target_track must be one of {sorted(TARGET_TRACKS)}")
    if target_track == "hosted_saas" and hosted_readiness_dossier is None:
        raise ValueError("target_track=hosted_saas requires --hosted-readiness-dossier")

    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and not force and any(output_dir.iterdir()):
        raise FileExistsError(f"{output_dir} is not empty; pass --force or choose a new --output-dir")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o700)

    generated_at = _utc_timestamp()
    release_dir = output_dir / "release"
    acceptance_dir = output_dir / "acceptance"
    dossier_dir = output_dir / "customer-dossier"
    launch_dir = output_dir / "launch-package"
    operations_dir = output_dir / "operations"
    support_bundle_path = acceptance_dir / "handoff-support-bundle.zip"
    acceptance_path = acceptance_dir / "handoff-acceptance.json"
    operations_path = operations_dir / "commercial-operations.json"
    operations_markdown_path = operations_dir / "commercial-operations.md"

    release = build_release_package(
        output_dir=release_dir,
        version_label=version_label or f"{target_track}-{time.strftime('%Y%m%d', time.gmtime())}",
        signing_key=signing_key,
        signing_public_key=signing_public_key,
    )
    release_zip = Path(str(release["zip_path"]))
    release_manifest = Path(str(release["manifest_path"]))
    release_sha256_file = Path(str(release["sha256_path"]))
    release_signature, release_public_key = _require_signature_paths(release)

    release_verification = verify_release_package(
        release_zip,
        manifest_path=release_manifest,
        sha256_path=release_sha256_file,
        signature_path=release_signature,
        public_key_path=release_public_key,
        require_signature=True,
    )

    acceptance = run_handoff_acceptance(
        base_url=base_url,
        token=token,
        target_track=target_track,
        release_zip=release_zip,
        release_manifest=release_manifest,
        release_sha256_file=release_sha256_file,
        release_signature=release_signature,
        release_public_key=release_public_key,
        hosted_readiness_dossier=hosted_readiness_dossier,
        require_release=True,
        require_signature=True,
        require_hosted_dossier=target_track == "hosted_saas",
        download_support_bundle=True,
        support_bundle_output=support_bundle_path,
        timeout=timeout,
    )
    _write_private_json(acceptance_path, acceptance, force=True)

    dossier = build_handoff_dossier(
        acceptance_report=acceptance_path,
        output_dir=dossier_dir,
        customer_id=customer_id,
        customer_name=customer_name,
        release_zip=release_zip,
        release_manifest=release_manifest,
        release_sha256_file=release_sha256_file,
        release_signature=release_signature,
        release_public_key=release_public_key,
    )
    dossier_zip = Path(str(dossier["zip_path"]))
    dossier_verification = verify_handoff_dossier(dossier_zip, release_zip=release_zip, require_release_zip=True)

    launch = build_commercial_launch_package(
        acceptance_report=acceptance_path,
        output_dir=launch_dir,
        target_track=target_track,
        customer_id=customer_id,
        customer_name=customer_name,
        release_zip=release_zip,
        release_manifest=release_manifest,
        release_sha256_file=release_sha256_file,
        release_signature=release_signature,
        release_public_key=release_public_key,
        handoff_dossier=dossier_zip,
        support_bundle=support_bundle_path,
        hosted_readiness_dossier=hosted_readiness_dossier,
    )
    launch_zip = Path(str(launch["zip_path"]))
    launch_verification = verify_commercial_launch_package(launch_zip)

    operations = build_commercial_operations_report(
        base_url=base_url,
        token=token,
        target_track=target_track,
        launch_package=launch_zip,
        require_launch_package=True,
        customer_id=customer_id,
        customer_name=customer_name,
        output=operations_path,
        markdown_output=operations_markdown_path,
        timeout=timeout,
    )
    operations_verification = verify_commercial_operations_report(operations_path, launch_package=launch_zip)

    steps = [
        _step("release_packaged", "packaged", release, artifact=release_zip),
        _step("release_verified", "verified", release_verification, artifact=release_zip),
        _step("handoff_acceptance", "passed", acceptance, artifact=acceptance_path),
        _step("handoff_dossier_built", "ready", dossier, artifact=dossier_zip),
        _step("handoff_dossier_verified", "verified", dossier_verification, artifact=dossier_zip),
        _step("commercial_launch_package_built", "ready", launch, artifact=launch_zip),
        _step("commercial_launch_package_verified", "verified", launch_verification, artifact=launch_zip),
        _step("commercial_operations_report_built", "ready", operations, artifact=operations_path),
        _step("commercial_operations_report_verified", "verified", operations_verification, artifact=operations_path),
    ]
    errors = [item for item in steps if not item["passed"]]
    suite = {
        "schema_version": SUITE_SCHEMA,
        "status": "passed" if not errors else "attention",
        "generated_at": generated_at,
        "base_url": base_url.rstrip("/"),
        "target_track": target_track,
        "customer": {"id": customer_id, "name": customer_name},
        "output_dir": str(output_dir),
        "steps": steps,
        "artifacts": {
            "release_zip": _file_record(release_zip),
            "release_manifest": _file_record(release_manifest),
            "release_sha256_file": _file_record(release_sha256_file),
            "release_signature": _file_record(release_signature),
            "release_public_key": _file_record(release_public_key),
            "handoff_acceptance": _file_record(acceptance_path),
            "support_bundle": _file_record(support_bundle_path),
            "handoff_dossier": _file_record(dossier_zip),
            "commercial_launch_package": _file_record(launch_zip),
            "commercial_operations_report": _file_record(operations_path),
            "commercial_operations_markdown": _file_record(operations_markdown_path),
        },
        "reports": {
            "release": _status_summary(release, path=release_zip),
            "release_verification": _status_summary(release_verification),
            "handoff_acceptance": _status_summary(acceptance, path=acceptance_path),
            "handoff_dossier": _status_summary(dossier, path=dossier_zip),
            "handoff_dossier_verification": _status_summary(dossier_verification),
            "commercial_launch_package": _status_summary(launch, path=launch_zip),
            "commercial_launch_package_verification": _status_summary(launch_verification),
            "commercial_operations": _status_summary(operations, path=operations_path),
            "commercial_operations_verification": _status_summary(operations_verification),
        },
        "summary": {"steps": len(steps), "passed": sum(1 for item in steps if item["passed"]), "errors": len(errors), "warnings": 0},
        "notes": [
            "This suite orchestrates the existing release, acceptance, dossier, launch, and operations verifiers without weakening their pass criteria.",
            "The suite report is private operator evidence and does not include console tokens.",
        ],
    }
    suite["suite_sha256"] = _digest(suite)
    _write_private_json(output_dir / "commercial-acceptance-suite.json", suite, force=True)
    return suite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the full Draftpaper-loop commercial acceptance suite.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:4888")
    parser.add_argument("--token", default=os.environ.get("DRAFTPAPER_CONSOLE_TOKEN", ""))
    parser.add_argument("--target-track", choices=sorted(TARGET_TRACKS), default="paid_local_handoff")
    parser.add_argument("--customer-id", required=True)
    parser.add_argument("--customer-name", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--signing-public-key", default="")
    parser.add_argument("--version-label", default="")
    parser.add_argument("--hosted-readiness-dossier", default="")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--require-passed", action="store_true", help="Exit non-zero unless the full suite passes.")
    args = parser.parse_args(argv)

    suite = run_commercial_acceptance_suite(
        output_dir=Path(args.output_dir),
        base_url=args.base_url,
        token=args.token,
        target_track=args.target_track,
        customer_id=args.customer_id,
        customer_name=args.customer_name,
        signing_key=Path(args.signing_key).expanduser(),
        signing_public_key=Path(args.signing_public_key).expanduser() if args.signing_public_key else None,
        version_label=args.version_label,
        hosted_readiness_dossier=Path(args.hosted_readiness_dossier).expanduser() if args.hosted_readiness_dossier else None,
        timeout=args.timeout,
        force=args.force,
    )
    print(json.dumps(suite, ensure_ascii=False, indent=2, sort_keys=True))
    if args.require_passed and suite.get("status") != "passed":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
