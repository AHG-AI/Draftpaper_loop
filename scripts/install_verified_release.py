#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

try:
    from verify_handoff_dossier import verify_handoff_dossier
    from verify_release_package import verify_release_package
except ImportError:  # pragma: no cover - direct import fallback for tests.
    import importlib.util

    scripts_dir = Path(__file__).resolve().parent

    release_spec = importlib.util.spec_from_file_location("draftpaper_verify_release_package", scripts_dir / "verify_release_package.py")
    if release_spec is None or release_spec.loader is None:
        verify_release_package = None  # type: ignore[assignment]
    else:
        release_module = importlib.util.module_from_spec(release_spec)
        release_spec.loader.exec_module(release_module)
        verify_release_package = release_module.verify_release_package  # type: ignore[assignment]

    dossier_spec = importlib.util.spec_from_file_location("draftpaper_verify_handoff_dossier", scripts_dir / "verify_handoff_dossier.py")
    if dossier_spec is None or dossier_spec.loader is None:
        verify_handoff_dossier = None  # type: ignore[assignment]
    else:
        dossier_module = importlib.util.module_from_spec(dossier_spec)
        dossier_spec.loader.exec_module(dossier_module)
        verify_handoff_dossier = dossier_module.verify_handoff_dossier  # type: ignore[assignment]


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _safe_member_name(name: str) -> bool:
    return bool(name) and not name.startswith("/") and "\\" not in name and all(part not in {"", ".", ".."} for part in name.split("/"))


def _package_root(zip_path: Path) -> tuple[str, list[str]]:
    with zipfile.ZipFile(zip_path) as archive:
        names = [name for name in archive.namelist() if name and not name.endswith("/")]
    roots = {name.split("/", 1)[0] for name in names if "/" in name and _safe_member_name(name)}
    unsafe = [name for name in names if not _safe_member_name(name)]
    if len(roots) != 1:
        raise ValueError("release zip must contain exactly one package root")
    return next(iter(roots)), unsafe


def _extract_release(zip_path: Path, install_root: Path, *, force: bool) -> Path:
    package, unsafe = _package_root(zip_path)
    if unsafe:
        raise ValueError(f"release zip contains unsafe member paths: {', '.join(unsafe[:10])}")
    destination = install_root / package
    if destination.exists():
        if not force:
            raise FileExistsError(f"{destination} already exists; pass --force to replace it")
        if not destination.is_dir():
            raise ValueError(f"{destination} exists and is not a directory")
        shutil.rmtree(destination)
    install_root.mkdir(parents=True, exist_ok=True)
    install_root.chmod(0o700)
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.namelist():
            if not member or member.endswith("/"):
                continue
            if not member.startswith(f"{package}/") or not _safe_member_name(member):
                raise ValueError(f"unsafe release member: {member}")
            target = install_root / member
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))
    return destination


def _required_install_files(install_dir: Path) -> list[str]:
    required = {
        "LICENSE",
        "COMMERCIAL_LICENSE.md",
        "COMPLIANCE.md",
        "release_manifest.json",
        "SHA256SUMS",
        "service-console.manifest.json",
        "scripts/deploy_local.sh",
        "scripts/verify_release_package.py",
        "scripts/verify_handoff_dossier.py",
        "scripts/install_verified_release.py",
        "scripts/serviceconsole_app.py",
    }
    manifest_path = install_dir / "release_manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            commercial_required = manifest.get("commercial_required_files") if isinstance(manifest, dict) else []
            if isinstance(commercial_required, list):
                required.update(str(item) for item in commercial_required if str(item).strip())
        except Exception as exc:
            return [f"release_manifest.json unreadable: {exc}"]
    return sorted(relative for relative in required if not (install_dir / relative).exists())


def _python_env(install_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    current = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(install_dir) + (os.pathsep + current if current else "")
    return env


def _run_installed_smoke(install_dir: Path, output: Path) -> dict[str, Any]:
    smoke_script = install_dir / "scripts" / "smoke_installed_release.py"
    if not smoke_script.exists():
        return {
            "status": "attention",
            "summary": {"checks": 1, "errors": 1, "warnings": 0},
            "checks": [_check("installed_smoke_script_present", False, "error", str(smoke_script), "Install a complete release package.")],
        }
    completed = subprocess.run(
        [
            sys.executable,
            str(smoke_script),
            "--install-dir",
            str(install_dir),
            "--output",
            str(output),
        ],
        cwd=install_dir,
        env=_python_env(install_dir),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    report: dict[str, Any]
    if output.exists():
        loaded = json.loads(output.read_text(encoding="utf-8"))
        report = loaded if isinstance(loaded, dict) else {}
    else:
        report = json.loads(completed.stdout) if completed.stdout.strip() else {}
    if not isinstance(report, dict):
        report = {}
    report.setdefault("status", "passed" if completed.returncode == 0 else "attention")
    report["command_returncode"] = completed.returncode
    if completed.returncode != 0 and completed.stderr:
        report["stderr_tail"] = completed.stderr[-1000:]
    return report


def install_verified_release(
    *,
    release_zip: Path,
    install_root: Path,
    release_manifest: Path | None = None,
    release_sha256_file: Path | None = None,
    release_signature: Path | None = None,
    release_public_key: Path | None = None,
    handoff_dossier: Path | None = None,
    require_signature: bool = False,
    require_dossier: bool = False,
    run_smoke: bool = False,
    smoke_output: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    release_zip = release_zip.expanduser().resolve()
    install_root = install_root.expanduser().resolve()
    checks: list[dict[str, Any]] = []

    if verify_release_package is None:
        release_report = {"status": "attention", "message": "verify_release_package.py is unavailable"}
    else:
        release_report = verify_release_package(
            release_zip,
            manifest_path=release_manifest.expanduser() if release_manifest is not None else None,
            sha256_path=release_sha256_file.expanduser() if release_sha256_file is not None else None,
            signature_path=release_signature.expanduser() if release_signature is not None else None,
            public_key_path=release_public_key.expanduser() if release_public_key is not None else None,
            require_signature=require_signature,
        )
    checks.append(_check("release_verified", release_report.get("status") == "verified", "error", str(release_report.get("status") or ""), "Verify the release package and sidecars before installing."))

    dossier_report: dict[str, Any] | None = None
    if handoff_dossier is not None:
        if verify_handoff_dossier is None:
            dossier_report = {"status": "attention", "message": "verify_handoff_dossier.py is unavailable"}
        else:
            dossier_report = verify_handoff_dossier(handoff_dossier, release_zip=release_zip, require_release_zip=True)
        checks.append(_check("handoff_dossier_verified", dossier_report.get("status") == "verified", "error", str(dossier_report.get("status") or ""), "Verify the customer handoff dossier against the release zip."))
    else:
        checks.append(_check("handoff_dossier_verified", not require_dossier, "error" if require_dossier else "warning", "not supplied", "Provide --handoff-dossier for customer handoff installs."))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    installed_dir = ""
    install_checks: list[dict[str, Any]] = []
    smoke_report: dict[str, Any] | None = None
    smoke_output_path = ""
    if not errors:
        try:
            extracted = _extract_release(release_zip, install_root, force=force)
            installed_dir = str(extracted)
            missing = _required_install_files(extracted)
            install_checks.append(_check("required_install_files_present", not missing, "error", ", ".join(missing) if missing else "ok"))
            if run_smoke:
                if missing:
                    install_checks.append(_check("installed_smoke_passed", False, "error", "required install files missing", "Install a complete release before running installed smoke."))
                else:
                    output = smoke_output.expanduser().resolve() if smoke_output is not None else install_root / "draftpaper-installed-smoke.json"
                    smoke_output_path = str(output)
                    smoke_report = _run_installed_smoke(extracted, output)
                    install_checks.append(_check("installed_smoke_passed", smoke_report.get("status") == "passed", "error", str(smoke_report.get("status") or ""), "Run scripts/smoke_installed_release.py and fix every error."))
        except Exception as exc:
            install_checks.append(_check("release_extracted", False, "error", str(exc)))
    checks.extend(install_checks)
    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]

    result = {
        "schema_version": "draftpaper.install-verified-release/v1",
        "status": "installed" if not errors and installed_dir else "attention",
        "generated_at": _utc_timestamp(),
        "release_zip": str(release_zip),
        "install_root": str(install_root),
        "installed_dir": installed_dir,
        "release_verification": release_report,
        "dossier_verification": dossier_report,
        "installed_smoke": smoke_report,
        "installed_smoke_output": smoke_output_path,
        "checks": checks,
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
        },
    }
    manifest_path = install_root / "draftpaper-install-manifest.json"
    install_root.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)
    result["install_manifest"] = str(manifest_path)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify and extract a Draftpaper-loop release zip into a local install directory.")
    parser.add_argument("--release-zip", required=True)
    parser.add_argument("--install-root", required=True)
    parser.add_argument("--release-manifest", default="")
    parser.add_argument("--release-sha256-file", default="")
    parser.add_argument("--release-signature", default="")
    parser.add_argument("--release-public-key", default="")
    parser.add_argument("--handoff-dossier", default="")
    parser.add_argument("--require-signature", action="store_true")
    parser.add_argument("--require-dossier", action="store_true")
    parser.add_argument("--run-smoke", action="store_true", help="Run scripts/smoke_installed_release.py after a successful extraction.")
    parser.add_argument("--smoke-output", default="", help="Optional installed smoke JSON output path. Defaults to <install-root>/draftpaper-installed-smoke.json.")
    parser.add_argument("--force", action="store_true", help="Replace an existing extracted package directory.")
    args = parser.parse_args(argv)
    result = install_verified_release(
        release_zip=Path(args.release_zip),
        install_root=Path(args.install_root),
        release_manifest=Path(args.release_manifest) if args.release_manifest else None,
        release_sha256_file=Path(args.release_sha256_file) if args.release_sha256_file else None,
        release_signature=Path(args.release_signature) if args.release_signature else None,
        release_public_key=Path(args.release_public_key) if args.release_public_key else None,
        handoff_dossier=Path(args.handoff_dossier) if args.handoff_dossier else None,
        require_signature=args.require_signature,
        require_dossier=args.require_dossier,
        run_smoke=args.run_smoke,
        smoke_output=Path(args.smoke_output) if args.smoke_output else None,
        force=args.force,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["status"] == "installed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
