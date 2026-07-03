#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "dist",
    "projects",
    "var",
}
DEFAULT_EXCLUDED_SUFFIXES = {".key", ".pem", ".pyc", ".pyo", ".sig", ".zip"}
DEFAULT_EXCLUDED_FILES = {
    ".DS_Store",
    "active-handoff.env",
    "billing-rates.json",
    "claim-confirmation.json",
    "claim-confirmation-verification.json",
    "commercial-approval.json",
    "commercial-approval-verification.json",
    "commercial-license-grant.json",
    "console-users.json",
    "hosted-acceptance.json",
    "hosted-readiness.json",
    "license-grant.json",
    "release-trust.json",
    "release-trust-verification.json",
    "security-review.json",
    "security-review-verification.json",
}
REQUIRED_COMMERCIAL_FILES = [
    "LICENSE",
    "NOTICE",
    "COMMERCIAL_LICENSE.md",
    "TRADEMARK.md",
    "COMPLIANCE.md",
    "docs/COMMERCIAL_READINESS.md",
    ".dockerignore",
    "deploy/production/Dockerfile",
    "deploy/production/README.md",
    "deploy/production/docker-compose.example.yml",
    "deploy/production/draftpaper-loop.env.example",
    "deploy/production/draftpaper-loop.service",
    "service-console.manifest.json",
    "scripts/deploy_local.sh",
    "scripts/build_commercial_launch_package.py",
    "scripts/build_commercial_operations_report.py",
    "scripts/build_handoff_dossier.py",
    "scripts/build_hosted_readiness_dossier.py",
    "scripts/collect_hosted_readiness_evidence.py",
    "scripts/generate_handoff_config.py",
    "scripts/install_verified_release.py",
    "scripts/prepare_commercial_approval.py",
    "scripts/prepare_hosted_readiness.py",
    "scripts/prepare_claim_confirmation.py",
    "scripts/prepare_release_trust.py",
    "scripts/prepare_security_review.py",
    "scripts/run_commercial_acceptance_suite.py",
    "scripts/run_hosted_production_acceptance.py",
    "scripts/package_release.py",
    "scripts/run_handoff_acceptance.py",
    "scripts/run_sample_workflow_acceptance.py",
    "scripts/serviceconsole_app.py",
    "scripts/smoke_installed_release.py",
    "scripts/validate_hosted_readiness.py",
    "scripts/verify_claim_confirmation.py",
    "scripts/verify_commercial_approval.py",
    "scripts/verify_commercial_launch_package.py",
    "scripts/verify_commercial_acceptance_suite.py",
    "scripts/verify_commercial_operations_report.py",
    "scripts/verify_handoff_dossier.py",
    "scripts/verify_hosted_evidence_collection.py",
    "scripts/verify_hosted_readiness_dossier.py",
    "scripts/verify_production_deployment_artifacts.py",
    "scripts/verify_release_package.py",
    "scripts/verify_release_trust.py",
    "scripts/verify_security_review.py",
    "scripts/verify_support_bundle.py",
]


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-") or "local"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _openssl_bin() -> str:
    found = shutil.which("openssl")
    if not found:
        raise RuntimeError("openssl is required for release signing")
    return found


def _run_openssl(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([_openssl_bin(), *args], check=True, text=True, capture_output=True)


def _derive_public_key(private_key: Path, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _run_openssl(["pkey", "-in", str(private_key), "-pubout", "-out", str(output_path)])
    return output_path


def sign_release_zip(
    zip_path: Path,
    *,
    private_key: Path,
    public_key: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    zip_path = zip_path.resolve()
    private_key = private_key.expanduser().resolve()
    output_dir = (output_dir or zip_path.parent).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if public_key is None:
        public_key = output_dir / f"{zip_path.stem}.public.pem"
        _derive_public_key(private_key, public_key)
    else:
        public_key = public_key.expanduser().resolve()
    signature_path = output_dir / f"{zip_path.name}.sig"
    _run_openssl(["dgst", "-sha256", "-sign", str(private_key), "-out", str(signature_path), str(zip_path)])
    return {
        "signature_algorithm": "openssl-dgst-sha256",
        "signature_path": str(signature_path),
        "signature_sha256": sha256_file(signature_path),
        "public_key_path": str(public_key),
        "public_key_sha256": sha256_file(public_key),
        "signed_at": _utc_timestamp(),
    }


def _should_skip(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    parts = relative.parts
    if any(part in DEFAULT_EXCLUDED_DIRS for part in parts[:-1]):
        return True
    if path.name in DEFAULT_EXCLUDED_FILES:
        return True
    if path.name.startswith(".env"):
        return True
    if path.suffix in DEFAULT_EXCLUDED_SUFFIXES:
        return True
    return False


def iter_package_files(root: Path = REPO_ROOT) -> list[Path]:
    root = root.resolve()
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if _should_skip(path, root):
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def _read_project_version(root: Path) -> str:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return "0.0.0"
    for line in pyproject.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
        if match:
            return match.group(1)
    return "0.0.0"


def build_release_package(
    *,
    root: Path = REPO_ROOT,
    output_dir: Path | None = None,
    version_label: str | None = None,
    signing_key: Path | None = None,
    signing_public_key: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    output_dir = (output_dir or root / "dist").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    project_version = _read_project_version(root)
    label = _slug(version_label or f"v{project_version}-local-commercial-pilot")
    package_stem = f"draftpaper-loop-{label}"
    zip_path = output_dir / f"{package_stem}.zip"

    files = iter_package_files(root)
    missing_required = [relative for relative in REQUIRED_COMMERCIAL_FILES if not (root / relative).exists()]
    file_hashes = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
        for path in files
    ]
    release_manifest = {
        "schema_version": "draftpaper.release/v1",
        "package": package_stem,
        "generated_at": _utc_timestamp(),
        "project_version": project_version,
        "version_label": label,
        "source_root_name": root.name,
        "file_count": len(file_hashes),
        "excluded_dirs": sorted(DEFAULT_EXCLUDED_DIRS),
        "excluded_suffixes": sorted(DEFAULT_EXCLUDED_SUFFIXES),
        "commercial_required_files": REQUIRED_COMMERCIAL_FILES,
        "missing_required_files": missing_required,
        "files": file_hashes,
    }
    release_manifest_bytes = (json.dumps(release_manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    sums_lines = [f"{item['sha256']}  {item['path']}" for item in file_hashes]
    sums_lines.append(f"{_sha256_bytes(release_manifest_bytes)}  release_manifest.json")
    sums_text = "\n".join(sums_lines) + "\n"

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            relative = path.relative_to(root).as_posix()
            archive.write(path, f"{package_stem}/{relative}")
        archive.writestr(f"{package_stem}/release_manifest.json", release_manifest_bytes)
        archive.writestr(f"{package_stem}/SHA256SUMS", sums_text)

    zip_sha256 = sha256_file(zip_path)
    external_manifest = {
        "status": "packaged",
        "package": package_stem,
        "zip_path": str(zip_path),
        "zip_sha256": zip_sha256,
        "zip_bytes": zip_path.stat().st_size,
        "file_count": len(file_hashes),
        "missing_required_files": missing_required,
        "generated_at": _utc_timestamp(),
    }
    manifest_path = output_dir / f"{package_stem}.manifest.json"
    sums_path = output_dir / f"{package_stem}.zip.sha256"
    external_manifest["manifest_path"] = str(manifest_path)
    external_manifest["sha256_path"] = str(sums_path)
    if signing_key is not None:
        external_manifest["signature"] = sign_release_zip(
            zip_path,
            private_key=signing_key,
            public_key=signing_public_key,
            output_dir=output_dir,
        )
    manifest_path.write_text(json.dumps(external_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    sums_path.write_text(f"{zip_sha256}  {zip_path.name}\n", encoding="utf-8")
    return external_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a Draftpaper-loop local commercial pilot release package.")
    parser.add_argument("--root", default=str(REPO_ROOT), help="Repository root to package.")
    parser.add_argument("--output-dir", default=None, help="Directory for generated package files. Defaults to <root>/dist.")
    parser.add_argument("--version-label", default=None, help="Release label suffix, for example 2026-07-03-pilot.")
    parser.add_argument("--signing-key", default=None, help="Optional PEM private key used to create <zip>.sig.")
    parser.add_argument("--signing-public-key", default=None, help="Optional PEM public key to include in signature metadata. If omitted, it is derived next to the package.")
    args = parser.parse_args(argv)

    result = build_release_package(
        root=Path(args.root),
        output_dir=Path(args.output_dir).expanduser() if args.output_dir else None,
        version_label=args.version_label,
        signing_key=Path(args.signing_key).expanduser() if args.signing_key else None,
        signing_public_key=Path(args.signing_public_key).expanduser() if args.signing_public_key else None,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not result["missing_required_files"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
