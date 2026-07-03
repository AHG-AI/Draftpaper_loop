#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any


FORBIDDEN_DIRS = {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", "__pycache__", "dist", "projects", "var"}
FORBIDDEN_SUFFIXES = {".key", ".pem", ".pyc", ".pyo", ".sig", ".zip"}
FORBIDDEN_FILES = {
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
    "operator-token.txt",
    "release-trust.json",
    "release-trust-verification.json",
    "security-review.json",
    "security-review-verification.json",
}


def sha256_bytes(data: bytes) -> str:
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
        raise RuntimeError("openssl is required for signature verification")
    return found


def _verify_signature(zip_path: Path, *, signature_path: Path, public_key_path: Path) -> tuple[bool, str]:
    completed = subprocess.run(
        [
            _openssl_bin(),
            "dgst",
            "-sha256",
            "-verify",
            str(public_key_path),
            "-signature",
            str(signature_path),
            str(zip_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    output = (completed.stdout + completed.stderr).strip()
    return completed.returncode == 0, output or f"exit={completed.returncode}"


def _check(item_id: str, passed: bool, severity: str, note: str) -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note}


def _parse_sha256_file(path: Path) -> tuple[str, str]:
    raw = path.read_text(encoding="utf-8").strip().splitlines()[0]
    parts = raw.split()
    if len(parts) < 2:
        raise ValueError("sha256 file must contain '<sha256>  <filename>'")
    return parts[0], parts[-1]


def _safe_sum_path(path: str) -> bool:
    return bool(path) and not path.startswith("/") and "\\" not in path and all(part not in {"", ".", ".."} for part in path.split("/"))


def _is_forbidden_relative(path: str) -> bool:
    parts = Path(path).parts
    if any(part in FORBIDDEN_DIRS for part in parts[:-1]):
        return True
    name = parts[-1] if parts else path
    if name in FORBIDDEN_FILES or name.startswith(".env"):
        return True
    suffix = Path(name).suffix
    return suffix in FORBIDDEN_SUFFIXES


def _package_prefix(names: list[str]) -> str:
    roots = {name.split("/", 1)[0] for name in names if name and "/" in name and not name.startswith("/")}
    if len(roots) != 1:
        raise ValueError("release zip must contain exactly one package root")
    return next(iter(roots))


def _read_json_from_zip(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    payload = json.loads(archive.read(name).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return payload


def _parse_internal_sums(text: str) -> dict[str, str]:
    sums: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        relative = relative.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected) or not _safe_sum_path(relative):
            raise ValueError(f"invalid SHA256SUMS line: {line}")
        sums[relative] = expected.lower()
    return sums


def verify_release_package(
    zip_path: Path,
    *,
    manifest_path: Path | None = None,
    sha256_path: Path | None = None,
    signature_path: Path | None = None,
    public_key_path: Path | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    zip_path = zip_path.expanduser().resolve()
    checks: list[dict[str, Any]] = []
    actual_zip_sha = ""
    package = ""
    checked_files = 0
    try:
        actual_zip_sha = sha256_file(zip_path)
        checks.append(_check("zip_exists", zip_path.exists(), "error", str(zip_path)))
    except OSError as exc:
        checks.append(_check("zip_exists", False, "error", str(exc)))
        return {"status": "attention", "zip_path": str(zip_path), "checks": checks, "summary": {"errors": 1, "warnings": 0, "checked_files": 0}}

    if sha256_path is not None:
        try:
            expected_sha, expected_name = _parse_sha256_file(sha256_path.expanduser())
            checks.append(_check("external_sha256_file", expected_sha.lower() == actual_zip_sha and expected_name == zip_path.name, "error", f"{expected_sha}  {expected_name}"))
        except Exception as exc:
            checks.append(_check("external_sha256_file", False, "error", str(exc)))

    try:
        with zipfile.ZipFile(zip_path) as archive:
            names = archive.namelist()
            bad_member = archive.testzip()
            checks.append(_check("zip_readable", bad_member is None, "error", bad_member or "ok"))
            package = _package_prefix(names)
            manifest_name = f"{package}/release_manifest.json"
            sums_name = f"{package}/SHA256SUMS"
            checks.append(_check("internal_manifest_present", manifest_name in names, "error", manifest_name))
            checks.append(_check("internal_sha256sums_present", sums_name in names, "error", sums_name))
            release_manifest = _read_json_from_zip(archive, manifest_name)
            checks.append(_check("release_schema", release_manifest.get("schema_version") == "draftpaper.release/v1", "error", str(release_manifest.get("schema_version") or "")))
            checks.append(_check("package_name_matches", release_manifest.get("package") == package, "error", f"{release_manifest.get('package')} vs {package}"))
            checks.append(_check("required_files_present", not release_manifest.get("missing_required_files"), "error", ", ".join(release_manifest.get("missing_required_files") or [])))

            manifest_files = {
                str(item.get("path") or ""): {
                    "sha256": str(item.get("sha256") or "").lower(),
                    "bytes": int(item.get("bytes") or 0),
                }
                for item in release_manifest.get("files", [])
                if isinstance(item, dict)
            }
            package_entries = {
                name[len(package) + 1:]
                for name in names
                if name.startswith(f"{package}/") and name not in {manifest_name, sums_name} and not name.endswith("/")
            }
            checks.append(_check("manifest_covers_entries", package_entries == set(manifest_files), "error", f"manifest={len(manifest_files)} entries={len(package_entries)}"))
            forbidden = sorted(path for path in package_entries if _is_forbidden_relative(path))
            checks.append(_check("private_path_exclusions", not forbidden, "error", ", ".join(forbidden[:20]) if forbidden else "ok"))

            internal_sums = _parse_internal_sums(archive.read(sums_name).decode("utf-8"))
            expected_sum_paths = set(manifest_files) | {"release_manifest.json"}
            checks.append(_check("sha256sums_covers_manifest", set(internal_sums) == expected_sum_paths, "error", f"sums={len(internal_sums)} expected={len(expected_sum_paths)}"))
            for relative, expected in internal_sums.items():
                archive_name = manifest_name if relative == "release_manifest.json" else f"{package}/{relative}"
                actual = sha256_bytes(archive.read(archive_name))
                if actual != expected:
                    checks.append(_check("internal_file_sha256", False, "error", f"{relative}: {actual} != {expected}"))
                    break
                checked_files += 1
            else:
                checks.append(_check("internal_file_sha256", True, "error", f"{checked_files} files"))

            for relative, item in manifest_files.items():
                data = archive.read(f"{package}/{relative}")
                if len(data) != item["bytes"] or sha256_bytes(data) != item["sha256"]:
                    checks.append(_check("release_manifest_file_hashes", False, "error", relative))
                    break
            else:
                checks.append(_check("release_manifest_file_hashes", True, "error", f"{len(manifest_files)} files"))
    except Exception as exc:
        checks.append(_check("zip_verification", False, "error", str(exc)))

    if manifest_path is not None:
        try:
            external = json.loads(manifest_path.expanduser().read_text(encoding="utf-8"))
            checks.append(_check("external_manifest_status", external.get("status") == "packaged", "error", str(external.get("status") or "")))
            checks.append(_check("external_manifest_zip_sha256", external.get("zip_sha256") == actual_zip_sha, "error", str(external.get("zip_sha256") or "")))
            if package:
                checks.append(_check("external_manifest_package", external.get("package") == package, "error", f"{external.get('package')} vs {package}"))
            signature = external.get("signature") if isinstance(external.get("signature"), dict) else {}
            if signature_path is None and signature:
                signature_path = Path(str(signature.get("signature_path") or ""))
            if public_key_path is None and signature:
                public_key_path = Path(str(signature.get("public_key_path") or ""))
        except Exception as exc:
            checks.append(_check("external_manifest", False, "error", str(exc)))

    if signature_path is not None or public_key_path is not None:
        if signature_path is None or public_key_path is None:
            checks.append(_check("signature_inputs", False, "error", "signature and public key are both required"))
        else:
            signature_path = signature_path.expanduser().resolve()
            public_key_path = public_key_path.expanduser().resolve()
            checks.append(_check("signature_file_exists", signature_path.exists(), "error", str(signature_path)))
            checks.append(_check("signature_public_key_exists", public_key_path.exists(), "error", str(public_key_path)))
            if signature_path.exists() and public_key_path.exists():
                try:
                    ok, note = _verify_signature(zip_path, signature_path=signature_path, public_key_path=public_key_path)
                    checks.append(_check("signature_verified", ok, "error", note))
                except Exception as exc:
                    checks.append(_check("signature_verified", False, "error", str(exc)))
    elif require_signature:
        checks.append(_check("signature_required", False, "error", "signature was required but not provided"))

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "status": "verified" if not errors else "attention",
        "zip_path": str(zip_path),
        "zip_sha256": actual_zip_sha,
        "signature_path": str(signature_path) if signature_path is not None else "",
        "public_key_path": str(public_key_path) if public_key_path is not None else "",
        "package": package,
        "summary": {
            "checks": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
            "checked_files": checked_files,
        },
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Draftpaper-loop release package before customer handoff.")
    parser.add_argument("zip_path", help="Release zip path.")
    parser.add_argument("--manifest", default=None, help="External .manifest.json generated next to the zip.")
    parser.add_argument("--sha256-file", default=None, help="External .zip.sha256 file generated next to the zip.")
    parser.add_argument("--signature", default=None, help="Detached signature file, usually <zip>.sig.")
    parser.add_argument("--public-key", default=None, help="PEM public key for detached signature verification.")
    parser.add_argument("--require-signature", action="store_true", help="Fail when a detached signature is not provided or discoverable from the manifest.")
    args = parser.parse_args(argv)
    result = verify_release_package(
        Path(args.zip_path),
        manifest_path=Path(args.manifest).expanduser() if args.manifest else None,
        sha256_path=Path(args.sha256_file).expanduser() if args.sha256_file else None,
        signature_path=Path(args.signature).expanduser() if args.signature else None,
        public_key_path=Path(args.public_key).expanduser() if args.public_key else None,
        require_signature=args.require_signature,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
