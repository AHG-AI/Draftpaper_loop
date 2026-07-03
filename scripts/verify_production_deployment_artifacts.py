#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_ROOT = REPO_ROOT / "deploy" / "production"
SCHEMA_VERSION = "draftpaper.production-deployment-artifacts-verification/v1"
REQUIRED_FILES = {
    ".dockerignore": REPO_ROOT / ".dockerignore",
    "Dockerfile": DEPLOY_ROOT / "Dockerfile",
    "docker-compose.example.yml": DEPLOY_ROOT / "docker-compose.example.yml",
    "draftpaper-loop.env.example": DEPLOY_ROOT / "draftpaper-loop.env.example",
    "draftpaper-loop.service": DEPLOY_ROOT / "draftpaper-loop.service",
    "README.md": DEPLOY_ROOT / "README.md",
}
PRIVATE_EXCLUSIONS = [
    ".env",
    ".env.*",
    "projects",
    "var",
    "*.pem",
    "*.key",
    "*.sig",
    "*.zip",
    "claim-confirmation.json",
    "claim-confirmation-verification.json",
    "console-users.json",
    "billing-rates.json",
    "commercial-approval.json",
    "commercial-approval-verification.json",
    "commercial-license-grant.json",
    "hosted-readiness.json",
    "release-trust.json",
    "release-trust-verification.json",
    "security-review.json",
    "security-review-verification.json",
]


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _check(item_id: str, passed: bool, severity: str, note: str, remediation: str = "") -> dict[str, Any]:
    return {"id": item_id, "passed": passed, "severity": severity, "note": note, "remediation": remediation}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig") if path.exists() else ""


def _contains_all(text: str, values: list[str]) -> bool:
    return all(value in text for value in values)


def _line_value(text: str, key: str) -> str:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=\s*(.*)$", re.MULTILINE)
    match = pattern.search(text)
    return match.group(1).strip() if match else ""


def verify_production_deployment_artifacts(*, root: Path = REPO_ROOT) -> dict[str, Any]:
    root = root.expanduser().resolve()
    deploy_root = root / "deploy" / "production"
    files = {
        ".dockerignore": root / ".dockerignore",
        "Dockerfile": deploy_root / "Dockerfile",
        "docker-compose.example.yml": deploy_root / "docker-compose.example.yml",
        "draftpaper-loop.env.example": deploy_root / "draftpaper-loop.env.example",
        "draftpaper-loop.service": deploy_root / "draftpaper-loop.service",
        "README.md": deploy_root / "README.md",
    }
    checks: list[dict[str, Any]] = []
    for label, path in files.items():
        checks.append(_check(f"{label}_exists", path.exists() and path.is_file(), "error", str(path), f"Restore {path.relative_to(root)}."))

    dockerignore = _read(files[".dockerignore"])
    dockerfile = _read(files["Dockerfile"])
    compose = _read(files["docker-compose.example.yml"])
    env_example = _read(files["draftpaper-loop.env.example"])
    service = _read(files["draftpaper-loop.service"])
    readme = _read(files["README.md"])

    missing_exclusions = [item for item in PRIVATE_EXCLUSIONS if item not in dockerignore]
    checks.append(_check("dockerignore_private_exclusions", not missing_exclusions, "error", ",".join(missing_exclusions) if missing_exclusions else "ok", "Exclude private runtime files, release artifacts, and project data from image context."))

    checks.extend(
        [
            _check("dockerfile_non_root_user", "USER draftpaper" in dockerfile, "error", "USER draftpaper", "Run the container as the draftpaper user."),
            _check("dockerfile_runtime_volumes", _contains_all(dockerfile, ["/data/projects", "/data/runtime", "/data/backups", "VOLUME"]), "error", "projects/runtime/backups volumes", "Declare writable runtime data volumes."),
            _check("dockerfile_healthcheck", "HEALTHCHECK" in dockerfile and "/health" in dockerfile, "error", "HEALTHCHECK /health", "Declare a container healthcheck against /health."),
            _check("dockerfile_exposes_port", "EXPOSE 4888" in dockerfile, "warning", "EXPOSE 4888", "Expose the internal console port for reverse proxy wiring."),
            _check("dockerfile_no_private_copy", all(item not in dockerfile for item in ["COPY var", "COPY projects", "COPY .env"]), "error", "no private COPY statements", "Do not copy runtime data or env files into the image."),
        ]
    )

    checks.extend(
        [
            _check("compose_loopback_binding", '"127.0.0.1:4888:4888"' in compose or "'127.0.0.1:4888:4888'" in compose, "error", "127.0.0.1:4888:4888", "Bind locally and expose externally only through HTTPS reverse proxy."),
            _check("compose_uses_env_file", "env_file:" in compose and "draftpaper-loop.env" in compose, "error", "env_file", "Use a private env file outside source control."),
            _check("compose_private_secret_mount", "./private:/run/secrets/draftpaper-loop:ro" in compose, "error", "private secret mount", "Mount private runtime files read-only."),
            _check("compose_read_only_root", "read_only: true" in compose, "warning", "read_only: true", "Keep the container filesystem read-only except volumes and tmpfs."),
            _check("compose_drops_capabilities", "cap_drop:" in compose and "- ALL" in compose, "warning", "cap_drop ALL", "Drop Linux capabilities by default."),
            _check("compose_no_new_privileges", "no-new-privileges:true" in compose, "error", "no-new-privileges:true", "Set no-new-privileges for the container."),
            _check("compose_healthcheck", "healthcheck:" in compose and "/health" in compose, "error", "healthcheck /health", "Declare a compose healthcheck."),
        ]
    )

    checks.extend(
        [
            _check("env_example_no_legacy_token", "DRAFTPAPER_CONSOLE_TOKEN=" not in env_example, "error", "no DRAFTPAPER_CONSOLE_TOKEN", "Use DRAFTPAPER_CONSOLE_USERS_FILE for auditable hosted/operator access."),
            _check("env_example_private_paths", _contains_all(env_example, [
                "DRAFTPAPER_CONSOLE_USERS_FILE=/run/secrets/draftpaper-loop/console-users.json",
                "DRAFTPAPER_LICENSE_FILE=/run/secrets/draftpaper-loop/commercial-license-grant.json",
                "DRAFTPAPER_CLAIM_CONFIRMATION_FILE=/run/secrets/draftpaper-loop/claim-confirmation.json",
                "DRAFTPAPER_COMMERCIAL_APPROVAL_FILE=/run/secrets/draftpaper-loop/commercial-approval.json",
                "DRAFTPAPER_RELEASE_TRUST_FILE=/run/secrets/draftpaper-loop/release-trust.json",
                "DRAFTPAPER_SECURITY_REVIEW_FILE=/run/secrets/draftpaper-loop/security-review.json",
                "DRAFTPAPER_HOSTED_READINESS_FILE=/run/secrets/draftpaper-loop/hosted-readiness.json",
            ]), "error", "private runtime paths", "Point private config to read-only mounted secret files."),
            _check("env_example_bounded_search", _line_value(env_example, "DRAFTPAPER_SEARCH_MAX_QUERIES") in {"1", "2", "3", "4", "5"}, "warning", f"max_queries={_line_value(env_example, 'DRAFTPAPER_SEARCH_MAX_QUERIES')}", "Keep external search bounded in hosted operations."),
        ]
    )

    checks.extend(
        [
            _check("systemd_non_root_user", "User=draftpaper" in service and "Group=draftpaper" in service, "error", "User=draftpaper", "Run systemd deployment as a dedicated non-root user."),
            _check("systemd_private_env", "EnvironmentFile=/etc/draftpaper-loop/draftpaper-loop.env" in service, "error", "EnvironmentFile", "Load private runtime config from /etc."),
            _check("systemd_loopback_binding", "--host 127.0.0.1" in service, "error", "--host 127.0.0.1", "Bind locally and expose externally only through HTTPS reverse proxy."),
            _check("systemd_hardening", _contains_all(service, ["NoNewPrivileges=true", "PrivateTmp=true", "ProtectSystem=strict", "ProtectHome=true"]), "error", "systemd hardening", "Keep baseline systemd hardening enabled."),
            _check("systemd_runtime_writes_scoped", "ReadWritePaths=" in service and "/var/lib/draftpaper-loop" in service, "warning", "ReadWritePaths", "Scope write access to runtime paths."),
        ]
    )

    checks.extend(
        [
            _check("readme_mentions_https_proxy", "HTTPS reverse proxy" in readme, "warning", "HTTPS reverse proxy", "Document HTTPS reverse proxy requirement."),
            _check("readme_mentions_hosted_evidence_boundary", "hosted_saas" in readme and "evidence" in readme, "warning", "hosted evidence boundary", "Keep hosted readiness evidence boundary visible."),
        ]
    )

    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "verified" if not errors else "attention",
        "generated_at": _utc_timestamp(),
        "root": str(root),
        "deploy_root": str(deploy_root),
        "summary": {"checks": len(checks), "errors": len(errors), "warnings": len(warnings)},
        "checks": checks,
        "notes": [
            "This verifier checks deployment artifacts and hardening declarations; it does not prove an external hosted deployment is live.",
            "Hosted SaaS readiness still requires independent evidence for identity, billing, storage/DR, worker isolation, and deployed production hardening.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Draftpaper-loop production deployment artifacts.")
    parser.add_argument("--root", default=str(REPO_ROOT))
    parser.add_argument("--output", default="")
    parser.add_argument("--require-verified", action="store_true")
    args = parser.parse_args(argv)
    result = verify_production_deployment_artifacts(root=Path(args.root))
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        output.chmod(0o600)
    print(text, end="")
    if args.require_verified and result.get("status") != "verified":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
