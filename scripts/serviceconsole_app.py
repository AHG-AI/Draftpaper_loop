#!/usr/bin/env python3
from __future__ import annotations

import argparse
import calendar
import hashlib
import hmac
import importlib.util
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import urllib.parse
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECTS_ROOT = Path(os.environ.get("DRAFTPAPER_PROJECTS_DIR", REPO_ROOT / "projects")).expanduser().resolve()
RUNTIME_ROOT = Path(os.environ.get("DRAFTPAPER_RUNTIME_DIR", REPO_ROOT / "var" / "serviceconsole")).expanduser().resolve()
PYTHON_BIN = os.environ.get("DRAFTPAPER_PYTHON", sys.executable)

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from draftpaper_cli.orchestrator import status_project
    from draftpaper_cli.project_scaffold import STAGE_ORDER, create_project
except Exception:  # pragma: no cover - exposed by /health.
    status_project = None  # type: ignore[assignment]
    create_project = None  # type: ignore[assignment]
    STAGE_ORDER = []  # type: ignore[assignment]


ACTION_REGISTRY: dict[str, dict[str, Any]] = {
    "status": {"label": "Status", "command": "status", "category": "Observe"},
    "run-pipeline": {"label": "Plan next action", "command": "run-pipeline", "category": "Observe"},
    "detect-artifact-drift": {"label": "Detect drift", "command": "detect-artifact-drift", "category": "Observe"},
    "sync-artifact-stale": {"label": "Sync stale stages", "command": "sync-artifact-stale", "category": "Control"},
    "search-literature-live": {
        "label": "Search literature (bounded)",
        "command": "search-literature",
        "category": "Evidence",
        "env": {
            "DRAFTPAPER_SEARCH_PROVIDERS": os.environ.get("DRAFTPAPER_SEARCH_PROVIDERS", "semantic_scholar,arxiv"),
            "DRAFTPAPER_SEARCH_TIMEOUT_SECONDS": os.environ.get("DRAFTPAPER_SEARCH_TIMEOUT_SECONDS", "6"),
            "DRAFTPAPER_SEARCH_MAX_QUERIES": os.environ.get("DRAFTPAPER_SEARCH_MAX_QUERIES", "4"),
        },
    },
    "search-literature-from-json": {"label": "Import literature JSON", "command": "search-literature", "category": "Evidence"},
    "resolve-journal-template": {"label": "Resolve journal template", "command": "resolve-journal-template", "category": "Evidence"},
    "generate-plan": {"label": "Generate research plan", "command": "generate-plan", "category": "Plan"},
    "inventory-data": {"label": "Inventory data", "command": "inventory-data", "category": "Data"},
    "classify-data-access": {"label": "Classify data access", "command": "classify-data-access", "category": "Data"},
    "prepare-data-acquisition": {"label": "Prepare data acquisition", "command": "prepare-data-acquisition", "category": "Data"},
    "assess-data-quality": {"label": "Assess data quality", "command": "assess-data-quality", "category": "Data"},
    "assess-data-feasibility": {"label": "Assess data feasibility", "command": "assess-data-feasibility", "category": "Data"},
    "build-data-context": {"label": "Build data context", "command": "build-data-context", "category": "Writing"},
    "write-data": {"label": "Write Data section", "command": "write-data", "category": "Writing"},
    "collect-method-plan": {"label": "Collect method plan", "command": "collect-method-plan", "category": "Methods"},
    "prepare-method-blueprint": {"label": "Prepare method blueprint", "command": "prepare-method-blueprint", "category": "Methods"},
    "plan-figures": {"label": "Plan figures", "command": "plan-figures", "category": "Results"},
    "generate-analysis-code": {"label": "Generate analysis code", "command": "generate-analysis-code", "category": "Methods"},
    "inventory-results": {"label": "Inventory results", "command": "inventory-results", "category": "Results"},
    "assess-result-validity": {"label": "Assess result validity", "command": "assess-result-validity", "category": "Results"},
    "assess-core-evidence": {"label": "Assess core evidence", "command": "assess-core-evidence", "category": "Results"},
    "write-results": {"label": "Write Results section", "command": "write-results", "category": "Writing"},
    "write-introduction": {"label": "Write Introduction", "command": "write-introduction", "category": "Writing"},
    "write-discussion": {"label": "Write Discussion", "command": "write-discussion", "category": "Writing"},
    "assemble-latex": {"label": "Assemble LaTeX", "command": "assemble-latex", "category": "Manuscript"},
    "run-integrity-gate": {"label": "Run integrity gate", "command": "run-integrity-gate", "category": "Review"},
    "audit-citations": {"label": "Audit citations", "command": "audit-citations", "category": "Review"},
    "run-citation-repair-loop": {"label": "Citation repair loop", "command": "run-citation-repair-loop", "category": "Review"},
    "review-draft": {"label": "Review draft", "command": "review-draft", "category": "Review"},
    "assess-publication-readiness": {"label": "Assess publication readiness", "command": "assess-publication-readiness", "category": "Review"},
    "diagnose-gate-failures": {"label": "Diagnose gate failures", "command": "diagnose-gate-failures", "category": "Review"},
    "generate-revision-plan": {"label": "Generate revision plan", "command": "generate-revision-plan", "category": "Revision"},
    "apply-revision": {"label": "Apply revision", "command": "apply-revision", "category": "Revision"},
    "re-review": {"label": "Re-review", "command": "re-review", "category": "Revision"},
}

LICENSE_BROAD_ACTION_FEATURES = {"*", "all", "paper_loop", "paid_local_handoff", "commercial_handoff"}
LICENSE_FEATURE_ACTIONS: dict[str, set[str]] = {
    "local_console": {"status", "run-pipeline", "detect-artifact-drift", "sync-artifact-stale"},
    "live_search": {"search-literature-live", "search-literature-from-json"},
    "literature_search": {"search-literature-live", "search-literature-from-json"},
    "journal_templates": {"resolve-journal-template"},
    "project_export": set(),
    "backup_restore": set(),
}

JOBS: dict[str, dict[str, Any]] = {}
JOB_PROCESSES: dict[str, subprocess.Popen[str]] = {}
JOBS_LOCK = threading.Lock()
AUDIT_LOCK = threading.Lock()
TERMINAL_JOB_STATUSES = {"succeeded", "failed", "cancelled", "unknown"}
DEFAULT_EXPORT_EXCLUDE_PREFIXES = ("data/raw/", "data/processed/")
PRIVATE_RUNTIME_FILENAMES = {
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
HANDOFF_ENV_KEYS = {
    "DRAFTPAPER_CLAIM_CONFIRMATION_FILE",
    "DRAFTPAPER_CLAIM_CONFIRMATION_PROJECT",
    "DRAFTPAPER_COMMERCIAL_APPROVAL_FILE",
    "DRAFTPAPER_LICENSE_FILE",
    "DRAFTPAPER_CONSOLE_USERS_FILE",
    "DRAFTPAPER_BILLING_RATES_FILE",
    "DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256",
    "DRAFTPAPER_HOSTED_READINESS_FILE",
    "DRAFTPAPER_RELEASE_TRUST_FILE",
    "DRAFTPAPER_RELEASE_ZIP",
    "DRAFTPAPER_RELEASE_MANIFEST_FILE",
    "DRAFTPAPER_RELEASE_SHA256_FILE",
    "DRAFTPAPER_RELEASE_SIGNATURE_FILE",
    "DRAFTPAPER_RELEASE_PUBLIC_KEY_FILE",
    "DRAFTPAPER_SECURITY_REVIEW_FILE",
    "DRAFTPAPER_SECURITY_AUDIT_FILE",
}
DEFAULT_ACTIVE_HANDOFF_ENV = REPO_ROOT / "var" / "private" / "active-handoff.env"
HOSTED_READINESS_SCHEMA = "draftpaper.hosted-readiness/v1"
HOSTED_READINESS_REQUIREMENTS: list[dict[str, Any]] = [
    {
        "id": "hosted_enterprise_auth",
        "evidence_key": "enterprise_auth",
        "note": "Hosted enterprise SSO/RBAC is implemented and verified.",
        "remediation": "Provide enterprise_auth evidence with provider, sso_protocol, rbac_model, tenant_isolation, mfa_supported=true, and audit_events=true.",
        "required_fields": ["provider", "sso_protocol", "rbac_model", "tenant_isolation"],
        "required_true": ["mfa_supported", "audit_events"],
    },
    {
        "id": "hosted_payment_collection",
        "evidence_key": "payment_collection",
        "note": "Hosted payment collection and server-side billing ledger are implemented and verified.",
        "remediation": "Provide payment_collection evidence with provider, ledger, webhook_validation, invoice_reconciliation, and customer_portal=true.",
        "required_fields": ["provider", "ledger"],
        "required_true": ["webhook_validation", "invoice_reconciliation", "customer_portal"],
    },
    {
        "id": "managed_storage_dr",
        "evidence_key": "managed_storage_dr",
        "note": "Managed off-machine storage, backups, and disaster recovery are implemented and verified.",
        "remediation": "Provide managed_storage_dr evidence with storage_provider, backup_region, restore_runbook, off_machine_backups=true, and restore_rehearsal_passed=true.",
        "required_fields": ["storage_provider", "backup_region", "restore_runbook"],
        "required_true": ["off_machine_backups", "restore_rehearsal_passed"],
    },
    {
        "id": "hosted_worker_isolation",
        "evidence_key": "worker_isolation",
        "note": "Hosted background workers provide retries, isolation, and progress streaming.",
        "remediation": "Provide worker_isolation evidence with queue_backend, isolation_boundary, retry_policy, automatic_retries=true, and progress_streaming=true.",
        "required_fields": ["queue_backend", "isolation_boundary", "retry_policy"],
        "required_true": ["automatic_retries", "progress_streaming"],
    },
    {
        "id": "deployment_hardening",
        "evidence_key": "deployment_hardening",
        "note": "Hosted deployment hardening and security review are complete.",
        "remediation": "Provide deployment_hardening evidence with environment, secrets_manager, security_review_id, tls_enforced=true, least_privilege=true, and incident_response_plan=true.",
        "required_fields": ["environment", "secrets_manager", "security_review_id"],
        "required_true": ["tls_enforced", "least_privilege", "incident_response_plan"],
    },
]
SUPPORT_BUNDLE_JOB_LIMIT = 50
SUPPORT_BUNDLE_AUDIT_LIMIT = 200
SUPPORT_REDACTED = "[redacted]"
SUPPORT_SENSITIVE_KEY_PARTS = (
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "password",
    "secret",
    "token",
)


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return default


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _parse_handoff_env_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].strip()
    if "=" not in stripped:
        raise ValueError(f"Unsupported handoff env line: {line.strip()}")
    key, raw_value = stripped.split("=", 1)
    key = key.strip()
    if key not in HANDOFF_ENV_KEYS:
        raise ValueError(f"Unsupported handoff env key: {key}")
    values = shlex.split(raw_value, comments=False, posix=True)
    if len(values) != 1:
        raise ValueError(f"Unsupported handoff env value for {key}")
    return key, values[0]


def load_handoff_env_file(path: Path | None = None) -> dict[str, Any]:
    explicit = path is not None
    if path is None:
        raw = os.environ.get("DRAFTPAPER_HANDOFF_ENV_FILE", "").strip()
        if raw:
            path = Path(raw).expanduser()
            explicit = True
        else:
            path = DEFAULT_ACTIVE_HANDOFF_ENV
    path = path.expanduser().resolve()
    if not path.exists():
        if explicit:
            raise FileNotFoundError(f"handoff env file not found: {path}")
        return {"status": "not_configured", "path": str(path), "loaded_keys": [], "skipped_existing": []}
    if not path.is_file():
        raise ValueError(f"handoff env path is not a file: {path}")

    loaded: list[str] = []
    skipped: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            parsed = _parse_handoff_env_line(line)
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: {exc}") from exc
        if parsed is None:
            continue
        key, value = parsed
        if os.environ.get(key, "").strip():
            skipped.append(key)
            continue
        os.environ[key] = value
        loaded.append(key)
    return {"status": "loaded", "path": str(path), "loaded_keys": loaded, "skipped_existing": skipped}


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _utc_day_start_epoch(now: float | None = None) -> float:
    current = time.gmtime(now or time.time())
    return float(calendar.timegm((current.tm_year, current.tm_mon, current.tm_mday, 0, 0, 0)))


def _timestamp_to_epoch(value: str) -> float:
    try:
        return float(calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")))
    except Exception:
        return 0.0


def _period_value_to_epoch(value: str | None) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    raw = str(value).strip()
    try:
        return float(raw)
    except ValueError:
        pass
    epoch = _timestamp_to_epoch(raw)
    return epoch if epoch > 0 else None


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tail_text(value: Any, *, limit: int = 2000) -> str:
    raw = str(value or "")
    if len(raw) <= limit:
        return raw
    return raw[-limit:]


def _support_path_roots() -> list[str]:
    roots = {
        str(REPO_ROOT),
        str(PROJECTS_ROOT),
        str(RUNTIME_ROOT),
        str(Path.home()),
        "/private/tmp",
        "/var/folders",
    }
    return sorted((root for root in roots if root and root != "/"), key=len, reverse=True)


def _redact_support_text(value: str) -> str:
    redacted = value
    for root in _support_path_roots():
        redacted = redacted.replace(root, SUPPORT_REDACTED)
    return redacted


def _redact_for_support(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if any(part in lowered for part in SUPPORT_SENSITIVE_KEY_PARTS):
                redacted[key_text] = SUPPORT_REDACTED
            else:
                redacted[key_text] = _redact_for_support(item)
        return redacted
    if isinstance(value, list):
        return [_redact_for_support(item) for item in value]
    if isinstance(value, str):
        return _redact_support_text(value)
    return value


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = int(str(raw).strip())
    except ValueError:
        return default
    return max(minimum, value)


def _payload_int(payload: dict[str, Any], name: str, default: int, *, minimum: int = 0) -> int:
    raw = payload.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, value)


def _optional_int(raw: Any, *, minimum: int = 0) -> int | None:
    if raw is None or str(raw).strip() == "":
        return None
    try:
        return max(minimum, int(str(raw).strip()))
    except (TypeError, ValueError):
        return None


def _first_optional_int(raw: dict[str, Any], *names: str, minimum: int = 0) -> int | None:
    for name in names:
        value = _optional_int(raw.get(name), minimum=minimum)
        if value is not None:
            return value
    return None


def _optional_float(raw: Any, *, minimum: float = 0.0) -> float | None:
    if raw is None or str(raw).strip() == "":
        return None
    try:
        return max(minimum, float(str(raw).strip()))
    except (TypeError, ValueError):
        return None


def _max_concurrent_jobs() -> int:
    return _env_int("DRAFTPAPER_MAX_CONCURRENT_JOBS", 2, minimum=1)


def _safe_slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-")


def _backups_root() -> Path:
    raw = os.environ.get("DRAFTPAPER_BACKUPS_DIR", "").strip()
    return Path(raw).expanduser().resolve() if raw else (RUNTIME_ROOT / "backups").resolve()


def _backup_rehearsal_log() -> Path:
    return RUNTIME_ROOT / "backup_rehearsals.jsonl"


def _billing_rates_file() -> Path | None:
    raw = os.environ.get("DRAFTPAPER_BILLING_RATES_FILE", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _license_file() -> Path | None:
    raw = os.environ.get("DRAFTPAPER_LICENSE_FILE", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _license_public_key_sha256_pin() -> str:
    return os.environ.get("DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256", "").strip().lower()


def _commercial_approval_file() -> Path | None:
    raw = os.environ.get("DRAFTPAPER_COMMERCIAL_APPROVAL_FILE", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _claim_confirmation_file() -> Path | None:
    raw = os.environ.get("DRAFTPAPER_CLAIM_CONFIRMATION_FILE", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _claim_confirmation_project_file() -> Path | None:
    raw = os.environ.get("DRAFTPAPER_CLAIM_CONFIRMATION_PROJECT", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _release_trust_file() -> Path | None:
    raw = os.environ.get("DRAFTPAPER_RELEASE_TRUST_FILE", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _release_artifact_file(env_key: str) -> Path | None:
    raw = os.environ.get(env_key, "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _security_review_file() -> Path | None:
    raw = os.environ.get("DRAFTPAPER_SECURITY_REVIEW_FILE", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _security_audit_evidence_file() -> Path | None:
    raw = os.environ.get("DRAFTPAPER_SECURITY_AUDIT_FILE", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _hosted_readiness_file() -> Path | None:
    raw = os.environ.get("DRAFTPAPER_HOSTED_READINESS_FILE", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _runtime_host() -> str:
    return os.environ.get("DRAFTPAPER_HOST", "127.0.0.1").strip() or "127.0.0.1"


def _runtime_port() -> int:
    try:
        return int(os.environ.get("DRAFTPAPER_PORT", "4888"))
    except ValueError:
        return 4888


def _console_token() -> str:
    return os.environ.get("DRAFTPAPER_CONSOLE_TOKEN", "").strip()


def _token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _access_users_file() -> Path | None:
    raw = os.environ.get("DRAFTPAPER_CONSOLE_USERS_FILE", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _normalize_access_user(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    user_id = str(raw.get("id") or raw.get("user") or raw.get("name") or "").strip()
    token_hash = str(raw.get("token_sha256") or raw.get("token_hash") or "").strip().lower()
    if not user_id or not token_hash:
        return None
    role = str(raw.get("role") or "viewer").strip().lower()
    if role not in {"admin", "operator", "viewer"}:
        role = "viewer"
    can_export_data = bool(raw.get("can_export_data", role == "admin"))
    max_jobs = raw.get("max_concurrent_jobs")
    try:
        max_concurrent_jobs = int(max_jobs) if max_jobs is not None and str(max_jobs).strip() != "" else None
    except (TypeError, ValueError):
        max_concurrent_jobs = None
    if max_concurrent_jobs is not None:
        max_concurrent_jobs = max(1, max_concurrent_jobs)
    return {
        "id": user_id,
        "role": role,
        "workspace": str(raw.get("workspace") or raw.get("workspace_id") or "default").strip() or "default",
        "billing_customer_id": str(raw.get("billing_customer_id") or raw.get("customer_id") or raw.get("workspace") or "default").strip() or "default",
        "billing_plan": str(raw.get("billing_plan") or raw.get("plan") or "local-pilot").strip() or "local-pilot",
        "token_sha256": token_hash,
        "projects": _string_list(raw.get("projects")),
        "project_prefixes": _string_list(raw.get("project_prefixes")),
        "allowed_actions": _string_list(raw.get("allowed_actions")) or ["*"],
        "blocked_actions": _string_list(raw.get("blocked_actions")),
        "can_export_data": can_export_data,
        "max_concurrent_jobs": max_concurrent_jobs,
        "daily_job_limit": _first_optional_int(raw, "daily_job_limit", "job_limit_per_day", "jobs_per_day"),
        "daily_backup_limit": _first_optional_int(raw, "daily_backup_limit", "backup_limit_per_day", "backups_per_day"),
        "backup_storage_bytes_limit": _first_optional_int(raw, "backup_storage_bytes_limit", "max_backup_bytes", "backup_bytes_limit"),
        "max_projects": _first_optional_int(raw, "max_projects"),
    }


def _access_users() -> list[dict[str, Any]]:
    path = _access_users_file()
    if path is None or not path.exists():
        return []
    payload = _read_json(path, {})
    users = payload.get("users") if isinstance(payload, dict) else payload
    if not isinstance(users, list):
        return []
    return [user for user in (_normalize_access_user(item) for item in users) if user is not None]


def _auth_required() -> bool:
    return bool(_console_token()) or bool(_access_users())


def _path_requires_auth(path: str) -> bool:
    return _auth_required() and path not in {"/", "/favicon.ico", "/health", "/api/health"}


def _request_token(handler: BaseHTTPRequestHandler) -> str:
    auth = handler.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    header = handler.headers.get("X-Draftpaper-Token", "")
    if header:
        return header.strip()
    query = urllib.parse.parse_qs(urllib.parse.urlparse(handler.path).query)
    return (query.get("token") or [""])[0].strip()


def _request_authorized(handler: BaseHTTPRequestHandler) -> bool:
    return _request_access_context(handler) is not None


def _local_admin_context() -> dict[str, Any]:
    return {
        "id": "local",
        "role": "admin",
        "workspace": "local",
        "billing_customer_id": "local",
        "billing_plan": "local-admin",
        "projects": [],
        "project_prefixes": [],
        "allowed_actions": ["*"],
        "blocked_actions": [],
        "can_export_data": True,
        "max_concurrent_jobs": None,
        "daily_job_limit": None,
        "daily_backup_limit": None,
        "backup_storage_bytes_limit": None,
        "max_projects": None,
        "source": "local",
    }


def _legacy_token_context() -> dict[str, Any]:
    context = _local_admin_context()
    context.update({"id": "token", "workspace": "legacy-token", "source": "DRAFTPAPER_CONSOLE_TOKEN"})
    return context


def _public_context(context: dict[str, Any] | None) -> dict[str, Any] | None:
    if context is None:
        return None
    return {
        "id": context.get("id"),
        "role": context.get("role"),
        "workspace": context.get("workspace"),
        "billing_customer_id": context.get("billing_customer_id"),
        "billing_plan": context.get("billing_plan"),
        "projects": context.get("projects") or [],
        "project_prefixes": context.get("project_prefixes") or [],
        "allowed_actions": context.get("allowed_actions") or [],
        "blocked_actions": context.get("blocked_actions") or [],
        "can_export_data": bool(context.get("can_export_data")),
        "max_concurrent_jobs": context.get("max_concurrent_jobs"),
        "daily_job_limit": context.get("daily_job_limit"),
        "daily_backup_limit": context.get("daily_backup_limit"),
        "backup_storage_bytes_limit": context.get("backup_storage_bytes_limit"),
        "max_projects": context.get("max_projects"),
        "source": context.get("source"),
    }


def _request_access_context(handler: BaseHTTPRequestHandler) -> dict[str, Any] | None:
    supplied = _request_token(handler)
    users = _access_users()
    if supplied:
        supplied_hash = _token_sha256(supplied)
        for user in users:
            if hmac.compare_digest(supplied_hash, str(user.get("token_sha256") or "")):
                context = dict(user)
                context["source"] = "DRAFTPAPER_CONSOLE_USERS_FILE"
                return context
        expected = _console_token()
        if expected and hmac.compare_digest(supplied, expected):
            return _legacy_token_context()
    if users or _console_token():
        return None
    return _local_admin_context()


def _request_actor(handler: BaseHTTPRequestHandler) -> str:
    context = _request_access_context(handler)
    return str((context or {}).get("id") or "unauthorized")


def access_policy_summary(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    users = _access_users()
    roles: dict[str, int] = {}
    for user in users:
        role = str(user.get("role") or "viewer")
        roles[role] = roles.get(role, 0) + 1
    return {
        "status": "reported",
        "auth_required": _auth_required(),
        "legacy_token_configured": bool(_console_token()),
        "users_file": str(_access_users_file()) if _access_users_file() else "",
        "users_count": len(users),
        "roles": roles,
        "actor": _public_context(context),
    }


def _context_has_project_scope(context: dict[str, Any] | None) -> bool:
    if not context:
        return False
    return bool(context.get("projects") or context.get("project_prefixes"))


def _project_allowed(context: dict[str, Any] | None, project_path: Path) -> bool:
    if context is None:
        return False
    return _project_slug_allowed(context, project_path.name)


def _project_slug_allowed(context: dict[str, Any] | None, slug: str) -> bool:
    if context is None:
        return False
    projects = set(str(item) for item in context.get("projects") or [])
    prefixes = [str(item) for item in context.get("project_prefixes") or []]
    if not projects and not prefixes:
        return True
    return slug in projects or any(slug.startswith(prefix) for prefix in prefixes)


def _require_role(context: dict[str, Any] | None, roles: set[str]) -> None:
    role = str((context or {}).get("role") or "")
    if role not in roles:
        raise PermissionError(f"role {role or 'anonymous'} is not allowed")


def _authorize_project_access(context: dict[str, Any] | None, project_path: Path) -> None:
    if not _project_allowed(context, project_path):
        raise PermissionError(f"project is outside this actor's access scope: {project_path.name}")


def _authorize_action(context: dict[str, Any] | None, action_id: str) -> None:
    _require_role(context, {"admin", "operator"})
    if action_id == "create-project" and _context_has_project_scope(context) and str(context.get("role")) != "admin":
        raise PermissionError("scoped operators cannot create new projects")
    allowed = set(str(item) for item in (context or {}).get("allowed_actions") or ["*"])
    blocked = set(str(item) for item in (context or {}).get("blocked_actions") or [])
    if "*" not in allowed and action_id not in allowed:
        raise PermissionError(f"action is not allowed for this actor: {action_id}")
    if action_id in blocked:
        raise PermissionError(f"action is blocked for this actor: {action_id}")


def _authorize_data_export(context: dict[str, Any] | None, *, include_data: bool) -> None:
    if include_data and not bool((context or {}).get("can_export_data")):
        raise PermissionError("this actor cannot export raw or processed data")


def _visible_actions(context: dict[str, Any] | None) -> list[dict[str, Any]]:
    actions = [{"id": key, **value} for key, value in ACTION_REGISTRY.items()]
    if context is None:
        return []
    if str(context.get("role")) == "viewer":
        return []
    allowed = set(str(item) for item in context.get("allowed_actions") or ["*"])
    blocked = set(str(item) for item in context.get("blocked_actions") or [])
    return [
        action
        for action in actions
        if ("*" in allowed or str(action["id"]) in allowed) and str(action["id"]) not in blocked
    ]


def _billing_config() -> dict[str, Any]:
    default = {
        "status": "default_zero_rates",
        "currency": "USD",
        "rates": {
            "job": 0.0,
            "backup": 0.0,
            "backup_gb": 0.0,
            "project": 0.0,
        },
        "rates_file": "",
    }
    path = _billing_rates_file()
    if path is None or not path.exists():
        return default
    payload = _read_json(path, {})
    if not isinstance(payload, dict):
        return {**default, "status": "invalid_rates_file", "rates_file": str(path)}
    raw_rates = payload.get("rates") if isinstance(payload.get("rates"), dict) else payload
    rates = dict(default["rates"])
    for key in rates:
        value = _optional_float(raw_rates.get(key) if isinstance(raw_rates, dict) else None)
        if value is not None:
            rates[key] = value
    return {
        "status": "configured",
        "currency": str(payload.get("currency") or default["currency"]),
        "rates": rates,
        "rates_file": str(path),
    }


def _security_check(
    item_id: str,
    passed: bool,
    severity: str,
    note: str,
    remediation: str = "",
) -> dict[str, Any]:
    return {
        "id": item_id,
        "passed": passed,
        "severity": severity,
        "note": note,
        "remediation": remediation,
    }


def _is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def _file_public_mode(path: Path) -> int:
    try:
        return path.stat().st_mode & 0o077
    except OSError:
        return 0


def _sha256_string(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()))


def _license_expiry_epoch(value: Any) -> float:
    raw = str(value or "").strip()
    if not raw:
        return 0.0
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            parsed = time.strptime(raw, fmt)
        except ValueError:
            continue
        if fmt == "%Y-%m-%d":
            return float(calendar.timegm((parsed.tm_year, parsed.tm_mon, parsed.tm_mday, 23, 59, 59)))
        return float(calendar.timegm(parsed))
    return 0.0


def _license_unsigned_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key not in {"grant_sha256", "sha256", "signature", "signed_at"}
    }


def _license_canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(_license_unsigned_payload(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _license_digest(payload: dict[str, Any]) -> str:
    return _sha256_bytes(_license_canonical_bytes(payload))


def _license_signature_path(raw: Any, *, base_dir: Path) -> Path | None:
    text = str(raw or "").strip()
    if not text:
        return None
    path = Path(text).expanduser()
    return path.resolve() if path.is_absolute() else (base_dir / path).resolve()


def _verify_license_signature(payload: dict[str, Any], license_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    signature = payload.get("signature")
    if not isinstance(signature, dict):
        return [
            _security_check(
                "license_signature_present",
                False,
                "warning",
                "License grant does not include a detached signature.",
                "Generate customer handoff config with --license-signing-key for signed grant evidence.",
            )
        ], {"configured": False, "verified": False}

    checks: list[dict[str, Any]] = []
    algorithm = str(signature.get("signature_algorithm") or signature.get("algorithm") or "").strip()
    signature_path = _license_signature_path(signature.get("signature_path"), base_dir=license_path.parent)
    public_key_path = _license_signature_path(signature.get("public_key_path"), base_dir=license_path.parent)
    checks.append(_security_check("license_signature_present", True, "warning", "License grant includes a detached signature."))
    checks.append(_security_check("license_signature_algorithm", algorithm == "openssl-dgst-sha256", "error", f"License signature algorithm is {algorithm or 'missing'}.", "Use openssl-dgst-sha256 signatures."))
    checks.append(_security_check("license_signature_file_exists", signature_path is not None and signature_path.exists(), "error", f"License signature file is {signature_path or 'missing'}.", "Keep the detached license signature next to the grant or update signature_path."))
    checks.append(_security_check("license_signature_public_key_exists", public_key_path is not None and public_key_path.exists(), "error", f"License public key file is {public_key_path or 'missing'}.", "Keep the license public key next to the grant or update public_key_path."))
    signature_sha256 = _sha256_file(signature_path) if signature_path is not None and signature_path.exists() else ""
    public_key_sha256 = _sha256_file(public_key_path) if public_key_path is not None and public_key_path.exists() else ""
    expected_signature_sha256 = str(signature.get("signature_sha256") or "").strip().lower()
    expected_public_key_sha256 = str(signature.get("public_key_sha256") or "").strip().lower()
    expected_license_sha256 = str(signature.get("license_sha256") or "").strip().lower()
    computed_license_sha256 = _license_digest(payload)
    public_key_pin = _license_public_key_sha256_pin()
    if expected_signature_sha256:
        checks.append(_security_check("license_signature_sha256_matches", hmac.compare_digest(expected_signature_sha256, signature_sha256), "error", "License signature file SHA256 matches the grant metadata.", "Regenerate the detached signature after authorized grant edits."))
    if expected_public_key_sha256:
        checks.append(_security_check("license_signature_public_key_sha256_matches", hmac.compare_digest(expected_public_key_sha256, public_key_sha256), "error", "License public key SHA256 matches the grant metadata.", "Keep the expected public key with the handoff record."))
    if expected_license_sha256:
        checks.append(_security_check("license_signature_payload_sha256_matches", hmac.compare_digest(expected_license_sha256, computed_license_sha256), "error", "Signed license payload SHA256 matches the grant metadata.", "Regenerate the detached signature after authorized grant edits."))
    checks.append(_security_check(
        "license_public_key_pin",
        not public_key_pin or (_sha256_string(public_key_pin) and hmac.compare_digest(public_key_pin, public_key_sha256)),
        "error" if public_key_pin else "info",
        "Configured license public key pin matches the verification key." if public_key_pin else "No license public key pin is configured; using the public key referenced by the grant.",
        "Set DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256 to the expected commercial license public key SHA256 for stronger handoff trust.",
    ))
    verified = False
    if algorithm == "openssl-dgst-sha256" and signature_path is not None and signature_path.exists() and public_key_path is not None and public_key_path.exists():
        openssl = shutil.which("openssl")
        if not openssl:
            checks.append(_security_check("license_signature_verified", False, "error", "openssl is unavailable.", "Install openssl to verify signed license grants."))
        else:
            with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
                canonical_path = Path(handle.name)
                handle.write(_license_canonical_bytes(payload))
            try:
                completed = subprocess.run(
                    [
                        openssl,
                        "dgst",
                        "-sha256",
                        "-verify",
                        str(public_key_path),
                        "-signature",
                        str(signature_path),
                        str(canonical_path),
                    ],
                    check=False,
                    text=True,
                    capture_output=True,
                )
            finally:
                canonical_path.unlink(missing_ok=True)
            output = (completed.stdout + completed.stderr).strip()
            verified = completed.returncode == 0
            checks.append(_security_check("license_signature_verified", verified, "error", output or f"exit={completed.returncode}", "Regenerate the detached license signature after authorized grant edits."))
    return checks, {
        "configured": True,
        "verified": verified,
        "signature_path": str(signature_path) if signature_path is not None else "",
        "public_key_path": str(public_key_path) if public_key_path is not None else "",
        "signature_sha256": signature_sha256,
        "public_key_sha256": public_key_sha256,
        "public_key_pin_configured": bool(public_key_pin),
        "public_key_pin_matched": bool(public_key_pin) and hmac.compare_digest(public_key_pin, public_key_sha256),
        "algorithm": algorithm,
    }


def _license_public_payload(payload: dict[str, Any]) -> dict[str, Any]:
    fields = [
        "schema_version",
        "license_id",
        "customer_id",
        "customer_name",
        "grant_type",
        "issued_at",
        "expires_at",
        "seats",
        "features",
        "allowed_actions",
        "workspaces",
        "contact_email",
        "terms",
    ]
    return {field: payload.get(field) for field in fields if field in payload}


def license_grant_summary(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    path = _license_file()
    checks: list[dict[str, Any]] = []
    if path is None:
        checks.append(_security_check(
            "license_file_configured",
            False,
            "warning",
            "No local commercial license grant file is configured.",
            "Set DRAFTPAPER_LICENSE_FILE for paid pilots or customer handoff.",
        ))
        return {
            "status": "unconfigured",
            "configured": False,
            "generated_at": _utc_timestamp(),
            "license_file": "",
            "grant": {},
            "computed_sha256": "",
            "checks": checks,
            "notes": [
                "Commercial authorization still requires a written license grant.",
                "This endpoint validates an offline local grant record; it is not DRM, telemetry, or remote activation.",
            ],
        }

    checks.append(_security_check("license_file_configured", True, "warning", f"License grant file configured at {path}."))
    checks.append(_security_check("license_file_exists", path.exists(), "error", f"License grant file exists at {path}.", "Create the file or unset DRAFTPAPER_LICENSE_FILE."))
    if not path.exists():
        return {
            "status": "invalid",
            "configured": True,
            "generated_at": _utc_timestamp(),
            "license_file": str(path) if str(context.get("role") or "") == "admin" else "",
            "grant": {},
            "computed_sha256": "",
            "checks": checks,
            "notes": ["License file path is configured but the file is missing."],
        }

    payload = _read_json(path, {})
    if not isinstance(payload, dict):
        checks.append(_security_check("license_file_shape", False, "error", "License grant file must contain a JSON object.", "Use the documented DRAFTPAPER_LICENSE_FILE JSON schema."))
        return {
            "status": "invalid",
            "configured": True,
            "generated_at": _utc_timestamp(),
            "license_file": str(path) if str(context.get("role") or "") == "admin" else "",
            "grant": {},
            "computed_sha256": "",
            "checks": checks,
            "notes": ["License file is not a valid grant object."],
        }

    public_mode = _file_public_mode(path)
    checks.append(_security_check("license_file_permissions", public_mode == 0, "warning", f"License grant file public permission bits are {oct(public_mode)}.", "Restrict license grant file permissions to owner-only, for example chmod 600."))
    try:
        relative_license_path = path.resolve().relative_to(REPO_ROOT)
    except ValueError:
        relative_license_path = None
    if relative_license_path is not None:
        release_excluded = (
            bool(relative_license_path.parts and relative_license_path.parts[0] in {"var", "projects"})
            or path.name in PRIVATE_RUNTIME_FILENAMES
            or path.name.startswith(".env")
            or path.suffix in {".pem", ".key"}
        )
        checks.append(_security_check(
            "license_file_release_excluded",
            release_excluded,
            "warning",
            "License grant file is outside source release scope or matches a release exclusion.",
            "Move the license grant under var/private or outside the repository before packaging.",
        ))
    required = ["license_id", "customer_name", "grant_type", "issued_at", "expires_at"]
    missing = [field for field in required if not str(payload.get(field) or "").strip()]
    checks.append(_security_check("license_required_fields", not missing, "error", "License grant includes required commercial fields.", f"Missing fields: {', '.join(missing)}" if missing else ""))
    seats = _optional_int(payload.get("seats"), minimum=1)
    checks.append(_security_check("license_seats", seats is not None, "error", "License grant declares a positive seat count.", "Set seats to a positive integer."))
    features = _string_list(payload.get("features"))
    checks.append(_security_check("license_features", bool(features), "warning", "License grant declares enabled feature scope.", "Add a features array such as ['local_console', 'paper_loop']."))
    expiry = _license_expiry_epoch(payload.get("expires_at"))
    now = time.time()
    checks.append(_security_check("license_expiry_parseable", expiry > 0, "error", "License grant expiry is parseable as YYYY-MM-DD or UTC timestamp.", "Use expires_at like 2026-12-31 or 2026-12-31T23:59:59Z."))
    checks.append(_security_check("license_not_expired", expiry == 0 or expiry >= now, "error", "License grant is not expired.", "Renew the commercial grant before customer use."))
    grant_hash = str(payload.get("grant_sha256") or payload.get("sha256") or "").strip().lower()
    computed_hash = _license_digest(payload)
    checks.append(_security_check("license_hash_present", bool(grant_hash), "warning", "License grant includes a local grant_sha256 fingerprint.", "Store grant_sha256 for handoff auditability."))
    if grant_hash:
        checks.append(_security_check("license_hash_matches", hmac.compare_digest(grant_hash, computed_hash), "error", "License grant fingerprint matches the grant contents.", "Recompute grant_sha256 after intentional license edits."))
    signature_checks, signature_summary = _verify_license_signature(payload, path)
    checks.extend(signature_checks)
    forbidden_remote_fields = [
        field
        for field in ("remote_check_url", "activation_url", "telemetry_url", "device_fingerprint", "machine_id_required")
        if field in payload
    ]
    checks.append(_security_check(
        "license_no_remote_activation",
        not forbidden_remote_fields,
        "error",
        "License grant does not require remote activation, telemetry, or device fingerprinting.",
        f"Remove prohibited fields: {', '.join(forbidden_remote_fields)}" if forbidden_remote_fields else "",
    ))
    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "status": "valid" if not errors else ("expired" if any(item["id"] == "license_not_expired" and not item["passed"] for item in checks) else "invalid"),
        "configured": True,
        "generated_at": _utc_timestamp(),
        "license_file": str(path) if str(context.get("role") or "") == "admin" else "",
        "grant": _license_public_payload(payload),
        "computed_sha256": computed_hash,
        "signature": signature_summary if str(context.get("role") or "") == "admin" else {key: signature_summary.get(key) for key in ("configured", "verified", "algorithm")},
        "summary": {
            "total": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
            "passed": sum(1 for item in checks if item["passed"]),
        },
        "checks": checks,
        "notes": [
            "This is an offline local commercial grant record for customer handoff auditability.",
            "It does not perform remote license checks, device fingerprinting, destructive checks, or telemetry.",
        ],
    }


def _license_entitlement_subjects(users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if users:
        subjects = []
        for user in users:
            subject = dict(user)
            subject["source"] = "DRAFTPAPER_CONSOLE_USERS_FILE"
            subjects.append(_public_context(subject) or {})
        return subjects
    if _console_token():
        return [_public_context(_legacy_token_context()) or {}]
    return []


def _licensed_action_scope(payload: dict[str, Any]) -> tuple[bool, set[str], str]:
    explicit = {str(item).strip() for item in _string_list(payload.get("allowed_actions"))}
    explicit.discard("")
    if explicit:
        normalized = {item.lower() for item in explicit}
        if normalized & {"*", "all"}:
            return True, set(), "allowed_actions"
        return False, explicit, "allowed_actions"

    features = {str(item).strip().lower() for item in _string_list(payload.get("features"))}
    features.discard("")
    if features & LICENSE_BROAD_ACTION_FEATURES:
        return True, set(), "features"
    allowed: set[str] = set()
    for feature in features:
        allowed.update(LICENSE_FEATURE_ACTIONS.get(feature, set()))
    return False, allowed, "features"


def _user_action_scope_violations(users: list[dict[str, Any]], payload: dict[str, Any]) -> list[str]:
    allow_all, licensed_actions, source = _licensed_action_scope(payload)
    if allow_all:
        return []
    violations: list[str] = []
    for user in users:
        user_id = str(user.get("id") or "unknown")
        allowed_actions = {str(item).strip() for item in user.get("allowed_actions") or [] if str(item).strip()}
        if not allowed_actions:
            continue
        if "*" in allowed_actions or "all" in {item.lower() for item in allowed_actions}:
            violations.append(f"{user_id}:*")
            continue
        extra = sorted(action for action in allowed_actions if action not in licensed_actions)
        violations.extend(f"{user_id}:{action}" for action in extra)
    return violations


def license_entitlement_summary(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    license_report = license_grant_summary(context=context)
    path = _license_file()
    payload = _read_json(path, {}) if path is not None and path.exists() else {}
    if not isinstance(payload, dict):
        payload = {}

    users = _access_users()
    subjects = _license_entitlement_subjects(users)
    seats = _optional_int(payload.get("seats"), minimum=1)
    subject_count = len(subjects)
    licensed_workspaces = set(_string_list(payload.get("workspaces")))
    customer_id = str(payload.get("customer_id") or "").strip()
    user_workspaces = {str(user.get("workspace") or "").strip() for user in users if str(user.get("workspace") or "").strip()}
    workspace_violations = sorted(workspace for workspace in user_workspaces if licensed_workspaces and workspace not in licensed_workspaces)
    customer_violations = sorted(
        str(user.get("id") or "unknown")
        for user in users
        if customer_id and str(user.get("billing_customer_id") or "").strip() != customer_id
    )
    action_violations = _user_action_scope_violations(users, payload)
    allow_all_actions, licensed_actions, action_scope_source = _licensed_action_scope(payload)

    checks = [
        _security_check("license_entitlement_license_valid", license_report.get("status") == "valid", "error", "Commercial license grant is valid for entitlement auditing.", "Fix /api/license before paid handoff."),
        _security_check("license_entitlement_access_configured", _auth_required(), "error", "Console access control is configured for entitlement auditing.", "Set DRAFTPAPER_CONSOLE_USERS_FILE with hashed users or DRAFTPAPER_CONSOLE_TOKEN."),
        _security_check("license_entitlement_users_file_scoped", bool(users), "warning", "Hashed users file provides auditable seat, workspace, customer, and action scope.", "Prefer DRAFTPAPER_CONSOLE_USERS_FILE over legacy single-token access for paid handoff."),
        _security_check("license_entitlement_seat_limit", seats is not None and subject_count <= seats, "error", f"Configured access subjects are within licensed seats: {subject_count}/{seats or 'missing'}.", "Reduce configured users or increase the written license seat count."),
        _security_check("license_entitlement_customer_declared", bool(customer_id), "warning", "License grant declares a customer_id for billing/customer alignment.", "Add customer_id to the commercial license grant."),
        _security_check("license_entitlement_workspaces_declared", bool(licensed_workspaces), "warning", "License grant declares allowed workspaces.", "Add workspaces to the commercial license grant."),
        _security_check("license_entitlement_workspace_scope", not workspace_violations, "error", "Every configured user workspace is covered by the license grant.", f"Unlicensed workspaces: {', '.join(workspace_violations)}" if workspace_violations else ""),
        _security_check("license_entitlement_customer_scope", not customer_violations, "error", "Every configured user billing customer matches the license customer_id.", f"Mismatched users: {', '.join(customer_violations)}" if customer_violations else ""),
        _security_check("license_entitlement_action_scope", not action_violations, "error", "Every configured user action is covered by license features or allowed_actions.", f"Unlicensed actions: {', '.join(action_violations[:20])}" if action_violations else ""),
    ]
    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "status": "passed" if not errors else "attention",
        "generated_at": _utc_timestamp(),
        "license_status": license_report.get("status"),
        "license_id": str((license_report.get("grant") or {}).get("license_id") or ""),
        "customer_id": customer_id,
        "seat_limit": seats,
        "subjects_count": subject_count,
        "subjects": subjects,
        "licensed_workspaces": sorted(licensed_workspaces),
        "licensed_action_scope": {
            "source": action_scope_source,
            "allow_all": allow_all_actions,
            "actions": [] if allow_all_actions else sorted(licensed_actions),
        },
        "violations": {
            "workspaces": workspace_violations,
            "customers": customer_violations,
            "actions": action_violations,
        },
        "summary": {
            "total": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
            "passed": sum(1 for item in checks if item["passed"]),
        },
        "checks": checks,
        "notes": [
            "This audit compares the local license grant with configured local access subjects.",
            "It is an offline handoff control and does not perform remote activation, telemetry, or device fingerprinting.",
        ],
    }


def _commercial_approval_verifier_module() -> Any:
    verifier_path = REPO_ROOT / "scripts" / "verify_commercial_approval.py"
    spec = importlib.util.spec_from_file_location("draftpaper_verify_commercial_approval", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/verify_commercial_approval.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _commercial_approval_preparer_module() -> Any:
    preparer_path = REPO_ROOT / "scripts" / "prepare_commercial_approval.py"
    spec = importlib.util.spec_from_file_location("draftpaper_prepare_commercial_approval", preparer_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/prepare_commercial_approval.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_commercial_approval_draft(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    license_path = _license_file()
    if license_path is None:
        raise ValueError("DRAFTPAPER_LICENSE_FILE is required before preparing commercial approval evidence")
    output = RUNTIME_ROOT / "commercial_approval_drafts" / "commercial-approval-draft.json"
    module = _commercial_approval_preparer_module()
    report = module.prepare_commercial_approval(
        output=output,
        license_file=license_path,
        root=REPO_ROOT,
        status="draft",
        verify=True,
    )
    append_audit(
        "commercial_approval_draft_prepared",
        actor=str(context.get("id") or "unknown"),
        output=str(output),
        verification_status=report.get("verification_status"),
    )
    return report


def commercial_approval_summary(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    approval_path = _commercial_approval_file()
    license_path = _license_file()
    if approval_path is None:
        checks = [
            _security_check(
                "commercial_approval_file_configured",
                False,
                "info",
                "No commercial approval evidence file is configured.",
                "Set DRAFTPAPER_COMMERCIAL_APPROVAL_FILE for customer-specific legal/contract approval evidence.",
            )
        ]
        return {
            "schema_version": "draftpaper.commercial-approval-verification/v1",
            "status": "unconfigured",
            "generated_at": _utc_timestamp(),
            "approval_file": "",
            "license_file": str(license_path) if license_path is not None else "",
            "approval": {},
            "computed_license_grant_sha256": "",
            "license_file_sha256": "",
            "checks": checks,
            "summary": {"checks": len(checks), "errors": 0, "warnings": 0, "passed": 0},
            "notes": [
                "Software support for private approval verification is present, but no customer approval evidence is configured.",
                "This does not create legal approval, sign contracts, collect payment, or prove hosted SaaS readiness.",
            ],
        }
    try:
        module = _commercial_approval_verifier_module()
        report = module.verify_commercial_approval(approval_file=approval_path, license_file=license_path, root=REPO_ROOT)
    except Exception as exc:
        checks = [
            _security_check(
                "commercial_approval_verifier_available",
                False,
                "error",
                str(exc),
                "Restore scripts/verify_commercial_approval.py and ensure it can be imported.",
            )
        ]
        report = {
            "schema_version": "draftpaper.commercial-approval-verification/v1",
            "status": "attention",
            "generated_at": _utc_timestamp(),
            "approval_file": str(approval_path),
            "license_file": str(license_path) if license_path is not None else "",
            "approval": {},
            "computed_license_grant_sha256": "",
            "license_file_sha256": "",
            "checks": checks,
            "summary": {"checks": 1, "errors": 1, "warnings": 0, "passed": 0},
            "notes": ["Commercial approval verification failed to run."],
        }
    if str(context.get("role") or "") != "admin":
        report = dict(report)
        report["approval_file"] = ""
        report["license_file"] = ""
    return report


def _claim_confirmation_verifier_module() -> Any:
    verifier_path = REPO_ROOT / "scripts" / "verify_claim_confirmation.py"
    spec = importlib.util.spec_from_file_location("draftpaper_verify_claim_confirmation", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/verify_claim_confirmation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _claim_confirmation_preparer_module() -> Any:
    preparer_path = REPO_ROOT / "scripts" / "prepare_claim_confirmation.py"
    spec = importlib.util.spec_from_file_location("draftpaper_prepare_claim_confirmation", preparer_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/prepare_claim_confirmation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_project_claim_confirmation_draft(
    project: str | Path,
    *,
    claims: list[str] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin", "operator"})
    project_path = _project_from_value(str(project), context=context)
    project_slug = project_path.name
    output_dir = RUNTIME_ROOT / "claim_confirmation_drafts" / _safe_slug(project_slug)
    output = output_dir / f"{_safe_slug(project_slug)}-claim-confirmation-draft.json"
    module = _claim_confirmation_preparer_module()
    report = module.prepare_claim_confirmation(
        project=project_path,
        output=output,
        claims=claims or [],
        status="draft",
        verify=True,
    )
    append_audit(
        "claim_confirmation_draft_prepared",
        actor=str(context.get("id") or "unknown"),
        project=project_slug,
        output=str(output),
        verification_status=report.get("verification_status"),
    )
    return report


def claim_confirmation_summary(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    confirmation_path = _claim_confirmation_file()
    project_path = _claim_confirmation_project_file()
    if confirmation_path is None:
        checks = [
            _security_check(
                "claim_confirmation_file_configured",
                False,
                "info",
                "No manuscript claim confirmation evidence file is configured.",
                "Set DRAFTPAPER_CLAIM_CONFIRMATION_FILE after domain/user review confirms manuscript claims and referenced project artifacts.",
            )
        ]
        return {
            "schema_version": "draftpaper.claim-confirmation-verification/v1",
            "status": "unconfigured",
            "generated_at": _utc_timestamp(),
            "confirmation_file": "",
            "project": str(project_path or ""),
            "confirmation": {},
            "observed": {},
            "checks": checks,
            "summary": {"checks": len(checks), "errors": 0, "warnings": 0, "passed": 0},
            "notes": [
                "Software support for private claim confirmation verification is present, but no user/domain confirmation evidence is configured.",
                "This does not create scientific truth, replace peer review, or prove hosted SaaS readiness.",
            ],
        }
    try:
        module = _claim_confirmation_verifier_module()
        report = module.verify_claim_confirmation(
            confirmation_file=confirmation_path,
            project=project_path,
        )
    except Exception as exc:
        checks = [
            _security_check(
                "claim_confirmation_verifier_available",
                False,
                "error",
                str(exc),
                "Restore scripts/verify_claim_confirmation.py and ensure it can be imported.",
            )
        ]
        report = {
            "schema_version": "draftpaper.claim-confirmation-verification/v1",
            "status": "attention",
            "generated_at": _utc_timestamp(),
            "confirmation_file": str(confirmation_path),
            "project": str(project_path or ""),
            "confirmation": {},
            "observed": {},
            "checks": checks,
            "summary": {"checks": 1, "errors": 1, "warnings": 0, "passed": 0},
            "notes": ["Claim confirmation verification failed to run."],
        }
    if str(context.get("role") or "") != "admin":
        report = dict(report)
        report["confirmation_file"] = ""
        report["project"] = ""
    return report


def _release_trust_verifier_module() -> Any:
    verifier_path = REPO_ROOT / "scripts" / "verify_release_trust.py"
    spec = importlib.util.spec_from_file_location("draftpaper_verify_release_trust", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/verify_release_trust.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _release_trust_preparer_module() -> Any:
    preparer_path = REPO_ROOT / "scripts" / "prepare_release_trust.py"
    spec = importlib.util.spec_from_file_location("draftpaper_prepare_release_trust", preparer_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/prepare_release_trust.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_release_trust_draft(
    *,
    release_zip: Path | None = None,
    release_manifest: Path | None = None,
    release_sha256_file: Path | None = None,
    release_signature: Path | None = None,
    release_public_key: Path | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    release_zip = release_zip or _release_artifact_file("DRAFTPAPER_RELEASE_ZIP")
    if release_zip is None:
        raise ValueError("release_zip is required or set DRAFTPAPER_RELEASE_ZIP before preparing release trust evidence")
    output = RUNTIME_ROOT / "release_trust_drafts" / f"{_safe_slug(release_zip.stem)}-release-trust-draft.json"
    module = _release_trust_preparer_module()
    report = module.prepare_release_trust(
        output=output,
        release_zip=release_zip,
        release_manifest=release_manifest or _release_artifact_file("DRAFTPAPER_RELEASE_MANIFEST_FILE"),
        release_sha256_file=release_sha256_file or _release_artifact_file("DRAFTPAPER_RELEASE_SHA256_FILE"),
        release_signature=release_signature or _release_artifact_file("DRAFTPAPER_RELEASE_SIGNATURE_FILE"),
        release_public_key=release_public_key or _release_artifact_file("DRAFTPAPER_RELEASE_PUBLIC_KEY_FILE"),
        status="draft",
        verify=True,
    )
    append_audit(
        "release_trust_draft_prepared",
        actor=str(context.get("id") or "unknown"),
        output=str(output),
        release_zip=str(release_zip),
        verification_status=report.get("verification_status"),
    )
    return report


def release_trust_summary(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    trust_path = _release_trust_file()
    if trust_path is None:
        checks = [
            _security_check(
                "release_trust_file_configured",
                False,
                "info",
                "No release trust evidence file is configured.",
                "Set DRAFTPAPER_RELEASE_TRUST_FILE plus release sidecar paths for certificate/notarization/third-party trust evidence.",
            )
        ]
        return {
            "schema_version": "draftpaper.release-trust-verification/v1",
            "status": "unconfigured",
            "generated_at": _utc_timestamp(),
            "trust_file": "",
            "release_zip": str(_release_artifact_file("DRAFTPAPER_RELEASE_ZIP") or ""),
            "release_manifest": str(_release_artifact_file("DRAFTPAPER_RELEASE_MANIFEST_FILE") or ""),
            "release_sha256_file": str(_release_artifact_file("DRAFTPAPER_RELEASE_SHA256_FILE") or ""),
            "release_signature": str(_release_artifact_file("DRAFTPAPER_RELEASE_SIGNATURE_FILE") or ""),
            "release_public_key": str(_release_artifact_file("DRAFTPAPER_RELEASE_PUBLIC_KEY_FILE") or ""),
            "trust": {},
            "observed": {},
            "checks": checks,
            "summary": {"checks": len(checks), "errors": 0, "warnings": 0, "passed": 0},
            "notes": [
                "Software support for private release trust verification is present, but no external trust evidence is configured.",
                "This does not obtain a certificate, notarize software, perform MDM allowlisting, or replace a third-party release trust program.",
            ],
        }
    try:
        module = _release_trust_verifier_module()
        report = module.verify_release_trust(
            trust_file=trust_path,
            release_zip=_release_artifact_file("DRAFTPAPER_RELEASE_ZIP"),
            release_manifest=_release_artifact_file("DRAFTPAPER_RELEASE_MANIFEST_FILE"),
            release_sha256_file=_release_artifact_file("DRAFTPAPER_RELEASE_SHA256_FILE"),
            release_signature=_release_artifact_file("DRAFTPAPER_RELEASE_SIGNATURE_FILE"),
            release_public_key=_release_artifact_file("DRAFTPAPER_RELEASE_PUBLIC_KEY_FILE"),
        )
    except Exception as exc:
        checks = [
            _security_check(
                "release_trust_verifier_available",
                False,
                "error",
                str(exc),
                "Restore scripts/verify_release_trust.py and ensure it can be imported.",
            )
        ]
        report = {
            "schema_version": "draftpaper.release-trust-verification/v1",
            "status": "attention",
            "generated_at": _utc_timestamp(),
            "trust_file": str(trust_path),
            "release_zip": str(_release_artifact_file("DRAFTPAPER_RELEASE_ZIP") or ""),
            "release_manifest": str(_release_artifact_file("DRAFTPAPER_RELEASE_MANIFEST_FILE") or ""),
            "release_sha256_file": str(_release_artifact_file("DRAFTPAPER_RELEASE_SHA256_FILE") or ""),
            "release_signature": str(_release_artifact_file("DRAFTPAPER_RELEASE_SIGNATURE_FILE") or ""),
            "release_public_key": str(_release_artifact_file("DRAFTPAPER_RELEASE_PUBLIC_KEY_FILE") or ""),
            "trust": {},
            "observed": {},
            "checks": checks,
            "summary": {"checks": 1, "errors": 1, "warnings": 0, "passed": 0},
            "notes": ["Release trust verification failed to run."],
        }
    if str(context.get("role") or "") != "admin":
        report = dict(report)
        for key in ("trust_file", "release_zip", "release_manifest", "release_sha256_file", "release_signature", "release_public_key"):
            report[key] = ""
    return report


def _security_review_verifier_module() -> Any:
    verifier_path = REPO_ROOT / "scripts" / "verify_security_review.py"
    spec = importlib.util.spec_from_file_location("draftpaper_verify_security_review", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/verify_security_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _security_review_preparer_module() -> Any:
    preparer_path = REPO_ROOT / "scripts" / "prepare_security_review.py"
    spec = importlib.util.spec_from_file_location("draftpaper_prepare_security_review", preparer_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/prepare_security_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _handoff_config_generator_module() -> Any:
    generator_path = REPO_ROOT / "scripts" / "generate_handoff_config.py"
    spec = importlib.util.spec_from_file_location("draftpaper_generate_handoff_config", generator_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/generate_handoff_config.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _commercial_acceptance_suite_module() -> Any:
    suite_path = REPO_ROOT / "scripts" / "run_commercial_acceptance_suite.py"
    spec = importlib.util.spec_from_file_location("draftpaper_run_commercial_acceptance_suite", suite_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/run_commercial_acceptance_suite.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _commercial_acceptance_suite_verifier_module() -> Any:
    verifier_path = REPO_ROOT / "scripts" / "verify_commercial_acceptance_suite.py"
    spec = importlib.util.spec_from_file_location("draftpaper_verify_commercial_acceptance_suite", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/verify_commercial_acceptance_suite.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _hosted_evidence_collector_module() -> Any:
    collector_path = REPO_ROOT / "scripts" / "collect_hosted_readiness_evidence.py"
    spec = importlib.util.spec_from_file_location("draftpaper_collect_hosted_readiness_evidence", collector_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/collect_hosted_readiness_evidence.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _hosted_readiness_preparer_module() -> Any:
    preparer_path = REPO_ROOT / "scripts" / "prepare_hosted_readiness.py"
    spec = importlib.util.spec_from_file_location("draftpaper_prepare_hosted_readiness", preparer_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/prepare_hosted_readiness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _hosted_readiness_dossier_builder_module() -> Any:
    builder_path = REPO_ROOT / "scripts" / "build_hosted_readiness_dossier.py"
    spec = importlib.util.spec_from_file_location("draftpaper_build_hosted_readiness_dossier", builder_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/build_hosted_readiness_dossier.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _hosted_readiness_dossier_verifier_module() -> Any:
    verifier_path = REPO_ROOT / "scripts" / "verify_hosted_readiness_dossier.py"
    spec = importlib.util.spec_from_file_location("draftpaper_verify_hosted_readiness_dossier", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/verify_hosted_readiness_dossier.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _hosted_production_acceptance_module() -> Any:
    acceptance_path = REPO_ROOT / "scripts" / "run_hosted_production_acceptance.py"
    spec = importlib.util.spec_from_file_location("draftpaper_run_hosted_production_acceptance", acceptance_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scripts/run_hosted_production_acceptance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _explicit_or_configured_hosted_readiness_file(raw_path: str = "") -> Path:
    if raw_path.strip():
        return Path(raw_path).expanduser().resolve()
    path = _hosted_readiness_file()
    if path is None:
        raise ValueError("hosted_readiness_file is required or DRAFTPAPER_HOSTED_READINESS_FILE must be configured")
    return path


def prepare_hosted_readiness_draft(
    *,
    base_url: str = "",
    token: str = "",
    environment: str = "local-rehearsal",
    timeout: float = 3.0,
    allow_localhost: bool = True,
    allow_insecure_http: bool = True,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    base_url = base_url.strip() or f"http://{_runtime_host()}:{_runtime_port()}"
    generated_at = _utc_timestamp()
    draft_root = RUNTIME_ROOT / "hosted_readiness_drafts" / _safe_slug(f"{environment}-{generated_at}")
    collection_dir = draft_root / "collection"
    collector = _hosted_evidence_collector_module()
    collection = collector.collect_hosted_readiness_evidence(
        base_url=base_url,
        output_dir=collection_dir,
        token=token,
        environment=environment,
        timeout=timeout,
        allow_localhost=allow_localhost,
        allow_insecure_http=allow_insecure_http,
        force=True,
    )
    preparer = _hosted_readiness_preparer_module()
    controls_template = draft_root / "hosted-readiness-controls.template.json"
    controls = preparer.write_controls_template(
        collection_report=Path(str(collection.get("report_path") or collection_dir / "hosted-readiness-evidence-collection.json")),
        output_file=controls_template,
        force=True,
    )
    append_audit(
        "hosted_readiness_draft_prepared",
        actor=str(context.get("id") or "unknown"),
        base_url=base_url,
        output_dir=str(draft_root),
        collection_status=collection.get("status"),
    )
    return {
        "schema_version": "draftpaper.hosted-readiness-draft-preparation/v1",
        "status": "prepared",
        "generated_at": generated_at,
        "base_url": base_url,
        "environment": environment,
        "output_dir": str(draft_root),
        "collection_status": collection.get("status"),
        "collection_summary": collection.get("summary") if isinstance(collection.get("summary"), dict) else {},
        "collection_report": collection.get("report_path"),
        "hosted_readiness_draft": (collection.get("hosted_readiness_draft") or {}).get("path") if isinstance(collection.get("hosted_readiness_draft"), dict) else "",
        "controls_template_status": controls.get("status"),
        "controls_template": controls.get("path"),
        "notes": [
            "This prepares hosted SaaS readiness draft material for operator review.",
            "Local rehearsal or collected probes do not prove hosted SaaS readiness until external controls are completed and validated.",
        ],
    }


def finalize_hosted_readiness(
    *,
    collection_report: str | Path,
    controls_file: str | Path,
    output_file: str | Path | None = None,
    report_output: str | Path | None = None,
    activate: bool = False,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    collection_path = Path(str(collection_report or "")).expanduser().resolve()
    controls_path = Path(str(controls_file or "")).expanduser().resolve()
    if not str(collection_report or "").strip():
        raise ValueError("collection_report is required")
    if not str(controls_file or "").strip():
        raise ValueError("controls_file is required")

    generated_at = _utc_timestamp()
    final_root = RUNTIME_ROOT / "hosted_readiness_final" / _safe_slug(f"{collection_path.stem}-{generated_at}")
    output_path = Path(str(output_file)).expanduser().resolve() if output_file else final_root / "hosted-readiness.json"
    report_path = Path(str(report_output)).expanduser().resolve() if report_output else final_root / "hosted-readiness-preparation.json"
    preparer = _hosted_readiness_preparer_module()
    preparation = preparer.prepare_hosted_readiness(
        collection_report=collection_path,
        controls_file=controls_path,
        output_file=output_path,
        report_output=report_path,
        force=True,
    )
    status = "ready" if preparation.get("status") == "ready" else "attention"
    activated = False
    prepared_output = Path(str(preparation.get("output_file") or output_path)).expanduser().resolve()
    if activate and status == "ready" and prepared_output.exists():
        os.environ["DRAFTPAPER_HOSTED_READINESS_FILE"] = str(prepared_output)
        activated = True
    append_audit(
        "hosted_readiness_finalized",
        actor=str(context.get("id") or "unknown"),
        status=status,
        collection_report=str(collection_path),
        controls_file=str(controls_path),
        output_file=str(prepared_output) if prepared_output.exists() else "",
        activated_in_process=activated,
    )
    return {
        "schema_version": "draftpaper.hosted-readiness-finalization/v1",
        "status": status,
        "generated_at": generated_at,
        "collection_report": str(collection_path),
        "controls_file": str(controls_path),
        "output_file": str(prepared_output) if prepared_output.exists() else str(output_path),
        "report_output": str(report_path),
        "activated_in_process": activated,
        "preparation_status": preparation.get("status"),
        "preparation_summary": preparation.get("summary") if isinstance(preparation.get("summary"), dict) else {},
        "validation": preparation.get("validation") if isinstance(preparation.get("validation"), dict) else {},
        "preparation": preparation,
        "notes": [
            "This finalizes hosted SaaS readiness evidence from a verified collection report and completed operator controls.",
            "Activation only affects the current console process; configure DRAFTPAPER_HOSTED_READINESS_FILE in the deployed service environment for durable hosted SaaS readiness.",
        ],
    }


def build_hosted_readiness_dossier_from_console(
    *,
    hosted_readiness_file: str = "",
    output_dir: str = "",
    output_zip: str = "",
    customer_id: str = "",
    customer_name: str = "",
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    evidence_path = _explicit_or_configured_hosted_readiness_file(hosted_readiness_file)
    generated_at = _utc_timestamp()
    customer_slug = _safe_slug(customer_id or customer_name or evidence_path.stem)
    dossier_root = RUNTIME_ROOT / "hosted_readiness_dossiers" / _safe_slug(f"{customer_slug}-{generated_at}")
    output_dir_path = Path(output_dir).expanduser().resolve() if output_dir.strip() else dossier_root
    output_zip_path = Path(output_zip).expanduser().resolve() if output_zip.strip() else None
    builder = _hosted_readiness_dossier_builder_module()
    dossier = builder.build_hosted_readiness_dossier(
        evidence_file=evidence_path,
        output_dir=output_dir_path,
        output_zip=output_zip_path,
        customer_id=customer_id,
        customer_name=customer_name,
    )
    verification: dict[str, Any] = {}
    zip_path_text = str(dossier.get("zip_path") or "")
    zip_path = Path(zip_path_text).expanduser() if zip_path_text else None
    if zip_path is not None and zip_path.exists():
        verifier = _hosted_readiness_dossier_verifier_module()
        verification = verifier.verify_hosted_readiness_dossier(zip_path)
    status = "verified" if dossier.get("status") == "ready" and verification.get("status") == "verified" else "attention"
    append_audit(
        "hosted_readiness_dossier_built",
        actor=str(context.get("id") or "unknown"),
        status=status,
        hosted_readiness_file=str(evidence_path),
        zip_path=str(zip_path) if zip_path is not None else "",
        verification_status=verification.get("status"),
    )
    return {
        "schema_version": "draftpaper.hosted-readiness-dossier-build/v1",
        "status": status,
        "generated_at": generated_at,
        "hosted_readiness_file": str(evidence_path),
        "output_dir": str(output_dir_path),
        "zip_path": str(zip_path) if zip_path is not None else "",
        "dossier_status": dossier.get("status"),
        "dossier_summary": dossier.get("summary") if isinstance(dossier.get("summary"), dict) else {},
        "verification_status": verification.get("status"),
        "verification_summary": verification.get("summary") if isinstance(verification.get("summary"), dict) else {},
        "dossier": dossier,
        "verification": verification,
        "notes": [
            "This builds and verifies a customer-facing hosted readiness dossier from hosted-readiness.json.",
            "The dossier excludes raw hosted readiness JSON, private runtime files, tokens, keys, signatures, archives, and customer project data.",
        ],
    }


def run_hosted_production_acceptance_from_console(
    *,
    base_url: str,
    token: str = "",
    hosted_readiness_file: str = "",
    hosted_readiness_dossier: str = "",
    output_file: str = "",
    timeout: float = 8.0,
    allow_localhost: bool = False,
    allow_insecure_http: bool = False,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    base_url = base_url.strip()
    if not base_url:
        raise ValueError("base_url is required")
    evidence_path = _explicit_or_configured_hosted_readiness_file(hosted_readiness_file)
    if not hosted_readiness_dossier.strip():
        raise ValueError("hosted_readiness_dossier is required")
    dossier_path = Path(hosted_readiness_dossier).expanduser().resolve()
    generated_at = _utc_timestamp()
    acceptance_root = RUNTIME_ROOT / "hosted_production_acceptance" / _safe_slug(f"{urllib.parse.urlparse(base_url).netloc or 'hosted'}-{generated_at}")
    explicit_output = bool(output_file.strip())
    output_path = Path(output_file).expanduser().resolve() if explicit_output else acceptance_root / "hosted-production-acceptance.json"
    acceptance = _hosted_production_acceptance_module()
    report = acceptance.run_hosted_production_acceptance(
        base_url=base_url,
        token=token,
        evidence_file=evidence_path,
        hosted_readiness_dossier=dossier_path,
        allow_localhost=allow_localhost,
        allow_insecure_http=allow_insecure_http,
        timeout=timeout,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not explicit_output:
        output_path.parent.chmod(0o700)
    _write_json(output_path, report)
    output_path.chmod(0o600)
    append_audit(
        "hosted_production_acceptance_run",
        actor=str(context.get("id") or "unknown"),
        status=report.get("status"),
        base_url=base_url,
        hosted_readiness_file=str(evidence_path),
        hosted_readiness_dossier=str(dossier_path),
        output_file=str(output_path),
    )
    return {
        "schema_version": "draftpaper.hosted-production-acceptance-run/v1",
        "status": report.get("status"),
        "generated_at": generated_at,
        "base_url": base_url.rstrip("/"),
        "hosted_readiness_file": str(evidence_path),
        "hosted_readiness_dossier": str(dossier_path),
        "output_file": str(output_path),
        "summary": report.get("summary") if isinstance(report.get("summary"), dict) else {},
        "report": report,
        "notes": [
            "This runs hosted production acceptance against the supplied hosted URL and writes an owner-only evidence report.",
            "Localhost and plain HTTP remain rejected unless the request explicitly sets rehearsal flags.",
        ],
    }


def prepare_security_review_draft(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    draft_dir = RUNTIME_ROOT / "security_review_drafts"
    security_audit_file = draft_dir / "security-audit.json"
    audit_report = security_audit(context=context)
    _write_json(security_audit_file, audit_report)
    security_audit_file.chmod(0o600)
    output = draft_dir / "security-review-draft.json"
    module = _security_review_preparer_module()
    report = module.prepare_security_review(
        output=output,
        security_audit_file=security_audit_file,
        status="draft",
        verify=True,
    )
    append_audit(
        "security_review_draft_prepared",
        actor=str(context.get("id") or "unknown"),
        output=str(output),
        security_audit_file=str(security_audit_file),
        verification_status=report.get("verification_status"),
    )
    return report


def generate_paid_handoff_config_from_console(
    *,
    customer_id: str,
    customer_name: str,
    output_dir: str = "",
    expires_at: str = "",
    seats: int = 1,
    license_id: str = "",
    grant_type: str = "paid-local-pilot",
    issued_at: str = "",
    workspace: str = "",
    billing_plan: str = "pilot-paid",
    features: list[str] | None = None,
    operator_id: str = "customer-admin",
    operator_role: str = "admin",
    operator_token: str = "",
    can_export_data: bool = False,
    currency: str = "USD",
    job_rate: float = 0.0,
    backup_rate: float = 0.0,
    storage_gb_month_rate: float = 0.0,
    write_token_file: bool = True,
    activate: bool = False,
    license_signing_key: str = "",
    license_public_key: str = "",
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    if not customer_id.strip():
        raise ValueError("customer_id is required")
    if not customer_name.strip():
        raise ValueError("customer_name is required")
    generator = _handoff_config_generator_module()
    customer_slug = _safe_slug(customer_id or customer_name)
    generated_at = _utc_timestamp()
    target_dir = Path(output_dir).expanduser().resolve() if output_dir.strip() else RUNTIME_ROOT / "paid_handoff_configs" / _safe_slug(f"{customer_slug}-{generated_at}")
    result = generator.generate_handoff_config(
        output_dir=target_dir,
        customer_id=customer_id.strip(),
        customer_name=customer_name.strip(),
        expires_at=expires_at.strip() or time.strftime("%Y-%m-%d", time.gmtime(time.time() + 365 * 86400)),
        seats=max(1, int(seats)),
        license_id=license_id.strip(),
        grant_type=grant_type.strip() or "paid-local-pilot",
        issued_at=issued_at.strip(),
        workspace=workspace.strip(),
        billing_plan=billing_plan.strip() or "pilot-paid",
        features=features if features else None,
        operator_id=operator_id.strip() or "customer-admin",
        operator_role=operator_role.strip() or "admin",
        operator_token=operator_token.strip(),
        can_export_data=can_export_data,
        currency=currency.strip() or "USD",
        job_rate=float(job_rate),
        backup_rate=float(backup_rate),
        storage_gb_month_rate=float(storage_gb_month_rate),
        write_token_file=write_token_file,
        activate=activate,
        active_env_path=DEFAULT_ACTIVE_HANDOFF_ENV,
        license_signing_key=Path(license_signing_key).expanduser().resolve() if license_signing_key.strip() else None,
        license_public_key=Path(license_public_key).expanduser().resolve() if license_public_key.strip() else None,
        force=True,
    )
    files = result.get("files") if isinstance(result.get("files"), dict) else {}
    activated_in_process = False
    if activate:
        env_values = {
            "DRAFTPAPER_LICENSE_FILE": str(files.get("license") or ""),
            "DRAFTPAPER_CONSOLE_USERS_FILE": str(files.get("users") or ""),
            "DRAFTPAPER_BILLING_RATES_FILE": str(files.get("billing") or ""),
            "DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256": str(files.get("license_public_key_sha256") or ""),
        }
        for key, value in env_values.items():
            if value:
                os.environ[key] = value
        activated_in_process = True
    append_audit(
        "paid_handoff_config_generated",
        actor=str(context.get("id") or "unknown"),
        customer_id=customer_id.strip(),
        output_dir=str(target_dir),
        activated=activate,
        license_signed=result.get("license_signed"),
    )
    return {
        "schema_version": "draftpaper.paid-handoff-config-preparation/v1",
        "status": result.get("status"),
        "generated_at": generated_at,
        "output_dir": result.get("output_dir"),
        "customer_id": result.get("customer_id"),
        "customer_name": result.get("customer_name"),
        "license_id": result.get("license_id"),
        "workspace": result.get("workspace"),
        "operator_id": result.get("operator_id"),
        "operator_role": result.get("operator_role"),
        "token_sha256": result.get("token_sha256"),
        "grant_sha256": result.get("grant_sha256"),
        "files": files,
        "activated": result.get("activated"),
        "activated_in_process": activated_in_process,
        "license_signed": result.get("license_signed"),
        "notes": [
            "This prepares paid local handoff runtime config without returning the plaintext operator token.",
            "The token file path is returned when written; read it only from the private runtime directory for customer handoff.",
            "Activation updates the current console process and writes the standard active handoff env file for the next startup.",
        ],
    }


def run_commercial_acceptance_suite_from_console(
    *,
    customer_id: str,
    customer_name: str,
    signing_key: str,
    output_dir: str = "",
    base_url: str = "",
    token: str = "",
    target_track: str = "paid_local_handoff",
    signing_public_key: str = "",
    version_label: str = "",
    hosted_readiness_dossier: str = "",
    timeout: float = 5.0,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    if not customer_id.strip():
        raise ValueError("customer_id is required")
    if not customer_name.strip():
        raise ValueError("customer_name is required")
    if not signing_key.strip():
        raise ValueError("signing_key is required for commercial acceptance suite")
    target_track = target_track.strip() or "paid_local_handoff"
    generated_at = _utc_timestamp()
    customer_slug = _safe_slug(customer_id or customer_name)
    suite_root = RUNTIME_ROOT / "commercial_acceptance_suites" / _safe_slug(f"{customer_slug}-{target_track}-{generated_at}")
    output_dir_path = Path(output_dir).expanduser().resolve() if output_dir.strip() else suite_root
    base = base_url.strip() or f"http://{_runtime_host()}:{_runtime_port()}"
    suite_module = _commercial_acceptance_suite_module()
    suite = suite_module.run_commercial_acceptance_suite(
        output_dir=output_dir_path,
        base_url=base,
        token=token,
        target_track=target_track,
        customer_id=customer_id.strip(),
        customer_name=customer_name.strip(),
        signing_key=Path(signing_key).expanduser().resolve(),
        signing_public_key=Path(signing_public_key).expanduser().resolve() if signing_public_key.strip() else None,
        version_label=version_label.strip(),
        hosted_readiness_dossier=Path(hosted_readiness_dossier).expanduser().resolve() if hosted_readiness_dossier.strip() else None,
        timeout=float(timeout),
        force=True,
    )
    suite_path = output_dir_path / "commercial-acceptance-suite.json"
    verification: dict[str, Any] = {}
    if suite_path.exists():
        verifier = _commercial_acceptance_suite_verifier_module()
        verification = verifier.verify_commercial_acceptance_suite(suite_path)
    status = "verified" if suite.get("status") == "passed" and verification.get("status") == "verified" else "attention"
    append_audit(
        "commercial_acceptance_suite_run",
        actor=str(context.get("id") or "unknown"),
        status=status,
        target_track=target_track,
        customer_id=customer_id.strip(),
        output_dir=str(output_dir_path),
        suite_status=suite.get("status"),
        verification_status=verification.get("status"),
    )
    return {
        "schema_version": "draftpaper.commercial-acceptance-suite-run/v1",
        "status": status,
        "generated_at": generated_at,
        "base_url": base.rstrip("/"),
        "target_track": target_track,
        "customer_id": customer_id.strip(),
        "customer_name": customer_name.strip(),
        "output_dir": str(output_dir_path),
        "suite_path": str(suite_path),
        "suite_status": suite.get("status"),
        "suite_summary": suite.get("summary") if isinstance(suite.get("summary"), dict) else {},
        "verification_status": verification.get("status"),
        "verification_summary": verification.get("summary") if isinstance(verification.get("summary"), dict) else {},
        "suite": suite,
        "verification": verification,
        "notes": [
            "This runs the full commercial acceptance suite and independently reverifies the generated suite artifacts.",
            "A signing key is required so release and launch evidence cannot be mistaken for an unsigned commercial handoff.",
            "The response and suite report do not include console tokens.",
        ],
    }


def security_review_summary(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    review_path = _security_review_file()
    audit_path = _security_audit_evidence_file()
    if review_path is None:
        checks = [
            _security_check(
                "security_review_file_configured",
                False,
                "info",
                "No third-party security review evidence file is configured.",
                "Set DRAFTPAPER_SECURITY_REVIEW_FILE for formal external security review evidence.",
            )
        ]
        return {
            "schema_version": "draftpaper.security-review-verification/v1",
            "status": "unconfigured",
            "generated_at": _utc_timestamp(),
            "review_file": "",
            "security_audit_file": str(audit_path or ""),
            "review": {},
            "observed": {},
            "checks": checks,
            "summary": {"checks": len(checks), "errors": 0, "warnings": 0, "passed": 0},
            "notes": [
                "Software support for private security review verification is present, but no external review evidence is configured.",
                "This does not perform a third-party review, replace penetration testing, or prove hosted SaaS readiness.",
            ],
        }
    try:
        module = _security_review_verifier_module()
        report = module.verify_security_review(
            review_file=review_path,
            security_audit_file=audit_path,
        )
    except Exception as exc:
        checks = [
            _security_check(
                "security_review_verifier_available",
                False,
                "error",
                str(exc),
                "Restore scripts/verify_security_review.py and ensure it can be imported.",
            )
        ]
        report = {
            "schema_version": "draftpaper.security-review-verification/v1",
            "status": "attention",
            "generated_at": _utc_timestamp(),
            "review_file": str(review_path),
            "security_audit_file": str(audit_path or ""),
            "review": {},
            "observed": {},
            "checks": checks,
            "summary": {"checks": 1, "errors": 1, "warnings": 0, "passed": 0},
            "notes": ["Security review verification failed to run."],
        }
    if str(context.get("role") or "") != "admin":
        report = dict(report)
        report["review_file"] = ""
        report["security_audit_file"] = ""
    return report


def _user_policy_security_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    path = _access_users_file()
    if path is None:
        checks.append(_security_check("users_file_optional", True, "info", "No local users file is configured; loopback local-admin mode is allowed for single-machine operation."))
        return checks
    checks.append(_security_check("users_file_exists", path.exists(), "error", f"Users file configured at {path}.", "Create the users file or unset DRAFTPAPER_CONSOLE_USERS_FILE."))
    if not path.exists():
        return checks
    public_mode = _file_public_mode(path)
    checks.append(_security_check("users_file_permissions", public_mode == 0, "warning", f"Users file public permission bits are {oct(public_mode)}.", "Restrict users file permissions to owner-only, for example chmod 600."))
    payload = _read_json(path, {})
    raw_users = payload.get("users") if isinstance(payload, dict) else payload
    if not isinstance(raw_users, list):
        checks.append(_security_check("users_file_shape", False, "error", "Users file must contain a users array.", "Use {'users': [...]} with token_sha256 entries."))
        return checks
    bad_plaintext: list[str] = []
    bad_hashes: list[str] = []
    for index, user in enumerate(raw_users):
        if not isinstance(user, dict):
            bad_hashes.append(str(index))
            continue
        forbidden_keys = {"token", "secret", "password", "api_key", "apikey"}
        if any(key in user for key in forbidden_keys):
            bad_plaintext.append(str(user.get("id") or index))
        token_hash = str(user.get("token_sha256") or user.get("token_hash") or "")
        if not _sha256_string(token_hash):
            bad_hashes.append(str(user.get("id") or index))
    checks.append(_security_check("users_no_plaintext_tokens", not bad_plaintext, "error", "Users policy does not include plaintext token fields.", "Remove plaintext token/secret/password/api_key fields and store only token_sha256."))
    checks.append(_security_check("users_token_hashes", not bad_hashes, "error", "Every configured user has a 64-character SHA256 token hash.", "Generate token hashes with hashlib.sha256(token.encode()).hexdigest()."))
    return checks


def _private_file_security_check(path: Path | None, item_id: str, label: str) -> list[dict[str, Any]]:
    if path is None:
        return [_security_check(f"{item_id}_optional", True, "info", f"No {label} file is configured.")]
    checks = [_security_check(f"{item_id}_exists", path.exists(), "error", f"{label} file configured at {path}.", f"Create the {label} file or unset the related environment variable.")]
    if path.exists():
        public_mode = _file_public_mode(path)
        checks.append(_security_check(f"{item_id}_permissions", public_mode == 0, "warning", f"{label} file public permission bits are {oct(public_mode)}.", "Restrict private config file permissions to owner-only, for example chmod 600."))
    return checks


def _truthy_evidence_value(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "verified", "passed", "complete"}
    return False


def _hosted_evidence_entries(section: dict[str, Any]) -> list[Any]:
    entries: list[Any] = []
    for key in ("evidence", "evidence_refs", "artifacts", "links"):
        raw = section.get(key)
        if isinstance(raw, list):
            entries.extend(item for item in raw if item)
        elif isinstance(raw, str) and raw.strip():
            entries.append(raw.strip())
    return entries


def _hosted_evidence_artifacts(section: dict[str, Any], *, base_dir: Path | None) -> dict[str, Any]:
    entries = _hosted_evidence_entries(section)
    refs: list[str] = []
    verified: list[str] = []
    problems: list[str] = []
    for index, entry in enumerate(entries):
        if isinstance(entry, dict):
            raw_path = str(entry.get("path") or entry.get("file") or "").strip()
            expected_sha = str(entry.get("sha256") or entry.get("sha256sum") or "").strip().lower()
            label = raw_path or str(entry.get("label") or entry.get("description") or index)
            if not raw_path:
                problems.append(f"evidence_path_missing={label}")
                continue
            refs.append(raw_path)
            artifact_path = Path(raw_path).expanduser()
            if not artifact_path.is_absolute() and base_dir is not None:
                artifact_path = base_dir / artifact_path
            artifact_path = artifact_path.resolve()
            if not artifact_path.exists() or not artifact_path.is_file():
                problems.append(f"evidence_file_missing={raw_path}")
                continue
            if not _sha256_string(expected_sha):
                problems.append(f"evidence_sha256_missing={raw_path}")
                continue
            actual_sha = _sha256_file(artifact_path)
            if hmac.compare_digest(actual_sha, expected_sha):
                verified.append(raw_path)
            else:
                problems.append(f"evidence_sha256_mismatch={raw_path}")
        else:
            ref = str(entry).strip()
            if ref:
                refs.append(ref)
    return {"refs": refs, "verified": verified, "problems": problems}


def _hosted_gate_from_evidence(requirement: dict[str, Any], payload: dict[str, Any], *, schema_ok: bool, evidence_base_dir: Path | None = None) -> dict[str, Any]:
    evidence_key = str(requirement["evidence_key"])
    raw_section = payload.get(evidence_key) if schema_ok else None
    section = raw_section if isinstance(raw_section, dict) else {}
    status = str(section.get("status") or "").strip().lower()
    missing_fields = [
        field
        for field in requirement.get("required_fields", [])
        if not str(section.get(str(field)) or "").strip()
    ]
    missing_true = [
        field
        for field in requirement.get("required_true", [])
        if not _truthy_evidence_value(section.get(str(field)))
    ]
    evidence = _hosted_evidence_artifacts(section, base_dir=evidence_base_dir)
    evidence_refs = evidence["refs"]
    verified_artifacts = evidence["verified"]
    evidence_problems = evidence["problems"]
    passed = schema_ok and status == "verified" and not missing_fields and not missing_true and bool(verified_artifacts) and not evidence_problems
    if passed:
        note = str(requirement["note"])
    elif not schema_ok:
        note = "Hosted readiness evidence file is missing or invalid."
    else:
        problems: list[str] = []
        if status != "verified":
            problems.append(f"status={status or 'missing'}")
        if missing_fields:
            problems.append("missing_fields=" + ",".join(missing_fields))
        if missing_true:
            problems.append("not_verified=" + ",".join(missing_true))
        if not evidence_refs:
            problems.append("evidence_refs=missing")
        elif not verified_artifacts:
            problems.append("verified_evidence_artifacts=missing")
        if evidence_problems:
            problems.extend(evidence_problems)
        note = "; ".join(problems)
    return _security_check(
        str(requirement["id"]),
        passed,
        "error",
        note,
        str(requirement["remediation"]),
    )


def hosted_readiness_summary(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    path = _hosted_readiness_file()
    checks: list[dict[str, Any]] = []
    payload: dict[str, Any] = {}
    schema_ok = False
    if path is None:
        checks.append(_security_check(
            "hosted_readiness_file_configured",
            False,
            "error",
            "No hosted readiness evidence file is configured.",
            "Set DRAFTPAPER_HOSTED_READINESS_FILE to a draftpaper.hosted-readiness/v1 evidence JSON file.",
        ))
    else:
        checks.append(_security_check("hosted_readiness_file_configured", True, "error", f"Hosted readiness evidence file configured at {path}."))
        checks.append(_security_check("hosted_readiness_file_exists", path.exists(), "error", f"Hosted readiness evidence file exists at {path}.", "Create the evidence file or unset DRAFTPAPER_HOSTED_READINESS_FILE."))
        if path.exists():
            public_mode = _file_public_mode(path)
            checks.append(_security_check("hosted_readiness_file_permissions", public_mode == 0, "warning", f"Hosted readiness evidence file public permission bits are {oct(public_mode)}.", "Restrict hosted readiness evidence to owner-only, for example chmod 600."))
            loaded = _read_json(path, {})
            if isinstance(loaded, dict):
                payload = loaded
            else:
                checks.append(_security_check("hosted_readiness_file_shape", False, "error", "Hosted readiness evidence file must contain a JSON object.", "Use the documented draftpaper.hosted-readiness/v1 schema."))
        schema_ok = isinstance(payload, dict) and payload.get("schema_version") == HOSTED_READINESS_SCHEMA
        if path is not None and path.exists() and "hosted_readiness_file_shape" not in {item["id"] for item in checks}:
            checks.append(_security_check("hosted_readiness_schema", schema_ok, "error", f"Hosted readiness schema is {payload.get('schema_version') or 'missing'}.", f"Set schema_version to {HOSTED_READINESS_SCHEMA}."))
    if path is None:
        gates = [
            _security_check(
                str(requirement["id"]),
                False,
                "error",
                "Hosted readiness evidence file is not configured.",
                "Set DRAFTPAPER_HOSTED_READINESS_FILE to a draftpaper.hosted-readiness/v1 evidence JSON file.",
            )
            for requirement in HOSTED_READINESS_REQUIREMENTS
        ]
    else:
        evidence_base_dir = path.parent if path is not None else None
        gates = [_hosted_gate_from_evidence(requirement, payload, schema_ok=schema_ok, evidence_base_dir=evidence_base_dir) for requirement in HOSTED_READINESS_REQUIREMENTS]
    gate_errors = [item for item in gates if item["severity"] == "error" and not item["passed"]]
    check_errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in [*checks, *gates] if item["severity"] == "warning" and not item["passed"]]
    if gate_errors or check_errors:
        status = "not_ready" if path is None else "attention"
    elif warnings:
        status = "attention"
    else:
        status = "ready"
    return {
        "schema_version": "draftpaper.hosted-readiness-report/v1",
        "status": status,
        "generated_at": _utc_timestamp(),
        "hosted_readiness_file": str(path) if path is not None and str(context.get("role") or "") == "admin" else "",
        "environment": str(payload.get("environment") or ""),
        "summary": {
            "gates": len(gates),
            "passed": sum(1 for item in gates if item.get("passed")),
            "errors": len(gate_errors) + len(check_errors),
            "warnings": len(warnings),
        },
        "checks": checks,
        "gates": gates,
        "notes": [
            "Hosted readiness requires external evidence; local paid handoff readiness is not enough for SaaS claims.",
            "This preflight records operator evidence and does not replace legal approval or third-party security assessment.",
        ],
    }


def _release_packaging_security_check() -> dict[str, Any]:
    package_script = REPO_ROOT / "scripts" / "package_release.py"
    if not package_script.exists():
        return _security_check("release_packager_secret_exclusions", False, "error", "Release packager is missing.", "Restore scripts/package_release.py.")
    source = package_script.read_text(encoding="utf-8", errors="replace")
    has_env_exclusion = ".env" in source
    has_key_exclusion = ".pem" in source and ".key" in source
    has_signature_exclusion = ".sig" in source
    has_private_config_exclusion = all(name in source for name in PRIVATE_RUNTIME_FILENAMES)
    return _security_check(
        "release_packager_secret_exclusions",
        has_env_exclusion and has_key_exclusion and has_signature_exclusion and has_private_config_exclusion,
        "error",
        "Release package excludes .env*, .pem, .key, .sig, and private runtime config material.",
        "Keep secret-file exclusions in scripts/package_release.py.",
    )


def _repo_secret_file_checks() -> list[dict[str, Any]]:
    sensitive = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in REPO_ROOT.iterdir()
        if path.is_file() and (path.name.startswith(".env") or path.suffix in {".pem", ".key", ".sig"} or path.name in PRIVATE_RUNTIME_FILENAMES)
    ]
    allowed_private = {".env.local"}
    unexpected = [item for item in sensitive if item not in allowed_private]
    checks = [
        _security_check(
            "repo_secret_files",
            not unexpected,
            "error",
            "Repository root does not contain unexpected .env/.pem/.key/.sig/private-runtime files.",
            "Move secrets into private runtime paths outside source release scope.",
        )
    ]
    if ".env.local" in sensitive:
        checks.append(_security_check("env_local_release_excluded", True, "info", ".env.local is allowed only as a private runtime file and is excluded from release packages."))
    return checks


def security_audit(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    host = _runtime_host()
    checks: list[dict[str, Any]] = []
    auth_required = _auth_required()
    loopback = _is_loopback_host(host)
    checks.append(_security_check(
        "bind_host_auth",
        loopback or auth_required,
        "error",
        f"Console host is {host}; authentication required is {auth_required}.",
        "Set DRAFTPAPER_CONSOLE_TOKEN or DRAFTPAPER_CONSOLE_USERS_FILE before binding to a non-loopback host.",
    ))
    checks.append(_security_check(
        "loopback_default_mode",
        loopback or auth_required,
        "warning",
        "Unauthenticated local-admin mode is acceptable only on loopback.",
        "Use hashed-token users policy for shared customer/operator trials.",
    ))
    checks.extend(_user_policy_security_checks())
    checks.extend(_private_file_security_check(_billing_rates_file(), "billing_rates_file", "billing rates"))
    checks.extend(_private_file_security_check(_claim_confirmation_file(), "claim_confirmation_file", "manuscript claim confirmation evidence"))
    checks.extend(_private_file_security_check(_commercial_approval_file(), "commercial_approval_file", "commercial approval evidence"))
    checks.extend(_private_file_security_check(_release_trust_file(), "release_trust_file", "release trust evidence"))
    checks.extend(_private_file_security_check(_security_review_file(), "security_review_file", "third-party security review evidence"))
    checks.extend(_private_file_security_check(_security_audit_evidence_file(), "security_audit_evidence_file", "saved security audit evidence"))
    checks.extend(license_grant_summary(context=context)["checks"])
    checks.append(_security_check("runtime_root_outside_release", RUNTIME_ROOT.resolve() != REPO_ROOT.resolve(), "info", f"Runtime root is {RUNTIME_ROOT}."))
    checks.append(_security_check("backups_root_configured", bool(str(_backups_root())), "info", f"Backups root is {_backups_root()}."))
    manifest = _read_json(REPO_ROOT / "service-console.manifest.json", {})
    checks.append(_security_check("manifest_secrets_policy", isinstance(manifest, dict) and bool(manifest.get("secrets_policy")), "error", "Service Console manifest declares a secrets policy.", "Add secrets_policy to service-console.manifest.json."))
    checks.append(_release_packaging_security_check())
    checks.extend(_repo_secret_file_checks())
    checks.append(_security_check("commercial_license_docs", (REPO_ROOT / "COMMERCIAL_LICENSE.md").exists() and (REPO_ROOT / "COMPLIANCE.md").exists(), "error", "Commercial license and compliance boundary documents are present."))
    errors = [item for item in checks if item["severity"] == "error" and not item["passed"]]
    warnings = [item for item in checks if item["severity"] == "warning" and not item["passed"]]
    return {
        "status": "passed" if not errors else "attention",
        "score": round(sum(1 for item in checks if item["passed"]) / len(checks), 2) if checks else 1.0,
        "summary": {
            "total": len(checks),
            "errors": len(errors),
            "warnings": len(warnings),
            "passed": sum(1 for item in checks if item["passed"]),
        },
        "checks": checks,
        "notes": [
            "This is a local preflight security audit, not a formal third-party security assessment.",
            "Do not expose the console on a non-loopback host without token or users-file authentication.",
        ],
    }


def _actor_id(context: dict[str, Any] | None) -> str:
    return str((context or {}).get("id") or "unknown")


def _quota_limits(context: dict[str, Any] | None) -> dict[str, int | None]:
    return {
        "daily_job_limit": (context or {}).get("daily_job_limit"),
        "daily_backup_limit": (context or {}).get("daily_backup_limit"),
        "backup_storage_bytes_limit": (context or {}).get("backup_storage_bytes_limit"),
        "max_projects": (context or {}).get("max_projects"),
    }


def _actor_jobs(context: dict[str, Any] | None) -> list[dict[str, Any]]:
    actor = _actor_id(context)
    if actor == "unknown":
        return []
    return [job for job in JOBS.values() if str(job.get("actor") or "") == actor]


def _actor_backups(context: dict[str, Any] | None) -> list[dict[str, Any]]:
    actor = _actor_id(context)
    if actor == "unknown":
        return []
    return [backup for backup in list_project_backups(context=context) if str(backup.get("actor") or "") == actor]


def _subject_contexts(context: dict[str, Any] | None) -> list[dict[str, Any]]:
    context = context or _local_admin_context()
    if str(context.get("role") or "") != "admin":
        return [context]
    users = []
    for user in _access_users():
        subject = dict(user)
        subject["source"] = "DRAFTPAPER_CONSOLE_USERS_FILE"
        users.append(subject)
    if users:
        return users
    return [context]


def _job_in_period(job: dict[str, Any], start: float, end: float) -> bool:
    created_at = float(job.get("created_at") or 0)
    return start <= created_at < end


def _backup_in_period(backup: dict[str, Any], start: float, end: float) -> bool:
    created_at = _timestamp_to_epoch(str(backup.get("created_at") or ""))
    return start <= created_at < end


def billing_report(
    *,
    context: dict[str, Any] | None = None,
    start: float | None = None,
    end: float | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    period_start = start if start is not None else _utc_day_start_epoch()
    period_end = end if end is not None else time.time()
    if period_end <= period_start:
        raise ValueError("billing period end must be after start")
    config = _billing_config()
    rates = config["rates"]
    subjects = []
    totals = {
        "jobs_count": 0,
        "backups_count": 0,
        "backup_storage_bytes": 0,
        "projects_count": 0,
        "amount": 0.0,
    }
    for subject in _subject_contexts(context):
        actor = _actor_id(subject)
        jobs = [
            job
            for job in JOBS.values()
            if str(job.get("actor") or "") == actor and _job_in_period(job, period_start, period_end)
        ]
        backups_all = _actor_backups(subject)
        backups_in_period = [backup for backup in backups_all if _backup_in_period(backup, period_start, period_end)]
        backup_storage_bytes = sum(int(backup.get("archive_bytes") or 0) for backup in backups_all if backup.get("archive_exists", True))
        projects_count = len(list_projects(context=subject))
        backup_gb = backup_storage_bytes / (1024 ** 3)
        line_items = [
            {"id": "jobs", "quantity": len(jobs), "unit_rate": rates["job"], "amount": len(jobs) * rates["job"]},
            {"id": "backups", "quantity": len(backups_in_period), "unit_rate": rates["backup"], "amount": len(backups_in_period) * rates["backup"]},
            {"id": "backup_gb", "quantity": backup_gb, "unit_rate": rates["backup_gb"], "amount": backup_gb * rates["backup_gb"]},
            {"id": "projects", "quantity": projects_count, "unit_rate": rates["project"], "amount": projects_count * rates["project"]},
        ]
        amount = round(sum(float(item["amount"]) for item in line_items), 6)
        subject_payload = {
            "actor": _public_context(subject),
            "billing_customer_id": subject.get("billing_customer_id") or subject.get("workspace") or actor,
            "billing_plan": subject.get("billing_plan") or "local-pilot",
            "usage": {
                "jobs_count": len(jobs),
                "succeeded_jobs_count": sum(1 for job in jobs if job.get("status") == "succeeded"),
                "failed_jobs_count": sum(1 for job in jobs if job.get("status") == "failed"),
                "backups_count": len(backups_in_period),
                "backup_storage_bytes": backup_storage_bytes,
                "projects_count": projects_count,
            },
            "line_items": line_items,
            "amount": amount,
        }
        subjects.append(subject_payload)
        totals["jobs_count"] += len(jobs)
        totals["backups_count"] += len(backups_in_period)
        totals["backup_storage_bytes"] += backup_storage_bytes
        totals["projects_count"] += projects_count
        totals["amount"] = round(float(totals["amount"]) + amount, 6)
    return {
        "status": "reported",
        "generated_at": _utc_timestamp(),
        "period": {
            "start": _utc_timestamp_from_epoch(period_start),
            "end": _utc_timestamp_from_epoch(period_end),
        },
        "currency": config["currency"],
        "billing_config_status": config["status"],
        "rates_file": config["rates_file"] if str((context or {}).get("role")) == "admin" else "",
        "rates": rates,
        "subjects": subjects,
        "totals": totals,
        "notes": [
            "Local billing report is for commercial pilot reconciliation.",
            "Amounts are estimates from local configured rates and are not payment collection.",
        ],
    }


def quota_summary(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    day_start = _utc_day_start_epoch()
    jobs = _actor_jobs(context)
    backups = _actor_backups(context)
    jobs_today = sum(1 for job in jobs if float(job.get("created_at") or 0) >= day_start)
    backups_today = sum(1 for backup in backups if _timestamp_to_epoch(str(backup.get("created_at") or "")) >= day_start)
    backup_storage_bytes = sum(int(backup.get("archive_bytes") or 0) for backup in backups if backup.get("archive_exists", True))
    projects_count = len(list_projects(context=context))
    return {
        "status": "reported",
        "actor": _public_context(context),
        "window": {"day_start": _utc_timestamp_from_epoch(day_start)},
        "limits": _quota_limits(context),
        "usage": {
            "jobs_today": jobs_today,
            "backups_today": backups_today,
            "backup_storage_bytes": backup_storage_bytes,
            "projects_count": projects_count,
        },
    }


def _utc_timestamp_from_epoch(value: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))


def _quota_remaining(limit: int | None, used: int, *, pending: int = 0) -> bool:
    return limit is None or used + pending <= limit


def _enforce_job_quota(context: dict[str, Any] | None) -> None:
    summary = quota_summary(context=context)
    limit = summary["limits"].get("daily_job_limit")
    used = int(summary["usage"]["jobs_today"])
    if not _quota_remaining(limit, used, pending=1):
        raise PermissionError(f"daily job quota exceeded: {used}/{limit}")


def _enforce_backup_quota(context: dict[str, Any] | None, *, archive_bytes: int) -> None:
    summary = quota_summary(context=context)
    daily_limit = summary["limits"].get("daily_backup_limit")
    backups_today = int(summary["usage"]["backups_today"])
    if not _quota_remaining(daily_limit, backups_today, pending=1):
        raise PermissionError(f"daily backup quota exceeded: {backups_today}/{daily_limit}")
    storage_limit = summary["limits"].get("backup_storage_bytes_limit")
    storage_used = int(summary["usage"]["backup_storage_bytes"])
    if not _quota_remaining(storage_limit, storage_used, pending=archive_bytes):
        raise PermissionError(f"backup storage quota exceeded: {storage_used + archive_bytes}/{storage_limit}")


def _enforce_project_quota(context: dict[str, Any] | None) -> None:
    summary = quota_summary(context=context)
    limit = summary["limits"].get("max_projects")
    used = int(summary["usage"]["projects_count"])
    if not _quota_remaining(limit, used, pending=1):
        raise PermissionError(f"project quota exceeded: {used}/{limit}")


def append_audit(event: str, *, status: str = "ok", **details: Any) -> dict[str, Any]:
    payload = {
        "ts": _utc_timestamp(),
        "event": event,
        "status": status,
        "details": details,
    }
    path = RUNTIME_ROOT / "audit" / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, ensure_ascii=False)
    with AUDIT_LOCK:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    return payload


def read_audit_events(*, limit: int = 100) -> list[dict[str, Any]]:
    path = RUNTIME_ROOT / "audit" / "audit.jsonl"
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            events.append(payload)
    return events[-max(0, limit):]


def _project_from_value(value: str | None, *, context: dict[str, Any] | None = None) -> Path:
    if not value:
        raise ValueError("project is required")
    raw = Path(value).expanduser()
    candidate = raw if raw.is_absolute() else PROJECTS_ROOT / raw
    candidate = candidate.resolve()
    root = PROJECTS_ROOT.resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"project must be under {root}")
    if not (candidate / "project.json").exists():
        raise ValueError(f"project.json not found: {candidate}")
    if context is not None:
        _authorize_project_access(context, candidate)
    return candidate


def _project_file(project: str, relative: str, *, context: dict[str, Any] | None = None) -> Path:
    project_path = _project_from_value(project, context=context)
    target = (project_path / relative).resolve()
    if target != project_path and project_path not in target.parents:
        raise ValueError("file path escapes project")
    return target


def _export_skip(relative: str, *, include_data: bool) -> bool:
    if relative.endswith(".DS_Store") or "__pycache__/" in relative or relative.endswith(".pyc"):
        return True
    if not include_data and any(relative.startswith(prefix) for prefix in DEFAULT_EXPORT_EXCLUDE_PREFIXES):
        return True
    return False


def export_project_archive(
    project: str | Path,
    *,
    include_data: bool = False,
    context: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    project_path = _project_from_value(str(project), context=context) if not isinstance(project, Path) else project.resolve()
    if not (project_path / "project.json").exists():
        raise ValueError(f"project.json not found: {project_path}")
    if context is not None:
        _authorize_project_access(context, project_path)
        _authorize_data_export(context, include_data=include_data)
    buffer = io.BytesIO()
    files: list[str] = []
    skipped: list[str] = []
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(item for item in project_path.rglob("*") if item.is_file()):
            relative = path.relative_to(project_path).as_posix()
            if _export_skip(relative, include_data=include_data):
                skipped.append(relative)
                continue
            archive.write(path, f"{project_path.name}/{relative}")
            files.append(relative)
        manifest = {
            "project": project_path.name,
            "generated_at": _utc_timestamp(),
            "include_data": include_data,
            "file_count": len(files),
            "skipped_count": len(skipped),
            "skipped_prefixes": [] if include_data else list(DEFAULT_EXPORT_EXCLUDE_PREFIXES),
        }
        archive.writestr(f"{project_path.name}/export_manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return buffer.getvalue(), {"status": "exported", **manifest, "archive_bytes": len(buffer.getvalue())}


def _backup_manifest_paths() -> list[Path]:
    root = _backups_root()
    if not root.exists():
        return []
    return sorted(root.glob("*/*.manifest.json"))


def _backup_payload_for_context(payload: dict[str, Any], context: dict[str, Any] | None) -> dict[str, Any]:
    public = dict(payload)
    if str((context or {}).get("role") or "") != "admin":
        public.pop("archive_path", None)
        public.pop("manifest_path", None)
    return public


def create_project_backup(
    project: str | Path,
    *,
    include_data: bool = False,
    reason: str = "manual",
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin", "operator"})
    archive, export_manifest = export_project_archive(project, include_data=include_data, context=context)
    _enforce_backup_quota(context, archive_bytes=len(archive))
    project_slug = str(export_manifest["project"])
    created_at = _utc_timestamp()
    backup_id = f"{project_slug}-{_safe_slug(created_at)}-{uuid.uuid4().hex[:8]}"
    backup_dir = _backups_root() / project_slug
    backup_dir.mkdir(parents=True, exist_ok=True)
    archive_path = backup_dir / f"{backup_id}.zip"
    manifest_path = backup_dir / f"{backup_id}.manifest.json"
    archive_path.write_bytes(archive)
    manifest = {
        "schema_version": "draftpaper.project-backup/v1",
        "status": "available",
        "backup_id": backup_id,
        "project": project_slug,
        "created_at": created_at,
        "reason": str(reason or "manual"),
        "include_data": include_data,
        "actor": context.get("id"),
        "workspace": context.get("workspace"),
        "archive_path": str(archive_path),
        "manifest_path": str(manifest_path),
        "archive_sha256": _sha256_bytes(archive),
        "archive_bytes": len(archive),
        "file_count": export_manifest.get("file_count"),
        "skipped_count": export_manifest.get("skipped_count"),
        "skipped_prefixes": export_manifest.get("skipped_prefixes"),
        "restore_supported": True,
    }
    _write_json(manifest_path, manifest)
    append_audit(
        "project_backup_created",
        actor=str(context.get("id") or "unknown"),
        project=project_slug,
        backup_id=backup_id,
        include_data=include_data,
        archive_bytes=len(archive),
    )
    return _backup_payload_for_context(manifest, context)


def list_project_backups(
    *,
    project: str | None = None,
    context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    context = context or _local_admin_context()
    backups: list[dict[str, Any]] = []
    for path in _backup_manifest_paths():
        payload = _read_json(path, {})
        if not isinstance(payload, dict):
            continue
        project_slug = str(payload.get("project") or path.parent.name)
        if project and project_slug != project:
            continue
        if not _project_slug_allowed(context, project_slug):
            continue
        archive_path = Path(str(payload.get("archive_path") or ""))
        payload["archive_exists"] = archive_path.exists()
        backups.append(_backup_payload_for_context(payload, context))
    return sorted(backups, key=lambda item: str(item.get("created_at") or ""), reverse=True)


def _backup_by_id(backup_id: str, *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    safe_id = _safe_slug(backup_id)
    for backup in list_project_backups(context=context):
        if backup.get("backup_id") == safe_id:
            return backup
    raise ValueError(f"backup not found: {safe_id}")


def _verify_backup_payload(backup: dict[str, Any]) -> dict[str, Any]:
    archive_path = Path(str(backup.get("archive_path") or ""))
    manifest_path = Path(str(backup.get("manifest_path") or ""))
    checks: list[dict[str, Any]] = []
    archive_exists = archive_path.exists()
    manifest_exists = manifest_path.exists()
    checks.append({"id": "manifest_exists", "passed": manifest_exists, "note": str(manifest_path)})
    checks.append({"id": "archive_exists", "passed": archive_exists, "note": str(archive_path)})
    actual_sha = ""
    zip_readable = False
    contains_project_json = False
    if archive_exists:
        try:
            actual_sha = _sha256_file(archive_path)
            expected_sha = str(backup.get("archive_sha256") or "")
            checks.append({"id": "archive_sha256", "passed": bool(expected_sha) and actual_sha == expected_sha, "note": actual_sha})
        except OSError as exc:
            checks.append({"id": "archive_sha256", "passed": False, "note": str(exc)})
        try:
            with zipfile.ZipFile(archive_path) as archive:
                names = archive.namelist()
                bad_member = archive.testzip()
                zip_readable = bad_member is None
                contains_project_json = any(name.endswith("/project.json") for name in names)
                checks.append({"id": "zip_readable", "passed": zip_readable, "note": bad_member or "ok"})
                checks.append({"id": "project_json_present", "passed": contains_project_json, "note": "project.json present" if contains_project_json else "missing project.json"})
        except (OSError, zipfile.BadZipFile) as exc:
            checks.append({"id": "zip_readable", "passed": False, "note": str(exc)})
            checks.append({"id": "project_json_present", "passed": False, "note": "zip unreadable"})
    else:
        checks.append({"id": "archive_sha256", "passed": False, "note": "archive missing"})
        checks.append({"id": "zip_readable", "passed": False, "note": "archive missing"})
        checks.append({"id": "project_json_present", "passed": False, "note": "archive missing"})
    passed = all(bool(item.get("passed")) for item in checks)
    return {
        "backup_id": backup.get("backup_id"),
        "project": backup.get("project"),
        "created_at": backup.get("created_at"),
        "include_data": backup.get("include_data"),
        "archive_bytes": backup.get("archive_bytes"),
        "archive_exists": archive_exists,
        "manifest_exists": manifest_exists,
        "actual_archive_sha256": actual_sha,
        "status": "verified" if passed else "attention",
        "checks": checks,
    }


def verify_project_backups(
    *,
    project: str | None = None,
    context: dict[str, Any] | None = None,
    record_audit: bool = True,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    backups = list_project_backups(project=project, context=context)
    items = [_verify_backup_payload(backup) for backup in backups]
    failed = [item for item in items if item["status"] != "verified"]
    payload = {
        "status": "verified" if not failed else "attention",
        "generated_at": _utc_timestamp(),
        "backups_root": str(_backups_root()),
        "project": project or "",
        "summary": {
            "total": len(items),
            "verified": len(items) - len(failed),
            "attention": len(failed),
        },
        "backups": items,
    }
    if record_audit:
        append_audit("project_backups_verified", actor=str(context.get("id") or "unknown"), project=project or "", total=len(items), attention=len(failed))
    return payload


def cleanup_project_backups(
    *,
    keep: int = 10,
    max_age_days: int | None = None,
    project: str | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    backups = list_project_backups(project=project, context=context)
    keep = max(0, keep)
    cutoff = time.time() - max_age_days * 86400 if max_age_days is not None and max_age_days >= 0 else None
    removed: list[str] = []
    for index, backup in enumerate(backups):
        created_epoch = _timestamp_to_epoch(str(backup.get("created_at") or ""))
        remove_by_count = index >= keep
        remove_by_age = cutoff is not None and created_epoch > 0 and created_epoch < cutoff
        if not (remove_by_count or remove_by_age):
            continue
        for key in ("archive_path", "manifest_path"):
            path = Path(str(backup.get(key) or ""))
            if path.exists() and _backups_root() in path.resolve().parents:
                path.unlink()
        removed.append(str(backup.get("backup_id") or ""))
    append_audit("project_backups_cleanup", actor=str(context.get("id") or "unknown"), removed_count=len(removed), keep=keep, max_age_days=max_age_days, project=project or "")
    return {"status": "cleaned", "removed_count": len(removed), "removed_backups": removed, "kept_backups": keep, "max_age_days": max_age_days}


def _zip_project_root(archive: zipfile.ZipFile) -> str:
    roots = {
        name.split("/", 1)[0]
        for name in archive.namelist()
        if name and not name.startswith("/") and "/" in name
    }
    if len(roots) != 1:
        raise ValueError("backup archive must contain exactly one project root")
    return next(iter(roots))


def _extract_backup_archive(archive_path: Path, destination_project: Path) -> dict[str, Any]:
    destination_project = destination_project.resolve()
    file_count = 0
    total_bytes = 0
    with zipfile.ZipFile(archive_path) as archive:
        root_name = _zip_project_root(archive)
        for member in archive.infolist():
            if member.is_dir():
                continue
            name = member.filename
            if name.startswith("/") or "\\" in name:
                raise ValueError("unsafe backup archive path")
            parts = name.split("/")
            if not parts or parts[0] != root_name or any(part in {"", ".", ".."} for part in parts[1:]):
                raise ValueError("unsafe backup archive path")
            relative = Path(*parts[1:])
            target_file = (destination_project / relative).resolve()
            if destination_project not in target_file.parents:
                raise ValueError("unsafe backup archive path")
            target_file.parent.mkdir(parents=True, exist_ok=True)
            data = archive.read(member)
            target_file.write_bytes(data)
            file_count += 1
            total_bytes += len(data)
    project_json = destination_project / "project.json"
    if not project_json.exists():
        raise ValueError("restored backup does not contain project.json")
    metadata = _read_json(project_json, {})
    if not isinstance(metadata, dict):
        raise ValueError("restored project.json must contain a JSON object")
    return {
        "archive_root": root_name,
        "file_count": file_count,
        "total_bytes": total_bytes,
        "project_id": metadata.get("project_id") or destination_project.name,
        "title": metadata.get("title") or metadata.get("idea") or destination_project.name,
        "field": metadata.get("field") or "",
    }


def append_backup_rehearsal(report: dict[str, Any]) -> dict[str, Any]:
    path = _backup_rehearsal_log()
    path.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOCK:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(report, ensure_ascii=False, sort_keys=True) + "\n")
    return report


def read_backup_rehearsals(*, limit: int = 200) -> list[dict[str, Any]]:
    path = _backup_rehearsal_log()
    if limit <= 0 or not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    events: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            events.append(payload)
    return events


def rehearse_project_backup(
    backup_id: str,
    *,
    context: dict[str, Any] | None = None,
    record_audit: bool = True,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    backup = _backup_by_id(backup_id, context=context)
    generated_at = _utc_timestamp()
    archive_path = Path(str(backup.get("archive_path") or ""))
    checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema_version": "draftpaper.backup-rehearsal/v1",
        "status": "failed",
        "generated_at": generated_at,
        "backup_id": backup.get("backup_id"),
        "project": backup.get("project"),
        "actor": context.get("id"),
        "workspace": context.get("workspace"),
        "archive_sha256": "",
        "checks": checks,
    }
    tmp_parent: Path | None = None
    try:
        if not archive_path.exists():
            raise ValueError(f"backup archive not found: {archive_path}")
        expected_sha = str(backup.get("archive_sha256") or "")
        actual_sha = _sha256_file(archive_path)
        report["archive_sha256"] = actual_sha
        checks.append({"id": "archive_sha256", "passed": not expected_sha or actual_sha == expected_sha, "note": actual_sha})
        if expected_sha and actual_sha != expected_sha:
            raise ValueError("backup archive checksum mismatch")
        RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
        tmp_parent = Path(tempfile.mkdtemp(prefix="rehearse-", dir=str(RUNTIME_ROOT)))
        rehearsal_slug = _safe_slug(str(backup.get("project") or "rehearsal")) or "rehearsal"
        extracted = _extract_backup_archive(archive_path, tmp_parent / rehearsal_slug)
        checks.append({"id": "safe_extract", "passed": True, "note": "archive extracted to temporary rehearsal directory"})
        checks.append({"id": "project_json_present", "passed": True, "note": str(extracted.get("project_id") or rehearsal_slug)})
        report.update(
            {
                "status": "passed",
                "archive_root": extracted.get("archive_root"),
                "file_count": extracted.get("file_count"),
                "total_bytes": extracted.get("total_bytes"),
                "project_id": extracted.get("project_id"),
                "title": extracted.get("title"),
                "field": extracted.get("field"),
                "temporary_path_removed": True,
            }
        )
    except Exception as exc:
        checks.append({"id": "restore_rehearsal", "passed": False, "note": str(exc)})
        report["error"] = str(exc)
    finally:
        if tmp_parent is not None:
            shutil.rmtree(tmp_parent, ignore_errors=True)
    if record_audit:
        append_backup_rehearsal(report)
        append_audit(
            "project_backup_rehearsed",
            status=str(report.get("status") or "failed"),
            actor=str(context.get("id") or "unknown"),
            backup_id=str(backup.get("backup_id") or ""),
            project=str(backup.get("project") or ""),
        )
    return report


def rehearse_project_backups(
    *,
    project: str | None = None,
    backup_id: str | None = None,
    context: dict[str, Any] | None = None,
    record_audit: bool = True,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    backups = [_backup_by_id(backup_id, context=context)] if backup_id else list_project_backups(project=project, context=context)
    reports = [
        rehearse_project_backup(str(backup.get("backup_id") or ""), context=context, record_audit=record_audit)
        for backup in backups
    ]
    failed = [item for item in reports if item.get("status") != "passed"]
    return {
        "status": "passed" if not failed else "attention",
        "generated_at": _utc_timestamp(),
        "project": project or "",
        "backup_id": backup_id or "",
        "summary": {
            "total": len(reports),
            "passed": len(reports) - len(failed),
            "failed": len(failed),
        },
        "rehearsals": reports,
    }


def backup_rehearsal_summary(
    *,
    project: str | None = None,
    context: dict[str, Any] | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    backups = list_project_backups(project=project, context=context)
    latest: dict[str, dict[str, Any]] = {}
    for event in read_backup_rehearsals(limit=limit):
        backup_id = str(event.get("backup_id") or "")
        if not backup_id:
            continue
        if backup_id not in latest or str(event.get("generated_at") or "") > str(latest[backup_id].get("generated_at") or ""):
            latest[backup_id] = event
    items: list[dict[str, Any]] = []
    missing_or_stale = 0
    failed = 0
    for backup in backups:
        backup_id = str(backup.get("backup_id") or "")
        expected_sha = str(backup.get("archive_sha256") or "")
        event = latest.get(backup_id)
        passed = bool(event) and event.get("status") == "passed" and (not expected_sha or event.get("archive_sha256") == expected_sha)
        stale = bool(event) and bool(expected_sha) and event.get("archive_sha256") != expected_sha
        if not passed:
            missing_or_stale += 1
            if event and event.get("status") != "passed":
                failed += 1
        items.append(
            {
                "backup_id": backup_id,
                "project": backup.get("project"),
                "status": "passed" if passed else ("stale" if stale else ("failed" if event else "missing")),
                "created_at": backup.get("created_at"),
                "archive_sha256": expected_sha,
                "last_rehearsed_at": event.get("generated_at") if event else "",
                "last_rehearsal_status": event.get("status") if event else "",
            }
        )
    return {
        "status": "passed" if backups and missing_or_stale == 0 else ("no_backups" if not backups else "attention"),
        "generated_at": _utc_timestamp(),
        "project": project or "",
        "summary": {
            "total_backups": len(backups),
            "passed": len(backups) - missing_or_stale,
            "missing_or_stale": missing_or_stale,
            "failed": failed,
        },
        "backups": items,
    }


def restore_project_backup(
    backup_id: str,
    *,
    target_slug: str | None = None,
    overwrite: bool = False,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    backup = _backup_by_id(backup_id, context=context)
    archive_path = Path(str(backup.get("archive_path") or ""))
    if not archive_path.exists():
        raise ValueError(f"backup archive not found: {archive_path}")
    expected_sha = str(backup.get("archive_sha256") or "")
    actual_sha = _sha256_file(archive_path)
    if expected_sha and actual_sha != expected_sha:
        raise ValueError("backup archive checksum mismatch")
    slug = _safe_slug(target_slug or str(backup.get("project") or ""))
    if not slug:
        raise ValueError("target_slug is required")
    target_path = (PROJECTS_ROOT / slug).resolve()
    if PROJECTS_ROOT.resolve() not in target_path.parents:
        raise ValueError("target project escapes projects root")
    if target_path.exists() and not overwrite:
        raise ValueError(f"target project already exists: {slug}")

    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    tmp_parent = Path(tempfile.mkdtemp(prefix="restore-", dir=str(RUNTIME_ROOT)))
    tmp_project = tmp_parent / slug
    try:
        _extract_backup_archive(archive_path, tmp_project)
        PROJECTS_ROOT.mkdir(parents=True, exist_ok=True)
        if target_path.exists():
            shutil.rmtree(target_path)
        shutil.move(str(tmp_project), str(target_path))
    finally:
        shutil.rmtree(tmp_parent, ignore_errors=True)
    append_audit("project_backup_restored", actor=str(context.get("id") or "unknown"), backup_id=str(backup.get("backup_id")), project=slug, overwrite=overwrite)
    return {"status": "restored", "backup_id": backup.get("backup_id"), "project": slug, "path": str(target_path), "archive_sha256": actual_sha}


def _job_visible(context: dict[str, Any] | None, job: dict[str, Any]) -> bool:
    if context is None:
        return False
    if str(context.get("role")) == "admin":
        return True
    actor = str(context.get("id") or "")
    if actor and job.get("actor") == actor:
        return True
    project = str(job.get("project") or "")
    if not project:
        return False
    try:
        project_path = _project_from_value(project)
    except ValueError:
        return False
    return _project_allowed(context, project_path)


def _active_job_count(*, context: dict[str, Any] | None = None) -> int:
    jobs = JOBS.values()
    if context is not None:
        jobs = [job for job in jobs if _job_visible(context, job)]
    return sum(1 for job in jobs if job.get("status") not in TERMINAL_JOB_STATUSES)


def usage_summary(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    with JOBS_LOCK:
        jobs = [job for job in JOBS.values() if _job_visible(context, job)]
        status_counts: dict[str, int] = {}
        action_counts: dict[str, int] = {}
        for job in jobs:
            status = str(job.get("status") or "unknown")
            action = str(job.get("action") or "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
            action_counts[action] = action_counts.get(action, 0) + 1
        active_count = sum(1 for job in jobs if job.get("status") not in TERMINAL_JOB_STATUSES)
    projects = list_projects(context=context)
    audit_events = read_audit_events(limit=10000)
    backups = list_project_backups(context=context)
    billing_config = _billing_config()
    return {
        "status": "reported",
        "projects_count": len(projects),
        "jobs_count": len(jobs),
        "backups_count": len(backups),
        "active_jobs": active_count,
        "max_concurrent_jobs": _max_concurrent_jobs(),
        "job_status_counts": status_counts,
        "job_action_counts": action_counts,
        "audit_event_count": len(audit_events) if str((context or {}).get("role")) == "admin" else None,
        "runtime_root": str(RUNTIME_ROOT),
        "backups_root": str(_backups_root()),
        "access_policy": access_policy_summary(context=context),
        "quota": quota_summary(context=context),
        "billing": {
            "status": "available",
            "config_status": billing_config["status"],
            "currency": billing_config["currency"],
        },
    }


def _support_job_snapshot(job: dict[str, Any]) -> dict[str, Any]:
    snapshot = {
        key: value
        for key, value in job.items()
        if key not in {"command", "stdout", "stderr"}
    }
    snapshot["command_length"] = len(job.get("command") or [])
    snapshot["stdout_bytes"] = len(str(job.get("stdout") or "").encode("utf-8"))
    snapshot["stderr_bytes"] = len(str(job.get("stderr") or "").encode("utf-8"))
    snapshot["output_omitted"] = True
    return snapshot


def _zip_support_json(
    archive: zipfile.ZipFile,
    prefix: str,
    name: str,
    payload: Any,
    entries: list[dict[str, Any]],
) -> None:
    relative = f"{prefix}/{name}"
    raw = json.dumps(_redact_for_support(payload), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    archive.writestr(relative, raw)
    entries.append({"path": name, "bytes": len(raw), "sha256": _sha256_bytes(raw)})


def build_support_bundle(*, context: dict[str, Any] | None = None) -> tuple[bytes, dict[str, Any]]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    generated_at = _utc_timestamp()
    prefix = f"draftpaper-support-{_safe_slug(generated_at)}"
    with JOBS_LOCK:
        jobs = sorted(
            (dict(job) for job in JOBS.values()),
            key=lambda item: item.get("created_at") or 0,
            reverse=True,
        )[:SUPPORT_BUNDLE_JOB_LIMIT]
    projects = list_projects(context=context)
    audit_events = read_audit_events(limit=SUPPORT_BUNDLE_AUDIT_LIMIT)
    manifest = {
        "schema_version": "draftpaper.support-bundle/v1",
        "status": "generated",
        "generated_at": generated_at,
        "actor": _public_context(context),
        "repo_root": str(REPO_ROOT),
        "projects_root": str(PROJECTS_ROOT),
        "runtime_root": str(RUNTIME_ROOT),
        "job_limit": SUPPORT_BUNDLE_JOB_LIMIT,
        "audit_limit": SUPPORT_BUNDLE_AUDIT_LIMIT,
        "privacy": {
            "redacted_value": SUPPORT_REDACTED,
            "redacted_key_parts": list(SUPPORT_SENSITIVE_KEY_PARTS),
            "redacted_path_roots": True,
            "includes_project_files": False,
            "includes_raw_or_processed_data": False,
            "notes": [
                "This bundle contains local diagnostic metadata only.",
                "It does not include project artifact files, raw data, processed data, private config files, or release archives.",
            ],
        },
    }
    payloads = {
        "health.json": {
            "status": "ok",
            "service": "DraftpaperLoop",
            "repo_root": str(REPO_ROOT),
            "projects_root": str(PROJECTS_ROOT),
            "python": PYTHON_BIN,
            "cli_importable": status_project is not None,
            "auth_required": _auth_required(),
        },
        "commercial_readiness.json": commercial_readiness(),
        "handoff_readiness.json": handoff_readiness(context=context),
        "hosted_readiness.json": hosted_readiness_summary(context=context),
        "security_audit.json": security_audit(context=context),
        "license.json": license_grant_summary(context=context),
        "license_entitlements.json": license_entitlement_summary(context=context),
        "claim_confirmation.json": claim_confirmation_summary(context=context),
        "license_approval.json": commercial_approval_summary(context=context),
        "release_trust.json": release_trust_summary(context=context),
        "security_review.json": security_review_summary(context=context),
        "access_policy.json": access_policy_summary(context=context),
        "usage.json": usage_summary(context=context),
        "quota.json": quota_summary(context=context),
        "billing.json": billing_report(context=context),
        "backup_verification.json": verify_project_backups(context=context, record_audit=False),
        "backup_rehearsals.json": backup_rehearsal_summary(context=context),
        "projects.json": {
            "status": "listed",
            "projects_root": str(PROJECTS_ROOT),
            "projects_count": len(projects),
            "projects": projects,
        },
        "jobs.json": {
            "status": "listed",
            "jobs_count": len(jobs),
            "jobs": [_support_job_snapshot(job) for job in jobs],
        },
        "audit.json": {
            "status": "listed",
            "events_count": len(audit_events),
            "events": audit_events,
        },
        "service_console_manifest.json": _read_json(REPO_ROOT / "service-console.manifest.json", {}),
    }
    buffer = io.BytesIO()
    entries: list[dict[str, Any]] = []
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in payloads.items():
            _zip_support_json(archive, prefix, name, payload, entries)
        manifest["files"] = entries
        _zip_support_json(archive, prefix, "support_manifest.json", manifest, entries)
    archive_bytes = buffer.getvalue()
    public_manifest = _redact_for_support({**manifest, "archive_bytes": len(archive_bytes), "archive_sha256": _sha256_bytes(archive_bytes)})
    return archive_bytes, public_manifest


def _stage_counts(metadata: dict[str, Any]) -> dict[str, int]:
    counts = {"draft": 0, "pending": 0, "stale": 0, "completed": 0, "approved": 0, "failed": 0, "other": 0}
    for stage in (metadata.get("stages") or {}).values():
        if not isinstance(stage, dict):
            continue
        if stage.get("stale"):
            counts["stale"] += 1
            continue
        status = str(stage.get("status") or "other")
        counts[status if status in counts else "other"] += 1
    return counts


def _outputs(project_path: Path) -> list[dict[str, Any]]:
    candidates = [
        "references/literature_review_notes.html",
        "research_plan/research_plan.zh-CN.md",
        "research_plan/research_plan.md",
        "journal_profile/journal_profile.json",
        "data/data_inventory.json",
        "data/data_quality_report.json",
        "data/data_feasibility_report.json",
        "method_plan/method_requirements.json",
        "results/figure_plan.html",
        "core_evidence/core_evidence_report.html",
        "latex/main.pdf",
        "quality_checks/quality_report.json",
    ]
    found = []
    for relative in candidates:
        path = project_path / relative
        if path.exists():
            found.append({"path": relative, "size": path.stat().st_size, "mtime": path.stat().st_mtime})
    return sorted(found, key=lambda item: item["mtime"], reverse=True)[:10]


def project_summary(project_path: Path) -> dict[str, Any]:
    metadata = _read_json(project_path / "project.json", {})
    payload: dict[str, Any] = {
        "project_id": metadata.get("project_id") or project_path.name,
        "slug": project_path.name,
        "path": str(project_path),
        "title": metadata.get("title") or metadata.get("idea") or project_path.name,
        "field": metadata.get("field", ""),
        "target_journal": metadata.get("target_journal", ""),
        "current_stage": metadata.get("current_stage", ""),
        "stage_counts": _stage_counts(metadata),
        "outputs": _outputs(project_path),
    }
    if status_project is not None:
        try:
            status = status_project(project_path)
            payload["pipeline_state"] = status.get("pipeline_state")
            payload["next_action"] = status.get("next_action")
        except Exception as exc:
            payload["pipeline_state"] = "error"
            payload["next_action"] = {"command": "status", "reason": str(exc)}
    return payload


def _stage_manifest_path(project_path: Path, stage: str, stage_meta: dict[str, Any]) -> Path:
    raw = str(stage_meta.get("manifest") or "").strip()
    if raw:
        return (project_path / raw).resolve()
    return (project_path / ("quality_checks" if stage == "quality_checks" else stage) / "stage_manifest.json").resolve()


def _stage_outputs(project_path: Path, manifest: dict[str, Any]) -> tuple[list[str], list[str]]:
    outputs = [str(item) for item in manifest.get("output_files") or [] if str(item).strip()]
    missing = [relative for relative in outputs if not (project_path / relative).exists()]
    return outputs, missing


def _stage_current(stage_meta: dict[str, Any], *, manifest_exists: bool, missing_outputs: list[str]) -> bool:
    return (
        str(stage_meta.get("status") or "") in {"draft", "approved", "completed"}
        and not bool(stage_meta.get("stale"))
        and manifest_exists
        and not missing_outputs
    )


def project_stage_graph(project: str | Path, *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    project_path = _project_from_value(str(project), context=context) if not isinstance(project, Path) else project.expanduser().resolve()
    if context is not None:
        _authorize_project_access(context, project_path)
    metadata = _read_json(project_path / "project.json", {})
    stages = metadata.get("stages") if isinstance(metadata.get("stages"), dict) else {}
    ordered = [stage for stage in STAGE_ORDER if stage in stages]
    ordered.extend(stage for stage in stages if stage not in ordered)
    stage_index = {stage: index for index, stage in enumerate(ordered)}
    reverse_deps: dict[str, list[str]] = {stage: [] for stage in ordered}
    edges: list[dict[str, str]] = []
    for stage in ordered:
        stage_meta = stages.get(stage) if isinstance(stages.get(stage), dict) else {}
        for dependency in [str(item) for item in stage_meta.get("depends_on") or []]:
            edges.append({"from": dependency, "to": stage})
            reverse_deps.setdefault(dependency, []).append(stage)

    nodes: list[dict[str, Any]] = []
    current_stages: set[str] = set()
    stale_stages: list[str] = []
    failed_stages: list[str] = []
    for stage in ordered:
        stage_meta = stages.get(stage) if isinstance(stages.get(stage), dict) else {}
        manifest_path = _stage_manifest_path(project_path, stage, stage_meta)
        manifest = _read_json(manifest_path, {}) if manifest_path.exists() else {}
        outputs, missing_outputs = _stage_outputs(project_path, manifest)
        is_current = _stage_current(stage_meta, manifest_exists=manifest_path.exists(), missing_outputs=missing_outputs)
        if is_current:
            current_stages.add(stage)
        if bool(stage_meta.get("stale")):
            stale_stages.append(stage)
        if str(stage_meta.get("status") or "") == "failed":
            failed_stages.append(stage)
        blocked_by = [
            dependency
            for dependency in [str(item) for item in stage_meta.get("depends_on") or []]
            if dependency not in current_stages
        ]
        node_state = "current" if is_current else "stale" if bool(stage_meta.get("stale")) else str(stage_meta.get("status") or "pending")
        if missing_outputs and node_state in {"draft", "approved", "completed"}:
            node_state = "missing_outputs"
        nodes.append(
            {
                "id": stage,
                "order": stage_index.get(stage, 999),
                "status": str(stage_meta.get("status") or "pending"),
                "state": node_state,
                "stale": bool(stage_meta.get("stale")),
                "is_current": is_current,
                "is_active": stage == metadata.get("current_stage"),
                "blocked_by": blocked_by,
                "dependents": sorted(reverse_deps.get(stage, []), key=lambda item: stage_index.get(item, 999)),
                "depends_on": [str(item) for item in stage_meta.get("depends_on") or []],
                "manifest": str(manifest_path.relative_to(project_path)) if project_path in manifest_path.parents or manifest_path == project_path else str(manifest_path),
                "manifest_exists": manifest_path.exists(),
                "output_count": len(outputs),
                "missing_outputs": missing_outputs[:20],
                "last_updated": stage_meta.get("last_updated"),
            }
        )

    status: dict[str, Any] = {}
    if status_project is not None:
        try:
            status = status_project(project_path)
        except Exception as exc:
            status = {"pipeline_state": "error", "next_action": {"command": "status", "reason": str(exc)}}
    next_action = status.get("next_action") if isinstance(status.get("next_action"), dict) else {}
    next_stage = str(next_action.get("stage") or "")
    for node in nodes:
        node["is_next"] = bool(next_stage and node["id"] == next_stage)

    return {
        "schema_version": "draftpaper.stage-graph/v1",
        "status": "reported",
        "project": {
            "id": metadata.get("project_id") or project_path.name,
            "slug": project_path.name,
            "title": metadata.get("title") or metadata.get("idea") or project_path.name,
            "path": str(project_path) if (context or {}).get("role") == "admin" else "",
        },
        "pipeline_state": status.get("pipeline_state") or "unknown",
        "current_stage": metadata.get("current_stage"),
        "next_action": next_action,
        "summary": {
            "stages": len(nodes),
            "current": sum(1 for node in nodes if node["is_current"]),
            "stale": len(stale_stages),
            "failed": len(failed_stages),
            "blocked": sum(1 for node in nodes if node["blocked_by"]),
            "missing_outputs": sum(1 for node in nodes if node["missing_outputs"]),
        },
        "stale_propagation": {
            "stale_stages": stale_stages,
            "edges": [edge for edge in edges if edge["to"] in stale_stages or edge["from"] in stale_stages],
        },
        "nodes": nodes,
        "edges": sorted(edges, key=lambda edge: (stage_index.get(edge["from"], 999), stage_index.get(edge["to"], 999))),
        "notes": [
            "This graph is read-only and derived from project.json plus stage_manifest.json files.",
            "Blocked means at least one declared dependency is not current; stale means an upstream change should be reviewed before continuing.",
        ],
    }


def list_projects(*, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    PROJECTS_ROOT.mkdir(parents=True, exist_ok=True)
    return sorted(
        (
            project_summary(path.parent)
            for path in PROJECTS_ROOT.glob("*/project.json")
            if context is None or _project_allowed(context, path.parent.resolve())
        ),
        key=lambda item: item["slug"].lower(),
    )


def _commercial_capability_checks() -> list[tuple[str, bool, str]]:
    return [
        ("core_cli", True, "Staged loop CLI is present."),
        ("tests", (REPO_ROOT / "tests").exists(), "Unit tests are present."),
        ("service_console_manifest", (REPO_ROOT / "service-console.manifest.json").exists(), "Service Console manifest is present."),
        ("local_console", (REPO_ROOT / "scripts" / "serviceconsole_app.py").exists(), "Local operator console is present."),
        ("optional_auth", True, "Operator API supports optional DRAFTPAPER_CONSOLE_TOKEN protection."),
        ("local_access_policy", True, "Optional local users file supports role, project-scope, action-scope, and data-export controls."),
        ("project_export", True, "Project artifacts can be exported as a zip handoff package."),
        ("backup_retention", True, "Project backups, restore, checksum verification, and retention cleanup are available locally."),
        ("backup_integrity_audit", True, "Admin backup verification can audit every local backup archive for presence, checksum, zip readability, and project metadata."),
        ("backup_restore_rehearsal", True, "Admin backup restore rehearsal can safely extract backups to a temporary directory and record DR evidence without overwriting projects."),
        ("release_packaging", (REPO_ROOT / "scripts" / "package_release.py").exists(), "Source release packages can be generated with manifest and SHA256 checksums."),
        ("release_verification", (REPO_ROOT / "scripts" / "verify_release_package.py").exists(), "Release packages can be verified independently for zip SHA256, internal file checksums, manifest coverage, required files, and private-file exclusions."),
        ("release_signing", (REPO_ROOT / "scripts" / "package_release.py").exists() and (REPO_ROOT / "scripts" / "verify_release_package.py").exists() and shutil.which("openssl") is not None, "Release packages can be signed and verified with an OpenSSL detached SHA256 signature."),
        ("release_trust_verification", (REPO_ROOT / "scripts" / "verify_release_trust.py").exists(), "External release trust evidence can be verified against a specific release package, manifest, signature, and public key."),
        ("release_trust_preparation", (REPO_ROOT / "scripts" / "prepare_release_trust.py").exists(), "Private release trust drafts can be prepared from a signed release package and sidecar hashes."),
        ("paid_handoff_config_generation", (REPO_ROOT / "scripts" / "generate_handoff_config.py").exists(), "Paid local handoff runtime config can be generated from the console without hand-written license, users, billing, or env files."),
        ("commercial_approval_preparation", (REPO_ROOT / "scripts" / "prepare_commercial_approval.py").exists(), "Private commercial approval drafts can be prepared from the license grant and commercial boundary document hashes."),
        ("claim_confirmation_preparation", (REPO_ROOT / "scripts" / "prepare_claim_confirmation.py").exists(), "Private claim confirmation drafts can be prepared from project artifacts with hashes for user/domain review."),
        ("claim_confirmation_verification", (REPO_ROOT / "scripts" / "verify_claim_confirmation.py").exists(), "Private user/domain confirmation evidence can be verified for manuscript claims, project binding, and referenced artifact hashes."),
        ("audit_log", True, "Operator actions are recorded in a local audit log."),
        ("usage_controls", True, "Local usage reporting and job concurrency limits are available."),
        ("job_timeline_retry", True, "Jobs keep a local event timeline and terminal jobs can be retried from their saved request payload."),
        ("stage_dependency_graph", True, "Project stage dependency graph exposes current, stale, blocked, and missing-output stages for operator review."),
        ("support_bundle", True, "Admin support bundle exports redacted local diagnostics for customer handoff and support escalation."),
        ("support_bundle_verification", (REPO_ROOT / "scripts" / "verify_support_bundle.py").exists(), "Support bundles can be independently verified for required diagnostics, redaction, private-file exclusions, and manifest hashes."),
        ("handoff_acceptance_report", (REPO_ROOT / "scripts" / "run_handoff_acceptance.py").exists(), "Customer handoff acceptance checks can be run as a saved JSON evidence report."),
        ("sample_workflow_acceptance", (REPO_ROOT / "scripts" / "run_sample_workflow_acceptance.py").exists(), "Offline sample workflow acceptance can prove project creation, reference import, data gates, generated analysis code, figure rendering, and result-validity gates without external services."),
        ("handoff_dossier", (REPO_ROOT / "scripts" / "build_handoff_dossier.py").exists(), "Customer-facing handoff evidence dossiers can be generated without full runtime payloads or private token material."),
        ("handoff_dossier_verification", (REPO_ROOT / "scripts" / "verify_handoff_dossier.py").exists(), "Customer handoff dossiers can be independently verified for digest, sidecar, release, and private-file checks."),
        ("commercial_launch_package", (REPO_ROOT / "scripts" / "build_commercial_launch_package.py").exists() and (REPO_ROOT / "scripts" / "verify_commercial_launch_package.py").exists(), "Commercial launch packages can bundle and independently reverify release, handoff, support, and hosted readiness evidence."),
        ("commercial_operations_report", (REPO_ROOT / "scripts" / "build_commercial_operations_report.py").exists() and (REPO_ROOT / "scripts" / "verify_commercial_operations_report.py").exists(), "Commercial operations reports can summarize and verify customer-safe post-handoff health, billing, quota, backup, license, and launch-package evidence."),
        ("commercial_acceptance_suite", (REPO_ROOT / "scripts" / "run_commercial_acceptance_suite.py").exists() and (REPO_ROOT / "scripts" / "verify_commercial_acceptance_suite.py").exists(), "The full release, handoff, dossier, launch, and operations acceptance chain can be run and independently verified as one private operator evidence suite."),
        ("commercial_acceptance_suite_console", True, "The full commercial acceptance suite can be run and reverified from the console."),
        ("verified_release_install", (REPO_ROOT / "scripts" / "install_verified_release.py").exists(), "Verified release packages can be extracted only after release and optional dossier verification."),
        ("installed_release_smoke", (REPO_ROOT / "scripts" / "smoke_installed_release.py").exists(), "Extracted customer installs can be smoke-tested without network calls or customer data imports."),
        ("hosted_evidence_collection", (REPO_ROOT / "scripts" / "collect_hosted_readiness_evidence.py").exists(), "Hosted readiness evidence can be collected from a real hosted URL into a private hashed evidence draft before SaaS acceptance."),
        ("hosted_evidence_collection_verification", (REPO_ROOT / "scripts" / "verify_hosted_evidence_collection.py").exists(), "Hosted evidence collection reports can be independently verified for artifact hashes, draft boundaries, and redaction before SaaS acceptance."),
        ("hosted_readiness_preparation", (REPO_ROOT / "scripts" / "prepare_hosted_readiness.py").exists(), "Verified hosted probes and operator external-control evidence can be assembled into hosted-readiness.json with hash checks before SaaS acceptance."),
        ("hosted_readiness_finalization", True, "The console can finalize completed hosted controls into a private hosted-readiness.json and optionally activate it for the current process."),
        ("hosted_readiness_dossier", (REPO_ROOT / "scripts" / "build_hosted_readiness_dossier.py").exists() and (REPO_ROOT / "scripts" / "verify_hosted_readiness_dossier.py").exists(), "Hosted SaaS readiness evidence can be packaged and independently verified without embedding raw private readiness files."),
        ("hosted_production_acceptance", (REPO_ROOT / "scripts" / "run_hosted_production_acceptance.py").exists(), "Hosted production acceptance can probe the actual hosted URL and compare API readiness, private evidence, and hosted readiness dossier status."),
        ("production_deployment_artifacts", (REPO_ROOT / "scripts" / "verify_production_deployment_artifacts.py").exists() and (REPO_ROOT / "deploy" / "production" / "Dockerfile").exists(), "Production deployment artifacts for container and systemd hosted operation are present and independently verifiable."),
        ("local_quota_controls", True, "Local actor quotas can limit daily jobs, backups, backup storage, and project count."),
        ("local_billing_reports", True, "Local billing reports can summarize usage and configured rate estimates by actor/workspace."),
        ("security_audit", True, "Local security audit reports host/auth, secret-file, users-policy, release-package, and license-boundary checks."),
        ("security_review_verification", (REPO_ROOT / "scripts" / "verify_security_review.py").exists(), "Formal third-party security review evidence can be verified for scope, artifacts, and unresolved critical/high findings."),
        ("security_review_preparation", (REPO_ROOT / "scripts" / "prepare_security_review.py").exists(), "Private security review drafts can be prepared from a saved local security audit report."),
        ("local_license_grant", True, "Offline commercial license grant records can be validated for paid pilot/customer handoff without remote activation."),
        ("license_entitlement_audit", True, "Offline entitlement audit compares the license grant with configured seats, workspaces, customers, and action scopes."),
        ("commercial_approval_verification", (REPO_ROOT / "scripts" / "verify_commercial_approval.py").exists(), "Private commercial approval evidence can be verified against license grant hashes and commercial boundary document hashes."),
        ("bounded_live_search", True, "Live search supports provider, timeout, and query-count limits."),
        ("license_boundary", (REPO_ROOT / "COMMERCIAL_LICENSE.md").exists(), "Commercial license boundary is documented."),
        ("compliance_boundary", (REPO_ROOT / "COMPLIANCE.md").exists(), "Compliance boundary is documented."),
    ]


def _readiness_track(track_id: str, label: str, gates: list[dict[str, Any]], *, forced_status: str | None = None) -> dict[str, Any]:
    failed_errors = [item for item in gates if item.get("severity") == "error" and not item.get("passed")]
    failed_warnings = [item for item in gates if item.get("severity") == "warning" and not item.get("passed")]
    if forced_status is not None:
        status = forced_status
    elif failed_errors:
        status = "blocked"
    elif failed_warnings:
        status = "attention"
    else:
        status = "ready"
    return {
        "id": track_id,
        "label": label,
        "status": status,
        "summary": {
            "total": len(gates),
            "passed": sum(1 for item in gates if item.get("passed")),
            "errors": len(failed_errors),
            "warnings": len(failed_warnings),
        },
        "gates": gates,
    }


def _next_readiness_actions(tracks: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    for track in tracks:
        for gate in track.get("gates", []):
            if gate.get("passed"):
                continue
            remediation = str(gate.get("remediation") or "").strip()
            note = str(gate.get("note") or gate.get("id") or "").strip()
            action = remediation or note
            if action and action not in actions:
                actions.append(action)
    return actions[:10]


def handoff_readiness(*, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin"})
    capability_checks = _commercial_capability_checks()
    capability_map = {item_id: ok for item_id, ok, _ in capability_checks}
    security = security_audit(context=context)
    license_report = license_grant_summary(context=context)
    entitlement_report = license_entitlement_summary(context=context)
    claim_confirmation_report = claim_confirmation_summary(context=context)
    approval_report = commercial_approval_summary(context=context)
    release_trust_report = release_trust_summary(context=context)
    security_review_report = security_review_summary(context=context)
    backup_report = verify_project_backups(context=context, record_audit=False)
    rehearsal = backup_rehearsal_summary(context=context)
    billing_config = _billing_config()
    hosted_report = hosted_readiness_summary(context=context)
    security_errors_clear = int(security.get("summary", {}).get("errors") or 0) == 0
    backup_total = int(backup_report.get("summary", {}).get("total") or 0)

    local_pilot_gates = [
        _security_check("core_cli", bool(capability_map.get("core_cli")), "error", "Staged loop CLI is present.", "Restore the draftpaper CLI package."),
        _security_check("service_console", bool(capability_map.get("local_console")) and bool(capability_map.get("service_console_manifest")), "error", "Local operator console and Service Console manifest are present.", "Restore scripts/serviceconsole_app.py and service-console.manifest.json."),
        _security_check("test_suite_present", bool(capability_map.get("tests")), "error", "Unit test suite is present.", "Restore tests before offering assisted delivery."),
        _security_check("security_errors_clear", security_errors_clear, "error", "Local security audit has no error findings.", "Run /api/security-audit and fix every severity=error finding."),
        _security_check("release_packaging", bool(capability_map.get("release_packaging")), "error", "Release packaging with manifest and SHA256 is available.", "Restore scripts/package_release.py."),
        _security_check("release_verification", bool(capability_map.get("release_verification")), "error", "Release verifier is available for customer-side package integrity checks.", "Restore scripts/verify_release_package.py."),
        _security_check("release_signing", bool(capability_map.get("release_signing")), "warning", "OpenSSL detached release signing is available.", "Install openssl and use scripts/package_release.py --signing-key for signed handoff packages."),
        _security_check("stage_dependency_graph", bool(capability_map.get("stage_dependency_graph")), "error", "Project stage dependency graph is available for stale propagation and next-action review.", "Restore /api/project-stage-graph and the console Stage graph view."),
        _security_check("support_bundle", bool(capability_map.get("support_bundle")), "error", "Support bundle export is available for diagnostics.", "Restore /api/support-bundle."),
        _security_check("support_bundle_verification", bool(capability_map.get("support_bundle_verification")), "error", "Support bundle verifier is available for independent redaction and manifest checks.", "Restore scripts/verify_support_bundle.py."),
        _security_check("handoff_acceptance_report", bool(capability_map.get("handoff_acceptance_report")), "error", "Handoff acceptance report runner is available for saved customer evidence.", "Restore scripts/run_handoff_acceptance.py."),
        _security_check("sample_workflow_acceptance", bool(capability_map.get("sample_workflow_acceptance")), "error", "Offline sample workflow acceptance runner is available for customer-repeatable functional proof.", "Restore scripts/run_sample_workflow_acceptance.py."),
        _security_check("handoff_dossier", bool(capability_map.get("handoff_dossier")), "error", "Customer-facing handoff dossier builder is available.", "Restore scripts/build_handoff_dossier.py."),
        _security_check("handoff_dossier_verification", bool(capability_map.get("handoff_dossier_verification")), "error", "Customer-facing handoff dossier verifier is available.", "Restore scripts/verify_handoff_dossier.py."),
        _security_check("commercial_launch_package", bool(capability_map.get("commercial_launch_package")), "error", "Commercial launch package builder and verifier are available.", "Restore scripts/build_commercial_launch_package.py and scripts/verify_commercial_launch_package.py."),
        _security_check("commercial_operations_report", bool(capability_map.get("commercial_operations_report")), "error", "Commercial operations report builder and verifier are available.", "Restore scripts/build_commercial_operations_report.py and scripts/verify_commercial_operations_report.py."),
        _security_check("commercial_acceptance_suite", bool(capability_map.get("commercial_acceptance_suite")), "error", "Commercial acceptance suite runner and verifier are available for one-command private delivery evidence.", "Restore scripts/run_commercial_acceptance_suite.py and scripts/verify_commercial_acceptance_suite.py."),
        _security_check("commercial_acceptance_suite_console", bool(capability_map.get("commercial_acceptance_suite_console")), "error", "Commercial acceptance suite can be run from the console.", "Restore /api/commercial-acceptance-suite."),
        _security_check("verified_release_install", bool(capability_map.get("verified_release_install")), "error", "Verified release install helper is available.", "Restore scripts/install_verified_release.py."),
        _security_check("installed_release_smoke", bool(capability_map.get("installed_release_smoke")), "error", "Installed release smoke tester is available.", "Restore scripts/smoke_installed_release.py."),
    ]

    paid_handoff_gates = [
        _security_check("commercial_license_valid", license_report.get("status") == "valid", "error", "A local commercial license grant is valid.", "Set DRAFTPAPER_LICENSE_FILE to a valid paid customer grant before handoff."),
        _security_check("license_entitlements_valid", entitlement_report.get("status") == "passed", "error", "License seats, workspaces, customers, and action scopes match configured local access.", "Run /api/license-entitlements and fix every severity=error finding before paid handoff."),
        _security_check("access_control_configured", _auth_required(), "error", "Console authentication is configured for customer/operator handoff.", "Set DRAFTPAPER_CONSOLE_USERS_FILE with hashed tokens or DRAFTPAPER_CONSOLE_TOKEN."),
        _security_check("security_errors_clear", security_errors_clear, "error", "Local security audit has no error findings.", "Run /api/security-audit and fix every severity=error finding."),
        _security_check("backups_verified", backup_report.get("status") == "verified", "error", "All visible local backups pass integrity verification.", "Run /api/backups/verify and repair or remove attention backups."),
        _security_check("backup_sample_present", backup_total > 0, "warning", "At least one backup exists for restore rehearsal evidence.", "Create and verify a backup before a paid customer handoff."),
        _security_check("backup_restore_rehearsal", rehearsal.get("status") == "passed", "error", "Current visible backups have passed a restore rehearsal with matching archive checksums.", "Run POST /api/backups/rehearse and fix failed or stale backups before paid handoff."),
        _security_check("billing_rates_configured", billing_config.get("status") == "configured", "warning", "Billing rates are configured for local pilot reconciliation.", "Set DRAFTPAPER_BILLING_RATES_FILE when charging by usage."),
        _security_check("paid_handoff_config_generation", bool(capability_map.get("paid_handoff_config_generation")), "error", "Paid handoff config generator is available in the console.", "Restore scripts/generate_handoff_config.py and /api/paid-handoff-config."),
        _security_check("support_bundle", bool(capability_map.get("support_bundle")), "error", "Support bundle export is available for diagnostics.", "Restore /api/support-bundle."),
        _security_check("support_bundle_verification", bool(capability_map.get("support_bundle_verification")), "error", "Support bundle verifier is available for independent redaction and manifest checks.", "Restore scripts/verify_support_bundle.py."),
        _security_check("sample_workflow_acceptance", bool(capability_map.get("sample_workflow_acceptance")), "error", "Offline sample workflow acceptance runner is available for customer-repeatable functional proof.", "Restore scripts/run_sample_workflow_acceptance.py."),
        _security_check("stage_dependency_graph", bool(capability_map.get("stage_dependency_graph")), "error", "Project stage dependency graph is available for customer/operator stale propagation review.", "Restore /api/project-stage-graph and the console Stage graph view."),
        _security_check("handoff_dossier", bool(capability_map.get("handoff_dossier")), "error", "Customer-facing handoff dossier builder is available.", "Restore scripts/build_handoff_dossier.py."),
        _security_check("handoff_dossier_verification", bool(capability_map.get("handoff_dossier_verification")), "error", "Customer-facing handoff dossier verifier is available.", "Restore scripts/verify_handoff_dossier.py."),
        _security_check("commercial_launch_package", bool(capability_map.get("commercial_launch_package")), "error", "Commercial launch package builder and verifier are available.", "Restore scripts/build_commercial_launch_package.py and scripts/verify_commercial_launch_package.py."),
        _security_check("commercial_operations_report", bool(capability_map.get("commercial_operations_report")), "error", "Commercial operations report builder and verifier are available.", "Restore scripts/build_commercial_operations_report.py and scripts/verify_commercial_operations_report.py."),
        _security_check("commercial_acceptance_suite", bool(capability_map.get("commercial_acceptance_suite")), "error", "Commercial acceptance suite runner and verifier are available for one-command private delivery evidence.", "Restore scripts/run_commercial_acceptance_suite.py and scripts/verify_commercial_acceptance_suite.py."),
        _security_check("verified_release_install", bool(capability_map.get("verified_release_install")), "error", "Verified release install helper is available.", "Restore scripts/install_verified_release.py."),
        _security_check("installed_release_smoke", bool(capability_map.get("installed_release_smoke")), "error", "Installed release smoke tester is available.", "Restore scripts/smoke_installed_release.py."),
    ]

    hosted_saas_gates = [
        *list(hosted_report.get("gates") or []),
        _security_check("hosted_evidence_collection", bool(capability_map.get("hosted_evidence_collection")), "error", "Hosted evidence collector is available for private hashed live URL evidence capture.", "Restore scripts/collect_hosted_readiness_evidence.py."),
        _security_check("hosted_evidence_collection_verification", bool(capability_map.get("hosted_evidence_collection_verification")), "error", "Hosted evidence collection verifier is available for independent artifact hash and redaction checks.", "Restore scripts/verify_hosted_evidence_collection.py."),
        _security_check("hosted_readiness_preparation", bool(capability_map.get("hosted_readiness_preparation")), "error", "Hosted readiness preparation helper is available to fail closed while assembling verified probes and operator evidence.", "Restore scripts/prepare_hosted_readiness.py."),
        _security_check("hosted_readiness_finalization", bool(capability_map.get("hosted_readiness_finalization")), "error", "Hosted readiness finalization is available from the console after operator controls are completed.", "Restore the /api/hosted-readiness-finalize route."),
        _security_check("hosted_production_acceptance", bool(capability_map.get("hosted_production_acceptance")), "error", "Hosted production acceptance runner is available for external hosted URL verification.", "Restore scripts/run_hosted_production_acceptance.py."),
        _security_check("production_deployment_artifacts", bool(capability_map.get("production_deployment_artifacts")), "error", "Production deployment artifacts and verifier are available for container/systemd hosted operation.", "Restore deploy/production/* and scripts/verify_production_deployment_artifacts.py."),
    ]

    tracks = [
        _readiness_track("local_operator_pilot", "Local operator pilot", local_pilot_gates),
        _readiness_track("paid_local_handoff", "Paid local customer handoff", paid_handoff_gates),
        _readiness_track(
            "hosted_saas",
            "Hosted SaaS / enterprise platform",
            hosted_saas_gates,
            forced_status="not_ready" if hosted_report.get("status") == "not_ready" else None,
        ),
    ]
    if tracks[2]["status"] == "ready":
        grade = "hosted_saas_ready"
    elif tracks[1]["status"] == "ready":
        grade = "paid_local_handoff_ready"
    elif tracks[0]["status"] == "ready":
        grade = "local_operator_pilot_ready"
    else:
        grade = "not_ready"
    return {
        "status": "assessed",
        "generated_at": _utc_timestamp(),
        "commercial_grade": grade,
        "tracks": tracks,
        "security_summary": security.get("summary"),
        "license_status": license_report.get("status"),
        "license_entitlement_status": entitlement_report.get("status"),
        "commercial_approval_status": approval_report.get("status"),
        "claim_confirmation_status": claim_confirmation_report.get("status"),
        "release_trust_status": release_trust_report.get("status"),
        "security_review_status": security_review_report.get("status"),
        "backup_summary": backup_report.get("summary"),
        "backup_rehearsal_summary": rehearsal.get("summary"),
        "billing_config_status": billing_config.get("status"),
        "hosted_readiness_status": hosted_report.get("status"),
        "next_required_actions": _next_readiness_actions(tracks),
        "notes": [
            "Local operator pilot readiness does not imply paid customer handoff readiness.",
            "Paid local handoff readiness does not imply hosted SaaS or enterprise platform readiness.",
        ],
    }


def commercial_readiness() -> dict[str, Any]:
    checks = _commercial_capability_checks()
    passed = sum(1 for _, ok, _ in checks if ok)
    handoff = handoff_readiness(context=_local_admin_context())
    claim_confirmation = claim_confirmation_summary(context=_local_admin_context())
    approval = commercial_approval_summary(context=_local_admin_context())
    release_trust = release_trust_summary(context=_local_admin_context())
    security_review = security_review_summary(context=_local_admin_context())
    hosted_track = next((track for track in handoff["tracks"] if track.get("id") == "hosted_saas"), {})
    hosted_gaps = [
        str(gate.get("remediation") or gate.get("note") or gate.get("id"))
        for gate in hosted_track.get("gates", [])
        if not gate.get("passed")
    ]
    remaining_gaps = [
        "Manuscript claim/domain confirmation evidence is not configured." if claim_confirmation.get("status") != "verified" else "",
        "Real customer handoff still needs configured external commercial approval evidence." if approval.get("status") != "verified" else "",
        "Certificate-backed code signing, notarization, or third-party release trust evidence is not configured." if release_trust.get("status") != "verified" else "",
        "Formal third-party security review evidence is not configured." if security_review.get("status") != "verified" else "",
        *hosted_gaps,
    ]
    remaining_gaps = list(dict.fromkeys(item for item in remaining_gaps if item))
    return {
        "status": "assessed",
        "score": round(passed / len(checks), 2),
        "commercial_grade": handoff["commercial_grade"],
        "readiness_tracks": handoff["tracks"],
        "checks": [{"id": item_id, "passed": ok, "note": note} for item_id, ok, note in checks],
        "remaining_gaps": remaining_gaps,
    }


def _add_arg(args: list[str], flag: str, value: Any) -> None:
    if value is None or value == "":
        return
    if isinstance(value, list):
        for item in value:
            if item is not None and str(item) != "":
                args.extend([flag, str(item)])
        return
    args.extend([flag, str(value)])


def cli_command(
    action_id: str,
    payload: dict[str, Any],
    *,
    context: dict[str, Any] | None = None,
) -> tuple[list[str], dict[str, str]]:
    if context is not None:
        _authorize_action(context, action_id)
    if action_id == "create-project":
        if context is not None:
            _enforce_project_quota(context)
        idea = str(payload.get("idea") or "").strip()
        field = str(payload.get("field") or "").strip()
        if not idea or not field:
            raise ValueError("idea and field are required")
        args = [
            PYTHON_BIN, "-m", "draftpaper_cli.cli", "create-project",
            "--root", str(PROJECTS_ROOT),
            "--idea", idea,
            "--field", field,
            "--target-journal", str(payload.get("target_journal") or "General Academic Journal"),
        ]
        if payload.get("overwrite"):
            args.append("--overwrite")
        return args, {}

    action = ACTION_REGISTRY.get(action_id)
    if not action:
        raise ValueError(f"unknown action: {action_id}")
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    project_path = _project_from_value(str(payload.get("project") or ""), context=context)
    args = [PYTHON_BIN, "-m", "draftpaper_cli.cli", str(action["command"]), "--project", str(project_path)]
    if action_id.startswith("search-literature"):
        _add_arg(args, "--query", params.get("query"))
        _add_arg(args, "--limit", params.get("limit"))
        if action_id == "search-literature-from-json":
            _add_arg(args, "--from-json", params.get("from_json"))
    elif action_id == "resolve-journal-template":
        _add_arg(args, "--target-journal", params.get("target_journal"))
        _add_arg(args, "--from-html", params.get("from_html"))
        _add_arg(args, "--guideline-url", params.get("guideline_url"))
        _add_arg(args, "--overleaf-url", params.get("overleaf_url"))
    elif action_id == "collect-method-plan":
        notes = params.get("method_note") or params.get("method_notes") or []
        if isinstance(notes, str):
            notes = [notes]
        _add_arg(args, "--method-note", notes)
        _add_arg(args, "--primary-metric", params.get("primary_metric"))
        _add_arg(args, "--minimum-primary-metric", params.get("minimum_primary_metric"))
    elif action_id in {"plan-figures", "generate-analysis-code"}:
        if params.get("use_review_tasks"):
            args.append("--use-review-tasks")
        if action_id == "generate-analysis-code" and params.get("auto_plan_figures"):
            args.append("--auto-plan-figures")
    elif action_id == "audit-citations" and params.get("final", True):
        args.append("--final")
    return args, dict(action.get("env") or {})


def _persist_job(job: dict[str, Any]) -> None:
    _write_json(RUNTIME_ROOT / "jobs" / f"{_safe_slug(str(job['id']))}.json", job)


def _job_event(job: dict[str, Any], event: str, *, status: str | None = None, **details: Any) -> dict[str, Any]:
    payload = {
        "ts": _utc_timestamp(),
        "event": event,
        "status": status if status is not None else job.get("status"),
        "details": details,
    }
    events = job.setdefault("events", [])
    if isinstance(events, list):
        events.append(payload)
        if len(events) > 200:
            del events[:-200]
    else:
        job["events"] = [payload]
    return payload


def _load_jobs() -> None:
    for path in (RUNTIME_ROOT / "jobs").glob("*.json"):
        job = _read_json(path, {})
        if isinstance(job, dict) and job.get("id"):
            if job.get("status") in {"queued", "running", "cancelling"}:
                job["status"] = "unknown"
                job["finished_at"] = job.get("finished_at") or time.time()
                job["stderr"] = (str(job.get("stderr") or "") + "\nConsole restarted before this job reported completion. Check project artifacts before retrying.").strip()
                _job_event(job, "console_restarted", status="unknown", message="Console restarted before this job reported completion.")
                _persist_job(job)
            JOBS[str(job["id"])] = job


def cancel_job(job_id: str, *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    _require_role(context or _local_admin_context(), {"admin", "operator"})
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise ValueError("job not found")
        if context is not None and not _job_visible(context, job):
            raise PermissionError("job is outside this actor's access scope")
        if job.get("status") in TERMINAL_JOB_STATUSES:
            return job
        job["cancel_requested"] = True
        _job_event(job, "cancel_requested", status=str(job.get("status") or "unknown"))
        process = JOB_PROCESSES.get(job_id)
        if process is None or process.poll() is not None:
            job["status"] = "cancelled"
            job["finished_at"] = time.time()
            job["returncode"] = process.returncode if process is not None else None
            _job_event(job, "cancelled", status="cancelled", immediate=True)
            _persist_job(job)
            append_audit("job_cancelled", status="cancelled", job_id=job_id, immediate=True)
            return job
        job["status"] = "cancelling"
        _job_event(job, "cancelling", status="cancelling", pid=process.pid)
        _persist_job(job)

    try:
        process.terminate()
    except ProcessLookupError:
        pass
    append_audit("job_cancel_requested", status="cancelling", job_id=job_id, pid=process.pid)
    return job


def job_events(job_id: str, *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise ValueError("job not found")
        if context is not None and not _job_visible(context, job):
            raise PermissionError("job is outside this actor's access scope")
        events = list(job.get("events") or [])
    return {"status": "listed", "job_id": job_id, "events": events}


def retry_job(job_id: str, *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or _local_admin_context()
    _require_role(context, {"admin", "operator"})
    with JOBS_LOCK:
        source = JOBS.get(job_id)
        if not source:
            raise ValueError("job not found")
        if not _job_visible(context, source):
            raise PermissionError("job is outside this actor's access scope")
        if source.get("status") not in TERMINAL_JOB_STATUSES:
            raise ValueError("only terminal jobs can be retried")
        action = str(source.get("action") or "")
        payload = source.get("request_payload")
        if not isinstance(payload, dict):
            raise ValueError("job does not contain retryable request payload")
        _job_event(source, "retry_requested", status=str(source.get("status") or "unknown"))
        _persist_job(source)
    retry = start_job(action, dict(payload), context=context, retry_of=job_id)
    append_audit("job_retry_queued", actor=str(context.get("id") or "unknown"), source_job_id=job_id, retry_job_id=retry["id"], action=action)
    return {"status": "queued", "source_job": source, "job": retry}


def cleanup_jobs(*, keep: int = 20, context: dict[str, Any] | None = None) -> dict[str, Any]:
    _require_role(context or _local_admin_context(), {"admin", "operator"})
    with JOBS_LOCK:
        terminal = [
            job
            for job in JOBS.values()
            if job.get("status") in TERMINAL_JOB_STATUSES and (context is None or _job_visible(context, job))
        ]
        terminal.sort(key=lambda item: item.get("created_at") or 0, reverse=True)
        removable = terminal[max(0, keep):]
        removed = []
        for job in removable:
            job_id = str(job.get("id") or "")
            if not job_id:
                continue
            JOBS.pop(job_id, None)
            path = RUNTIME_ROOT / "jobs" / f"{_safe_slug(job_id)}.json"
            if path.exists():
                path.unlink()
            removed.append(job_id)
    append_audit("jobs_cleanup", removed_count=len(removed), kept_terminal_jobs=keep)
    return {"status": "cleaned", "removed_count": len(removed), "removed_jobs": removed, "kept_terminal_jobs": keep}


def delete_job(job_id: str, *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    _require_role(context or _local_admin_context(), {"admin", "operator"})
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise ValueError("job not found")
        if context is not None and not _job_visible(context, job):
            raise PermissionError("job is outside this actor's access scope")
        if job.get("status") not in TERMINAL_JOB_STATUSES:
            raise ValueError("only terminal jobs can be cleared")
        JOBS.pop(job_id, None)
        path = RUNTIME_ROOT / "jobs" / f"{_safe_slug(job_id)}.json"
        if path.exists():
            path.unlink()
    append_audit("job_deleted", job_id=job_id)
    return {"status": "deleted", "job_id": job_id}


def start_job(
    action: str,
    payload: dict[str, Any],
    *,
    context: dict[str, Any] | None = None,
    retry_of: str | None = None,
) -> dict[str, Any]:
    context = context or _local_admin_context()
    _authorize_action(context, action)
    command, extra_env = cli_command(action, payload, context=context)
    label = "Create project" if action == "create-project" else ACTION_REGISTRY[action]["label"]
    project_value = "" if action == "create-project" else str(payload.get("project") or "")
    project_slug = ""
    if project_value:
        project_slug = _project_from_value(project_value, context=context).name
    attempt = 1
    if retry_of:
        source_attempt = 1
        source_job = JOBS.get(retry_of)
        if source_job is not None:
            source_attempt = _optional_int(source_job.get("attempt"), minimum=1) or 1
        previous_retries = sum(1 for item in JOBS.values() if str(item.get("retry_of") or "") == str(retry_of))
        attempt = source_attempt + previous_retries + 1
    job = {
        "id": uuid.uuid4().hex[:12],
        "action": action,
        "label": label,
        "status": "queued",
        "command": command,
        "request_payload": payload,
        "actor": context.get("id"),
        "workspace": context.get("workspace"),
        "project": project_slug,
        "retry_of": retry_of or "",
        "attempt": attempt,
        "created_at": time.time(),
        "started_at": None,
        "finished_at": None,
        "returncode": None,
        "stdout": "",
        "stderr": "",
    }
    _job_event(job, "queued", status="queued", action=action, project=project_slug, retry_of=retry_of or "")
    with JOBS_LOCK:
        active_count = _active_job_count()
        max_concurrent = _max_concurrent_jobs()
        if active_count >= max_concurrent:
            raise ValueError(f"max concurrent jobs reached: {active_count}/{max_concurrent}")
        actor_max = context.get("max_concurrent_jobs")
        if actor_max:
            actor_active = _active_job_count(context=context)
            if actor_active >= int(actor_max):
                raise ValueError(f"max concurrent jobs reached for actor {context.get('id')}: {actor_active}/{actor_max}")
        _enforce_job_quota(context)
        JOBS[job["id"]] = job
        _persist_job(job)
    append_audit("job_queued", actor=str(context.get("id") or "unknown"), workspace=str(context.get("workspace") or ""), project=project_slug, action=action, job_id=job["id"], label=label)

    def run() -> None:
        env = os.environ.copy()
        env.update(extra_env)
        with JOBS_LOCK:
            if job.get("cancel_requested"):
                job["status"] = "cancelled"
                job["finished_at"] = time.time()
                _job_event(job, "cancelled_before_start", status="cancelled")
                _persist_job(job)
                return
            job["started_at"] = time.time()
            try:
                process = subprocess.Popen(
                    command,
                    cwd=str(REPO_ROOT),
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            except Exception as exc:
                job["status"] = "failed"
                job["finished_at"] = time.time()
                job["returncode"] = None
                job["stderr"] = str(exc)
                _job_event(job, "start_failed", status="failed", message=str(exc))
                _persist_job(job)
                return
            JOB_PROCESSES[job["id"]] = process
            job["pid"] = process.pid
            job["status"] = "running"
            _job_event(job, "started", status="running", pid=process.pid)
            _persist_job(job)
        stdout, stderr = process.communicate()
        with JOBS_LOCK:
            JOB_PROCESSES.pop(job["id"], None)
            if job.get("cancel_requested"):
                job["status"] = "cancelled"
            else:
                job["status"] = "succeeded" if process.returncode == 0 else "failed"
            job["finished_at"] = time.time()
            job["returncode"] = process.returncode
            job["stdout"] = stdout[-20000:]
            job["stderr"] = stderr[-20000:]
            _job_event(job, "finished", status=str(job["status"]), returncode=process.returncode)
            _persist_job(job)
        append_audit("job_finished", status=str(job["status"]), action=action, job_id=job["id"], returncode=process.returncode)

    threading.Thread(target=run, daemon=True).start()
    return job


def _body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length") or "0")
    if length <= 0:
        return {}
    payload = json.loads(handler.rfile.read(length).decode("utf-8"))
    return payload if isinstance(payload, dict) else {}


def _json(handler: BaseHTTPRequestHandler, payload: Any, status: int = 200) -> None:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _text(handler: BaseHTTPRequestHandler, body: str, status: int = 200, content_type: str = "text/plain; charset=utf-8") -> None:
    raw = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _binary(handler: BaseHTTPRequestHandler, body: bytes, *, filename: str, content_type: str = "application/octet-stream") -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _unauthorized(handler: BaseHTTPRequestHandler) -> None:
    body = json.dumps({"status": "error", "message": "authorization required"}, ensure_ascii=False).encode("utf-8")
    handler.send_response(HTTPStatus.UNAUTHORIZED)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("WWW-Authenticate", 'Bearer realm="DraftpaperLoop"')
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def index_html() -> str:
    actions = json.dumps([{"id": key, **value} for key, value in ACTION_REGISTRY.items()], ensure_ascii=False)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Draftpaper Loop Console</title>
<style>
:root{{--bg:#f6f8fb;--panel:#fff;--line:#d8dee8;--ink:#18212b;--muted:#637083;--accent:#1d7874;--warn:#9a5a00;--bad:#a6333a}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
header{{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:18px 22px;background:#fff;border-bottom:1px solid var(--line);position:sticky;top:0}}
h1{{font-size:20px;margin:0}} h2{{font-size:15px;margin:0 0 10px}} main{{display:grid;grid-template-columns:360px 1fr;gap:18px;padding:18px;max-width:1440px;margin:auto}}
section{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}} .stack{{display:grid;gap:12px}} .row{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}
label{{display:grid;gap:4px;color:var(--muted);font-size:12px}} label.check{{display:flex;align-items:center;gap:6px}} label.check input{{width:auto}} input,select{{width:100%;border:1px solid #bcc7d5;border-radius:6px;padding:7px 8px}}
button{{border:1px solid #b8c4d2;background:#fff;border-radius:6px;padding:7px 10px;cursor:pointer}} button.primary{{background:var(--accent);color:#fff;border-color:var(--accent)}}
.token-inline{{display:flex;align-items:center;gap:6px}} .token-inline input{{width:160px}} .token-status.bad{{color:var(--bad)}} .token-status.ok{{color:var(--accent)}}
.project{{border:1px solid var(--line);border-radius:8px;padding:10px;display:grid;gap:8px;cursor:pointer}} .project.active{{border-color:var(--accent);box-shadow:0 0 0 2px rgba(29,120,116,.12)}}
.title{{font-weight:650}} .muted{{color:var(--muted)}} .chips{{display:flex;gap:6px;flex-wrap:wrap}} .chip{{border:1px solid var(--line);border-radius:999px;padding:2px 7px;font-size:12px;background:#f8fafc}} .chip.warn{{color:var(--warn);border-color:#e6c27e;background:#fff8e8}} .chip.bad{{color:var(--bad);border-color:#e3a2a7;background:#fff0f1}}
.readiness-head{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px}} .metric{{border:1px solid var(--line);border-radius:8px;padding:9px;background:#fbfcfe}} .metric b{{display:block;font-size:18px}} .track-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px}} .track{{border:1px solid var(--line);border-left-width:4px;border-radius:8px;padding:9px;background:#fff}} .track.ready{{border-left-color:var(--accent)}} .track.warn{{border-left-color:var(--warn)}} .track.bad{{border-left-color:var(--bad)}} .next-list{{margin:0;padding-left:18px;color:var(--muted)}} .next-list li{{margin:3px 0}}
.stage-graph{{display:grid;gap:6px;margin-top:10px}} .stage-node{{border:1px solid var(--line);border-left-width:4px;border-radius:8px;padding:8px;background:#fff}} .stage-node.ready{{border-left-color:var(--accent)}} .stage-node.warn{{border-left-color:var(--warn)}} .stage-node.bad{{border-left-color:var(--bad)}} .stage-node.next{{box-shadow:0 0 0 2px rgba(29,120,116,.12)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px}} pre{{margin:0;white-space:pre-wrap;word-break:break-word;background:#0f1720;color:#dbe7f3;padding:12px;border-radius:8px;max-height:360px;overflow:auto}} .job{{border-top:1px solid var(--line);padding:10px 0}} .job:first-child{{border-top:0;padding-top:0}} .outputs a{{display:block;color:#0b5cad;text-decoration:none;padding:4px 0}}
@media(max-width:920px){{main{{grid-template-columns:1fr}} header{{align-items:flex-start;flex-direction:column}}}}
</style></head>
<body>
<header><div><h1>Draftpaper Loop Console</h1><div class="muted">Local projects: {PROJECTS_ROOT}</div></div><div class="row"><div class="token-inline"><input id="tokenInput" type="password" autocomplete="off" placeholder="Operator token"><button id="saveTokenBtn">Save token</button><span id="tokenStatus" class="token-status muted"></span></div><button id="tokenBtn">Token</button><button id="refreshBtn">Refresh</button><button id="accessBtn">Access</button><button id="usageBtn">Usage</button><button id="quotaBtn">Quota</button><button id="billingBtn">Billing</button><button id="licenseBtn">License</button><button id="entitlementsBtn">Entitlements</button><button id="paidConfigBtn">Paid Config</button><button id="suiteBtn">Suite</button><button id="claimsBtn">Claims</button><button id="approvalBtn">Approval</button><button id="approvalDraftBtn">Approval Draft</button><button id="trustBtn">Trust</button><button id="trustDraftBtn">Trust Draft</button><button id="secReviewBtn">Sec Review</button><button id="secReviewDraftBtn">Sec Draft</button><button id="hostedDraftBtn">Hosted Draft</button><button id="hostedFinalizeBtn">Hosted Final</button><button id="hostedDossierBtn">Hosted Dossier</button><button id="hostedAcceptBtn">Hosted Accept</button><button id="backupsBtn">Backups</button><button id="rehearsalsBtn">Rehearsals</button><button id="auditBtn">Audit</button><button id="securityBtn">Security</button><button id="supportBtn">Support</button><button id="readinessBtn">Readiness</button><button id="handoffBtn">Handoff</button></div></header>
<main>
<div class="stack">
<section><h2>Create project</h2><div class="stack"><label>Idea<input id="idea" placeholder="Research idea"></label><label>Field<input id="field" placeholder="machine learning astronomy"></label><label>Target journal<input id="targetJournal" placeholder="General Academic Journal"></label><button class="primary" id="createBtn">Create</button></div></section>
<section><h2>Projects</h2><div id="projects" class="stack"></div></section>
</div>
<div class="stack">
<section><div class="row" style="justify-content:space-between"><h2>Commercial readiness</h2><button id="refreshReadinessBtn">Refresh readiness</button></div><div id="readinessSummary" class="stack"><div class="muted">Loading readiness.</div></div></section>
<section><h2>Selected project</h2><div id="selected" class="muted">No project selected.</div></section>
<section><h2>Actions</h2><div class="row"><label style="flex:1">Action<select id="actionSelect"></select></label><label style="width:120px">Limit<input id="limit" type="number" min="1" max="50" value="12"></label></div><div class="grid" style="margin-top:8px"><label>Query<input id="query"></label><label>JSON path<input id="fromJson"></label><label>HTML template path<input id="fromHtml"></label><label>Method note<input id="methodNote"></label><label>Release zip path<input id="releaseZipPath" placeholder="/path/to/release.zip"></label><label>Handoff customer ID<input id="handoffCustomerId" placeholder="CUST-A"></label><label>Handoff customer name<input id="handoffCustomerName" placeholder="Customer A"></label><label>Handoff output dir<input id="handoffOutputDir" placeholder="/path/to/handoff-CUST-A"></label><label>Handoff expires<input id="handoffExpiresAt" placeholder="2099-12-31"></label><label>Handoff seats<input id="handoffSeats" type="number" min="1" value="1"></label><label>Handoff workspace<input id="handoffWorkspace" placeholder="customer-workspace"></label><label>Operator ID<input id="handoffOperatorId" placeholder="customer-admin"></label><label>Billing currency<input id="handoffCurrency" placeholder="USD"></label><label>Job rate<input id="handoffJobRate" type="number" min="0" step="0.01" value="0"></label><label>Backup rate<input id="handoffBackupRate" type="number" min="0" step="0.01" value="0"></label><label>Storage GB-month rate<input id="handoffStorageRate" type="number" min="0" step="0.01" value="0"></label><label>License signing key<input id="handoffSigningKey" placeholder="/path/to/license-signing.pem"></label><label>Suite output dir<input id="suiteOutputDir" placeholder="/path/to/commercial-suite"></label><label>Suite track<select id="suiteTargetTrack"><option value="paid_local_handoff">paid_local_handoff</option><option value="hosted_saas">hosted_saas</option></select></label><label>Suite version label<input id="suiteVersionLabel" placeholder="CUST-A-paid-handoff"></label><label>Suite public key<input id="suitePublicKey" placeholder="/path/to/public.pem"></label><label>Suite timeout<input id="suiteTimeout" type="number" min="1" step="1" value="5"></label><label class="check"><input id="handoffCanExportData" type="checkbox">Data export</label><label class="check"><input id="handoffActivate" type="checkbox">Activate</label><label>Hosted base URL<input id="hostedBaseUrl" placeholder="https://draftpaper.example.com"></label><label>Hosted collection report<input id="hostedCollectionReportPath" placeholder="/path/to/hosted-readiness-evidence-collection.json"></label><label>Hosted controls file<input id="hostedControlsPath" placeholder="/path/to/hosted-readiness-controls.json"></label><label>Hosted evidence file<input id="hostedEvidenceFilePath" placeholder="/path/to/hosted-readiness.json"></label><label>Hosted output file<input id="hostedOutputPath" placeholder="/path/to/hosted-readiness.json"></label><label>Hosted dossier dir<input id="hostedDossierOutputDir" placeholder="/path/to/hosted-readiness-dossier"></label><label>Hosted dossier zip<input id="hostedDossierZipPath" placeholder="/path/to/hosted-readiness-dossier.zip"></label><label>Customer ID<input id="hostedCustomerId" placeholder="CUST-A"></label><label>Customer name<input id="hostedCustomerName" placeholder="Customer A"></label><label>Acceptance output<input id="hostedAcceptanceOutputPath" placeholder="/path/to/hosted-production-acceptance.json"></label><label class="check"><input id="hostedAllowLocal" type="checkbox">Local rehearsal</label><label class="check"><input id="hostedAllowHttp" type="checkbox">Allow HTTP</label></div><div class="row" style="margin-top:10px"><button class="primary" id="runBtn">Run action</button><button id="statusBtn">Status</button><button id="syncBtn">Sync stale</button></div></section>
<section><div class="row" style="justify-content:space-between"><h2>Jobs</h2><button id="cleanupJobsBtn">Cleanup</button></div><div id="jobs"></div></section>
<section><h2>Output</h2><pre id="output">Ready.</pre></section>
</div>
</main>
<script>
const actions={actions}; let selected=null; let projects=[]; let readinessCache={{commercial:null,handoff:null}};
const sel=document.getElementById('actionSelect'); for(const a of actions){{const o=document.createElement('option');o.value=a.id;o.textContent=`${{a.category}} / ${{a.label}}`;sel.appendChild(o);}}
const queryToken=new URLSearchParams(location.search).get('token'); if(queryToken) localStorage.setItem('draftpaperConsoleToken',queryToken);
const tokenInput=document.getElementById('tokenInput'); const tokenStatus=document.getElementById('tokenStatus'); tokenInput.value=localStorage.getItem('draftpaperConsoleToken')||'';
function setTokenStatus(message,kind=''){{tokenStatus.textContent=message||''; tokenStatus.className='token-status muted '+kind}}
function authHeaders(){{const token=localStorage.getItem('draftpaperConsoleToken')||''; return token?{{'X-Draftpaper-Token':token}}:{{}}}}
async function api(path,opt={{}},retry=true){{const r=await fetch(path,{{...opt,headers:{{'Content-Type':'application/json',...authHeaders(),...(opt.headers||{{}})}}}});const t=await r.text();let p;try{{p=JSON.parse(t)}}catch{{p={{status:'error',raw:t}}}} if(r.status===401&&retry){{setTokenStatus('Token required','bad');throw p}} if(!r.ok)throw p; setTokenStatus(localStorage.getItem('draftpaperConsoleToken')?'Token active':'','ok'); return p}}
function show(v){{document.getElementById('output').textContent=typeof v==='string'?v:JSON.stringify(v,null,2)}}
function esc(v){{return String(v??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]))}}
function trackClass(status){{if(status==='ready'||status==='passed'||status==='verified')return'ready'; if(status==='blocked'||status==='not_ready'||status==='attention')return'bad'; return'warn'}}
function renderReadiness(commercial,handoff){{readinessCache={{commercial,handoff}}; const box=document.getElementById('readinessSummary'); const tracks=handoff.tracks||commercial.readiness_tracks||[]; const hosted=tracks.find(t=>t.id==='hosted_saas')||{{gates:[],summary:{{}}}}; const failed=(hosted.gates||[]).filter(g=>!g.passed).slice(0,5); const actions=(handoff.next_required_actions||commercial.remaining_gaps||[]).slice(0,4); const cards=tracks.map(t=>`<div class="track ${{trackClass(t.status)}}"><div class="title">${{esc(t.label||t.id)}}</div><div class="chips" style="margin-top:6px"><span class="chip ${{trackClass(t.status)==='bad'?'bad':trackClass(t.status)==='warn'?'warn':''}}">${{esc(t.status||'unknown')}}</span><span class="chip">${{t.summary?.passed??0}}/${{t.summary?.total??0}}</span><span class="chip ${{(t.summary?.errors||0)?'bad':''}}">errors ${{t.summary?.errors??0}}</span></div></div>`).join(''); const failedHtml=failed.length?`<div><div class="title">Hosted gaps</div><ul class="next-list">${{failed.map(g=>`<li>${{esc(g.id)}}: ${{esc(g.remediation||g.note||'')}}</li>`).join('')}}</ul></div>`:''; const nextHtml=actions.length?`<div><div class="title">Next actions</div><ul class="next-list">${{actions.map(a=>`<li>${{esc(a)}}</li>`).join('')}}</ul></div>`:'<div class="muted">No blocking local handoff actions.</div>'; box.innerHTML=`<div class="readiness-head"><div class="metric"><span class="muted">Grade</span><b>${{esc(handoff.commercial_grade||commercial.commercial_grade||'unknown')}}</b></div><div class="metric"><span class="muted">Score</span><b>${{commercial.score??'n/a'}}</b></div><div class="metric"><span class="muted">Hosted</span><b>${{esc(hosted.status||'unknown')}}</b></div></div><div class="track-grid">${{cards}}</div>${{failedHtml}}${{nextHtml}}<div class="row"><button data-readiness-json="commercial">Commercial JSON</button><button data-readiness-json="handoff">Handoff JSON</button></div>`; for(const b of box.querySelectorAll('button[data-readiness-json]')) b.onclick=()=>show(readinessCache[b.dataset.readinessJson])}}
async function refreshReadiness(){{const box=document.getElementById('readinessSummary'); try{{const commercial=await api('/api/commercial-readiness'); const handoff=await api('/api/handoff-readiness'); renderReadiness(commercial,handoff)}}catch(e){{box.innerHTML='<div class="chip bad">Readiness unavailable</div>';show(e)}}}}
function renderProjects(){{const box=document.getElementById('projects');box.innerHTML=''; if(!projects.length){{box.innerHTML='<div class="muted">No projects yet.</div>';return}} for(const p of projects){{const stale=p.stage_counts?.stale||0;const card=document.createElement('div');card.className='project'+(selected&&selected.path===p.path?' active':'');card.innerHTML=`<div class="title">${{p.title}}</div><div class="muted">${{p.slug}} · ${{p.current_stage||'stage unknown'}}</div><div class="chips"><span class="chip">${{p.pipeline_state||'unknown'}}</span><span class="chip ${{stale?'warn':''}}">stale ${{stale}}</span><span class="chip">draft ${{p.stage_counts?.draft||0}}</span></div>`;card.onclick=()=>{{selected=p;renderProjects();renderSelected()}};box.appendChild(card)}}}}
function renderSelected(){{const box=document.getElementById('selected'); if(!selected){{box.textContent='No project selected.';return}} const outputs=(selected.outputs||[]).map(o=>`<a href="/api/file?project=${{encodeURIComponent(selected.slug)}}&path=${{encodeURIComponent(o.path)}}" target="_blank">${{o.path}}</a>`).join(''); box.innerHTML=`<div class="title">${{selected.title}}</div><div class="muted">${{selected.field||''}} · ${{selected.target_journal||''}}</div><div style="margin-top:8px"><strong>Next:</strong> ${{selected.next_action?.command||'none'}} - ${{selected.next_action?.reason||''}}</div><div class="row" style="margin-top:8px"><button onclick="exportSelected(false)">Export package</button><button onclick="exportSelected(true)">Export with data</button><button onclick="backupSelected(false)">Backup</button><button onclick="backupSelected(true)">Backup with data</button><button onclick="prepareClaimDraft()">Claim draft</button><button onclick="loadStageGraph()">Stage graph</button></div><div id="stageGraph" class="stage-graph"></div><div class="outputs" style="margin-top:8px">${{outputs||'<span class="muted">No preview outputs yet.</span>'}}</div>`}}
function stageNodeClass(n){{if(n.stale||n.state==='failed'||n.state==='missing_outputs')return'bad'; if(n.blocked_by?.length)return'warn'; if(n.is_current)return'ready'; return'warn'}}
async function loadStageGraph(){{if(!selected)return; const graph=await api(`/api/project-stage-graph?project=${{encodeURIComponent(selected.slug)}}`); const box=document.getElementById('stageGraph'); const nodes=(graph.nodes||[]).map(n=>`<div class="stage-node ${{stageNodeClass(n)}} ${{n.is_next?'next':''}}"><div class="row" style="justify-content:space-between"><span class="title">${{esc(n.id)}}</span><span class="chip ${{n.stale?'bad':n.blocked_by?.length?'warn':''}}">${{esc(n.state)}}</span></div><div class="muted">depends: ${{esc((n.depends_on||[]).join(', ')||'none')}}</div>${{n.blocked_by?.length?`<div class="muted">blocked by: ${{esc(n.blocked_by.join(', '))}}</div>`:''}}${{n.missing_outputs?.length?`<div class="muted">missing outputs: ${{esc(n.missing_outputs.join(', '))}}</div>`:''}}</div>`).join(''); box.innerHTML=`<div class="readiness-head"><div class="metric"><span class="muted">Pipeline</span><b>${{esc(graph.pipeline_state)}}</b></div><div class="metric"><span class="muted">Current</span><b>${{graph.summary?.current??0}}/${{graph.summary?.stages??0}}</b></div><div class="metric"><span class="muted">Stale</span><b>${{graph.summary?.stale??0}}</b></div></div>${{nodes}}`; show(graph)}}
async function refresh(){{const p=await api('/api/projects');projects=p.projects||[]; if(selected) selected=projects.find(x=>x.path===selected.path)||selected; renderProjects();renderSelected();await refreshJobs();await refreshReadiness()}}
function jobControls(j){{const controls=[`<button data-job="${{j.id}}">Open</button>`,`<button data-events="${{j.id}}">Events</button>`]; if(['queued','running','cancelling'].includes(j.status)) controls.push(`<button data-cancel="${{j.id}}">Cancel</button>`); if(['succeeded','failed','cancelled','unknown'].includes(j.status)) controls.push(`<button data-retry="${{j.id}}">Retry</button>`,`<button data-delete="${{j.id}}">Clear</button>`); return controls.join(' ')}}
async function refreshJobs(){{const p=await api('/api/jobs'); const jobs=p.jobs||[]; const box=document.getElementById('jobs'); box.innerHTML=jobs.slice(0,8).map(j=>`<div class="job"><div class="row"><strong>${{j.label}}</strong><span class="chip ${{j.status==='failed'?'bad':j.status==='running'||j.status==='cancelling'?'warn':''}}">${{j.status}}</span>${{jobControls(j)}}</div><div class="muted">${{j.id}} · pid=${{j.pid??''}} · rc=${{j.returncode??''}} · attempt=${{j.attempt??1}}</div></div>`).join('')||'<div class="muted">No jobs.</div>'; for(const b of box.querySelectorAll('button[data-job]')) b.onclick=async()=>show(await api('/api/jobs/'+b.dataset.job)); for(const b of box.querySelectorAll('button[data-events]')) b.onclick=async()=>show(await api('/api/jobs/'+b.dataset.events+'/events')); for(const b of box.querySelectorAll('button[data-cancel]')) b.onclick=async()=>{{show(await api('/api/jobs/'+b.dataset.cancel+'/cancel',{{method:'POST',body:'{{}}'}}));await refreshJobs()}}; for(const b of box.querySelectorAll('button[data-retry]')) b.onclick=async()=>{{show(await api('/api/jobs/'+b.dataset.retry+'/retry',{{method:'POST',body:'{{}}'}}));await refreshJobs()}}; for(const b of box.querySelectorAll('button[data-delete]')) b.onclick=async()=>{{show(await api('/api/jobs/'+b.dataset.delete,{{method:'DELETE'}}));await refreshJobs()}}}}
async function start(action,extra={{}}){{const params={{query:query.value,limit:limit.value,from_json:fromJson.value,from_html:fromHtml.value,target_journal:targetJournal.value,method_note:methodNote.value,...extra}};const p=await api('/api/jobs',{{method:'POST',body:JSON.stringify({{action,project:selected?.slug,params}})}});show(p);await refreshJobs()}}
async function exportSelected(includeData){{if(!selected)return; const url=`/api/project-export?project=${{encodeURIComponent(selected.slug)}}${{includeData?'&include_data=1':''}}`; const r=await fetch(url,{{headers:authHeaders()}}); if(r.status===401){{await api('/api/projects'); return exportSelected(includeData)}} if(!r.ok){{show(await r.text());return}} const blob=await r.blob(); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=`${{selected.slug}}${{includeData?'-with-data':''}}.zip`; a.click(); URL.revokeObjectURL(a.href)}}
async function downloadSupportBundle(){{const r=await fetch('/api/support-bundle',{{headers:authHeaders()}}); if(r.status===401){{await api('/api/projects'); return downloadSupportBundle()}} if(!r.ok){{show(await r.text());return}} const blob=await r.blob(); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='draftpaper-support-bundle.zip'; a.click(); URL.revokeObjectURL(a.href)}}
async function backupSelected(includeData){{if(!selected)return; const p=await api('/api/project-backup',{{method:'POST',body:JSON.stringify({{project:selected.slug,include_data:includeData,reason:'console'}})}});show(p)}}
async function prepareClaimDraft(){{if(!selected)return; const p=await api('/api/project-claim-confirmation-draft',{{method:'POST',body:JSON.stringify({{project:selected.slug}})}});show(p);await refreshReadiness()}}
async function generatePaidConfig(){{const payload={{customer_id:handoffCustomerId.value.trim(),customer_name:handoffCustomerName.value.trim(),output_dir:handoffOutputDir.value.trim(),expires_at:handoffExpiresAt.value.trim(),seats:handoffSeats.value||1,workspace:handoffWorkspace.value.trim(),operator_id:handoffOperatorId.value.trim()||'customer-admin',currency:handoffCurrency.value.trim()||'USD',job_rate:handoffJobRate.value||0,backup_rate:handoffBackupRate.value||0,storage_gb_month_rate:handoffStorageRate.value||0,license_signing_key:handoffSigningKey.value.trim(),can_export_data:handoffCanExportData.checked,activate:handoffActivate.checked}}; const p=await api('/api/paid-handoff-config',{{method:'POST',body:JSON.stringify(payload)}});show(p);await refreshReadiness()}}
async function runCommercialSuite(){{const payload={{customer_id:handoffCustomerId.value.trim()||hostedCustomerId.value.trim(),customer_name:handoffCustomerName.value.trim()||hostedCustomerName.value.trim(),output_dir:suiteOutputDir.value.trim(),base_url:hostedBaseUrl.value.trim(),target_track:suiteTargetTrack.value,signing_key:handoffSigningKey.value.trim(),signing_public_key:suitePublicKey.value.trim(),version_label:suiteVersionLabel.value.trim(),hosted_readiness_dossier:hostedDossierZipPath.value.trim(),timeout:suiteTimeout.value||5}}; const p=await api('/api/commercial-acceptance-suite',{{method:'POST',body:JSON.stringify(payload)}});show(p);await refreshReadiness()}}
async function prepareTrustDraft(){{const releaseZip=releaseZipPath.value.trim(); const p=await api('/api/release-trust-draft',{{method:'POST',body:JSON.stringify({{release_zip:releaseZip}})}});show(p);await refreshReadiness()}}
async function prepareHostedDraft(){{const baseUrl=hostedBaseUrl.value.trim(); const p=await api('/api/hosted-readiness-draft',{{method:'POST',body:JSON.stringify({{base_url:baseUrl}})}});show(p);await refreshReadiness()}}
async function finalizeHostedReadiness(){{const payload={{collection_report:hostedCollectionReportPath.value.trim(),controls_file:hostedControlsPath.value.trim(),output_file:hostedOutputPath.value.trim(),activate:true}}; const p=await api('/api/hosted-readiness-finalize',{{method:'POST',body:JSON.stringify(payload)}});show(p);await refreshReadiness()}}
async function buildHostedDossier(){{const payload={{hosted_readiness_file:hostedEvidenceFilePath.value.trim()||hostedOutputPath.value.trim(),output_dir:hostedDossierOutputDir.value.trim(),output_zip:hostedDossierZipPath.value.trim(),customer_id:hostedCustomerId.value.trim(),customer_name:hostedCustomerName.value.trim()}}; const p=await api('/api/hosted-readiness-dossier',{{method:'POST',body:JSON.stringify(payload)}}); if(p.zip_path&&!hostedDossierZipPath.value.trim())hostedDossierZipPath.value=p.zip_path; show(p);await refreshReadiness()}}
async function runHostedAcceptance(){{const payload={{base_url:hostedBaseUrl.value.trim(),hosted_readiness_file:hostedEvidenceFilePath.value.trim()||hostedOutputPath.value.trim(),hosted_readiness_dossier:hostedDossierZipPath.value.trim(),output_file:hostedAcceptanceOutputPath.value.trim(),allow_localhost:hostedAllowLocal.checked,allow_insecure_http:hostedAllowHttp.checked}}; const p=await api('/api/hosted-production-acceptance',{{method:'POST',body:JSON.stringify(payload)}});show(p);await refreshReadiness()}}
tokenBtn.onclick=()=>tokenInput.focus(); saveTokenBtn.onclick=async()=>{{const token=tokenInput.value.trim(); if(token){{localStorage.setItem('draftpaperConsoleToken',token); setTokenStatus('Token saved','ok')}}else{{localStorage.removeItem('draftpaperConsoleToken'); setTokenStatus('Token cleared','')}} await refresh().catch(show)}};
refreshBtn.onclick=refresh; refreshReadinessBtn.onclick=refreshReadiness; accessBtn.onclick=async()=>show(await api('/api/access-policy')); usageBtn.onclick=async()=>show(await api('/api/usage')); quotaBtn.onclick=async()=>show(await api('/api/quota')); billingBtn.onclick=async()=>show(await api('/api/billing')); licenseBtn.onclick=async()=>show(await api('/api/license')); entitlementsBtn.onclick=async()=>show(await api('/api/license-entitlements')); paidConfigBtn.onclick=generatePaidConfig; suiteBtn.onclick=runCommercialSuite; claimsBtn.onclick=async()=>show(await api('/api/claim-confirmation')); approvalBtn.onclick=async()=>show(await api('/api/license-approval')); approvalDraftBtn.onclick=async()=>{{show(await api('/api/commercial-approval-draft',{{method:'POST',body:'{{}}'}}));await refreshReadiness()}}; trustBtn.onclick=async()=>show(await api('/api/release-trust')); trustDraftBtn.onclick=prepareTrustDraft; secReviewBtn.onclick=async()=>show(await api('/api/security-review')); secReviewDraftBtn.onclick=async()=>{{show(await api('/api/security-review-draft',{{method:'POST',body:'{{}}'}}));await refreshReadiness()}}; hostedDraftBtn.onclick=prepareHostedDraft; hostedFinalizeBtn.onclick=finalizeHostedReadiness; hostedDossierBtn.onclick=buildHostedDossier; hostedAcceptBtn.onclick=runHostedAcceptance; backupsBtn.onclick=async()=>show(await api('/api/backups')); rehearsalsBtn.onclick=async()=>show(await api('/api/backups/rehearsals')); auditBtn.onclick=async()=>show(await api('/api/audit?limit=50')); securityBtn.onclick=async()=>show(await api('/api/security-audit')); supportBtn.onclick=downloadSupportBundle; readinessBtn.onclick=async()=>show(await api('/api/commercial-readiness')); handoffBtn.onclick=async()=>show(await api('/api/handoff-readiness')); cleanupJobsBtn.onclick=async()=>{{show(await api('/api/jobs/cleanup',{{method:'POST',body:JSON.stringify({{keep:20}})}}));await refreshJobs()}}; createBtn.onclick=async()=>{{const p=await api('/api/jobs',{{method:'POST',body:JSON.stringify({{action:'create-project',idea:idea.value,field:field.value,target_journal:targetJournal.value||'General Academic Journal'}})}});show(p);await refreshJobs();await refreshReadiness()}}; runBtn.onclick=async()=>start(sel.value); statusBtn.onclick=async()=>start('status'); syncBtn.onclick=async()=>start('sync-artifact-stale'); setInterval(refreshJobs,2500); refresh().catch(show);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "DraftpaperLoopConsole/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        try:
            context = _request_access_context(self)
            if _path_requires_auth(parsed.path) and context is None:
                append_audit("auth_failed", status="denied", method="GET", path=parsed.path, remote=self.client_address[0])
                _unauthorized(self)
                return
            if parsed.path == "/":
                _text(self, index_html(), content_type="text/html; charset=utf-8")
            elif parsed.path == "/favicon.ico":
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("Cache-Control", "max-age=86400")
                self.end_headers()
            elif parsed.path in {"/health", "/api/health"}:
                _json(self, {"status": "ok", "service": "DraftpaperLoop", "repo_root": str(REPO_ROOT), "projects_root": str(PROJECTS_ROOT), "python": PYTHON_BIN, "cli_importable": status_project is not None, "auth_required": _auth_required()})
            elif parsed.path == "/api/actions":
                _json(self, {"status": "listed", "actions": _visible_actions(context)})
            elif parsed.path == "/api/projects":
                _json(self, {"status": "listed", "projects_root": str(PROJECTS_ROOT), "projects": list_projects(context=context)})
            elif parsed.path == "/api/project-stage-graph":
                project = (query.get("project") or [""])[0]
                _json(self, project_stage_graph(project, context=context))
            elif parsed.path == "/api/commercial-readiness":
                _json(self, commercial_readiness())
            elif parsed.path == "/api/handoff-readiness":
                _json(self, handoff_readiness(context=context))
            elif parsed.path == "/api/hosted-readiness":
                _json(self, hosted_readiness_summary(context=context))
            elif parsed.path == "/api/access-policy":
                _json(self, access_policy_summary(context=context))
            elif parsed.path == "/api/usage":
                _json(self, usage_summary(context=context))
            elif parsed.path == "/api/quota":
                _json(self, quota_summary(context=context))
            elif parsed.path == "/api/billing":
                start = _period_value_to_epoch((query.get("start") or [""])[0])
                end = _period_value_to_epoch((query.get("end") or [""])[0])
                _json(self, billing_report(context=context, start=start, end=end))
            elif parsed.path == "/api/license":
                _json(self, license_grant_summary(context=context))
            elif parsed.path == "/api/license-entitlements":
                _json(self, license_entitlement_summary(context=context))
            elif parsed.path == "/api/claim-confirmation":
                _json(self, claim_confirmation_summary(context=context))
            elif parsed.path == "/api/license-approval":
                _json(self, commercial_approval_summary(context=context))
            elif parsed.path == "/api/release-trust":
                _json(self, release_trust_summary(context=context))
            elif parsed.path == "/api/security-review":
                _json(self, security_review_summary(context=context))
            elif parsed.path == "/api/security-audit":
                _json(self, security_audit(context=context))
            elif parsed.path == "/api/backups":
                project = (query.get("project") or [""])[0] or None
                _json(self, {"status": "listed", "backups_root": str(_backups_root()), "backups": list_project_backups(project=project, context=context)})
            elif parsed.path == "/api/backups/verify":
                project = (query.get("project") or [""])[0] or None
                _json(self, verify_project_backups(project=project, context=context))
            elif parsed.path == "/api/backups/rehearsals":
                project = (query.get("project") or [""])[0] or None
                _json(self, backup_rehearsal_summary(project=project, context=context))
            elif parsed.path == "/api/audit":
                _require_role(context, {"admin"})
                limit = int((query.get("limit") or ["100"])[0] or "100")
                _json(self, {"status": "listed", "events": read_audit_events(limit=max(0, min(limit, 1000)))})
            elif parsed.path == "/api/project-export":
                project = (query.get("project") or [""])[0]
                include_data = (query.get("include_data") or ["0"])[0] in {"1", "true", "yes"}
                archive, manifest = export_project_archive(project, include_data=include_data, context=context)
                append_audit("project_exported", actor=str((context or {}).get("id") or "unknown"), project=manifest["project"], include_data=include_data, archive_bytes=manifest["archive_bytes"])
                filename = f"{manifest['project']}{'-with-data' if include_data else ''}.zip"
                _binary(self, archive, filename=filename, content_type="application/zip")
            elif parsed.path == "/api/support-bundle":
                archive, manifest = build_support_bundle(context=context)
                append_audit("support_bundle_exported", actor=str((context or {}).get("id") or "unknown"), archive_bytes=manifest["archive_bytes"])
                _binary(self, archive, filename="draftpaper-support-bundle.zip", content_type="application/zip")
            elif parsed.path == "/api/jobs":
                with JOBS_LOCK:
                    jobs = sorted((job for job in JOBS.values() if _job_visible(context, job)), key=lambda item: item.get("created_at") or 0, reverse=True)
                _json(self, {"status": "listed", "jobs": jobs})
            elif parsed.path.startswith("/api/jobs/") and parsed.path.endswith("/events"):
                job_id = parsed.path.split("/")[-2]
                _json(self, job_events(job_id, context=context))
            elif parsed.path.startswith("/api/jobs/"):
                job_id = parsed.path.rsplit("/", 1)[-1]
                with JOBS_LOCK:
                    job = JOBS.get(job_id)
                if job and not _job_visible(context, job):
                    raise PermissionError("job is outside this actor's access scope")
                _json(self, job or {"status": "error", "message": "job not found"}, 200 if job else HTTPStatus.NOT_FOUND)
            elif parsed.path == "/api/file":
                project = (query.get("project") or [""])[0]
                relative = (query.get("path") or [""])[0]
                target = _project_file(project, relative, context=context)
                if not target.exists() or not target.is_file():
                    _json(self, {"status": "error", "message": "file not found"}, HTTPStatus.NOT_FOUND)
                    return
                content_type = "text/html; charset=utf-8" if target.suffix.lower() == ".html" else "text/plain; charset=utf-8"
                _text(self, target.read_text(encoding="utf-8", errors="replace"), content_type=content_type)
            else:
                _json(self, {"status": "error", "message": "not found"}, HTTPStatus.NOT_FOUND)
        except PermissionError as exc:
            _json(self, {"status": "error", "message": str(exc)}, HTTPStatus.FORBIDDEN)
        except Exception as exc:
            _json(self, {"status": "error", "message": str(exc)}, HTTPStatus.BAD_REQUEST)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        try:
            context = _request_access_context(self)
            if _path_requires_auth(parsed.path) and context is None:
                append_audit("auth_failed", status="denied", method="POST", path=parsed.path, remote=self.client_address[0])
                _unauthorized(self)
                return
            payload = _body(self)
            if parsed.path == "/api/projects":
                _authorize_action(context, "create-project")
                _enforce_project_quota(context)
                if create_project is None:
                    raise ValueError("draftpaper_cli is not importable")
                project = create_project(
                    root=PROJECTS_ROOT,
                    idea=str(payload.get("idea") or ""),
                    field=str(payload.get("field") or ""),
                    target_journal=str(payload.get("target_journal") or "General Academic Journal"),
                    overwrite=bool(payload.get("overwrite")),
                )
                _json(self, {"status": "created", "project": project_summary(project.path)})
                append_audit("project_created_direct", actor=str((context or {}).get("id") or "unknown"), project=project.project_slug)
            elif parsed.path == "/api/jobs":
                action = str(payload.get("action") or "")
                if action == "create-project":
                    job_payload = payload
                else:
                    job_payload = {"project": payload.get("project"), "params": payload.get("params") if isinstance(payload.get("params"), dict) else {}}
                job = start_job(action, job_payload, context=context)
                append_audit("job_request", actor=str((context or {}).get("id") or "unknown"), action=action, job_id=job["id"])
                _json(self, {"status": "queued", "job": job}, HTTPStatus.ACCEPTED)
            elif parsed.path == "/api/project-backup":
                project = str(payload.get("project") or "")
                include_data = bool(payload.get("include_data"))
                reason = str(payload.get("reason") or "manual")
                backup = create_project_backup(project, include_data=include_data, reason=reason, context=context)
                _json(self, {"status": "created", "backup": backup}, HTTPStatus.CREATED)
            elif parsed.path == "/api/project-claim-confirmation-draft":
                project = str(payload.get("project") or "")
                raw_claims = payload.get("claims") if isinstance(payload.get("claims"), list) else []
                claims = [str(item).strip() for item in raw_claims if str(item).strip()]
                report = prepare_project_claim_confirmation_draft(project, claims=claims, context=context)
                _json(self, report, HTTPStatus.CREATED)
            elif parsed.path == "/api/paid-handoff-config":
                raw_features = payload.get("features") if isinstance(payload.get("features"), list) else []
                features = [str(item).strip() for item in raw_features if str(item).strip()]
                _json(
                    self,
                    generate_paid_handoff_config_from_console(
                        customer_id=str(payload.get("customer_id") or ""),
                        customer_name=str(payload.get("customer_name") or ""),
                        output_dir=str(payload.get("output_dir") or ""),
                        expires_at=str(payload.get("expires_at") or ""),
                        seats=int(payload.get("seats") or 1),
                        license_id=str(payload.get("license_id") or ""),
                        grant_type=str(payload.get("grant_type") or "paid-local-pilot"),
                        issued_at=str(payload.get("issued_at") or ""),
                        workspace=str(payload.get("workspace") or ""),
                        billing_plan=str(payload.get("billing_plan") or "pilot-paid"),
                        features=features or None,
                        operator_id=str(payload.get("operator_id") or "customer-admin"),
                        operator_role=str(payload.get("operator_role") or "admin"),
                        operator_token=str(payload.get("operator_token") or ""),
                        can_export_data=bool(payload.get("can_export_data")),
                        currency=str(payload.get("currency") or "USD"),
                        job_rate=float(payload.get("job_rate") or 0.0),
                        backup_rate=float(payload.get("backup_rate") or 0.0),
                        storage_gb_month_rate=float(payload.get("storage_gb_month_rate") or 0.0),
                        write_token_file=not bool(payload.get("no_token_file")),
                        activate=bool(payload.get("activate")),
                        license_signing_key=str(payload.get("license_signing_key") or ""),
                        license_public_key=str(payload.get("license_public_key") or ""),
                        context=context,
                    ),
                    HTTPStatus.CREATED,
                )
            elif parsed.path == "/api/commercial-acceptance-suite":
                _json(
                    self,
                    run_commercial_acceptance_suite_from_console(
                        customer_id=str(payload.get("customer_id") or ""),
                        customer_name=str(payload.get("customer_name") or ""),
                        signing_key=str(payload.get("signing_key") or ""),
                        output_dir=str(payload.get("output_dir") or ""),
                        base_url=str(payload.get("base_url") or ""),
                        token=_request_token(self),
                        target_track=str(payload.get("target_track") or "paid_local_handoff"),
                        signing_public_key=str(payload.get("signing_public_key") or ""),
                        version_label=str(payload.get("version_label") or ""),
                        hosted_readiness_dossier=str(payload.get("hosted_readiness_dossier") or ""),
                        timeout=float(payload.get("timeout") or 5.0),
                        context=context,
                    ),
                    HTTPStatus.CREATED,
                )
            elif parsed.path == "/api/commercial-approval-draft":
                _json(self, prepare_commercial_approval_draft(context=context), HTTPStatus.CREATED)
            elif parsed.path == "/api/release-trust-draft":
                path_keys = {
                    "release_zip": payload.get("release_zip"),
                    "release_manifest": payload.get("release_manifest"),
                    "release_sha256_file": payload.get("release_sha256_file"),
                    "release_signature": payload.get("release_signature"),
                    "release_public_key": payload.get("release_public_key"),
                }
                paths = {
                    key: Path(str(value)).expanduser().resolve()
                    for key, value in path_keys.items()
                    if str(value or "").strip()
                }
                _json(self, prepare_release_trust_draft(context=context, **paths), HTTPStatus.CREATED)
            elif parsed.path == "/api/hosted-readiness-draft":
                _json(
                    self,
                    prepare_hosted_readiness_draft(
                        base_url=str(payload.get("base_url") or ""),
                        token=_request_token(self),
                        environment=str(payload.get("environment") or "local-rehearsal"),
                        timeout=float(payload.get("timeout") or 3.0),
                        context=context,
                    ),
                    HTTPStatus.CREATED,
                )
            elif parsed.path == "/api/hosted-readiness-finalize":
                _json(
                    self,
                    finalize_hosted_readiness(
                        collection_report=str(payload.get("collection_report") or ""),
                        controls_file=str(payload.get("controls_file") or ""),
                        output_file=str(payload.get("output_file") or "") or None,
                        report_output=str(payload.get("report_output") or "") or None,
                        activate=bool(payload.get("activate")),
                        context=context,
                    ),
                    HTTPStatus.CREATED,
                )
            elif parsed.path == "/api/hosted-readiness-dossier":
                _json(
                    self,
                    build_hosted_readiness_dossier_from_console(
                        hosted_readiness_file=str(payload.get("hosted_readiness_file") or ""),
                        output_dir=str(payload.get("output_dir") or ""),
                        output_zip=str(payload.get("output_zip") or ""),
                        customer_id=str(payload.get("customer_id") or ""),
                        customer_name=str(payload.get("customer_name") or ""),
                        context=context,
                    ),
                    HTTPStatus.CREATED,
                )
            elif parsed.path == "/api/hosted-production-acceptance":
                _json(
                    self,
                    run_hosted_production_acceptance_from_console(
                        base_url=str(payload.get("base_url") or ""),
                        token=_request_token(self),
                        hosted_readiness_file=str(payload.get("hosted_readiness_file") or ""),
                        hosted_readiness_dossier=str(payload.get("hosted_readiness_dossier") or ""),
                        output_file=str(payload.get("output_file") or ""),
                        timeout=float(payload.get("timeout") or 8.0),
                        allow_localhost=bool(payload.get("allow_localhost")),
                        allow_insecure_http=bool(payload.get("allow_insecure_http")),
                        context=context,
                    ),
                    HTTPStatus.CREATED,
                )
            elif parsed.path == "/api/security-review-draft":
                _json(self, prepare_security_review_draft(context=context), HTTPStatus.CREATED)
            elif parsed.path == "/api/backups/cleanup":
                keep = _payload_int(payload, "keep", 10)
                max_age = payload.get("max_age_days")
                max_age_days = int(max_age) if max_age is not None and str(max_age).strip() != "" else None
                project = str(payload.get("project") or "") or None
                _json(self, cleanup_project_backups(keep=keep, max_age_days=max_age_days, project=project, context=context))
            elif parsed.path == "/api/backups/rehearse":
                backup_id = str(payload.get("backup_id") or "") or None
                project = str(payload.get("project") or "") or None
                _json(self, rehearse_project_backups(backup_id=backup_id, project=project, context=context))
            elif parsed.path.startswith("/api/backups/") and parsed.path.endswith("/rehearse"):
                backup_id = parsed.path.split("/")[-2]
                _json(self, rehearse_project_backups(backup_id=backup_id, context=context))
            elif parsed.path.startswith("/api/backups/") and parsed.path.endswith("/restore"):
                backup_id = parsed.path.split("/")[-2]
                target_slug = str(payload.get("target_slug") or "") or None
                overwrite = bool(payload.get("overwrite"))
                _json(self, restore_project_backup(backup_id, target_slug=target_slug, overwrite=overwrite, context=context))
            elif parsed.path == "/api/jobs/cleanup":
                keep = _payload_int(payload, "keep", 20)
                _json(self, cleanup_jobs(keep=max(0, keep), context=context))
            elif parsed.path.startswith("/api/jobs/") and parsed.path.endswith("/cancel"):
                job_id = parsed.path.split("/")[-2]
                _json(self, {"status": "cancel_requested", "job": cancel_job(job_id, context=context)})
            elif parsed.path.startswith("/api/jobs/") and parsed.path.endswith("/retry"):
                job_id = parsed.path.split("/")[-2]
                _json(self, retry_job(job_id, context=context), HTTPStatus.ACCEPTED)
            else:
                _json(self, {"status": "error", "message": "not found"}, HTTPStatus.NOT_FOUND)
        except PermissionError as exc:
            _json(self, {"status": "error", "message": str(exc)}, HTTPStatus.FORBIDDEN)
        except Exception as exc:
            _json(self, {"status": "error", "message": str(exc)}, HTTPStatus.BAD_REQUEST)

    def do_DELETE(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        try:
            context = _request_access_context(self)
            if _path_requires_auth(parsed.path) and context is None:
                append_audit("auth_failed", status="denied", method="DELETE", path=parsed.path, remote=self.client_address[0])
                _unauthorized(self)
                return
            if parsed.path.startswith("/api/jobs/"):
                job_id = parsed.path.rsplit("/", 1)[-1]
                _json(self, delete_job(job_id, context=context))
            else:
                _json(self, {"status": "error", "message": "not found"}, HTTPStatus.NOT_FOUND)
        except PermissionError as exc:
            _json(self, {"status": "error", "message": str(exc)}, HTTPStatus.FORBIDDEN)
        except Exception as exc:
            _json(self, {"status": "error", "message": str(exc)}, HTTPStatus.BAD_REQUEST)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Draftpaper Loop local Service Console app.")
    parser.add_argument("--host", default=os.environ.get("DRAFTPAPER_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DRAFTPAPER_PORT", "4888")))
    args = parser.parse_args(argv)
    os.environ["DRAFTPAPER_HOST"] = str(args.host)
    os.environ["DRAFTPAPER_PORT"] = str(args.port)
    handoff_env = load_handoff_env_file()
    PROJECTS_ROOT.mkdir(parents=True, exist_ok=True)
    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    _load_jobs()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(json.dumps({"status": "listening", "service": "DraftpaperLoop", "url": f"http://{args.host}:{args.port}/", "projects_root": str(PROJECTS_ROOT), "handoff_env": handoff_env}, ensure_ascii=False), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
