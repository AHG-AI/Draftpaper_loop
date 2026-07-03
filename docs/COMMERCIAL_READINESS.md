# Draftpaper-loop Commercial Readiness

This document defines the current commercial handoff boundary for Draftpaper-loop.
It is intentionally operational: it states what is ready to use, how to verify it,
and which gaps must remain visible before a hosted or paid deployment.

## Product Intent

Draftpaper-loop is not a one-shot paper generator. It is a local-first research
paper loop engine that keeps a paper project in an auditable state:

- project passport and stage manifests
- evidence-first literature outputs
- journal profile and LaTeX constraints
- data, method, result, and core-evidence gates
- citation audit and citation repair loop
- reviewer-style revision routing
- discipline module capture and validation

The commercial value is the loop: every generated or reviewed artifact is tied
to visible files, stages, evidence, and commands that can be rerun or inspected.

## Current Commercial Grade

Current grade: local commercial pilot ready.

Machine-readable readiness is split into three tracks:

- `local_operator_pilot`: local demos, internal trials, and assisted delivery
- `paid_local_handoff`: customer handoff with configured auth, valid local
  commercial license grant, verified and rehearsed backups, support bundle, and
  clean security errors
- `hosted_saas`: self-serve hosted product, enterprise platform, and
  multi-tenant deployment

`/api/commercial-readiness` exposes the broad capability inventory and embeds
these tracks. `/api/handoff-readiness` is the stricter preflight gate to check
before telling a customer that a paid local handoff is ready. A ready local
operator pilot does not imply a ready paid handoff or a ready SaaS product.

Ready for:

- local operator demos
- internal team trials
- paid consulting or assisted delivery where an operator runs the tool
- scoped local customer/operator access using hashed token policies
- single-machine research workflow packaging
- checksum-verified local project backups, restore, and retention cleanup
- local preflight security audit for auth, secret files, release packaging, and
  config permissions
- source release package handoff with manifest, checksums, verification, and
  optional detached signatures
- discipline-module prototyping with visible provenance

Not yet ready for:

- self-serve SaaS
- public multi-tenant hosting
- hosted billing and remote usage accounting
- enterprise SSO/RBAC
- unattended long-running production queues
- legal/compliance claims beyond the source-available license package

## Local Operator Console

The local console is the commercial operator shell. It does not replace the CLI;
it wraps the CLI with safe, repeatable actions and visible job records.

Files:

- `service-console.manifest.json`
- `scripts/deploy_local.sh`
- `scripts/serviceconsole_app.py`

Default URL:

```bash
http://127.0.0.1:4888/
```

The console home page includes an operator readiness panel showing the current
commercial grade, local pilot, paid local handoff, hosted SaaS track status,
hosted gaps, and next required action. Token-protected installs use the inline
operator-token field in the page header; the older prompt-based flow is not
required.

Each selected project includes a Stage graph view backed by
`/api/project-stage-graph?project=<slug>`. The graph is read-only and derived
from `project.json` plus `stage_manifest.json` files. It exposes every stage,
dependency edge, stale flag, blocked dependency, missing declared output, current
stage, and next orchestrator action. This gives customer operators a visible
explanation for why the loop is moving forward, waiting, or routing backward
after upstream evidence changes.

Start directly:

```bash
bash scripts/deploy_local.sh
```

Or start from AHouse Service Console by selecting `DraftpaperLoop` and running
`deploy-local`.

Health check:

```bash
curl -sS http://127.0.0.1:4888/health
```

Expected health fields:

- `status=ok`
- `service=DraftpaperLoop`
- `cli_importable=true`
- `auth_required=false` unless `DRAFTPAPER_CONSOLE_TOKEN` is set

Optional local API token:

```bash
export DRAFTPAPER_CONSOLE_TOKEN="replace-with-local-secret"
bash scripts/deploy_local.sh
```

When the token is set, non-health API routes require one of:

- `Authorization: Bearer <token>`
- `X-Draftpaper-Token: <token>`
- `?token=<token>` for local browser handoff only

Optional local job concurrency limit:

```bash
export DRAFTPAPER_MAX_CONCURRENT_JOBS=2
```

The limit is local-process only. It prevents accidental operator fan-out during
demos or assisted delivery. Actor-level local quotas are configured separately
in the local access policy.

## Paid Handoff Config Generator

For paid local handoff, prefer the generator over hand-written private JSON. It
creates a commercial license grant, hashed-token users policy, billing rates,
`handoff-env.sh`, and a private manifest under an excluded runtime directory.

The Service Console exposes the same generator as `POST
/api/paid-handoff-config` and the `Paid Config` button. Fill the customer,
expiry, seat, billing-rate, and optional signing-key fields; when `Activate` is
checked, the route writes the standard active handoff env file and updates the
current console process to use the generated license, users, billing, and
license trust-pin values. The response returns file paths, hashes, and status
only. It does not return the plaintext operator token; if token-file output is
enabled, the token is written as an owner-only private runtime file for handoff.

Example:

```bash
python scripts/generate_handoff_config.py \
  --output-dir "$PWD/var/private/handoff-CUST-A" \
  --customer-id CUST-A \
  --customer-name "Customer A" \
  --expires-at 2026-12-31 \
  --seats 3 \
  --job-rate 2.5 \
  --backup-rate 1.25 \
  --storage-gb-month-rate 0.05 \
  --activate
```

For a paid customer record, sign the commercial license grant with a private key
kept outside the source release:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$PWD/var/private/license-signing.pem"

python scripts/generate_handoff_config.py \
  --output-dir "$PWD/var/private/handoff-CUST-A" \
  --customer-id CUST-A \
  --customer-name "Customer A" \
  --expires-at 2026-12-31 \
  --seats 3 \
  --license-signing-key "$PWD/var/private/license-signing.pem" \
  --activate \
  --force
```

When `--license-signing-key` is used, the generator writes
`commercial-license-grant.json.sig` and
`commercial-license-grant.public.pem` next to the private grant. `/api/license`
verifies the detached OpenSSL SHA256 signature whenever the grant contains a
`signature` object. Unsigned grants can still be used for assisted local pilots,
but they report a warning until signed.

Signed handoff env files also include
`DRAFTPAPER_LICENSE_PUBLIC_KEY_SHA256`. This is a non-secret trust pin for the
expected license verification key. With the pin configured, `/api/license`
rejects a grant if the public key referenced by the grant does not match the
pinned SHA256.

`--activate` writes `var/private/active-handoff.env`, which the standard local
console startup loads automatically. Then restart through Service Console or run
the local script:

```bash
bash scripts/deploy_local.sh
curl -H "X-Draftpaper-Token: $(cat var/private/handoff-CUST-A/operator-token.txt)" \
  -sS http://127.0.0.1:4888/api/handoff-readiness
```

The users file stores only `token_sha256`. The plaintext operator token is
written separately to `operator-token.txt` with owner-only permissions unless
`--no-token-file` is used. These files are runtime handoff material; they are
excluded from source release packages by the `var/` exclusion and by private
runtime filenames. If you do not want an active handoff config, omit
`--activate` and source the generated `handoff-env.sh` manually before startup.

## Local Access Policy

For assisted commercial pilots, use a local users file when different operators
or customer reviewers need different access. This remains local access control,
not hosted SSO/RBAC.

Create a token hash without printing or storing the token in the repository:

```bash
python - <<'PY'
import getpass, hashlib
token = getpass.getpass("token: ")
print(hashlib.sha256(token.encode("utf-8")).hexdigest())
PY
```

Store the users file outside source control, for example under `var/private/`:

```json
{
  "users": [
    {
      "id": "client-reviewer",
      "role": "viewer",
      "workspace": "client-a",
      "billing_customer_id": "CUST-A",
      "billing_plan": "pilot-paid",
      "token_sha256": "<sha256>",
      "projects": ["client-a-paper"]
    },
    {
      "id": "operator-a",
      "role": "operator",
      "workspace": "client-a",
      "token_sha256": "<sha256>",
      "projects": ["client-a-paper"],
      "allowed_actions": ["status", "sync-artifact-stale", "audit-citations"],
      "can_export_data": false,
      "max_concurrent_jobs": 1,
      "daily_job_limit": 20,
      "daily_backup_limit": 5,
      "backup_storage_bytes_limit": 5368709120,
      "max_projects": 3
    }
  ]
}
```

Start with the policy:

```bash
export DRAFTPAPER_CONSOLE_USERS_FILE="$PWD/var/private/console-users.json"
bash scripts/deploy_local.sh
```

Role behavior:

- `admin`: can see all projects unless scoped, run all actions, export raw data,
  inspect audit logs, and clear jobs.
- `operator`: can run allowed actions on scoped projects, view relevant jobs,
  and export handoff packages without raw/processed data unless
  `can_export_data=true`.
- `viewer`: can list and preview scoped projects but cannot run jobs or export
  raw/processed data.

Project scoping supports exact `projects` and prefix-based `project_prefixes`.
Action scoping supports `allowed_actions` and `blocked_actions`. The endpoint
`/api/access-policy` reports the active actor and policy summary without
returning token hashes or secrets.

Local quota fields:

- `max_concurrent_jobs`: active jobs this actor may run at once
- `daily_job_limit`: jobs this actor may queue per UTC day
- `daily_backup_limit`: backups this actor may create per UTC day
- `backup_storage_bytes_limit`: total local backup bytes this actor may retain
- `max_projects`: visible projects plus one pending create cannot exceed this

These are local commercial-pilot controls. They are useful for paid assisted
delivery and customer trials, but they are not a hosted billing system.

Optional local billing rates file:

```json
{
  "currency": "USD",
  "rates": {
    "job": 2.5,
    "backup": 1.25,
    "backup_gb": 0.05,
    "project": 10
  }
}
```

Start with rates:

```bash
export DRAFTPAPER_BILLING_RATES_FILE="$PWD/var/private/billing-rates.json"
bash scripts/deploy_local.sh
```

The billing report is for local pilot reconciliation. It estimates amounts from
configured rates and local usage records; it does not collect payment or replace
a hosted billing system.

## Local Commercial License Grant

For paid pilots and customer handoff, store the written commercial
authorization as an offline local grant record. This is audit metadata for the
operator and customer; it is not remote activation, DRM, telemetry, device
fingerprinting, or a destructive license check.

Store the grant file outside source control, for example:

```bash
mkdir -p var/private
cat > var/private/commercial-license-grant.json <<'JSON'
{
  "schema_version": 1,
  "license_id": "DPL-COMM-2026-001",
  "customer_id": "CUST-A",
  "customer_name": "Customer A",
  "grant_type": "commercial_pilot",
  "issued_at": "2026-07-03T00:00:00Z",
  "expires_at": "2026-12-31",
  "seats": 3,
  "features": ["local_console", "paper_loop", "project_export", "backup_restore"],
  "workspaces": ["client-a"],
  "contact_email": "ops@example.com",
  "terms": "COMMERCIAL_LICENSE.md"
}
JSON
```

Compute the local grant fingerprint and add it as `grant_sha256`:

```bash
python - <<'PY'
import json, hashlib
from pathlib import Path
path = Path("var/private/commercial-license-grant.json")
payload = json.loads(path.read_text())
payload.pop("grant_sha256", None)
payload.pop("sha256", None)
payload.pop("signature", None)
payload.pop("signed_at", None)
digest = hashlib.sha256(
    json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
payload["grant_sha256"] = digest
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
print(digest)
PY
```

Start with the grant:

```bash
export DRAFTPAPER_LICENSE_FILE="$PWD/var/private/commercial-license-grant.json"
bash scripts/deploy_local.sh
```

Verify:

```bash
curl -sS http://127.0.0.1:4888/api/license
curl -sS http://127.0.0.1:4888/api/license-entitlements
```

The validator checks required customer/grant fields, positive `seats`,
parseable and non-expired `expires_at`, optional feature scope, local
`grant_sha256` consistency, optional detached signature verification, signature
file/public-key/payload SHA256 consistency, optional public-key pin matching,
and private file permissions. It also rejects prohibited fields such as
`remote_check_url`, `activation_url`, `telemetry_url`, `device_fingerprint`, or
`machine_id_required`.

The entitlement audit compares the local license grant against the configured
access subjects. It checks seat count, licensed workspaces, `customer_id` /
`billing_customer_id` alignment, and whether user `allowed_actions` are covered
by license `allowed_actions` or feature scope. For paid handoff, fix every
severity=`error` finding before sharing the handoff dossier or operations
report.

## Commercial Approval Evidence

The software now supports a private approval evidence record for customer
handoff. This records the external legal/contract approval reference that
authorized a specific commercial license grant. It is a verification workflow,
not a contract generator and not legal approval by itself.

Store the approval file outside source control, for example:

```bash
python scripts/prepare_commercial_approval.py \
  --license-file var/private/commercial-license-grant.json \
  --output var/private/commercial-approval.json
```

The prepared file defaults to `status=draft`, binds the current license grant
SHA256, full license-file SHA256, and hashes for `LICENSE`, `NOTICE`,
`COMMERCIAL_LICENSE.md`, and `COMPLIANCE.md`. Verification remains `attention`
until an external approver has reviewed the evidence and supplied the approval
reference. To write approved evidence from the CLI, provide the external
approval fields explicitly:

```bash
python scripts/prepare_commercial_approval.py \
  --license-file var/private/commercial-license-grant.json \
  --output var/private/commercial-approval.json \
  --status approved \
  --approval-authority "customer procurement" \
  --approval-reference "CONTRACT-001" \
  --approved-by "legal approver" \
  --evidence-ref "contract/CONTRACT-001"
```

The Service Console also exposes `POST /api/commercial-approval-draft` and the
`Approval Draft` button. That action writes a private draft under the runtime
directory and does not mark approval as complete.

Manual JSON generation is still possible when an external system already
produces the approval record:

```bash
mkdir -p var/private
python - <<'PY'
import hashlib, json
from pathlib import Path

root = Path(".")
license_file = root / "var/private/commercial-license-grant.json"
license_payload = json.loads(license_file.read_text())
unsigned = {
    key: value
    for key, value in license_payload.items()
    if key not in {"grant_sha256", "sha256", "signature", "signed_at"}
}
license_digest = hashlib.sha256(
    json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
document_hashes = {
    relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
    for relative in ["LICENSE", "NOTICE", "COMMERCIAL_LICENSE.md", "COMPLIANCE.md"]
}
approval = {
    "schema_version": "draftpaper.commercial-approval/v1",
    "status": "approved",
    "approval_reference": "LEGAL-APPROVAL-ID",
    "approval_authority": "external-contract",
    "approved_by": "legal@example.invalid",
    "approved_at": "2026-07-03T00:00:00Z",
    "customer_id": license_payload["customer_id"],
    "customer_name": license_payload["customer_name"],
    "license_id": license_payload["license_id"],
    "scope": ["paid_local_handoff"],
    "evidence_refs": ["contract-or-approval-system-reference"],
    "license_grant_sha256": license_digest,
    "license_file_sha256": hashlib.sha256(license_file.read_bytes()).hexdigest(),
    "document_hashes": document_hashes
}
path = root / "var/private/commercial-approval.json"
path.write_text(json.dumps(approval, ensure_ascii=False, indent=2) + "\n")
path.chmod(0o600)
PY
```

Start with the approval evidence:

```bash
export DRAFTPAPER_COMMERCIAL_APPROVAL_FILE="$PWD/var/private/commercial-approval.json"
export DRAFTPAPER_LICENSE_FILE="$PWD/var/private/commercial-license-grant.json"
bash scripts/deploy_local.sh
```

Verify:

```bash
python scripts/verify_commercial_approval.py \
  --approval-file var/private/commercial-approval.json \
  --license-file var/private/commercial-license-grant.json \
  --output var/private/commercial-approval-verification.json

curl -sS http://127.0.0.1:4888/api/license-approval
```

The verifier checks owner-only file permissions, required approval fields,
`status=approved`, parseable `approved_at`, non-future approval time, declared
commercial scope, external evidence references, no obvious token/password/key
material, license/customer alignment, canonical license grant SHA256, optional
full license-file SHA256, and hashes for `LICENSE`, `NOTICE`,
`COMMERCIAL_LICENSE.md`, and `COMPLIANCE.md`.

This closes the product workflow gap for recording and verifying commercial
approval evidence, but each real customer still needs actual external approval
from the project author or legal authority. Do not use a local smoke-test
approval file as proof of a real contract.

## Operator API

Readiness:

```bash
curl -sS http://127.0.0.1:4888/api/commercial-readiness
```

Customer handoff readiness:

```bash
curl -sS http://127.0.0.1:4888/api/handoff-readiness
```

Projects:

```bash
curl -sS http://127.0.0.1:4888/api/projects
```

Actions:

```bash
curl -sS http://127.0.0.1:4888/api/actions
```

Usage summary:

```bash
curl -sS http://127.0.0.1:4888/api/usage
```

Quota summary:

```bash
curl -sS http://127.0.0.1:4888/api/quota
```

Billing usage report:

```bash
curl -sS http://127.0.0.1:4888/api/billing
```

Commercial license grant:

```bash
curl -sS http://127.0.0.1:4888/api/license
```

Security audit:

```bash
curl -sS http://127.0.0.1:4888/api/security-audit
```

Download a redacted support bundle as admin:

```bash
curl -sS -o /tmp/draftpaper-support-bundle.zip \
  http://127.0.0.1:4888/api/support-bundle

python scripts/verify_support_bundle.py /tmp/draftpaper-support-bundle.zip
```

Access policy summary:

```bash
curl -sS http://127.0.0.1:4888/api/access-policy
```

Local audit log:

```bash
curl -sS 'http://127.0.0.1:4888/api/audit?limit=50'
```

Audit events are stored locally in:

```bash
var/serviceconsole/audit/audit.jsonl
```

The audit log records local operator events such as job queue/finish, cancel,
cleanup, export, and authorization failures. It does not send telemetry.

## Support Bundle

The support bundle is a local diagnostics package for customer handoff, support
escalation, and paid pilot troubleshooting. It includes redacted JSON snapshots
for health, commercial readiness, handoff readiness, security audit, license
grant status, license entitlement audit, access policy, usage, quota, billing,
backup verification, backup restore rehearsals, project summaries, recent job
timelines, recent audit events, and the Service Console manifest.

The bundle intentionally does not include project artifact files, raw data,
processed data, private runtime config files, release archives, job stdout, or
job stderr. Sensitive keys such as `token`, `secret`, `password`, `api_key`,
`authorization`, and `cookie` are replaced with `[redacted]`. Local machine path
roots such as the repo, projects, runtime, home, and temporary directory
prefixes are also replaced with `[redacted]`. Verify downloaded bundles with
`scripts/verify_support_bundle.py` before attaching them to a customer support
or handoff record.

## Security Preflight

Run the local security audit before a paid pilot, customer demo, or package
handoff:

```bash
curl -sS http://127.0.0.1:4888/api/security-audit
```

The audit checks:

- non-loopback host binding requires `DRAFTPAPER_CONSOLE_TOKEN` or
  `DRAFTPAPER_CONSOLE_USERS_FILE`
- local users file exists when configured
- users file stores `token_sha256`, not plaintext `token`, `secret`,
  `password`, or `api_key` fields
- users file and billing-rates file are not world-readable
- configured commercial license grant file is valid, local-only, and not
  world-readable
- release packaging excludes `.env*`, `.pem`, `.key`, `.sig`, and known private
  runtime JSON files such as `console-users.json`, `billing-rates.json`, and
  `commercial-license-grant.json`
- unexpected root-level `.env*`, `.pem`, `.key`, or `.sig` files are not present
- Service Console manifest declares a secrets policy
- commercial license and compliance documents are present

This is a local preflight audit, not a formal third-party security assessment.

## Formal Security Review Evidence

For commercial customers that require a third-party review, penetration test,
vendor assessment, or compliance security review, store the external review
evidence in a private file and verify it before handoff. This workflow verifies
the evidence record and referenced artifacts; it does not perform the external
review.

Prepare a private draft from the current local security audit:

```bash
curl -sS http://127.0.0.1:4888/api/security-audit \
  > var/private/security-audit.json

python scripts/prepare_security_review.py \
  --security-audit-file var/private/security-audit.json \
  --output var/private/security-review.json
```

The local console exposes the same preparation step as `Sec Draft` and
`POST /api/security-review-draft`. It saves a private security-audit snapshot
and a draft review record under the runtime root. A draft intentionally verifies
as `attention`; set `status` to `verified` only after an external review,
penetration test, vendor assessment, or compliance review is complete.

Example evidence file:

```json
{
  "schema_version": "draftpaper.security-review/v1",
  "status": "verified",
  "review_type": "third_party_security_review",
  "review_authority": "external-security-provider",
  "review_reference": "SEC-REVIEW-ID",
  "reviewed_by": "security@example.invalid",
  "reviewed_at": "2026-07-03T00:00:00Z",
  "target": "draftpaper-loop-local-commercial-release",
  "scope": ["operator_console", "release_package", "local_data_controls"],
  "evidence_refs": ["security-review/SEC-REVIEW-ID"],
  "findings_summary": {
    "critical_open": 0,
    "high_open": 0,
    "medium_open": 0,
    "low_open": 0,
    "informational_open": 0
  },
  "artifacts": [
    {
      "path": "security-review-report.pdf",
      "sha256": "<artifact sha256>",
      "description": "redacted external review report"
    }
  ],
  "security_audit_sha256": "<saved /api/security-audit report sha256>"
}
```

Verify:

```bash
python scripts/verify_security_review.py \
  --review-file var/private/security-review.json \
  --security-audit-file var/private/security-audit.json \
  --output var/private/security-review-verification.json
```

To expose status in the local console:

```bash
export DRAFTPAPER_SECURITY_REVIEW_FILE="$PWD/var/private/security-review.json"
export DRAFTPAPER_SECURITY_AUDIT_FILE="$PWD/var/private/security-audit.json"
bash scripts/deploy_local.sh
curl -sS http://127.0.0.1:4888/api/security-review
```

The verifier checks owner-only evidence-file permissions, required review
fields, allowed external review type, parseable and non-future `reviewed_at`,
reviewed scope, external evidence references, no obvious token/password/key
material, open finding counts by severity, zero open critical/high findings,
optional risk acceptance references for open medium findings, review artifact
hashes, and optional saved `/api/security-audit` status/hash.

Create project job:

```bash
curl -sS -X POST http://127.0.0.1:4888/api/jobs \
  -H 'Content-Type: application/json' \
  --data '{"action":"create-project","idea":"Demo paper loop","field":"workflow engineering","target_journal":"General Academic Journal"}'
```

Cancel a running job:

```bash
curl -sS -X POST http://127.0.0.1:4888/api/jobs/<job_id>/cancel \
  -H 'Content-Type: application/json' \
  --data '{}'
```

Clear a terminal job:

```bash
curl -sS -X DELETE http://127.0.0.1:4888/api/jobs/<job_id>
```

Inspect a job event timeline:

```bash
curl -sS http://127.0.0.1:4888/api/jobs/<job_id>/events
```

Retry a failed, cancelled, or unknown job from its saved request payload:

```bash
curl -sS -X POST http://127.0.0.1:4888/api/jobs/<job_id>/retry \
  -H 'Content-Type: application/json' \
  --data '{}'
```

Each job stores a bounded local `events` timeline with lifecycle events such as
`queued`, `started`, `finished`, `cancel_requested`, `cancelled`, and
`retry_requested`. If the console restarts while a job was queued, running, or
cancelling, the loader marks the job `unknown`, adds a `console_restarted`
event, and keeps the saved request payload available for operator retry.

Cleanup old terminal jobs:

```bash
curl -sS -X POST http://127.0.0.1:4888/api/jobs/cleanup \
  -H 'Content-Type: application/json' \
  --data '{"keep":20}'
```

Preview project output:

```bash
curl -sS 'http://127.0.0.1:4888/api/file?project=<slug>&path=references%2Fliterature_review_notes.html'
```

Export a project handoff package without raw or processed data:

```bash
curl -sS -o project-export.zip \
  'http://127.0.0.1:4888/api/project-export?project=<slug>'
```

Export with local raw/processed data only when the recipient is authorized to
receive those files:

```bash
curl -sS -o project-export-with-data.zip \
  'http://127.0.0.1:4888/api/project-export?project=<slug>&include_data=1'
```

## Local Backup And Retention

Project exports are handoff packages. Backups are local recovery artifacts. By
default backups exclude `data/raw/` and `data/processed/` for safer customer
review and operator handoff; include those directories only for authorized
recipients.

Default backup root:

```bash
var/serviceconsole/backups/
```

Optional backup root:

```bash
export DRAFTPAPER_BACKUPS_DIR="/path/to/private/draftpaper-backups"
```

Create a backup without raw or processed data:

```bash
curl -sS -X POST http://127.0.0.1:4888/api/project-backup \
  -H 'Content-Type: application/json' \
  --data '{"project":"<slug>","reason":"before-customer-handoff"}'
```

Create a backup with raw/processed data only when the active actor is authorized:

```bash
curl -sS -X POST http://127.0.0.1:4888/api/project-backup \
  -H 'Content-Type: application/json' \
  --data '{"project":"<slug>","include_data":true,"reason":"full-local-recovery"}'
```

List backups:

```bash
curl -sS http://127.0.0.1:4888/api/backups
```

Verify all backup archives as admin:

```bash
curl -sS http://127.0.0.1:4888/api/backups/verify
```

Rehearse backup restore safely in a temporary directory as admin:

```bash
curl -sS -X POST http://127.0.0.1:4888/api/backups/rehearse \
  -H 'Content-Type: application/json' \
  --data '{"backup_id":"<backup_id>"}'
```

Check restore rehearsal coverage for current backups:

```bash
curl -sS http://127.0.0.1:4888/api/backups/rehearsals
```

Restore a backup as admin:

```bash
curl -sS -X POST http://127.0.0.1:4888/api/backups/<backup_id>/restore \
  -H 'Content-Type: application/json' \
  --data '{"overwrite":false}'
```

Cleanup old backups as admin:

```bash
curl -sS -X POST http://127.0.0.1:4888/api/backups/cleanup \
  -H 'Content-Type: application/json' \
  --data '{"keep":10,"max_age_days":30}'
```

Each backup has a sidecar manifest containing `backup_id`, project slug,
creation timestamp, actor, `include_data`, archive size, and archive SHA256.
Restore verifies the archive checksum before writing a project directory.
`/api/backups/verify` checks every visible backup for manifest presence,
archive presence, SHA256 match, zip readability, and `project.json` presence.
`/api/backups/rehearse` performs a checksum-verified temporary extraction and
records restore rehearsal evidence without overwriting the live `projects/`
directory. `/api/backups/rehearsals` reports whether current backups have a
passing rehearsal record with the matching archive SHA256.
Scoped operators can create non-raw backups for their projects. Raw/processed
data backup still requires `can_export_data=true`; restore and retention cleanup
are admin-only operations.

## Source Release Package

For a local commercial pilot handoff, build a source release package rather
than sending the working directory. The package excludes runtime state such as
local projects, audit logs, virtual environments, caches, and previous `dist/`
output.

Build:

```bash
python scripts/package_release.py --version-label 2026-07-03-local-pilot
```

Signed build with an OpenSSL private key:

```bash
python scripts/package_release.py \
  --version-label 2026-07-03-local-pilot \
  --signing-key /path/to/private/release-signing.pem
```

Artifacts:

- `dist/draftpaper-loop-<label>.zip`
- `dist/draftpaper-loop-<label>.manifest.json`
- `dist/draftpaper-loop-<label>.zip.sha256`
- optional `dist/draftpaper-loop-<label>.zip.sig`
- optional derived public key `dist/draftpaper-loop-<label>.public.pem`

The zip contains:

- project source and docs
- `release_manifest.json`
- `SHA256SUMS`

Before handing the package to another operator, inspect the external manifest,
confirm `missing_required_files=[]`, verify the `.zip.sha256` value, and verify
the zip's internal `SHA256SUMS` entries against the files inside the package.
Use the customer-side verifier:

```bash
python scripts/verify_release_package.py \
  dist/draftpaper-loop-<label>.zip \
  --manifest dist/draftpaper-loop-<label>.manifest.json \
  --sha256-file dist/draftpaper-loop-<label>.zip.sha256
```

For signed packages, require signature verification:

```bash
python scripts/verify_release_package.py \
  dist/draftpaper-loop-<label>.zip \
  --manifest dist/draftpaper-loop-<label>.manifest.json \
  --sha256-file dist/draftpaper-loop-<label>.zip.sha256 \
  --require-signature
```

The verifier checks the external zip SHA256, external manifest, internal
`release_manifest.json`, internal `SHA256SUMS`, required commercial files,
manifest coverage, and private runtime file exclusions. This is integrity
verification. When the package was built with `--signing-key`, the verifier also
checks the detached OpenSSL SHA256 signature using the public key recorded in the
external manifest. This is local detached signing, not a certificate-backed
notarization or third-party code-signing program.

## Release Trust Evidence

For customers that require certificate-backed code signing, notarization, MDM
allowlisting, or a third-party release trust program, store a private release
trust evidence record and verify it against the exact release package and
sidecars. This workflow verifies evidence binding; it does not obtain a
certificate, notarize software, or replace a third-party review.

Prepare a fail-closed private draft from a signed release package:

```bash
python scripts/prepare_release_trust.py \
  --output var/private/release-trust.json \
  --release-zip dist/draftpaper-loop-<label>.zip \
  --release-manifest dist/draftpaper-loop-<label>.manifest.json \
  --release-sha256-file dist/draftpaper-loop-<label>.zip.sha256 \
  --release-signature dist/draftpaper-loop-<label>.zip.sig \
  --release-public-key dist/draftpaper-loop-<label>.public.pem
```

The prepared file defaults to `status=draft`, records the release zip and
sidecar hashes, and keeps verification at `attention` until external trust
evidence is supplied. To write verified evidence from the CLI, provide the
external trust authority, trust reference, verifier, and evidence reference:

```bash
python scripts/prepare_release_trust.py \
  --output var/private/release-trust.json \
  --release-zip dist/draftpaper-loop-<label>.zip \
  --release-manifest dist/draftpaper-loop-<label>.manifest.json \
  --release-sha256-file dist/draftpaper-loop-<label>.zip.sha256 \
  --release-signature dist/draftpaper-loop-<label>.zip.sig \
  --release-public-key dist/draftpaper-loop-<label>.public.pem \
  --status verified \
  --trust-authority "external-review-provider" \
  --trust-reference TRUST-APPROVAL-ID \
  --verified-by "release reviewer" \
  --evidence-ref "third-party-release-review/TRUST-APPROVAL-ID"
```

The Service Console exposes `POST /api/release-trust-draft` and the `Trust
Draft` button. The API accepts release sidecar paths in the request body or
uses `DRAFTPAPER_RELEASE_*` environment variables when configured.

Example evidence file:

```json
{
  "schema_version": "draftpaper.release-trust/v1",
  "status": "verified",
  "trust_type": "third_party_release_trust",
  "trust_authority": "external-review-provider",
  "trust_reference": "TRUST-APPROVAL-ID",
  "verified_by": "release@example.invalid",
  "verified_at": "2026-07-03T00:00:00Z",
  "package": "draftpaper-loop-2026-07-03-local-pilot",
  "evidence_refs": ["third-party-release-review/TRUST-APPROVAL-ID"],
  "release_zip_sha256": "<zip sha256>",
  "release_manifest_sha256": "<manifest sha256>",
  "release_sha256_file_sha256": "<zip.sha256 sidecar sha256>",
  "release_signature_sha256": "<zip.sig sha256>",
  "release_public_key_sha256": "<public key sha256>"
}
```

Verify:

```bash
python scripts/verify_release_trust.py \
  --trust-file var/private/release-trust.json \
  --release-zip dist/draftpaper-loop-<label>.zip \
  --release-manifest dist/draftpaper-loop-<label>.manifest.json \
  --release-sha256-file dist/draftpaper-loop-<label>.zip.sha256 \
  --release-signature dist/draftpaper-loop-<label>.zip.sig \
  --release-public-key dist/draftpaper-loop-<label>.public.pem \
  --output var/private/release-trust-verification.json
```

To expose status in the local console:

```bash
export DRAFTPAPER_RELEASE_TRUST_FILE="$PWD/var/private/release-trust.json"
export DRAFTPAPER_RELEASE_ZIP="$PWD/dist/draftpaper-loop-<label>.zip"
export DRAFTPAPER_RELEASE_MANIFEST_FILE="$PWD/dist/draftpaper-loop-<label>.manifest.json"
export DRAFTPAPER_RELEASE_SHA256_FILE="$PWD/dist/draftpaper-loop-<label>.zip.sha256"
export DRAFTPAPER_RELEASE_SIGNATURE_FILE="$PWD/dist/draftpaper-loop-<label>.zip.sig"
export DRAFTPAPER_RELEASE_PUBLIC_KEY_FILE="$PWD/dist/draftpaper-loop-<label>.public.pem"
bash scripts/deploy_local.sh
curl -sS http://127.0.0.1:4888/api/release-trust
```

The verifier checks owner-only evidence-file permissions, required trust fields,
allowed `trust_type`, parseable and non-future `verified_at`, external evidence
references, no obvious token/password/key material, release zip hash, optional
sidecar hashes, external manifest package/zip alignment, `.zip.sha256` sidecar
alignment, and the release package's detached signature via
`scripts/verify_release_package.py`.

## Commercial Acceptance Suite

For paid local handoff, the preferred operator path is the full commercial
acceptance suite. It runs the release build, release verification, handoff
acceptance, customer dossier build and verification, launch package build and
verification, operations report build, and operations report verification in one
private evidence directory:

The Service Console exposes this as `POST /api/commercial-acceptance-suite` and
the `Suite` button. It requires a signing key path, customer details, target
track, and output directory or uses a private runtime directory by default. The
route runs the suite and then calls `verify_commercial_acceptance_suite.py` on
the generated top-level report, so the console response includes both suite
status and independent verification status. The request token is used only for
probing the local console and downloading the support bundle; it is not written
to the suite report.

```bash
TOKEN="$(cat var/private/handoff-CUST-A/operator-token.txt)"

python scripts/run_commercial_acceptance_suite.py \
  --base-url http://127.0.0.1:4888 \
  --token "$TOKEN" \
  --target-track paid_local_handoff \
  --customer-id CUST-A \
  --customer-name "Customer A" \
  --signing-key var/private/handoff-CUST-A/license-signing.pem \
  --version-label CUST-A-paid-handoff \
  --output-dir var/private/commercial-suite-CUST-A \
  --require-passed
```

Then reverify the top-level suite report and the artifacts it references:

```bash
python scripts/verify_commercial_acceptance_suite.py \
  var/private/commercial-suite-CUST-A/commercial-acceptance-suite.json
```

The suite creates:

- `release/` with the signed release zip, manifest, `.zip.sha256`, detached
  signature, and public key
- `acceptance/handoff-acceptance.json` plus the exact downloaded support bundle
- `customer-dossier/handoff-dossier.zip`
- `launch-package/commercial-launch-package.zip`
- `operations/commercial-operations.json` and `.md`
- `commercial-acceptance-suite.json`, a private top-level status report with
  artifact hashes and step outcomes

The suite does not weaken any underlying gate. It simply orchestrates the same
verifiers documented below and reports `attention` when any required step does
not reach its expected status. The suite verifier checks the suite schema and
digest, every step outcome, every recorded artifact hash, and reruns the
release, handoff dossier, support bundle, launch package, and operations report
verifiers.

For hosted SaaS, pass `--target-track hosted_saas` and include
`--hosted-readiness-dossier`. The hosted track still requires independently
verified external hosted evidence; a local suite report cannot substitute for
hosted production acceptance.

## Handoff Acceptance Report

Before a paid local handoff, generate a saved acceptance report after the
console is running with the customer's private handoff config:

```bash
python scripts/run_handoff_acceptance.py \
  --target-track paid_local_handoff \
  --release-zip dist/draftpaper-loop-<label>.zip \
  --release-manifest dist/draftpaper-loop-<label>.manifest.json \
  --release-sha256-file dist/draftpaper-loop-<label>.zip.sha256 \
  --require-release \
  --require-signature \
  --download-support-bundle \
  --support-bundle-output var/private/handoff-support-bundle.zip \
  --output var/private/handoff-acceptance.json
```

The report records health, commercial readiness, handoff readiness, security
audit, hosted readiness, license status, access policy, quota, billing, backup
verification, backup restore rehearsal status, optional support-bundle hash, and
release package verification. It has a `report_sha256` so the exact acceptance
evidence can be archived with the customer record. It is not legal approval,
code signing, or a third-party security assessment.

The top-level `evidence_summary` is the review surface for handoff approval. It
summarizes the target track status, handoff track failures, license status and
signature plus public-key pin verification, security audit errors/warnings,
release package verification and signature status, backup
verification/rehearsal status, hosted readiness gates, and support-bundle hash
plus support-bundle verification status without promoting private token or key
material.

## Customer Handoff Dossier

After the acceptance report passes, build a customer-facing dossier from the
saved report and release sidecars:

```bash
python scripts/build_handoff_dossier.py \
  --acceptance-report var/private/handoff-acceptance.json \
  --release-zip dist/draftpaper-loop-<label>.zip \
  --release-manifest dist/draftpaper-loop-<label>.manifest.json \
  --release-sha256-file dist/draftpaper-loop-<label>.zip.sha256 \
  --release-signature dist/draftpaper-loop-<label>.zip.sig \
  --release-public-key dist/draftpaper-loop-<label>.public.pem \
  --customer-id CUST-A \
  --customer-name "Customer A" \
  --output-dir var/private/handoff-dossier-CUST-A
```

The dossier zip includes `handoff-dossier.json`,
`handoff-acceptance-summary.json`, and release sidecar files such as the
manifest, `.zip.sha256`, detached signature, and release public key. It does
not include the release zip body, full acceptance `payloads`, private license
files, operator token files, project data, or signing private keys. Send the
release zip separately and compare it against the recorded `zip_sha256`.

Verify the dossier before sending it, and the recipient can rerun the same
command after receiving the separate release zip:

```bash
python scripts/verify_handoff_dossier.py \
  var/private/handoff-dossier-CUST-A/handoff-dossier.zip \
  --release-zip dist/draftpaper-loop-<label>.zip \
  --require-release-zip
```

The verifier checks the dossier digest, customer-safe summary, private-file
exclusions, release sidecar hashes, release signature status, and when supplied
the separate release zip through `scripts/verify_release_package.py`.

## Commercial Launch Package

For a paid customer record, bundle the verified release, release sidecars,
customer handoff dossier, and redacted support bundle into one commercial
launch evidence package:

```bash
python scripts/build_commercial_launch_package.py \
  --target-track paid_local_handoff \
  --acceptance-report var/private/handoff-acceptance.json \
  --release-zip dist/draftpaper-loop-<label>.zip \
  --release-manifest dist/draftpaper-loop-<label>.manifest.json \
  --release-sha256-file dist/draftpaper-loop-<label>.zip.sha256 \
  --release-signature dist/draftpaper-loop-<label>.zip.sig \
  --release-public-key dist/draftpaper-loop-<label>.public.pem \
  --handoff-dossier var/private/handoff-dossier-CUST-A/handoff-dossier.zip \
  --support-bundle var/private/handoff-support-bundle.zip \
  --customer-id CUST-A \
  --customer-name "Customer A" \
  --output-dir var/private/launch-package-CUST-A
```

For hosted SaaS launch records, use `--target-track hosted_saas` and add the
verified hosted readiness dossier:

```bash
python scripts/build_commercial_launch_package.py \
  --target-track hosted_saas \
  --acceptance-report var/private/hosted-acceptance.json \
  --release-zip dist/draftpaper-loop-<label>.zip \
  --release-manifest dist/draftpaper-loop-<label>.manifest.json \
  --release-sha256-file dist/draftpaper-loop-<label>.zip.sha256 \
  --release-signature dist/draftpaper-loop-<label>.zip.sig \
  --release-public-key dist/draftpaper-loop-<label>.public.pem \
  --handoff-dossier var/private/handoff-dossier-CUST-A/handoff-dossier.zip \
  --hosted-readiness-dossier var/private/hosted-readiness-dossier-CUST-A/hosted-readiness-dossier.zip \
  --support-bundle var/private/hosted-support-bundle.zip \
  --customer-id CUST-A \
  --customer-name "Customer A" \
  --output-dir var/private/launch-package-CUST-A
```

Then independently reverify the package before sending or archiving it:

```bash
python scripts/verify_commercial_launch_package.py \
  var/private/launch-package-CUST-A/commercial-launch-package.zip
```

The launch package verifier unpacks the bundle and reruns the underlying
release, handoff dossier, support bundle, and hosted readiness dossier
verifiers. It also checks artifact hashes, package digest, private-file
exclusions, and that the acceptance summary matches the target track. It does
not embed raw acceptance payloads, private license files, env files, tokens,
signing private keys, customer project data, or unredacted runtime state.

## Commercial Operations Report

After launch package verification, generate a customer-safe operations report
for handoff archives, renewal review, or support escalation:

```bash
python scripts/build_commercial_operations_report.py \
  --target-track paid_local_handoff \
  --launch-package var/private/launch-package-CUST-A/commercial-launch-package.zip \
  --require-launch-package \
  --customer-id CUST-A \
  --customer-name "Customer A" \
  --output var/private/operations-CUST-A/commercial-operations.json \
  --markdown-output var/private/operations-CUST-A/commercial-operations.md
```

Then verify the archived report, optionally rechecking the launch package:

```bash
python scripts/verify_commercial_operations_report.py \
  var/private/operations-CUST-A/commercial-operations.json \
  --launch-package var/private/launch-package-CUST-A/commercial-launch-package.zip
```

The operations report summarizes commercial grade, target-track readiness,
license status and signature, security audit, billing status and totals, quota
usage, backup verification, restore rehearsal, hosted readiness status, and
launch package verification. It excludes raw endpoint payloads, token material,
private license paths, env files, and machine-local path roots. The verifier
checks the report digest, embedded error checks, security error count, path
redaction, sensitive-value redaction, and launch package hash match when a
launch package is supplied.

The Service Console exposes the same flow as `POST
/api/commercial-operations-report` and the `Ops Report` button. The route writes
the JSON report and Markdown summary to a private runtime directory by default,
then immediately runs `verify_commercial_operations_report.py` against the saved
JSON. The request token is used only to probe the local console endpoints and is
not written to the archived operations report. Use the optional launch-package
path and `Require launch` control when the operations record is part of a paid
handoff archive.

## Verified Local Install

After the release zip and dossier verify, install the release into a clean local
directory through the verified installer:

```bash
python scripts/install_verified_release.py \
  --release-zip dist/draftpaper-loop-<label>.zip \
  --release-manifest dist/draftpaper-loop-<label>.manifest.json \
  --release-sha256-file dist/draftpaper-loop-<label>.zip.sha256 \
  --release-signature dist/draftpaper-loop-<label>.zip.sig \
  --release-public-key dist/draftpaper-loop-<label>.public.pem \
  --handoff-dossier var/private/handoff-dossier-CUST-A/handoff-dossier.zip \
  --require-signature \
  --require-dossier \
  --run-smoke \
  --install-root /path/to/customer/install-root
```

The installer verifies the release package first, verifies the dossier when
provided, refuses unsafe zip member paths, refuses to overwrite an existing
extracted package unless `--force` is used, and writes an owner-only
`draftpaper-install-manifest.json`. With `--run-smoke`, it also runs
`scripts/smoke_installed_release.py` against the extracted package and writes an
owner-only `draftpaper-installed-smoke.json` under the install root. It does not
run external literature search, hosted services, customer jobs, or data imports.

After installation, run the installed-release smoke test against the extracted
package directory if it was not already run through `--run-smoke`:

```bash
python scripts/smoke_installed_release.py \
  --install-dir /path/to/customer/install-root/draftpaper-loop-<label> \
  --output /path/to/customer/install-root/draftpaper-installed-smoke.json
```

The smoke test checks required handoff files, Service Console manifest
readability, Python syntax for critical scripts, CLI help importability, and a
local create/status project cycle in a temporary directory. It writes an
owner-only JSON report and does not call external literature providers, hosted
services, customer jobs, or data imports.

## Sample Workflow Acceptance

Before a paid demo or assisted delivery, run the offline sample workflow
acceptance check to prove the core loop can execute beyond create/status smoke:

```bash
python scripts/run_sample_workflow_acceptance.py \
  --output var/private/sample-workflow-acceptance.json
```

For debugging or a customer walkthrough, retain the generated sample project:

```bash
python scripts/run_sample_workflow_acceptance.py \
  --work-dir var/private/sample-workflow-acceptance-run \
  --output var/private/sample-workflow-acceptance.json
```

The report checks project creation, offline reference import, data inventory,
data quality/feasibility gates, method planning, figure planning, generated
analysis code, method verification, generated figure quality, result-validity
gate output, and orchestrator status. A passing report proves the local loop is
functionally runnable without external services. It does not certify a real
scientific result; customer domain data and user confirmation are still required
before treating manuscript claims as publishable.

## Claim Confirmation Evidence

For a real customer manuscript, store a private user/domain confirmation record
after the reviewer has checked the manuscript claims against the project's data,
result-validity output, core evidence, figures, and reviewer notes. This
workflow verifies the confirmation record, project binding, and referenced
artifact hashes. It does not create scientific truth, replace peer review, or
prove hosted SaaS readiness.

Example private evidence file:

```json
{
  "schema_version": "draftpaper.claim-confirmation/v1",
  "status": "confirmed",
  "project_id": "customer-paper-slug",
  "project_slug": "customer-paper-slug",
  "confirmation_reference": "CLAIM-REVIEW-001",
  "confirmed_by": "domain reviewer",
  "confirmed_at": "2026-07-03T00:00:00Z",
  "scope": ["result_claims", "domain_data", "figures"],
  "claims": [
    {
      "id": "C1",
      "claim": "Primary result claim as stated in the manuscript.",
      "status": "confirmed",
      "reviewer": "domain reviewer",
      "evidence_refs": [
        "result_validity/result_validity_report.json",
        "core_evidence/core_evidence_report.json"
      ]
    }
  ],
  "artifacts": [
    {
      "path": "result_validity/result_validity_report.json",
      "sha256": "<artifact sha256>"
    }
  ]
}
```

Verify:

```bash
python scripts/verify_claim_confirmation.py \
  --confirmation-file var/private/customer/claim-confirmation.json \
  --project projects/customer-paper-slug \
  --output var/private/customer/claim-confirmation-verification.json
```

To prepare a fail-closed private draft from an existing project, generate the
artifact hash scaffold first:

```bash
python scripts/prepare_claim_confirmation.py \
  --project projects/customer-paper-slug \
  --output var/private/customer/claim-confirmation.json \
  --claim "Primary result claim to be reviewed by the domain owner."
```

The prepared file defaults to `status=draft` and claim status `needs_review`, so
verification remains `attention` until the reviewer explicitly confirms the
claims and audit fields. To write confirmed evidence from the CLI, provide the
reviewer, review reference, and claim text explicitly:

```bash
python scripts/prepare_claim_confirmation.py \
  --project projects/customer-paper-slug \
  --output var/private/customer/claim-confirmation.json \
  --status confirmed \
  --confirmed-by "domain reviewer" \
  --confirmation-reference CLAIM-REVIEW-001 \
  --claim "Primary result claim reviewed against the project evidence."
```

For the local console, set:

```bash
export DRAFTPAPER_CLAIM_CONFIRMATION_FILE=/absolute/private/claim-confirmation.json
export DRAFTPAPER_CLAIM_CONFIRMATION_PROJECT=/absolute/path/to/projects/customer-paper-slug
```

The console exposes this status at `/api/claim-confirmation`, includes the
redacted summary in support bundles as `claim_confirmation.json`, and surfaces
the status in `/api/handoff-readiness` as `claim_confirmation_status`. The
selected project view also has a `Claim draft` action that writes a private
draft under the Service Console runtime directory for reviewer completion.

For hosted SaaS acceptance, configure and verify
`DRAFTPAPER_HOSTED_READINESS_FILE` first, build and verify the hosted readiness
dossier, then target the hosted track:

```bash
python scripts/run_handoff_acceptance.py \
  --target-track hosted_saas \
  --release-zip dist/draftpaper-loop-<label>.zip \
  --release-manifest dist/draftpaper-loop-<label>.manifest.json \
  --release-sha256-file dist/draftpaper-loop-<label>.zip.sha256 \
  --hosted-readiness-dossier var/private/hosted-readiness-dossier-CUST-A/hosted-readiness-dossier.zip \
  --require-release \
  --require-signature \
  --download-support-bundle \
  --support-bundle-output var/private/hosted-support-bundle.zip \
  --output var/private/hosted-acceptance.json
```

When `--target-track hosted_saas` is used, the report requires
`/api/hosted-readiness` to return `status=ready`, every hosted gate to pass, and
`--hosted-readiness-dossier` to verify. This keeps hosted acceptance separate
from paid local handoff acceptance and prevents a raw private evidence JSON from
being mistaken for a reviewed hosted SaaS evidence package.

## Hosted Evidence Collection

After a hosted deployment is reachable, collect a private live evidence packet
from the actual hosted URL before editing the final hosted readiness file:

```bash
python scripts/collect_hosted_readiness_evidence.py \
  --base-url https://draftpaper.example.com \
  --output-dir var/private/hosted-evidence-CUST-A \
  --require-collected
```

Then independently verify the collection report and every referenced artifact:

```bash
python scripts/verify_hosted_evidence_collection.py \
  var/private/hosted-evidence-CUST-A/hosted-readiness-evidence-collection.json
```

Generate an operator controls template, fill it with external SSO/RBAC,
payment, storage/DR, worker-isolation, and deployment-hardening evidence, then
prepare the final private readiness file:

```bash
python scripts/prepare_hosted_readiness.py \
  --collection-report var/private/hosted-evidence-CUST-A/hosted-readiness-evidence-collection.json \
  --write-controls-template \
  --output var/private/hosted-evidence-CUST-A/hosted-readiness-controls.json

python scripts/prepare_hosted_readiness.py \
  --collection-report var/private/hosted-evidence-CUST-A/hosted-readiness-evidence-collection.json \
  --controls-file var/private/hosted-evidence-CUST-A/hosted-readiness-controls.json \
  --output var/private/hosted-evidence-CUST-A/hosted-readiness.json \
  --report-output var/private/hosted-evidence-CUST-A/hosted-readiness-preparation.json \
  --require-ready
```

The collector probes health, commercial readiness, handoff readiness, hosted
readiness, security audit, access policy, quota, billing, license, entitlement,
backup verification, restore rehearsal, and HTTPS certificate evidence. It
writes owner-only JSON artifacts with SHA256 values plus
`hosted-readiness.draft.json`, whose sections remain `pending` until the
operator verifies external identity, billing, storage/DR, worker isolation, and
deployment controls.
The verifier checks the collection digest, artifact hashes, draft hash, path
boundaries, redaction, and confirms that the draft has not been silently changed
to verified controls.
The preparation helper fails closed: it writes `hosted-readiness.json` only when
the collection is independently verified, every hosted control has an approver
reference, every required field/boolean is satisfied, and each operator evidence
artifact has a matching SHA256.

For local rehearsal only, use explicit downgrade flags:

```bash
python scripts/collect_hosted_readiness_evidence.py \
  --base-url http://127.0.0.1:4888 \
  --output-dir var/private/hosted-evidence-rehearsal \
  --allow-localhost \
  --allow-insecure-http
```

The Service Console also exposes `POST /api/hosted-readiness-draft` and the
`Hosted Draft` button. With an empty hosted base URL, it collects a local
rehearsal packet from the running console, writes
`hosted-readiness.draft.json`, and writes a
`hosted-readiness-controls.template.json` file under the private runtime root.
If a real hosted URL is entered, the same route collects from that URL using the
operator token from the authenticated request. The route never marks hosted SaaS
ready by itself; the controls template must still be completed with external
operator evidence and pass `prepare_hosted_readiness.py --require-ready`.

After the controls file is completed, the Service Console can finish the same
evidence assembly through `POST /api/hosted-readiness-finalize` or the
`Hosted Final` button. Provide the collection report path, completed controls
file path, and optionally an output path. The route calls the same fail-closed
preparation helper used by the CLI, writes `hosted-readiness.json` plus a
private preparation report under the runtime root when no explicit output path
is supplied, and can activate the ready evidence file for the current console
process. That activation is only process-local; durable hosted operation still
requires configuring `DRAFTPAPER_HOSTED_READINESS_FILE` in the deployed service
environment.

The hosted handoff can then continue in the Service Console without dropping to
the shell. `POST /api/hosted-readiness-dossier` and the `Hosted Dossier` button
build and independently verify a customer-facing hosted readiness dossier from
the configured or supplied `hosted-readiness.json`. `POST
/api/hosted-production-acceptance` and the `Hosted Accept` button run the
hosted production acceptance probe against the supplied hosted base URL, local
hosted readiness evidence, and verified dossier zip, then write an owner-only
acceptance report. Production acceptance still rejects localhost and plain HTTP
unless the operator explicitly enables rehearsal flags in the console.

Do not treat a successful collection or preparation report as hosted SaaS
readiness by itself. The prepared `hosted-readiness.json` must still pass
`validate_hosted_readiness.py`, the hosted readiness dossier verifier, and hosted
production acceptance against the live URL.

## Hosted Readiness Evidence

Hosted SaaS readiness is evidence-gated. Without a configured evidence file,
`/api/hosted-readiness` reports `not_ready` and `/api/handoff-readiness` keeps
the `hosted_saas` track blocked. This prevents local paid handoff readiness
from being mistaken for an enterprise hosted deployment.

Set a private hosted evidence file:

```bash
export DRAFTPAPER_HOSTED_READINESS_FILE="$PWD/var/private/hosted-readiness.json"
```

Minimal schema:

```json
{
  "schema_version": "draftpaper.hosted-readiness/v1",
  "environment": "production",
  "enterprise_auth": {
    "status": "verified",
    "provider": "oidc-provider",
    "sso_protocol": "oidc",
    "rbac_model": "organization-workspace-role",
    "tenant_isolation": "workspace-scoped policies",
    "mfa_supported": true,
    "audit_events": true,
    "evidence": [
      {
        "path": "evidence/security-review/AUTH-001.txt",
        "sha256": "<sha256>",
        "description": "SSO/RBAC security review evidence"
      }
    ]
  },
  "payment_collection": {
    "status": "verified",
    "provider": "payment-provider",
    "ledger": "server-side ledger",
    "webhook_validation": true,
    "invoice_reconciliation": true,
    "customer_portal": true,
    "evidence": [
      {
        "path": "evidence/billing-review/BILL-001.txt",
        "sha256": "<sha256>",
        "description": "Payment webhook and ledger reconciliation evidence"
      }
    ]
  },
  "managed_storage_dr": {
    "status": "verified",
    "storage_provider": "managed-object-storage",
    "backup_region": "separate-region",
    "restore_runbook": "runbooks/restore.md",
    "off_machine_backups": true,
    "restore_rehearsal_passed": true,
    "evidence": [
      {
        "path": "evidence/dr-rehearsal/DR-001.txt",
        "sha256": "<sha256>",
        "description": "Off-machine backup restore rehearsal evidence"
      }
    ]
  },
  "worker_isolation": {
    "status": "verified",
    "queue_backend": "managed-queue",
    "isolation_boundary": "per-tenant worker identity",
    "retry_policy": "bounded exponential backoff",
    "automatic_retries": true,
    "progress_streaming": true,
    "evidence": [
      {
        "path": "evidence/worker-review/WORKER-001.txt",
        "sha256": "<sha256>",
        "description": "Hosted queue and worker isolation evidence"
      }
    ]
  },
  "deployment_hardening": {
    "status": "verified",
    "environment": "production",
    "secrets_manager": "managed-secret-store",
    "security_review_id": "SEC-REVIEW-001",
    "tls_enforced": true,
    "least_privilege": true,
    "incident_response_plan": true,
    "evidence": [
      {
        "path": "evidence/security-review/SEC-001.txt",
        "sha256": "<sha256>",
        "description": "Deployment hardening and security review evidence"
      }
    ]
  }
}
```

The hosted gate is ready only when every section has `status=verified`, the
required fields are present, required boolean controls are true, and at least
one local evidence artifact exists with a matching SHA256. Relative evidence
paths are resolved from the directory containing `hosted-readiness.json`.
String-only links can be kept as context, but they do not satisfy the gate. The
file should be owner-only (`chmod 600`) and kept under `var/private/` or another
private runtime path.

Generate a private template and validate it before startup or in CI:

```bash
python scripts/validate_hosted_readiness.py \
  --write-template var/private/hosted-readiness.json

python scripts/validate_hosted_readiness.py \
  --evidence-file var/private/hosted-readiness.json \
  --require-ready \
  --output var/private/hosted-readiness-report.json
```

`--require-ready` exits non-zero unless every hosted gate passes. The report is
written owner-only and uses the same rules as `/api/hosted-readiness`.

## Hosted Readiness Dossier

After hosted readiness validates as `ready`, build a customer-facing hosted
evidence dossier:

```bash
python scripts/build_hosted_readiness_dossier.py \
  --evidence-file var/private/hosted-readiness.json \
  --output-dir var/private/hosted-readiness-dossier-CUST-A \
  --customer-id CUST-A \
  --customer-name "Customer A"
```

Then verify the dossier before using it for hosted SaaS acceptance or enterprise
review:

```bash
python scripts/verify_hosted_readiness_dossier.py \
  var/private/hosted-readiness-dossier-CUST-A/hosted-readiness-dossier.zip
```

The hosted dossier includes a readiness summary, the validation report, and
only explicitly referenced evidence artifacts whose SHA256 values match the
private hosted readiness file. It intentionally excludes the raw
`hosted-readiness.json`, private keys, token files, env files, signatures,
archives, runtime state, and customer project data.

## Production Deployment Artifacts

Hosted and enterprise deployments should use the production deployment artifacts
under `deploy/production/` as the starting point:

- `Dockerfile` runs the console as a non-root `draftpaper` user and keeps
  project, runtime, and backup data on mounted volumes
- `docker-compose.example.yml` binds the service to `127.0.0.1:4888`, expects
  private runtime files through a read-only `private/` mount, drops Linux
  capabilities, and enables `no-new-privileges`
- `draftpaper-loop.env.example` points identity, license, billing, and hosted
  readiness configuration to read-only runtime paths
- `draftpaper-loop.service` provides a systemd option with a non-root user,
  loopback binding, and baseline hardening controls

Verify these artifacts before using them as deployment evidence:

```bash
python scripts/verify_production_deployment_artifacts.py \
  --require-verified \
  --output var/private/production-deployment-artifacts-report.json
```

This verifier checks the deployment files, `.dockerignore` private-file
exclusions, non-root execution, health checks, loopback binding for reverse
proxy deployment, secret-file mounting, and compose/systemd hardening controls.
It does not prove that an external hosted deployment is live; the hosted
readiness file still needs real evidence for identity, billing, storage/DR,
worker isolation, and deployment hardening.

## Hosted Production Acceptance

After the hosted service is deployed and `DRAFTPAPER_HOSTED_READINESS_FILE` is
configured on that service, run the hosted production acceptance check against
the actual hosted URL:

```bash
python scripts/run_hosted_production_acceptance.py \
  --base-url https://draftpaper.example.com \
  --evidence-file var/private/hosted-readiness.json \
  --hosted-readiness-dossier var/private/hosted-readiness-dossier-CUST-A/hosted-readiness-dossier.zip \
  --require-passed \
  --output var/private/hosted-production-acceptance.json
```

The check probes `/health`, `/api/commercial-readiness`,
`/api/handoff-readiness`, `/api/hosted-readiness`, security, license,
entitlement, backup verification, and restore rehearsal endpoints. It also
validates the private hosted readiness evidence file and independently verifies
the hosted readiness dossier. The report is owner-only and contains only
customer-safe status summaries, gate IDs, and hashes; it does not include raw
hosted readiness JSON, evidence files, tokens, cookies, secrets, or customer
project data.

`run_hosted_production_acceptance.py` rejects `localhost` and plain HTTP by
default. For local rehearsal only, use both explicit flags:

```bash
python scripts/run_hosted_production_acceptance.py \
  --base-url http://127.0.0.1:4888 \
  --evidence-file var/private/hosted-readiness.json \
  --hosted-readiness-dossier var/private/hosted-readiness-dossier-CUST-A/hosted-readiness-dossier.zip \
  --allow-localhost \
  --allow-insecure-http
```

Do not use a local rehearsal report as hosted SaaS production evidence.

## Live Search Guardrails

Live literature search uses external services and must be bounded in operator
flows. The console starts with conservative defaults:

```bash
DRAFTPAPER_SEARCH_PROVIDERS=semantic_scholar,arxiv
DRAFTPAPER_SEARCH_TIMEOUT_SECONDS=6
DRAFTPAPER_SEARCH_MAX_QUERIES=4
```

The full CLI still supports the richer provider set. For demos and assisted
delivery, prefer offline JSON or Zotero import when deterministic output matters.

## Acceptance Checklist

Before claiming a local commercial build is ready, run:

```bash
python -m unittest discover -s tests
bash -n scripts/deploy_local.sh
python -m py_compile scripts/serviceconsole_app.py scripts/package_release.py scripts/generate_handoff_config.py scripts/verify_release_package.py scripts/verify_handoff_dossier.py scripts/verify_support_bundle.py scripts/build_commercial_launch_package.py scripts/verify_commercial_launch_package.py scripts/build_commercial_operations_report.py scripts/verify_commercial_operations_report.py scripts/install_verified_release.py scripts/smoke_installed_release.py scripts/run_commercial_acceptance_suite.py scripts/verify_commercial_acceptance_suite.py scripts/collect_hosted_readiness_evidence.py scripts/verify_hosted_evidence_collection.py scripts/prepare_hosted_readiness.py scripts/run_hosted_production_acceptance.py scripts/run_sample_workflow_acceptance.py scripts/run_handoff_acceptance.py scripts/build_handoff_dossier.py scripts/build_hosted_readiness_dossier.py scripts/verify_hosted_readiness_dossier.py scripts/verify_production_deployment_artifacts.py scripts/validate_hosted_readiness.py draftpaper_cli/literature_search.py
python scripts/verify_production_deployment_artifacts.py --require-verified
python scripts/run_sample_workflow_acceptance.py --output /tmp/draftpaper-sample-workflow-acceptance.json
python scripts/package_release.py --output-dir /tmp/draftpaper-release-check --version-label acceptance-check
python scripts/verify_release_package.py \
  /tmp/draftpaper-release-check/draftpaper-loop-acceptance-check.zip \
  --manifest /tmp/draftpaper-release-check/draftpaper-loop-acceptance-check.manifest.json \
  --sha256-file /tmp/draftpaper-release-check/draftpaper-loop-acceptance-check.zip.sha256
curl -sS http://127.0.0.1:4888/health
curl -sS http://127.0.0.1:4888/api/commercial-readiness
curl -sS http://127.0.0.1:4888/api/handoff-readiness
curl -sS http://127.0.0.1:4888/api/license
curl -sS http://127.0.0.1:4888/api/security-audit
curl -sS -o /tmp/draftpaper-support-bundle.zip http://127.0.0.1:4888/api/support-bundle
```

Then verify through the console:

- create a project
- import a literature JSON fixture
- preview `references/literature_review_notes.html`
- run `status`
- cancel a synthetic or long-running job when needed
- inspect `/api/jobs/<job_id>/events` for queued/started/finished/retry events
- retry a failed or unknown job with `/api/jobs/<job_id>/retry`
- clear or cleanup terminal jobs
- export a project handoff zip and confirm raw data is excluded by default
- create a project backup, verify the sidecar SHA256, restore it, and run
  retention cleanup
- run `/api/backups/verify` and confirm all current backups are `verified`
- run `/api/backups/rehearse` and confirm `/api/backups/rehearsals` is `passed`
- generate a source release package and run `scripts/verify_release_package.py`
- prefer `scripts/run_commercial_acceptance_suite.py` for paid local customer
  records so the release, handoff acceptance, dossier, launch package,
  operations report, and their verifiers run as one private evidence chain
- run `scripts/verify_commercial_acceptance_suite.py` against the generated
  `commercial-acceptance-suite.json` before archiving or sharing the evidence
- run `scripts/run_handoff_acceptance.py` and archive the JSON report for the
  intended handoff track when manually decomposing the suite
- run `scripts/build_handoff_dossier.py` and archive the customer-facing dossier
  zip next to the signed release sidecars
- run `scripts/verify_handoff_dossier.py` against the dossier zip and separate
  release zip before sending or archiving customer evidence
- run `scripts/build_commercial_launch_package.py` and
  `scripts/verify_commercial_launch_package.py` so release, handoff dossier,
  support bundle, and hosted readiness dossier evidence can be checked as one
  customer/operator launch record
- run `scripts/build_commercial_operations_report.py` and
  `scripts/verify_commercial_operations_report.py` so post-handoff license,
  billing, quota, backup, security, and launch-package evidence can be archived
  as one customer-safe operations record
- run `scripts/install_verified_release.py` into a clean install root and keep
  the generated install manifest with the customer record
- run `scripts/smoke_installed_release.py` against the installed release and
  keep the generated smoke report with the customer record
- repeat an API request with `DRAFTPAPER_CONSOLE_TOKEN` enabled when access control matters
- inspect `/api/usage` and `/api/audit?limit=50`
- inspect `/api/handoff-readiness` and confirm the intended track is `ready`
- configure `DRAFTPAPER_CONSOLE_USERS_FILE` and verify a scoped viewer cannot
  run jobs or see other projects
- verify a scoped operator can run allowed actions but cannot export
  raw/processed data unless explicitly permitted
- configure `daily_job_limit`, `daily_backup_limit`,
  `backup_storage_bytes_limit`, and `max_projects`, then verify over-limit
  requests are rejected
- configure `DRAFTPAPER_BILLING_RATES_FILE` and verify `/api/billing` reports
  line items and totals for the active actor/workspace
- configure `DRAFTPAPER_LICENSE_FILE` for paid handoff and verify
  `/api/license` reports `status=valid`; for paid customer records, generate
  with `--license-signing-key` and confirm `license_signature_verified` passes
- configure `DRAFTPAPER_HOSTED_READINESS_FILE` only after hosted identity,
  payment, storage/DR, workers, and deployment hardening have independent
  evidence; then verify `scripts/validate_hosted_readiness.py --require-ready`
  and `/api/hosted-readiness`
- collect private live hosted evidence with
  `scripts/collect_hosted_readiness_evidence.py --require-collected`, then
  verify it with `scripts/verify_hosted_evidence_collection.py` and prepare the
  final evidence file with `scripts/prepare_hosted_readiness.py --require-ready`
- verify `deploy/production/` with
  `scripts/verify_production_deployment_artifacts.py --require-verified`
  before using the deployment files as hosted/enterprise evidence
- after hosted readiness is verified, run
  `scripts/build_hosted_readiness_dossier.py` and
  `scripts/verify_hosted_readiness_dossier.py` before hosted SaaS acceptance
- run `/api/security-audit`, fix any `severity=error` findings, and explain
  remaining warnings before customer handoff
- download `/api/support-bundle`, confirm it contains diagnostic JSON and does
  not contain project raw/processed data, then verify it with
  `scripts/verify_support_bundle.py`
- set `DRAFTPAPER_MAX_CONCURRENT_JOBS=1` and verify a second running job is rejected

## License Boundary

Commercial use requires written authorization from the project author. The
current repository includes source-available non-commercial terms plus a
commercial license notice. For a paid local pilot, configure
`DRAFTPAPER_LICENSE_FILE` and keep the corresponding written authorization with
the customer record. Do not present local console readiness as permission for
SaaS, resale, enterprise deployment, or integration into a paid product.

Relevant files:

- `LICENSE`
- `COMMERCIAL_LICENSE.md`
- `NOTICE`
- `TRADEMARK.md`
- `COMPLIANCE.md`

## Remaining Product Gaps

The following gaps should stay visible in demos and commercial discussions:

- hosted multi-user authentication and enterprise role management until
  `enterprise_auth` evidence is verified
- workspace isolation beyond local project directories until hosted tenant
  isolation evidence is verified
- hosted payment collection and remote billing integration until
  `payment_collection` evidence is verified
- hosted background queue with automatic retries, worker isolation, and progress
  streaming until `worker_isolation` evidence is verified
- hosted deployment hardening until `deployment_hardening` evidence is verified
- managed off-machine backup storage and disaster recovery automation until
  `managed_storage_dr` evidence is verified
- real customer paper claims still require domain data and explicit user
  confirmation in `DRAFTPAPER_CLAIM_CONFIRMATION_FILE`; the verifier only
  checks the provided evidence record and cannot create scientific truth
- real customer handoff still requires actual external approval evidence in
  `DRAFTPAPER_COMMERCIAL_APPROVAL_FILE`; the verifier only checks the provided
  evidence record and cannot create legal approval
- certificate-backed code signing, notarization, or a third-party release trust
  program still requires actual external evidence in
  `DRAFTPAPER_RELEASE_TRUST_FILE`; the verifier only checks the provided
  evidence record and cannot create release trust
- formal third-party security review still requires actual external evidence in
  `DRAFTPAPER_SECURITY_REVIEW_FILE`; the verifier only checks the provided
  evidence record and cannot perform the review

The hosted readiness dossier workflow now packages verified external evidence
when it exists, but it does not replace the underlying enterprise auth, payment,
storage, worker, deployment, legal approval, or security-review work. These are product
gaps, not core loop gaps. The core loop is already testable through the Python
package, CLI, project artifacts, and local operator console.
