# Draftpaper Loop Production Deployment

This directory contains deployment artifacts for a hardened hosted or enterprise
environment. These files are examples and must be combined with real hosted
identity, billing, storage/DR, worker isolation, and deployment-hardening
evidence before the `hosted_saas` readiness track can pass.

## Container Deployment

1. Copy `draftpaper-loop.env.example` to `draftpaper-loop.env`.
2. Create `private/` next to the compose file and place customer-specific
   runtime files there:
   - `console-users.json`
   - `commercial-license-grant.json`
   - `billing-rates.json`
   - `hosted-readiness.json`
3. Keep `private/` and `draftpaper-loop.env` out of source control.
4. Start the service behind an HTTPS reverse proxy:

```bash
docker compose -f deploy/production/docker-compose.example.yml up -d --build
```

The compose example binds the service to `127.0.0.1:4888`; expose it externally
only through an HTTPS proxy that terminates TLS and applies access controls.

## Systemd Deployment

For a non-container host, install the project under `/opt/draftpaper-loop`, keep
runtime data under `/var/lib/draftpaper-loop`, and keep private config in
`/etc/draftpaper-loop`. The supplied `draftpaper-loop.service` runs the console
as the `draftpaper` user with `NoNewPrivileges`, `PrivateTmp`, and a strict
read-only system view except for the configured runtime paths.

## Verification

Run the verifier before using these artifacts in commercial or hosted evidence:

```bash
python scripts/verify_production_deployment_artifacts.py
```

This verifies that deployment files exist, the image runs as a non-root user,
health checks are declared, private files are excluded from image context, and
the compose/systemd examples include basic hardening controls.

After the hosted URL is live, collect private live evidence for the hosted
readiness file:

```bash
python scripts/collect_hosted_readiness_evidence.py \
  --base-url https://draftpaper.example.com \
  --output-dir var/private/hosted-evidence-CUST-A \
  --require-collected

python scripts/verify_hosted_evidence_collection.py \
  var/private/hosted-evidence-CUST-A/hosted-readiness-evidence-collection.json

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

The collector writes hashed API/TLS artifacts and a pending
`hosted-readiness.draft.json`; it does not by itself make the hosted SaaS track
ready. The preparation helper writes final hosted readiness evidence only after
the collection verifies and operator evidence artifacts match their hashes.
