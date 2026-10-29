# Runbook: LiteLLM Directory Sync

Status: **Production-ready core.** The service polls enabled Active Directory and Okta sources, persists changes and cursors to PostgreSQL, processes the outbox through LiteLLM, and records immutable audit rows.

Audience: the engineer who installs, configures, starts, verifies, and recovers this service.

**This runbook covers the service.** It assumes AD, Okta, LiteLLM, and PostgreSQL already exist. Those systems are not installed, deployed, or provisioned by this project. Appendix A explains how to stand up disposable test instances for local development, clearly marked as outside the project.

---

## 0. What you are building

```text
 Active Directory (USN) / Okta (System Log) ──> identity-lifecycle worker ──> LiteLLM gateway ──> keys ──> models
 │
 └──> PostgreSQL (cursor, outbox, canonical store, audit)
```

Current command status:

| Process | Command | Role |
|---|---|---|
| Worker | `identity-lifecycle worker` | Active Directory & Okta poller, durable outbox consumer, LiteLLM writes |
| API | `identity-lifecycle api` | Inbound HTTP API, health probes (`/healthz`, `/readyz`), Okta Event Hook ingress |
| Scheduler | `identity-lifecycle scheduler` | Periodic directory reconciliation engine, drift detection, outbox emission |

Start order: PostgreSQL and LiteLLM -> apply migrations -> identity-lifecycle worker -> identity-lifecycle scheduler -> identity-lifecycle api.

The worker, scheduler, and API take `--config PATH`, which defaults to `config/config.yaml` . Configuration is validated at startup. The API process provides `/healthz`, `/readyz`, and Okta Event Hook ingress at `/api/v1/hooks/okta`.

### 0.1 What this project owns, and what the operator provides

This is an open-source service. It connects to systems you already run. It ships no infrastructure.

| This project | The operator provides |
|---|---|
| The service, its config schema, its tests | An AD forest, OUs, groups, and a certificate authority |
| Client adapters for Active Directory, Okta, and LiteLLM | An Okta org or AD domain, app/account integration, and read credentials |
| Connection config: `server`, `group_dn`, `group_id`, `base_url` | A running LiteLLM gateway with a management key |
| Test doubles in `tests/fixtures/` | PostgreSQL 16 or later |
| Documentation for connecting and operating | Credentials, hostnames, and network access |

A dependency appears here only as a connection block in `config.yaml`. If a value is missing, the service fails fast at startup with the missing key named. There is no default host, tenant, or credential.

The service is a **read-only consumer of Active Directory and Okta** and writes only to LiteLLM. Both AD and Okta sources are supported and can be enabled individually or together. The sections below distinguish the working worker path from features that remain deferred.

---

## 1. Prerequisites

- Python 3.12 and `uv` for the service and repository gates.
- Docker for PostgreSQL-backed integration tests. The worker itself connects to an operator-managed PostgreSQL database.
- PostgreSQL for a running worker, LiteLLM for access writes, and an Okta org with the read-only scopes for a live demonstration. Configure credentials in the process environment.
- `psql` is optional and useful for inspecting the database.

The unit and contract tests use local fakes. Do not use production credentials for development or acceptance tests.

## 2. Get the code and configure

```bash
git clone <repo-url> identity-lifecycle
cd identity-lifecycle
git rev-parse HEAD # record the commit you are running
cp config/config.example.yaml config/config.yaml
cp .env.example .env
git check-ignore -v config/config.yaml .env
git status --short # expected: no output
```

The clone URL is supplied by the operator. `.env` and `config/config.yaml` are ignored by git. Keep credentials in the process environment or a secret manager; never put secret values in the config or repository.

### 2.1 Environment variables

The sample contains enabled Active Directory and Okta sources. `.env` is not loaded automatically, so export values or configure the service manager to inject them.

| Variable | Used by | Purpose |
|---|---|---|
| `DATABASE_URL` | service | PostgreSQL connection string, for example `postgresql+psycopg://user:pass@host:5432/identity_lifecycle` |
| `LIFECYCLE_MASTER_KEY` | config | Required by the shipped config; reserved for the API command, which is not implemented |
| `LOG_LEVEL` | worker | Optional default for `--log-level` |
| `LITELLM_BASE_URL` | service | LiteLLM gateway base URL |
| `LITELLM_MASTER_KEY` | service | LiteLLM management key |
| `AD_SERVER` | service | Active Directory LDAPS endpoint, for example `ldaps://dc01.corp.example.com:636` |
| `AD_BIND_DN` | service | Read-only bind DN for Active Directory |
| `AD_BIND_PASSWORD` | service | Read-only bind password for Active Directory |
| `AD_CA_CERT_PATH` | service | Path to CA bundle for LDAPS certificate verification |
| `OKTA_ORG_URL` | service | Okta org URL |
| `OKTA_CLIENT_ID` | service | OAuth service app client identifier |
| `OKTA_KEY_ID` | service | Registered OAuth signing key identifier |
| `OKTA_PRIVATE_KEY_PATH` | service | Path to the OAuth private signing key |

Generate `LIFECYCLE_MASTER_KEY` with `openssl rand -hex 32`. The Okta private key is provisioned by the operator and referenced by path; do not put its contents in the config or repository. Request only `okta.users.read`, `okta.groups.read`, and `okta.logs.read` for the Okta app.

## 3. Connect the service

The repository ships the service process only. It does not install or deploy PostgreSQL, Okta, LiteLLM, or AD.

```bash
uv sync --locked
uv run alembic upgrade head
uv run identity-lifecycle worker --config config/config.yaml
```

The worker validates config on startup, creates the configured identity source read clients (AD LDAPS, Okta HTTP) and LiteLLM gateway, polls configured feeds (AD USN poll, Okta System Log), commits changes and cursors atomically to PostgreSQL, then processes pending outbox rows. It runs until stopped. On SIGINT or SIGTERM it stops claiming new rows and finishes the batch it holds. A missing or unsupported source configuration fails with a typed error. There is no separate config validation command.

### 3.1 Run tests

```bash
uv run pytest tests/contract tests/unit
uv run pytest tests/integration
uv run pytest
```

The integration suite uses testcontainers PostgreSQL and requires Docker. The counts change as tests are added; use the command exit status and gate output for the current tree.

### 3.2 CLI commands

`identity-lifecycle version` prints the package version. `identity-lifecycle api`, `identity-lifecycle worker`, and `identity-lifecycle scheduler` run the three service processes, supporting `--config` and `--log-level`. The operator CLI subcommands are:
- `identity-lifecycle config validate [--config PATH]`: parses and validates configuration and environment references without starting server sockets or connecting to databases. Exits 0 on valid configuration, exits 3 (`CONFIG`) on invalid/missing configuration.
- `identity-lifecycle reconcile [--dry-run] [--config PATH] [--log-level LEVEL]`: runs a one-shot reconciliation pass across enabled identity sources and the LiteLLM gateway, detecting drift and enqueueing corrective outbox events (or evaluating drift only when `--dry-run` is supplied).
- `identity-lifecycle sync (--employee ID | --user ID) [--config PATH] [--log-level LEVEL]`: targeted manual resynchronization for a single person (FR17), evaluating target entitlements against LiteLLM and enqueueing an immediate corrective outbox event.
- `identity-lifecycle audit export [--from ISO_TIMESTAMP] [--to ISO_TIMESTAMP] [--employee ID | --user ID] [--format {csv,json}] [--ndjson] [--output PATH] [--config PATH] [--log-level LEVEL]`: exports access decision audit trails (FR14, FR30) filtered by date range and identity in RFC 4180 CSV or JSON/NDJSON format to stdout or a file.
- `identity-lifecycle outbox replay --id UUID [--config PATH] [--log-level LEVEL]`: resets dead or poisoned outbox rows by row ID or canonical event UUID back to `pending` with `attempts = 0` for worker re-processing.
- `identity-lifecycle source check [--source NAME] [--config PATH] [--log-level LEVEL]`: verifies read connectivity, TLS validation, authentication credentials, and group/member readability without writing to database or gateway.
- `identity-lifecycle source poll [--source NAME] [--once] [--config PATH] [--log-level LEVEL]`: executes on-demand (`--once`) or continuous polling of configured identity sources, committing change events to PostgreSQL outbox and advancing cursors and snapshots.

All 7 operator CLI subcommands reserved in ADR-007 §2 are implemented.

### 3.3 Contributor gates

Run the quick gate during development and all four repository gates before proposing a change for review:

```bash
uv run pytest tests/unit
uv run ruff check . && uv run mypy src && uv run pytest
```

`uv run ruff check . && uv run mypy src && uv run pytest` runs ruff, format check, strict mypy, and pytest. Docker-backed integration tests must run for changes that depend on PostgreSQL behavior.

### 3.4 Container build and deployment

The repository ships a multi-stage `Dockerfile` that packages the production service image without development dependencies, secrets, or dependency infrastructure. The image runs as unprivileged user `appuser` (UID/GID 10001), exposes port 8000, and defaults entrypoint to `identity-lifecycle`.

**1. Build the production service container:**

```bash
docker build -t identity-lifecycle:latest .
```

**2. Run database migrations using the container:**

```bash
docker run --rm \
 -e DATABASE_URL="postgresql+psycopg://user:pass@host:5432/identity_lifecycle" \
 --entrypoint alembic \
 identity-lifecycle:latest upgrade head
```

**3. Run service processes:**

Run the API service:
```bash
docker run -d --name identity-api \
 --restart unless-stopped \
 -p 8000:8000 \
 -v /path/to/config.yaml:/app/config/config.yaml:ro \
 --env-file .env \
 identity-lifecycle:latest api --config /app/config/config.yaml
```

Run the worker process:
```bash
docker run -d --name identity-worker \
 --restart unless-stopped \
 -v /path/to/config.yaml:/app/config/config.yaml:ro \
 --env-file .env \
 identity-lifecycle:latest worker --config /app/config/config.yaml
```

Run the scheduler process:
```bash
docker run -d --name identity-scheduler \
 --restart unless-stopped \
 -v /path/to/config.yaml:/app/config/config.yaml:ro \
 --env-file .env \
 identity-lifecycle:latest scheduler --config /app/config/config.yaml
```

---

## 4. PostgreSQL connection

PostgreSQL is an operator-managed dependency. Use PostgreSQL 16 or later and configure `DATABASE_URL` in the worker environment. Apply the tracked migration chain before starting the worker:

```bash
uv run alembic upgrade head
uv run alembic current
```

`alembic current` prints the applied revision. Verify the durable outbox and cursor tables when `psql` is available:

```bash
psql "$DATABASE_URL" -c '\d identity_event_outbox'
psql "$DATABASE_URL" -c '\d source_cursors'
```

The outbox stores canonical events for at-least-once processing. A System Log page and its source cursor are committed in one transaction, so a restart resumes from the last committed cursor. Grant the migration and runtime roles only the schema and table privileges the operator requires; the service does not need a PostgreSQL superuser account.

---

## 5. LiteLLM connection

**IMPLEMENTED — T-045.** You provide a running LiteLLM gateway; this project does not deploy one. The adapter targets v1.105.0 and proves each management write through read-back . The live acceptance test is restricted to a local nonproduction gateway and needs its URL and management key in the process environment.

### 5.1 What you need from the gateway operator

| Item | Example | Where it goes |
|---|---|---|
| Base URL | `https://litellm.internal.example.com` | `gateway.base_url` |
| Management key | `sk-...` | `LITELLM_MASTER_KEY` in the environment |
| The gateway version | `v1.105.0` | Record it; behavior varies by version |

The management key is a secret. It goes in the environment or a secret manager, never in `config.yaml`.

### 5.2 Verify the API surface

Run these checks against the gateway you will use. **ADR-004 records what v1.105.0 supports**, including behavior that differs from the original design.

```bash
export LL=$LITELLM_BASE_URL
export KEY=$LITELLM_MASTER_KEY

# create a user (pre-provisioning, FR5)
curl -s -X POST $LL/user/new -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' \
 -d '{"user_id":"lc-probe-001","user_email":"probe@example.com","user_role":"internal_user"}'

# create a team (FR34)
curl -s -X POST $LL/team/new -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"team_alias":"lc-probe-team"}'

# initial team membership: set it through user/new with teams 
curl -s -X POST $LL/user/new -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' \
 -d '{"user_id":"lc-probe-002","user_role":"internal_user","teams":["<team_id>"]}'

# set a budget
curl -s -X POST $LL/user/update -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"user_id":"lc-probe-001","max_budget":50,"budget_duration":"30d"}'

# list the user's keys
curl -s $LL/key/list -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
 -d '{"user_id":"lc-probe-001"}'

# revoke: block the key, not the user (see ADR-004)
curl -s -X POST $LL/key/block -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"key":"<key>"}'

# cleanup
curl -s -X POST $LL/user/delete -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"user_ids":["lc-probe-001","lc-probe-002"]}'
curl -s -X POST $LL/team/delete -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"team_ids":["<team_id>"]}'
```

If your gateway version differs from v1.105.0, record the results. A version that changes the revocation path is a design change, not an adapter detail.

### 5.3 Prove revocation

Run the acceptance flow with a local LiteLLM v1.105.0 instance:

```bash
LITELLM_BASE_URL="${LITELLM_BASE_URL:?set a local nonproduction URL}" \
LITELLM_MASTER_KEY="${LITELLM_MASTER_KEY:?set the local management key}" \
uv run pytest tests/integration/test_litellm_live.py -q
```

The test drives a synthetic join and leave through `IngestEvent` and `ProcessEvent`, with a
`FakeIdentitySource` and the real LiteLLM adapter. It creates a temporary team and user, blocks
the user's key through the adapter, confirms the key receives `401`, and deletes the temporary
objects. The key is held only in test memory. The test skips when either environment variable is
missing or the URL is not local; a skip means the live demo remains unverified.

---

## 6. Okta connection

The read-only Okta adapter and System Log poller are implemented. A live-org demonstration needs an Okta developer org, read scopes, and service-app signing key; those are currently unavailable. A hook secret is not required for the delivered System Log path. The worker uses OAuth private-key JWT with the fixed read-only scopes and does not run an Event Hook route.

The System Log poller is the delivered feed. It reads Users, Groups, and System Log data; Okta write calls are not part of the adapter.

### 6.1 What you need from the Okta administrator

| Item | Example | Where it goes |
|---|---|---|
| Org URL | `https://example.okta.com` | `okta.org_url` |
| Group ID | `00gEXAMPLE0000000000` | `group_id` in the source block and in each mapping |
| Read credential | OAuth service app with private-key JWT | `OKTA_CLIENT_ID` + `OKTA_KEY_ID` + `OKTA_PRIVATE_KEY_PATH` |
| Scopes | `okta.users.read`, `okta.groups.read`, `okta.logs.read` | Requested when the app is created |

The service only reads. Ask for read scopes only. If an admin offers a token with write scopes, decline it: the service has no write path and a broader credential is a liability.

### 6.2 Config block

```yaml
identity_sources:
 - source_name: okta
 source_type: okta
 enabled: true
 okta:
 org_url: os.environ/OKTA_ORG_URL
 oauth:
 client_id: os.environ/OKTA_CLIENT_ID
 key_id: os.environ/OKTA_KEY_ID
 private_key_path: os.environ/OKTA_PRIVATE_KEY_PATH
 group_id: 00gEXAMPLE0000000000
 stable_id: id
 cross_system_key: employeeNumber
 change_feed: system_log
 system_log:
 poll_interval_seconds: 60
 overlap_seconds: 60
 page_limit: 200
 requests_per_second: 2
 burst: 4
 retention_seconds: 604800
```

### 6.3 Operate the System Log path

Start the worker using section 3 after applying the database migrations. Add or remove a user from the configured Okta group, then allow up to `okta.system_log.poll_interval_seconds` for the next poll. The worker logs the page commit and processes the resulting outbox event through LiteLLM. Verify the account and key state in the gateway and inspect the audit and outbox rows in PostgreSQL (section 9.4).

The poller commits each page and its cursor in one transaction. It resumes from the saved `after` token after a restart; a gap triggers a full group sync and reseeds the cursor . Continuation pages are paced under `okta.system_log.requests_per_second`; the worker polls again at the configured interval after the drain completes.

### 6.4 Event Hook ingress

The Event Hook API route is delivered by `identity-lifecycle api`. When `change_feed: event_hook` is configured on an enabled Okta source, `identity-lifecycle api` mounts the hook route at its configured `path` (unconfigured paths return 404), verifies the GET handshake (`x-okta-verification-challenge`), authenticates POST payloads with shared secrets in constant time (the admin master key is not accepted), enforces per-IP moving window rate limiting (`verification_requests_per_minute` with HTTP 429 and `Retry-After`), validates IP allowlists and clock skew (300s window), bounds request bodies before buffering via early `Content-Length` and streaming cap enforcement (`max_body_bytes`, returning HTTP 413 `payload_too_large`), normalizes events, and transactionally commits them to `identity_event_outbox` for the worker to process. The unused `verification_token` parameter is not supported.

The worker process (`identity-lifecycle worker`) runs concurrently with the API process in dual-feed mode (Option A, D-011, D-014). It drains and processes events enqueued by the hook route, while simultaneously running the `OktaSystemLogPoller` at the configured `poll_interval_seconds` as the always-on second feed to catch any events missed by hook delivery.

The System Log gap rule provides the delivered worker path's recovery behavior. A detected gap triggers a full group sync and reseeds the cursor .

**A `okta_system_log_gap` log event.** Once per drain, on the first response, the poller compares the window against `covered_through` and the configured `system_log.retention_seconds` (default `604800`). A gap means that interval cannot be shown to have been read; the `reason` field is `cursor_unusable`, `clock_backwards`, `window_ahead_of_coverage`, or `aged_out`. Every gap triggers a full group sync and reseeds the cursor .

### 6.5 Verify directory connectivity

Run the diagnostic source check command to verify Okta OAuth credentials and target group readability:

```bash
uv run identity-lifecycle source check --source corp-okta
```


---

## 7. AD connection

The read-only Active Directory adapter and integer USN poller are implemented and composed into the worker. The service connects over LDAPS on port 636 with mandatory TLS certificate verification (`AD_CA_CERT_PATH`), tracks integer USNs per domain controller, diffs group member snapshots on each poll, and detects member additions, removals, and account disablement (`ACCOUNTDISABLE` bit 0x0002). Directory write operations are completely absent .

The 7.2 block below follows the same shape as `config/config.example.yaml`: `objectGUID` is the source identity, `employeeID` is a nullable cross-system link, and no separate fallback attribute is configured .

### 7.1 What you need from the directory team

| Item | Example | Where it goes |
|---|---|---|
| LDAPS URL | `ldaps://dc01.corp.example.com:636` | `ad.server` |
| Search base | `OU=AI Platform,DC=corp,DC=example,DC=com` | `ad.search_base` |
| Group DN | `CN=AI-Platform-Users,OU=Groups,...` | `ad.group_dn` and each mapping |
| Read-only bind DN | `CN=svc-identity-read,OU=Service Accounts,...` | `AD_BIND_DN` |
| Bind password | - | `AD_BIND_PASSWORD` |
| CA certificate | A PEM file | `AD_CA_CERT_PATH` |
| Confirmation that `employeeID` is populated and unique | - | The cross-system link; `objectGUID` is the identity |

Use a dedicated read-only account with no replication rights (`DS-Replication-Read` must not be granted); do not use a domain administrator account. `objectGUID` is the source identity whether or not `employeeID` is populated, and the cross-system link must be unambiguous .

### 7.2 Config block

```yaml
identity_sources:
 - source_name: corp-ad
 source_type: ad
 enabled: true
 ad:
 server: os.environ/AD_SERVER
 domain: example.com
 search_base: OU=AI Platform,DC=example,DC=com
 group_dn: CN=AI-Platform-Users,OU=Groups,OU=AI Platform,DC=example,DC=com
 bind_dn: os.environ/AD_BIND_DN
 bind_password: os.environ/AD_BIND_PASSWORD
 ca_cert_path: os.environ/AD_CA_CERT_PATH
 stable_id: objectGUID
 cross_system_key: employeeID
 change_feed: usn_poll
 poll_interval_seconds: 60
```

### 7.3 Operate the Active Directory USN poll path

Start the worker using section 3 after applying database migrations. The worker resolves the DC host once, reads RootDSE to identify the domain controller's `invocationID` and `highestCommittedUSN`, and runs `poll_once` every `ad.poll_interval_seconds`.

On each poll cycle, the worker reads the group object unconditionally, compares the directory members against the persisted `source_group_members` snapshot in PostgreSQL, checks for user attribute changes (such as account disablement via `userAccountControl`), and atomically commits outbox rows, updated snapshot, and the advanced integer USN cursor in a single database transaction.

### 7.4 Verify change detection

Membership changes in Active Directory (adding or removing a member from the target group) are detected at the next poll cycle. When a member is removed, `ADPoller` emits `group.member_removed`; when a member is added, it emits `group.member_added`. When an account is disabled (`ACCOUNTDISABLE` bit 0x0002), it emits `user.disabled`.

### 7.5 `uSNChanged` behavior you must know

- `uSNChanged` increases per domain controller. Pin one DC, or the cursor jumps and events are missed.
- The cursor is an integer, never a string: `"9999"` sorts above `"10000"` as text, so a text cursor moves backwards at the 10 000 boundary and every later change is skipped .
- A changed DC `invocationID`, a USN that moves backwards, or an absent or malformed token forces a full sync and re-seeds the cursor .
- Poll the **group object** as well as user objects; membership changes update the group's `member` attribute.
- A full group sync runs on cursor reset. Treat the change feed as an optimization, not the truth.

### 7.6 Verify Active Directory connectivity

Run the diagnostic source check command to verify LDAPS connection, TLS cert, and group readability:

```bash
uv run identity-lifecycle source check --source corp-ad
```

---

## 8. End-to-end verification

The automated composition test uses the real Okta adapter, poller, PostgreSQL outbox, worker, and process use case with fixture HTTP and Gateway clients. A live acceptance run requires an Okta developer org and a nonproduction LiteLLM management key; these prerequisites are currently missing.

For a live run, configure the enabled Okta source and LiteLLM Gateway, apply migrations, and start `uv run identity-lifecycle worker --config config/config.yaml`. Add a user to the configured group, wait up to the System Log poll interval, and verify the user, key, outbox status, and audit row. Remove the user and verify the key is blocked. The API health endpoints, manual sync, reconciliation, scheduler, and AD path are not delivered in v1.

---

## 9. Operations

The worker, scheduler, and api processes, operator CLI subcommands (`config validate`, `reconcile`, `sync`, `audit export`, `outbox replay`, `source check`, `source poll`), outbox inspection and replay, and database backup are available.

### 9.1 Start, stop, restart

Supervise the worker using the operator's process manager. This repository does not build a container image.

```bash
uv run identity-lifecycle worker
```

Logs include worker startup, System Log page commits, outbox outcomes, and worker shutdown. `--log-level` defaults to `LOG_LEVEL` from the environment, then `INFO`. On SIGINT or SIGTERM the worker stops claiming new rows and finishes the batch it holds; the 30-second shutdown budget is measured and logged, not enforced by killing a running write. An abandoned lease is recovered after expiration.

### 9.2 Pause ingestion

Stop the worker process to pause source polling and outbox processing. Pending rows remain durable in PostgreSQL. Do not disable the configured source to pause: rows for a disabled source are settled permanently by the event processor.

### 9.3 Force a resync

Operators can force immediate resynchronization using the operator CLI commands:

**1. Resynchronize an individual employee or user (FR17):**

```bash
uv run identity-lifecycle sync --employee E12345
# or by source user ID:
uv run identity-lifecycle sync --user 00u1234567890abcdef
```

This queries enabled identity sources, evaluates desired entitlements against the LiteLLM gateway, and transactionally enqueues an immediate corrective event into `identity_event_outbox` for worker processing. Exits 0 on success, exits 4 (`PERMANENT`) if the target is not found or has ambiguous links.

**2. Full reconciliation pass:**

Inspect drift in dry-run mode without mutating gateway state or outbox:
```bash
uv run identity-lifecycle reconcile --dry-run
```

Apply drift corrections and enqueue corrective outbox events:
```bash
uv run identity-lifecycle reconcile
```

**3. Run operator commands in Docker:**

Resynchronize via container:
```bash
docker run --rm \
 -v /path/to/config.yaml:/app/config/config.yaml:ro \
 --env-file .env \
 identity-lifecycle:latest sync --employee E12345 --config /app/config/config.yaml
```

Run one-shot reconciliation via container:
```bash
docker run --rm \
 -v /path/to/config.yaml:/app/config/config.yaml:ro \
 --env-file .env \
 identity-lifecycle:latest reconcile --dry-run --config /app/config/config.yaml
```

Validate configuration via container:
```bash
docker run --rm \
 -v /path/to/config.yaml:/app/config/config.yaml:ro \
 --env-file .env \
 identity-lifecycle:latest config validate --config /app/config/config.yaml
```

### 9.4 Inspect and replay the outbox

Inspect queue status:

```bash
psql "$DATABASE_URL" -c \
 "select status, count(*), min(next_attempt_at) from identity_event_outbox group by status;"
```

Inspect dead rows:

```bash
psql "$DATABASE_URL" -c \
 "select id, event_id, event_type, attempts, last_error from identity_event_outbox where status='dead';"
```

#### Replay dead or failed outbox events 

Once the upstream cause of a dead-letter failure (e.g. gateway misconfiguration, transient network partition, or missing dependency) has been resolved, replay the row by either its row surrogate `id` or canonical `event_id`:

```bash
# Replay by row surrogate ID or event UUID:
uv run identity-lifecycle outbox replay --id <uuid>
```

Running in Docker:

```bash
docker run --rm \
 -v /path/to/config.yaml:/app/config/config.yaml:ro \
 --env-file .env \
 identity-lifecycle:latest outbox replay --id <uuid> --config /app/config/config.yaml
```

Replaying resets the outbox row's status from `dead` to `pending`, clears `attempts` to 0, resets `last_error` to null, and moves `next_attempt_at` to the current time, making it immediately eligible for worker claim. Rows actively held under an unexpired lease in `status = 'processing'` are rejected with exit code 4 (`PERMANENT`) to prevent race conditions.

### 9.5 Rotate a credential

1. Provision a new Okta service-app signing key and update `OKTA_KEY_ID` and `OKTA_PRIVATE_KEY_PATH` in the secret store.
2. Restart the worker and verify it can poll and process an event.
3. Revoke the old key in Okta after the new key is confirmed.

The LiteLLM management key is also an operator-managed secret. Update `LITELLM_MASTER_KEY`, restart the worker, and verify a gateway read/write path before revoking the previous key. `LIFECYCLE_MASTER_KEY` is reserved for the undelivered API process.

### 9.6 Backup and restore

The database is the operator's. Use their normal procedure.

```bash
pg_dump "$DATABASE_URL" -Fc > backup.dump
pg_restore -d "$RESTORE_DATABASE_URL" backup.dump
```

RPO is 5 minutes, RTO is 1 hour for the service and 4 hours for a full resync. Test a restore every quarter.

### 9.7 Audit export

Audit records are stored in PostgreSQL (`audit_events` table) and capture every access decision,
actor, target, timestamp, action, outcome, and reason (FR14, FR30). Operators and compliance auditors
can export audit events filtered by date range and employee or source user:

```bash
# Export all audit records for a date range in RFC 4180 CSV to stdout:
uv run identity-lifecycle audit export --from 2026-01-01T00:00:00Z --to 2026-01-31T23:59:59Z --format csv

# Export audit records for a specific employee in JSON format to a file:
uv run identity-lifecycle audit export --employee E12345 --format json --output /var/log/audit/E12345.json

# Export audit records for a source user in newline-delimited JSON (NDJSON):
uv run identity-lifecycle audit export --user 00u1234567890abcdef --format json --ndjson

# Export all audit history up to the current time:
uv run identity-lifecycle audit export --format csv --output audit_export.csv
```

Exported columns (11 fields in order):
- `event_id`: Canonical event UUID.
- `timestamp`: UTC ISO-8601 timestamp (`occurred_at`).
- `actor`: System or component initiating the event (e.g. `corp-okta`, `corp-ad`).
- `action`: Access action (`create`, `update`, `revoke`, `no_change`).
- `source`: Identity source name.
- `person_id`: Internal person identifier.
- `employee_number`: Employee ID if linked, otherwise empty.
- `email`: Employee email address if linked, otherwise empty.
- `reason`: Policy resolution reason (e.g. `highest_precedence`, `new_hire`, `leave`).
- `outcome`: Access decision outcome (`granted`, `revoked`, `not_entitled`, `ambiguous_link`, etc.).
- `details`: Source event ID or audit event metadata.

### 9.8 Diagnostic source check 

Operators can diagnose and verify identity source connectivity, TLS/certificate configuration, authentication, and directory group and member readability without running a full sync or mutating gateway state. The `source check` command connects directly to the directory read-only APIs and does not require a database connection.

```bash
# Check all enabled sources:
uv run identity-lifecycle source check

# Check a specific source by configured name:
uv run identity-lifecycle source check --source corp-okta
uv run identity-lifecycle source check --source corp-ad
```

Running in Docker:

```bash
docker run --rm \
 -v /path/to/config.yaml:/app/config/config.yaml:ro \
 --env-file .env \
 identity-lifecycle:latest source check --source corp-okta --config /app/config/config.yaml
```

Output details:
- Prints connectivity status, groups inspected, and members found per source.
- Exits 0 if all checked sources are healthy and accessible.
- Exits 3 (`RETRYABLE`) if network connectivity or TLS handshake fails.
- Exits 4 (`PERMANENT`) if credentials fail authentication or the specified source name does not exist in configuration.

### 9.9 Manual and on-demand source polling 

Operators can trigger manual or on-demand source polling passes to ingest directory changes into PostgreSQL without running the full background worker process:

```bash
# Poll a single cycle across all enabled sources and exit:
uv run identity-lifecycle source poll --once

# Poll a specific source for one cycle/drain and exit:
uv run identity-lifecycle source poll --source corp-okta --once
uv run identity-lifecycle source poll --source corp-ad --once

# Run continuous source polling loop (ticks every poll interval until SIGINT/SIGTERM):
uv run identity-lifecycle source poll
uv run identity-lifecycle source poll --source corp-okta
```

Running in Docker:

```bash
docker run --rm \
 -v /path/to/config.yaml:/app/config/config.yaml:ro \
 --env-file .env \
 identity-lifecycle:latest source poll --source corp-okta --once --config /app/config/config.yaml
```

Output details:
- When `--once` is supplied: outputs enqueued event counts, execution latency, and overall summary to stdout.
- Transactional persistence: writes canonical events to `identity_event_outbox` and updates `source_cursors` (and `source_group_members` for AD) in PostgreSQL within atomic transactions (ER6, FR27).
- Exits 0 on success (or on clean SIGINT/SIGTERM termination in continuous mode).
- Exits 2 (`CONFIG`) if `DATABASE_URL` is missing or configuration is invalid.
- Exits 3 (`RETRYABLE`) if transient network or directory error occurs.
- Exits 4 (`PERMANENT`) if an unknown or disabled source name is passed or permanent directory error occurs.

### 9.10 Grace-period account deletion and rehire lifecycle (FR25, FR26, FR31, ADR-019)

When an employee leaves or is removed from an entitled group:
1. **Immediate Revocation (15-Minute SLA)**:
 - Team memberships are removed immediately and all API keys held by the user are blocked via `gateway.revoke_keys`.
 - The user record in LiteLLM is NOT deleted immediately. Instead, a scheduled deletion deadline (`delete_after = now + timedelta(hours=reconciliation.grace_period_hours)`) is persisted to `litellm_accounts` in PostgreSQL (default: 24 hours).
2. **Rehire Before Expiration (FR26)**:
 - If the employee is rehired before `delete_after` arrives, the pending deletion is cancelled (`delete_after = NULL`), the person record is reactivated (`status = 'active'`), the gateway account is updated with the current mapping's role, team, and budget policy, and new entitlements are issued.
 - Old keys remain revoked; fresh keys are issued upon subsequent login.
3. **Grace-Period Expiration Sweeper **:
 - Expired accounts (`delete_after <= now`) are detected during periodic reconciliation runs (`identity-lifecycle scheduler` or manual `identity-lifecycle reconcile`).
 - In dry-run mode (`--dry-run`), expired accounts are reported as drift (`kind="grace_period_expired"`) without mutating gateway or database state.
 - In live mode, expired users are deleted from the LiteLLM gateway (`POST /user/delete`). Deletion must succeed before local cleanup occurs:
 - On successful deletion, the user is removed from `litellm_accounts` and an `AuditEvent` with `action="delete_user"` and `decision="grace_period_expired"` is recorded.
 - If the user is already absent (404/not found), local state is cleaned up and audited with `reason="already_absent"`.
 - On retryable gateway errors (`RetryableError`), local account state and `delete_after` deadline are retained for the next sweep without writing a false success audit.
 - On other permanent errors (`PermanentError`), local state is preserved and audited as `delete_user_failed`.
 - `POST /api/v1/reconcile` returns HTTP 503 if any deletion fails in live mode; the scheduler logs warnings and continues running.

### 9.11 Observability, metrics, and SLA alerting 

The API process (`identity-lifecycle api`) exports Prometheus metrics at `/metrics` over HTTP:

```bash
curl http://localhost:8000/metrics
```

#### Key Metrics & Alerts

| Metric | Type | Meaning | Alert Condition |
|---|---|---|---|
| `identity_lifecycle_revocation_duration_seconds` | Histogram | Time from directory leave (`occurred_at`) to gateway key invalidation | Alert when p95 exceeds 600s |
| `identity_lifecycle_revocation_sla_violations_total` | Counter | Count of revocations taking longer than 15 minutes (900s) | Page on `increase(...) > 0` (NFR6 breach) |
| `identity_lifecycle_equal_precedence_failures_total` | Counter | Count of events failed permanently due to tied group precedence | Page on `increase(...) > 0` |
| `identity_lifecycle_events_processed_total` | Counter | Total events processed, labeled by `source`, `action`, `outcome` | Monitor processing rate and error ratio |
| `identity_lifecycle_event_processing_duration_seconds` | Histogram | Execution latency of event processing in worker | Warn if p99 exceeds 5.0s |

#### Equal-Precedence Recovery Procedure 

When `identity_lifecycle_equal_precedence_failures_total` increases:
1. Identify the failed event and affected person via `identity-lifecycle audit export --format json` (look for `decision: "failed"` and `reason: "equal_precedence"`).
2. Edit `config/config.yaml` to adjust group precedence rankings so that competing groups have distinct precedence levels (ensuring a gap of at least 10, per §10.9).
3. Validate configuration:
 ```bash
 identity-lifecycle config validate --config config/config.yaml
 ```
4. Replay dead outbox events:
 ```bash
 identity-lifecycle outbox replay --source <source_name>
 ```
5. The worker will re-process the event, select the clear winner, apply access on LiteLLM, and settle `DONE`.

### 9.12 Admin HTTP API endpoints (FR13, FR14, FR17, FR30, ADR-007, ADR-021)

The API process (`identity-lifecycle api`) exposes administrative endpoints requiring bearer authentication with `LIFECYCLE_MASTER_KEY`:

```bash
export LIFECYCLE_MASTER_KEY="your-secret-master-key"
```

#### 1. Audit Log Export (`GET /api/v1/audit/export`)

Query access decision audit records filtered by date range, employee, or user:

```bash
# Export in JSON format (default)
curl -s -H "Authorization: Bearer $LIFECYCLE_MASTER_KEY" \
 "http://localhost:8000/api/v1/audit/export?from=2026-01-01T00:00:00Z&to=2026-01-31T23:59:59Z"

# Export in RFC 4180 CSV format
curl -s -H "Authorization: Bearer $LIFECYCLE_MASTER_KEY" \
 "http://localhost:8000/api/v1/audit/export?format=csv&employee=E12345"

# Export in NDJSON format
curl -s -H "Authorization: Bearer $LIFECYCLE_MASTER_KEY" \
 "http://localhost:8000/api/v1/audit/export?format=ndjson&user=00uabc123"
```

#### 2. Targeted Manual Resync (`POST /api/v1/sync`)

Trigger targeted evaluation and corrective outbox enqueueing for a single identity:

```bash
# Sync by employee number
curl -s -X POST -H "Authorization: Bearer $LIFECYCLE_MASTER_KEY" \
 -H "Content-Type: application/json" \
 -d '{"employee": "E12345"}' \
 http://localhost:8000/api/v1/sync

# Sync by source user ID
curl -s -X POST -H "Authorization: Bearer $LIFECYCLE_MASTER_KEY" \
 -H "Content-Type: application/json" \
 -d '{"user": "00uabc123"}' \
 http://localhost:8000/api/v1/sync
```

#### 3. On-Demand Reconciliation (`POST /api/v1/reconcile`)

Trigger on-demand directory-to-gateway drift detection:

```bash
# Reconcile in dry-run mode (reports drift without mutations)
curl -s -X POST -H "Authorization: Bearer $LIFECYCLE_MASTER_KEY" \
 "http://localhost:8000/api/v1/reconcile?dry_run=true"

# Reconcile in live mode (emits corrective outbox events and performs deletions)
curl -s -X POST -H "Authorization: Bearer $LIFECYCLE_MASTER_KEY" \
 http://localhost:8000/api/v1/reconcile
```

#### 4. Concurrency and Threading Architecture 

All blocking operations on admin endpoints (`GET /api/v1/audit/export`, `POST /api/v1/sync`, `POST /api/v1/reconcile`, and database readiness probe `GET /readyz`) run in Starlette's worker threadpool. This ensures that heavy database queries, directory reads, and gateway reconciliations do not block the Uvicorn asyncio event loop, allowing `/healthz`, `/readyz`, and `/metrics` to remain immediately responsive. Each request creates and manages its own independent Unit of Work within the executing thread; database sessions are never shared across threads. Synchronous outbox persistence in hook ingestion is similarly offloaded to the worker threadpool.

---

## 10. Troubleshooting

### Process Exit Codes 

| Exit Code | Name | Description | Restart Behavior |
|---|---|---|---|
| `0` | `SUCCESS` | Clean termination | Normal exit |
| `3` | `CONFIG` | Configuration error, missing environment variable, invalid `LIFECYCLE_MASTER_KEY`, or dependency construction failure at startup | Do not restart; fix configuration |
| `4` | `PERMANENT` | Unrecoverable error (e.g. fatal data corruption, unrecognized subcommand) | Do not restart; requires investigation |
| `5` | `RETRYABLE` | Transient operational error (e.g. database connectivity loss during poll) | Restart with backoff |

The API process (`identity-lifecycle api`) fails closed with exit code 3 before binding the HTTP socket if any dependency (database configuration, `AdminToken`, gateway client, or identity sources) fails construction .

| Symptom | Likely cause | Fix |
|---|---|---|
| Startup names a missing or unresolved config key (exit 3) | Required value or `os.environ/VAR` is unset | Set the named value in the worker environment; the worker does not load `.env` automatically |
| Startup says an enabled source is unsupported (exit 3) | Event Hook or an unsupported source type is configured | Disable it or use the implemented `ad` (`usn_poll`) or `okta` (`system_log`) sources |
| Okta OAuth fails | Private key path, client ID, key ID, org URL, or read scopes are wrong | Check the injected values and Okta app grants; use only the three documented read scopes |
| Okta returns 429 or a transient 5xx | Vendor rate limit or temporary outage | Check worker logs and allow the poller retry policy to resume; pending outbox rows remain durable |
| A System Log gap is reported | Cursor is unusable, coverage is inconsistent, or the window aged out | The poller performs a full group sync and reseeds the cursor; confirm the configured retention assumption with the Okta operator |
| Database connection fails or tables are missing | `DATABASE_URL` is wrong, database is unreachable, or migrations are unapplied | Check connectivity and run `uv run alembic upgrade head` |
| Outbox rows remain pending | LiteLLM is unreachable or returning retryable errors | Check the gateway URL, management key, and worker logs; retryable rows are rescheduled |
| Outbox rows become dead | A permanent gateway or processing error occurred | Inspect `last_error`, correct the underlying cause, and track replay as deferred work; no replay command exists |
| A user keeps access after leaving | Key revocation was not applied or the event is not yet processed | Inspect outbox and audit rows, then verify the LiteLLM key state; revocation is key-scoped |
| `/healthz` or `/readyz` is unavailable | Health endpoints are not implemented | Monitor the process and dependencies with the operator's process and infrastructure monitoring |

## 11. Production checklist

The current worker path still needs a live acceptance run with nonproduction Okta and LiteLLM systems before it can be called operationally verified.

- [ ] Okta service app has only `okta.users.read`, `okta.groups.read`, and `okta.logs.read`.
- [ ] Okta group ID and mappings match the intended access policy.
- [ ] LiteLLM management credential is stored in the operator's secret manager.
- [ ] PostgreSQL access is scoped, encrypted in transit, backed up, and restore-tested.
- [ ] The worker is supervised and logs are collected; outbox backlog and dead rows are reviewed.
- [ ] Join and leave have been verified end to end, including key-scoped revocation and audit rows.
- [ ] No unsupported AD, Event Hook, API, scheduler, manual sync, or reconciliation capability is assumed to be present.
- [ ] No infrastructure for a dependency is present in the repository or service image.

## Appendix A: Disposable test instances (outside this project)

**Outside this project.** The examples below are for disposable local dependencies only. The repository does not ship their images, compose files, charts, or seed scripts (P-015, design 1.1).

**This appendix is not part of the project.** It exists so a contributor can exercise the service locally without access to a real directory or gateway. The AD and LiteLLM instances are the operator's own throwaway copies, in a separate environment, not deployments this repository performs .

Put these files in a directory outside the repository, or in a path that `.gitignore` excludes. Never commit them. Never reference them from `config.yaml` in a deployment. The paths below are illustrative names for files you create *outside* the clone; none of them is tracked.

### A.1 PostgreSQL

```bash
docker run -d --name lc-postgres \
 -e POSTGRES_USER=identity_lifecycle \
 -e POSTGRES_PASSWORD=dev-only-password \
 -e POSTGRES_DB=identity_lifecycle \
 -p 5432:5432 postgres:17-alpine
```

### A.2 LiteLLM with a mock model

```bash
docker run -d --name lc-litellm -p 4000:4000 \
 -e LITELLM_MASTER_KEY=sk-local-dev-master-key \
 ghcr.io/berriai/litellm:v1.105.0
```

The image starts with no models. Add a mock model in a local config if you need to make a call; the mock provider costs nothing.

Verify: `curl -s localhost:4000/health/liveliness`.

### A.3 Samba AD DC

```yaml
# docker-compose.ad.yml — keep this OUTSIDE the repository
services:
 samba-ad:
 image: nowsci/samba-domain
 environment:
 DOMAIN: CORP.EXAMPLE.COM
 DOMAINPASS: 'Passw0rd!ChangeMe'
 NOCOMPLEXITY: "false"
 DNSFORWARDER: 1.1.1.1
 ports:
 - "389:389"
 - "636:636"
 hostname: dc1
 domainname: corp.example.com
```

Then create a directory that looks like a real one:

```bash
docker compose -f docker-compose.ad.yml exec samba-ad \
 samba-tool ou create "OU=AI Platform,DC=corp,DC=example,DC=com"

docker compose -f docker-compose.ad.yml exec samba-ad \
 samba-tool group add "AI-Platform-Users" --groupou="OU=AI Platform"

docker compose -f docker-compose.ad.yml exec samba-ad \
 samba-tool user create alice 'Passw0rd!ChangeMe' \
 --given-name=Alice --surname=Smith --userou="OU=AI Platform"

# employeeID is not set by default; add it explicitly
docker compose -f docker-compose.ad.yml exec samba-ad \
 ldbmodify --url=ldap://localhost -U administrator%'Passw0rd!ChangeMe' <<'EOF'
dn: CN=alice,OU=AI Platform,DC=corp,DC=example,DC=com
changetype: modify
add: employeeID
employeeID: E12345
EOF

docker compose -f docker-compose.ad.yml exec samba-ad \
 samba-tool group addmembers "AI-Platform-Users" alice
```

Verify:

```bash
ldapsearch -H ldap://localhost:389 \
 -D "CN=administrator,CN=Users,DC=corp,DC=example,DC=com" \
 -w 'Passw0rd!ChangeMe' -b "OU=AI Platform,DC=corp,DC=example,DC=com" \
 "(objectClass=group)" cn member
```

For LDAPS, create a self-signed CA and server certificate, install the server certificate in the DC, and point `AD_CA_CERT_PATH` at the CA. Verify:

```bash
openssl s_client -connect localhost:636 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

This is a stand-in. It is not a production domain controller and its passwords are public in this document.

### A.4 Okta

There is no local stand-in. Use a free Okta Developer org and follow section 6, or use the `respx` fixtures in `tests/fixtures/`.

### A.5 Event Hook testing (deferred)

The worker does not expose an Event Hook route, so do not register a hook against it. A public HTTPS endpoint and hook validation can be tested only after the deferred ingress feature is implemented.

### A.6 Cleanup

```bash
docker rm -f lc-postgres lc-litellm
docker compose -f docker-compose.ad.yml down -v
```
