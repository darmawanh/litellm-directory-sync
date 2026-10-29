# LiteLLM Directory Sync

[![CI](https://github.com/darmawanh/litellm-directory-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/darmawanh/litellm-directory-sync/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Enterprise directory synchronization (Active Directory & Okta) and automated access lifecycle management for the [LiteLLM](https://github.com/BerriAI/litellm) AI gateway.

---

## Overview

**LiteLLM Directory Sync** is a production-ready, configurable service that reads identity and entitlement changes from enterprise directory systems (**Active Directory** and **Okta**) and synchronizes them into LiteLLM:

- **Lifecycle Automation**: Handles Joiners (pre-provisioning access), Movers (role and team transitions, budget updates), and Leavers (instant key revocation upon departure).
- **Group & Budget Mapping**: Automatically maps directory groups to LiteLLM teams, model permissions, and spend budgets.
- **Transactional Outbox Pattern**: State changes and gateway events commit atomically to PostgreSQL. Events are retried safely with exponential backoff and idempotency keys without distributed locks.
- **Continuous Reconciliation**: Detects and remediates drift between directory sources and the LiteLLM gateway.
- **Security by Design**: Operates as a strictly read-only consumer of Active Directory (LDAPS) and Okta (System Log & Event Hooks), holding only the permissions necessary to inspect memberships and enforce access in LiteLLM.

```text
Active Directory (LDAPS) ──┐
                           ├──> Worker / API ──> PostgreSQL (Outbox, State, Audit)
Okta (Log / Event Hooks) ──┘           │
                                       └──> LiteLLM Gateway (Keys, Teams, Budgets)
```

---

## Features

- **Multi-Source Support**:
  - **Active Directory**: Incremental polling via USN change tracking over LDAPS (port 636) with fail-safe regression detection.
  - **Okta**: Polling via Okta System Log API with cursor persistence, plus inbound webhook ingress for real-time Okta Event Hooks.
- **Access Policy Enforcement**:
  - Evaluates priority and precedence rules across overlapping groups.
  - Assigns models, RPM/TPM limits, and rolling dollar budgets based on directory group memberships.
  - Immediate key revocation on offboarding, with optional grace periods for team transfers.
- **High-Reliability Architecture**:
  - PostgreSQL outbox table decouples identity ingestion from gateway network calls.
  - Distributed worker coordination via PostgreSQL transactional advisory locks and heartbeat leasing.
- **Observability & Auditing**:
  - Structured logging with trace context.
  - Prometheus metrics for event latency, outbox queue lag, and sync status.
  - Comprehensive audit trail exports in CSV, JSON, and NDJSON.

---

## Quickstart

### Prerequisites

- Python 3.12+
- PostgreSQL 16+
- Running LiteLLM Proxy / Gateway instance
- [uv](https://github.com/astral-sh/uv) (recommended package manager)

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/darmawanh/litellm-directory-sync.git
cd litellm-directory-sync

# Install locked dependencies
uv sync --locked
```

### 2. Configuration

Copy the example configuration file and set your environment variables:

```bash
cp config/config.example.yaml config/config.yaml
cp .env.example .env
```

Edit `config/config.yaml` to specify your identity source connection parameters, group-to-model mappings, and budget policies. All secrets and endpoints are referenced dynamically from environment variables (`os.environ/VAR`).

### 3. Database Migrations

Apply the database schema to your PostgreSQL instance:

```bash
uv run alembic upgrade head
```

### 4. Running the Services

The application provides three complementary process commands:

#### Worker (Polling & Gateway Enforcement)
Polls directory sources, persists identity changes, and processes the transactional outbox:
```bash
uv run identity-lifecycle worker --config config/config.yaml
```

#### API (Health Probes & Webhooks)
Provides HTTP health/readiness endpoints (`/healthz`, `/readyz`), Prometheus metrics, and Okta Event Hook ingress:
```bash
uv run identity-lifecycle api --config config/config.yaml
```

#### Scheduler (Reconciliation)
Runs periodic background directory reconciliation and drift correction:
```bash
uv run identity-lifecycle scheduler --config config/config.yaml
```

---

## Testing & Quality

Run the comprehensive test suite locally:

```bash
# Run unit tests
uv run pytest tests/unit

# Run contract tests against gateway and IdP interfaces
uv run pytest tests/contract

# Run integration tests (requires local Docker daemon for PostgreSQL)
uv run pytest tests/integration

# Run linter and type checker
uv run ruff check .
uv run mypy src
```

---

## Documentation

- **[RUNBOOK.md](RUNBOOK.md)**: Production deployment, configuration reference, and operations guide.
- **[CONTRIBUTING.md](CONTRIBUTING.md)**: Contributor guidelines, code standards, and PR workflows.
- **[SECURITY.md](SECURITY.md)**: Vulnerability disclosure and security architecture.

---

## License

This project is licensed under the [MIT License](LICENSE).
