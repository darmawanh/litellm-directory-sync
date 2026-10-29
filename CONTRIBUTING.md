# Contributing to LiteLLM Directory Sync

Thank you for your interest in contributing! This project is a self-contained identity
lifecycle synchronization service that connects Active Directory and Okta to the LiteLLM gateway.

## Development Setup

Python 3.12 is required. We use [uv](https://github.com/astral-sh/uv) for fast, reproducible dependency management and virtual environments.

```bash
# Clone the repository
git clone https://github.com/darmawanh/litellm-directory-sync.git
cd litellm-directory-sync

# Install locked dependencies
uv sync --locked

# Install pre-commit hooks
uv run pre-commit install
```

`uv.lock` is committed. When modifying dependencies in `pyproject.toml`, run `uv lock` to update the lockfile.

## Quality Gates

Before submitting a pull request, ensure all four gates pass locally:

```bash
# 1. Linting
uv run ruff check .

# 2. Formatting
uv run ruff format --check .

# 3. Static Type Checking
uv run mypy src

# 4. Test Suite
uv run pytest
```

## Architecture & Code Guidelines

The codebase follows Clean Architecture principles:

```text
api and workers -> application -> domain
adapters -> ports
application -> ports
domain -> nothing
```

- **`domain`**: Pure models, events, error types, and core policies. Never imports third-party libraries, databases, or frameworks.
- **`ports`**: Protocols and abstract interfaces only.
- **`application`**: Use cases (e.g. event processing, reconciliation, audit export). Interacts with ports without knowing specific adapter implementations.
- **`adapters`**: Infrastructure and vendor implementations (LDAP client, Okta client, LiteLLM HTTP client, PostgreSQL persistence).
- **`api` & `workers`**: Entry points, background task loops, and FastAPI application endpoints.

### Key Rules

1. **System Boundary**: The service is a read-only consumer of identity sources (Active Directory and Okta) and writes only to LiteLLM.
2. **Transactional Outbox**: State transitions and outbox events commit together in a single PostgreSQL transaction.
3. **No Secrets**: Never commit credentials, tokens, or private keys. All configurations must reference environment variables (`os.environ/VAR`).
4. **Typed Errors**: Distinguish clearly between retryable errors (transient network failures, 5xx responses) and permanent errors (validation failures, 4xx responses).
5. **Tests**: All new features and bug fixes must be accompanied by comprehensive tests.

## Submitting Pull Requests

1. Fork the repository and create a feature branch (`git checkout -b feature/my-feature`).
2. Write tests covering your changes.
3. Ensure all quality gates pass (`ruff`, `mypy`, `pytest`).
4. Submit a clear and descriptive pull request.
