# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for identity-lifecycle production service
# Fulfills AI_PLATFORM_IDENTITY_DESIGN.md §14, §15 and AGENTS.md §3

# ==========================================
# Stage 1: Builder
# ==========================================
FROM python:3.12-slim AS builder

# Copy uv binary from official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Enable bytecode compilation and copy link mode for deterministic virtualenv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Install dependencies first for optimal layer caching
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project

# Copy source code and build/install project into .venv non-editable
COPY src/ ./src/
RUN uv sync --locked --no-dev --no-editable

# ==========================================
# Stage 2: Runtime
# ==========================================
FROM python:3.12-slim AS runtime

# Install system ca-certificates for secure outbound LDAPS and HTTPS connections
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create unprivileged non-root user and group (appuser:appuser, UID/GID 10001)
RUN groupadd --gid 10001 appuser && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv

# Copy application code, database migrations, alembic configuration, and config template
COPY --chown=appuser:appuser src/ /app/src/
COPY --chown=appuser:appuser migrations/ /app/migrations/
COPY --chown=appuser:appuser alembic.ini /app/alembic.ini
COPY --chown=appuser:appuser config/config.example.yaml /app/config/config.example.yaml

# Ensure virtualenv binaries are on PATH and Python output is unbuffered
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Expose port 8000 for identity-lifecycle api
EXPOSE 8000

# Set unprivileged non-root user
USER appuser

# Entrypoint executes identity-lifecycle CLI
ENTRYPOINT ["identity-lifecycle"]

# Default command displays CLI help
CMD ["--help"]
