# Security policy

## Reporting a vulnerability

Report a suspected vulnerability **privately**. Do not open a public issue, a public pull
request, or a discussion thread.

Use GitHub's private vulnerability reporting on the repository
(`Security` → `Report a vulnerability`). That is the only reporting channel this project
publishes: there is no security address in `pyproject.toml` or elsewhere in the repository,
so do not look for one. Include:

- the affected version or commit,
- what an attacker can do and under what conditions,
- the steps to reproduce, with secrets and personal data removed,
- any suggested fix.

Do not test against infrastructure you do not own. This repository ships no AD, Okta,
LiteLLM, or PostgreSQL instance; a report that requires one should describe the
configuration, not include a live tenant, hostname, or credential.

We will acknowledge a report, tell you whether we can reproduce it, and coordinate a
disclosure date with you. Please give us a reasonable window before publishing.

## No secrets in an issue or pull request

Never put a credential in an issue, a pull request, a comment, a log excerpt, a test
fixture, or a screenshot. That includes:

- the AD bind password and any certificate or private key;
- the Okta OAuth private key, Event Hook shared secret, and verification token;
- the LiteLLM master key or management key;
- the database password and `DATABASE_URL`.

If you have already exposed one, say so in the private report. Rotate it immediately and
treat it as compromised; deleting the comment is not enough, because the value remains in
notification email, forks, and caches.

`config/config.example.yaml` uses `os.environ/VAR` for every credential and
`tests/unit/test_config_example.py` fails the build if a literal value appears under a
credential key. Do not weaken that test.

## Credential posture: read-only on identity sources

The service is a **read-only consumer** of AD and Okta. It holds no credential that could
change a directory (design 1.1, NFR16):

- **AD** — a dedicated read-only service account over LDAPS on port 636, no replication
  rights, no write rights. Certificate verification against the operator's CA is
  mandatory and is never disabled to work around a chain error (design 12, ADR-005 §9).
- **Okta** — an OAuth service app with only the read scopes `okta.users.read`,
  `okta.groups.read`, and `okta.logs.read` (design 9.3, 12). The service does not accept an
  `SSWS` API token because its permissions cannot be constrained to these scopes.
- **PostgreSQL** — a scoped database role over TLS (design 9.3).

If the service could write to a directory, a bug in this service could alter the
operator's directory. That is why the `IdentitySource` port has no write method, and a
change that adds one is a scope change requiring an ADR (design 1.1).

## The service writes only to LiteLLM

LiteLLM is the enforcement point, so gateway writes are in scope and are the single
deliberate asymmetry (design 1.1, P-014). The gateway credential:

- is sent only in the `Authorization: Bearer` header, over HTTPS;
- is restricted to management endpoints;
- lives in the environment or a secret manager, never in `config.yaml` (NFR2);
- is rotated on a schedule.

The service does not create, modify, or delete anything in AD or Okta. It does not
configure LiteLLM's SSO, its UI, or its model routing (design 1, out of scope).

## Inbound surface

The Okta Event Hook endpoint is the only public endpoint (design 9.3). It requires a
shared-secret header compared in constant time, an IP allowlist enforced at the ingress
and again in the service, and replay protection on `event_id` with a bounded clock skew.
It never performs the gateway call inline: it verifies, validates, enqueues, and returns
(design 9.2).

## Data handling

- Secrets: the AD bind password, the Okta token and private key, the hook secret, and the
  LiteLLM key (design 12).
- Personal data: name, email, employee number, and department. Store only the attributes
  the service needs (NFR8, design 12).
- Audit records are retained for one year; personal data is deleted or anonymized after
  the retention period (NFR17, design 12).
- Logs are structured and must not contain a credential. A token, password, or key in a
  log line is a defect, not a debugging aid (design 15.3, 16.2 rule 11).

## Failure policy

Fail closed for new access and fail safe for existing access (NFR11, NFR12, P-008). If an
identity source is unavailable, do not create a new user or key; keep existing access
until the SLA expires and raise an alert.

## Supported versions

The project is at Phase 0 and has no released version yet. Security fixes target the
default branch. Once a release exists, this section will name the supported versions.

## Out of scope

- Vulnerabilities in AD, Okta, LiteLLM, or PostgreSQL themselves. Report those to the
  vendor; this project connects to those systems and does not ship them (design 1.1).
- A misconfiguration of the operator's own infrastructure, such as a directory account
  with write rights or a gateway key with unrelated permissions.
