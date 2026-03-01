# VaultKey

Self-hosted secrets and credential management platform for developers and small teams.

VaultKey stores API keys, database credentials, certificates, and environment-specific configuration with envelope encryption, RBAC, versioning, and a tamper-evident audit log.

## Features

- Envelope encryption with per-secret data keys
- Multi-tenant organizations and workspaces
- Role-based access control with path-prefix policies
- Secret versioning with rollback
- CLI for local development and CI injection
- Admin console with htmx
- Runtime API for application secret fetching
- Rotation reminders and break-glass emergency access

## Quick Start

```bash
cp .env.example .env
docker compose up -d
pip install -e ".[dev]"
vaultkey --help
uvicorn vaultkey.api.app:create_app --factory --reload --port 8090
```

## Architecture

Secrets are encrypted with AES-256-GCM using per-secret DEKs wrapped by a master key. Plaintext never touches the database.

## License

MIT
