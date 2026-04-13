# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CrowdStrike to Chronicle Intel Bridge (CCIB) — a Python service that continuously forwards CrowdStrike Falcon Intelligence indicators to Google Chronicle via a producer-consumer threading model. Requires Python >= 3.11.

## Development Commands

```bash
# Install with dev dependencies
uv pip install -e .[devel]

# Linting (matches CI — run all three before pushing)
uv run flake8 ccib
uv run pylint ccib
uv run bandit -l -i -r ccib

# Run the application
uv run python -m ccib
```

No automated tests exist yet. `pytest` is a dev dependency but unused.

## Architecture

**Producer-consumer with two daemon threads connected by a `Queue(maxsize=10)`:**

- `FalconReaderThread` (producer in `threads.py`) — polls Falcon Intel API on a configurable interval (default 60s), deduplicates via `ICache`, enqueues indicator batches
- `ChronicleWriterThread` (consumer in `threads.py`) — dequeues batches, splits into 250-item chunks (Chronicle API limit), sends with retry logic (30 attempts, exponential backoff, session recreation after 5 failures)

**Key modules in `ccib/`:**

| Module | Role |
|---|---|
| `__main__.py` | Entry point — loads config, validates, creates clients, starts threads |
| `config.py` | `FigConfig` extends ConfigParser; merges defaults.ini → config.ini → env vars |
| `falcon.py` | `FalconAPI` — wraps falconpy Intel SDK with generator-based pagination (1000/request) |
| `chronicle.py` | `Chronicle` — Google OAuth2 service account auth, 16+ regional endpoints |
| `threads.py` | `FalconReaderThread` and `ChronicleWriterThread` with retry/backoff |
| `icache.py` | `ICache` — in-memory deduplication via content comparison (ignores timestamps) |
| `log.py` | Logging setup: `YYYY-MM-DD HH:MM:SS ccib ThreadName LEVEL message` |

## Configuration

**Priority (highest first):** environment variables → `config/config.ini` → `config/defaults.ini`

Key env vars: `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_CLOUD_REGION`, `CHRONICLE_CUSTOMER_ID`, `CHRONICLE_REGION`, `GOOGLE_SERVICE_ACCOUNT_FILE`, `LOG_LEVEL`

## Linting Configuration (setup.cfg)

- **Max line length**: 160 (flake8 and pylint)
- **Max complexity**: 10 (flake8)
- **Disabled pylint checks**: C0114, C0115, C0116 (missing docstrings), C0103 (naming), R0903 (too few public methods), W0719 (broad exception)

## CI/CD (GitHub Actions)

- **linting.yml** — flake8, pylint, bandit on push/PR to main
- **container_build.yml** — Docker build verification on push/PR to main
- **docs.yml** — Markdown link checking on .md file changes
