# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This repository provides a Docker-based solution for running GitHub Actions self-hosted runners. It supports two modes:

1. **Static Pool Mode**: Fixed number of long-running runners using Docker Compose replicas
2. **Autoscaling Mode**: Webhook-driven ephemeral runners that scale based on demand

## Architecture

### Core Files

- **Dockerfile**: Multi-architecture runner container (static pool mode)
- **Dockerfile.ephemeral**: Ephemeral runner for autoscaling mode
- **entrypoint.sh**: Handles runner configuration and lifecycle (static mode)
- **ephemeral-entrypoint.sh**: Single-job runner lifecycle (autoscaling mode)
- **docker-compose.yml**: Static pool orchestration
- **docker-compose.autoscale.yml**: Autoscaling controller setup

### Controller (Autoscaling)

- **controller/webhook_server.py**: Python webhook server that handles `workflow_job` events
- **controller/Dockerfile**: Controller container image
- **controller/requirements.txt**: Python dependencies

### nginx (HTTPS Proxy)

- **nginx/nginx.conf**: Main config for HTTPS (requires external certificates)
- **nginx/nginx-init.conf**: HTTP-only config for development/testing
- **nginx/Dockerfile**: nginx reverse proxy image
- **nginx/entrypoint.sh**: Selects config based on environment

> **Note**: As of early 2025, nginx does not have native ACME support. Certificates must be provided externally (e.g., via certbot).

## Build and Run Commands

### Static Pool Mode (Original)

```bash
# Copy environment template and configure
cp .env.example .env
# Edit .env with your GitHub URL, token, and desired replica count

# Start runners
docker-compose up -d

# Scale runners
docker-compose up -d --scale gh-runner=5
```

### Autoscaling Mode

```bash
# Copy environment template and configure
cp .env.example .env
# Edit .env with:
#   GITHUB_URL, GITHUB_TOKEN, MAX_RUNNERS
#   WEBHOOK_DOMAIN, LETSENCRYPT_EMAIL (for HTTPS)
#   WEBHOOK_HOST (for auto-registering webhook)

# Start the full stack (nginx + controller)
docker-compose -f docker-compose.autoscale.yml up -d

# View logs
docker-compose -f docker-compose.autoscale.yml logs -f

# Check health
curl http://localhost:8080/health
```

### Building Images Locally

```bash
# Static pool runner
docker build -t gh-runner:latest .

# Ephemeral runner
docker build -t gh-runner:ephemeral -f Dockerfile.ephemeral .

# Controller
docker build -t gh-runner-controller:latest ./controller
```

## Configuration

### Single-Repo Mode (Simple Setup)

For a single repository, use environment variables:

- `GITHUB_URL`: Repository or organization URL
- `GITHUB_TOKEN`: GitHub PAT (auto-exchanges for registration token if PAT detected)

### Multi-Repo Mode (Multiple Repositories)

For multiple repositories, use a JSON config file:

```bash
# Set the config file path
REPOS_CONFIG_FILE=/config/repos.json

# Mount the config file in docker-compose
volumes:
  - ./repos.json:/config/repos.json:ro
```

See `repos.example.json` for the configuration format:

```json
{
  "repositories": [
    {
      "id": "myapp",
      "github_url": "https://github.com/myorg/myapp",
      "github_token": "ghp_xxx",
      "runner_labels": "self-hosted,linux",
      "max_runners": 5
    }
  ],
  "defaults": {
    "runner_image": "ghcr.io/depoll/gh-runner-docker:ephemeral",
    "max_runners": 10
  }
}
```

Each repository gets its own webhook endpoint: `/webhook/{repo_id}`

### Autoscaling-Specific Variables

- `WEBHOOK_HOST`: Public URL for auto-registering webhook with GitHub (e.g., `https://your-server.com`)
- `WEBHOOK_SECRET`: Manual webhook secret (auto-generated if not set) - single-repo mode only
- `MAX_RUNNERS`: Maximum concurrent ephemeral runners (default: 10)
- `RUNNER_IMAGE`: Docker image for ephemeral runners

### Webhook Setup Options

1. **Auto-registration** (recommended): Set `WEBHOOK_HOST` to your public URL. Controller registers webhook automatically.
   - Requires: `admin:repo_hook` (repo) or `admin:org_hook` (org) scope
   - Secret is auto-generated and persisted to `/data/secrets/{repo_id}`
   - Multi-repo: Each repo gets webhook at `{WEBHOOK_HOST}/webhook/{repo_id}`

2. **Manual setup**: Configure webhook in GitHub settings.
   - Single-repo: Use `/webhook` endpoint
   - Multi-repo: Use `/webhook/{repo_id}` endpoint for each repo

### Common Variables

- `RUNNER_NAME_PREFIX`: Prefix for runner names (default: "runner")
- `RUNNER_WORKDIR`: Working directory (default: "_work")
- `RUNNER_LABELS`: Comma-separated labels (default: "self-hosted,linux")
- `RUNNER_GROUP`: Runner group (default: "default")
- `REPLICAS`: Number of static runner instances (default: 3)

## Webhook Event Flow (Autoscaling)

0. On startup, controller optionally auto-registers webhook with GitHub API (if `WEBHOOK_HOST` set)
1. GitHub sends `workflow_job` webhook with `action: queued`
2. Controller verifies signature and checks labels
3. Controller spawns ephemeral runner container with `--ephemeral` flag
4. Runner registers with GitHub and picks up job
5. Runner completes job and auto-deregisters
6. Container exits and is removed
7. GitHub sends `workflow_job` with `action: completed`
8. Controller cleans up any remaining container state

## Runner Naming

- **Static mode**: `{RUNNER_NAME_PREFIX}-{container_id}` (e.g., runner-abc1)
- **Autoscaling mode**: `ephemeral-runner-{job_id}-{uuid}` (e.g., ephemeral-runner-12345-abc12345)

## Container Registry

The GitHub Action builds and publishes multi-architecture images to GHCR:
- `ghcr.io/depoll/gh-runner-docker:latest` - Static pool runner
- `ghcr.io/depoll/gh-runner-docker:ephemeral` - Ephemeral runner
- `ghcr.io/depoll/gh-runner-controller:latest` - Webhook controller

## Key Implementation Details

### Ephemeral Runner Flags

The ephemeral runner uses these important flags:
- `--ephemeral`: Runner auto-deregisters after one job
- `--disableupdate`: Prevents auto-updates (image controls version)
- `--replace`: Replaces existing runner with same name

### Webhook Signature Verification

The controller verifies webhooks using HMAC-SHA256:
```python
expected = 'sha256=' + hmac.new(
    WEBHOOK_SECRET.encode(),
    payload,
    hashlib.sha256
).hexdigest()
```

### Webhook Auto-Registration

The controller can auto-register webhooks via GitHub API:
1. `load_or_generate_secret()`: Checks env → persisted file → generates new
2. `register_webhook()`: Creates/updates webhook via GitHub REST API
3. Secret persisted to `/data/webhook_secret` for container restarts

### Health Check Endpoint

Controller provides `/health` endpoint returning:
- Active runner count and details
- Max runners configuration
- Runner status and job IDs