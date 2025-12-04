# GitHub Actions Self-Hosted Runners with Docker

A scalable Docker-based solution for running GitHub Actions self-hosted runners. Supports two modes:

1. **Static Pool Mode**: A fixed number of long-running runners (original behavior)
2. **Autoscaling Mode**: Webhook-driven ephemeral runners that scale dynamically based on demand

## Features

- **Multi-architecture**: Automatically builds for x64 and arm64
- **Two scaling modes**: Static pool or webhook-based autoscaling
- **Ephemeral runners**: Clean environment for each job (autoscaling mode)
- **Docker-in-Docker**: Full Docker support within runners
- **Auto-updates**: Watchtower integration for automatic image updates
- **Stateless**: No persistent volumes required

## Quick Start

### Static Pool Mode (Simple)

1. **Clone and configure:**
   ```bash
   git clone https://github.com/depoll/gh-runner-docker.git
   cd gh-runner-docker
   cp .env.example .env
   ```

2. **Edit `.env` with your settings:**
   ```bash
   GITHUB_URL=https://github.com/your-org/your-repo
   GITHUB_TOKEN=your_github_token_here
   REPLICAS=3
   ```

3. **Run the runners:**
   ```bash
   docker-compose up -d
   ```

### Autoscaling Mode (Recommended for Production)

1. **Clone and configure:**
   ```bash
   git clone https://github.com/depoll/gh-runner-docker.git
   cd gh-runner-docker
   cp .env.example .env
   ```

2. **Edit `.env` with your settings:**
   ```bash
   GITHUB_URL=https://github.com/your-org/your-repo
   GITHUB_TOKEN=your_github_token_here
   MAX_RUNNERS=10
   
   # Option A: Auto-register webhook (recommended)
   WEBHOOK_HOST=https://your-public-server.com
   
   # Option B: Manual webhook configuration
   # WEBHOOK_SECRET=$(openssl rand -hex 20)
   ```

3. **Build and run the controller:**
   ```bash
   # Build the ephemeral runner image
   docker build -t ghcr.io/depoll/gh-runner-docker:ephemeral -f Dockerfile.ephemeral .
   
   # Start the autoscaling controller
   docker-compose -f docker-compose.autoscale.yml up -d
   ```

4. **Webhook Setup** (choose one):

   **Option A: Automatic Registration (Recommended)**
   
   Set `WEBHOOK_HOST` to your server's public URL. The controller will:
   - Generate a secure webhook secret automatically
   - Register the webhook with GitHub
   - Persist the secret to survive restarts
   
   Required token scope: `admin:repo_hook` (repo) or `admin:org_hook` (org)

   **Option B: Manual Configuration**
   
   If you prefer manual setup or can't grant webhook admin permissions:
   - Set `WEBHOOK_SECRET` in your `.env` file
   - Go to repository/organization Settings → Webhooks → Add webhook
   - **Payload URL**: `http://your-server:8080/webhook`
   - **Content type**: `application/json`
   - **Secret**: Use the same value as `WEBHOOK_SECRET`
   - **Events**: Select "Let me select individual events" → Check only "Workflow jobs"

## Architecture

### Static Pool Mode

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Host                              │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │  gh-runner-1 │ │  gh-runner-2 │ │  gh-runner-3 │  ...   │
│  │  (persistent)│ │  (persistent)│ │  (persistent)│        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

### Autoscaling Mode

```
                          GitHub
                            │
                            │ workflow_job webhook
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Docker Host                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Webhook Controller                       │  │
│  │         (listens on port 8080)                       │  │
│  └──────────────────────────────────────────────────────┘  │
│         │                                                   │
│         │ spawns on "queued" event                         │
│         ▼                                                   │
│  ┌──────────────┐ ┌──────────────┐                        │
│  │  ephemeral   │ │  ephemeral   │  (auto-removed after   │
│  │  runner      │ │  runner      │   job completes)       │
│  └──────────────┘ └──────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITHUB_URL` | Yes | - | Repository or organization URL |
| `GITHUB_TOKEN` | Yes | - | GitHub PAT with appropriate scopes |
| `WEBHOOK_HOST` | No | - | Public URL for auto-registering webhook (e.g., `https://your-server.com`) |
| `WEBHOOK_SECRET` | No | Auto-generated | Webhook secret; auto-generated if not provided |
| `WEBHOOK_PORT` | No | `8080` | Port for webhook server |
| `MAX_RUNNERS` | No | `10` | Max concurrent ephemeral runners |
| `RUNNER_LABELS` | No | `self-hosted,linux` | Comma-separated runner labels |
| `RUNNER_GROUP` | No | `default` | Runner group name |
| `REPLICAS` | No | `3` | Number of static runners |
| `RUNNER_IMAGE` | No | `ghcr.io/depoll/gh-runner-docker:ephemeral` | Ephemeral runner image |

### GitHub Token Scopes

| Mode | Required Scopes |
|------|----------------|
| Repository runners | `repo` |
| Organization runners | `admin:org` |
| Auto-register webhook (repo) | `repo` + `admin:repo_hook` |
| Auto-register webhook (org) | `admin:org` + `admin:org_hook` |

> **Note**: If using manual webhook configuration, the `admin:*_hook` scopes are not required.

## Workflow Configuration

In your GitHub Actions workflows, use labels to target self-hosted runners:

```yaml
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
      - run: echo "Hello from self-hosted runner!"
```

For custom labels:

```yaml
jobs:
  build:
    runs-on: [self-hosted, linux, my-custom-label]
```

## Pre-built Images

Images are automatically built and published to GitHub Container Registry:

- `ghcr.io/depoll/gh-runner-docker:latest` - Static pool runner
- `ghcr.io/depoll/gh-runner-docker:ephemeral` - Ephemeral runner for autoscaling
- `ghcr.io/depoll/gh-runner-controller:latest` - Webhook controller

## Monitoring

### Health Check Endpoint

The autoscaling controller provides a health check endpoint:

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "active_runners": 2,
  "max_runners": 10,
  "runners": [
    {
      "job_id": 12345,
      "runner_name": "ephemeral-runner-12345-abc123",
      "status": "running",
      "started_at": "2024-01-15T10:30:00"
    }
  ]
}
```

### Logs

```bash
# Controller logs
docker-compose -f docker-compose.autoscale.yml logs -f controller

# Static runners logs
docker-compose logs -f gh-runner
```

## Troubleshooting

**Runners not appearing in GitHub:**
- Check your `GITHUB_URL` format
- Verify `GITHUB_TOKEN` has correct permissions
- Check container logs

**Webhook not receiving events:**
- If using auto-registration, check controller logs for registration status
- If using manual setup, verify `WEBHOOK_SECRET` matches GitHub settings
- Check if port 8080 is accessible from GitHub (use `WEBHOOK_HOST` for public URL)
- Review webhook delivery history in GitHub settings

**Auto-registration not working:**
- Ensure `WEBHOOK_HOST` is a publicly accessible URL
- Verify token has `admin:repo_hook` or `admin:org_hook` scope
- Check controller logs for API errors
- The secret is persisted in `/data/webhook_secret` inside the container

**Autoscaling not working:**
- Ensure `runs-on` labels include `self-hosted`
- Check controller health endpoint
- Verify Docker socket is mounted correctly

**Architecture issues:**
- The Dockerfile automatically detects and downloads the correct runner binary

## Security Considerations

- **Ephemeral runners** provide better isolation - each job runs in a fresh environment
- Store `GITHUB_TOKEN` and `WEBHOOK_SECRET` securely
- Consider using GitHub App authentication for production
- Use network policies to restrict runner access if needed

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.