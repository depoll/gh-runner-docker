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

### Autoscaling Mode - No Clone Required (Recommended)

The fastest way to get started - just download one file:

```bash
# Download the standalone compose file
curl -O https://raw.githubusercontent.com/depoll/gh-runner-docker/main/docker-compose.standalone.yml

# Create your .env file
cat > .env << 'EOF'
GITHUB_URL=https://github.com/your-org/your-repo
GITHUB_TOKEN=ghp_your_token_here
WEBHOOK_DOMAIN=webhook.example.com
LETSENCRYPT_EMAIL=admin@example.com
WEBHOOK_HOST=https://webhook.example.com
MAX_RUNNERS=10
EOF

# Start the stack
docker compose -f docker-compose.standalone.yml up -d
```

That's it! The stack will:
- Register the webhook with GitHub automatically  
- Spawn ephemeral runners when jobs are queued

> **Note**: For HTTPS, set `WEBHOOK_DOMAIN` and `LETSENCRYPT_EMAIL`. The included nginx image can obtain/renew Let's Encrypt certificates automatically. On first boot it may serve a temporary self-signed cert until ACME validation succeeds.

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

### Autoscaling Mode (From Source)

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
   
   # HTTPS with automatic Let's Encrypt (recommended)
   WEBHOOK_DOMAIN=webhook.example.com
   LETSENCRYPT_EMAIL=admin@example.com
   
   # Auto-register webhook with GitHub
   WEBHOOK_HOST=https://webhook.example.com
   ```

3. **Start the stack:**
   ```bash
   docker-compose -f docker-compose.autoscale.yml up -d
   ```
   
   The stack will:
   - Start nginx reverse proxy
   - Start the webhook controller
   - Auto-register the webhook with GitHub (if `WEBHOOK_HOST` is set)

   > **For HTTPS**: You'll need to provide SSL certificates. See the HTTPS Setup section below.
      > **For HTTPS**: Set `WEBHOOK_DOMAIN` and `LETSENCRYPT_EMAIL`. nginx can obtain/renew Let's Encrypt certificates automatically; first boot may briefly use a self-signed cert.

4. **Verify it's working:**
   ```bash
   # Check health endpoint
   curl https://webhook.example.com/health
   
   # View logs
   docker-compose -f docker-compose.autoscale.yml logs -f
   ```

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
                            │ workflow_job webhook (HTTPS)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Docker Host                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                   nginx (ports 80/443)                 │  │
│  │          TLS termination (certs provided externally)   │  │
│  │      TLS termination (automatic Let's Encrypt)         │  │
│  └──────────────────────────────────────────────────────┘  │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Webhook Controller                       │  │
│  │            (internal port 8080)                       │  │
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
| `WEBHOOK_DOMAIN` | HTTPS | - | Domain for Let's Encrypt certificate |
| `LETSENCRYPT_EMAIL` | HTTPS | - | Email for certificate notifications |
| `WEBHOOK_HOST` | No | - | Public URL for auto-registering webhook |
| `WEBHOOK_SECRET` | No | Auto-generated | Webhook secret; auto-generated if not provided |
| `MAX_RUNNERS` | No | `10` | Max concurrent ephemeral runners |
| `RUNNER_LABELS` | No | `self-hosted,linux` | Comma-separated runner labels |
| `RUNNER_GROUP` | No | - | Runner group name (organization-level runners only) |
| `REPLICAS` | No | `3` | Number of static runners |
| `RUNNER_IMAGE` | No | `ghcr.io/depoll/gh-runner-docker:ephemeral` | Ephemeral runner image |
| `DEBUG_SPAWN_LOGS` | No | - | Controller: log spawn details and tail runner logs |
| `DEBUG_KEEP_RUNNER_CONTAINER` | No | - | Controller: keep failed runner containers (disables `--rm`) |
| `DEBUG_DOTNET_DUMPS` | No | - | Runner: enable .NET crash minidumps under `/tmp/dotnet-dumps` (use with `DEBUG_KEEP_RUNNER_CONTAINER=true`) |
| `RUNNER_HTTPS_PROXY` | No | - | Controller: pass `HTTPS_PROXY/https_proxy` into runner containers (work around egress blocks) |
| `RUNNER_HTTP_PROXY` | No | - | Controller: pass `HTTP_PROXY/http_proxy` into runner containers |
| `RUNNER_ALL_PROXY` | No | - | Controller: pass `ALL_PROXY/all_proxy` into runner containers |
| `RUNNER_NO_PROXY` | No | - | Controller: pass `NO_PROXY/no_proxy` into runner containers |

> **ARM hosts + `runs-on: …, x64`**: The controller runs the runner container as `linux/amd64` under emulation (QEMU).

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

| Image | Description |
|-------|-------------|
| `ghcr.io/depoll/gh-runner-docker:latest` | Static pool runner |
| `ghcr.io/depoll/gh-runner-docker:ephemeral` | Ephemeral runner for autoscaling |
| `ghcr.io/depoll/gh-runner-controller:latest` | Webhook controller |
| `ghcr.io/depoll/gh-runner-nginx:latest` | nginx reverse proxy (bring your own certs) |

All images are multi-architecture (amd64 and arm64).

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
  "max_runners": 10
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
<!-- EOF -->
