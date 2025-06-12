# GitHub Actions Self-Hosted Runners with Docker

A scalable Docker-based solution for running multiple GitHub Actions self-hosted runners using Docker Compose. Supports both x64 and arm64 architectures with configurable replicas and zero host state requirements.

## Quick Start

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
   # Using pre-built image (recommended)
   # Edit docker-compose.yml to uncomment the image line
   docker-compose up -d
   
   # Or build locally
   docker-compose build
   docker-compose up -d
   ```

4. **Scale as needed:**
   ```bash
   docker-compose up -d --scale gh-runner=5
   ```

## Features

- **Multi-architecture**: Automatically builds for x64 and arm64
- **Scalable**: Use Docker Compose replicas or `--scale` flag
- **Stateless**: No persistent volumes, completely disposable runners
- **Auto-naming**: Runners get unique names like `runner-1`, `runner-2`, etc.
- **Configurable**: All settings via environment variables
- **CI/CD Ready**: Pre-built images published to GitHub Container Registry

## Configuration

### Required Environment Variables

- `GITHUB_URL`: Your repository or organization URL (e.g., `https://github.com/your-org/your-repo`)
- `GITHUB_TOKEN`: GitHub personal access token with repo access

### Optional Environment Variables

- `RUNNER_NAME_PREFIX`: Prefix for runner names (default: "runner")
- `RUNNER_WORKDIR`: Working directory (default: "_work")
- `RUNNER_LABELS`: Comma-separated labels (default: "docker,linux")
- `RUNNER_GROUP`: Runner group (default: "default")
- `REPLICAS`: Number of runner instances (default: 3)
- `DEPLOYMENT_ID`: Optional deployment identifier for grouping runners

> **Note:** Copy `.env.example` to `.env` and edit as needed. All variables above are read from `.env` by default.

## GitHub Token Setup

1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Create a token with `repo` scope (or `public_repo` for public repos only)
3. For organization repos, the token needs `admin:org` scope

## Pre-built Images

Images are automatically built and published to GitHub Container Registry:

```yaml
# In docker-compose.yml, use:
image: ghcr.io/depoll/gh-runner-docker:latest
# Instead of:
# build: .
```

Available tags:
- `latest` - Latest build from main branch
- `v1.0.0` - Specific version releases
- `main` - Latest main branch build

## Architecture

- **Dockerfile**: Multi-arch container with GitHub Actions runner
- **entrypoint.sh**: Handles runner registration, naming, and lifecycle
- **docker-compose.yml**: Orchestrates multiple runner instances
- **.env**: Local configuration (not tracked in git)

## Security Notes

- Runners are stateless and ephemeral
- No persistent storage mounted
- Each runner runs in an isolated container
- Token is only used for runner registration

## Troubleshooting

**Runners not appearing in GitHub:**
- Check your `GITHUB_URL` format
- Verify `GITHUB_TOKEN` has correct permissions
- Check container logs: `docker-compose logs gh-runner`

**Architecture issues:**
- The Dockerfile automatically detects and downloads the correct runner binary for your platform

**Scaling issues:**
- Use `docker-compose up -d --scale gh-runner=N` to set exact replica count
- Or set `REPLICAS=N` in `.env` and run `docker-compose up -d`

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.