# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This repository provides a Docker-based solution for running multiple GitHub Actions self-hosted runners using Docker Compose with replicas. The setup is platform-agnostic, supporting both x64 and arm64 architectures.

## Architecture

- **Dockerfile**: Multi-architecture GitHub Actions runner container
- **entrypoint.sh**: Handles runner configuration, naming, and lifecycle
- **docker-compose.yml**: Orchestrates multiple runner instances with replicas
- **.env.example**: Template for environment configuration

## Build and Run Commands

### Using pre-built image from GitHub Container Registry:
```bash
# Edit docker-compose.yml to use: image: ghcr.io/your-username/gh-runner-docker:latest
# Copy environment template and configure
cp .env.example .env
# Edit .env with your GitHub URL, token, and desired replica count

# Start runners
docker-compose up -d

# Scale runners
docker-compose up -d --scale gh-runner=5
```

### Build locally:
```bash
# Keep build: . in docker-compose.yml
docker-compose build

# Start runners
docker-compose up -d
```

### Configuration

Required environment variables:
- `GITHUB_URL`: Repository or organization URL
- `GITHUB_TOKEN`: GitHub personal access token or registration token

Optional environment variables:
- `RUNNER_NAME_PREFIX`: Prefix for runner names (default: "runner")
- `RUNNER_WORKDIR`: Working directory (default: "_work")
- `RUNNER_LABELS`: Comma-separated labels
- `RUNNER_GROUP`: Runner group (default: "default")
- `REPLICAS`: Number of runner instances (default: 3)

## Runner Naming

Each runner gets a unique name based on its instance number: `{RUNNER_NAME_PREFIX}-{instance_number}` (e.g., runner-1, runner-2, etc.)

## Container Registry

The GitHub Action automatically builds and publishes multi-architecture (amd64/arm64) images to GitHub Container Registry on:
- Push to main branch (tagged as `latest`)
- Tagged releases (tagged with version numbers)
- Pull requests (for testing, not published)