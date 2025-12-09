#!/usr/bin/env python3
"""
GitHub Actions Webhook Controller for Autoscaling Ephemeral Runners

This server receives workflow_job webhook events from GitHub and automatically
spawns ephemeral runner containers to handle jobs. It supports:
- Multiple repository configurations via JSON config file
- Automatic webhook registration with GitHub (generates its own secret per repo)
- Manual webhook secret configuration
- Runner spawning on 'queued' events
- Runner cleanup on 'completed' events
- Label-based filtering

Configuration Methods:
  1. Multi-repo mode: Set REPOS_CONFIG_FILE to path of JSON config file
  2. Single-repo mode: Use environment variables (backward compatible)

Environment Variables (single-repo mode):
  GITHUB_URL         - Repository (https://github.com/owner/repo) or 
                       Organization URL (https://github.com/owner)
  GITHUB_ACCESS_TOKEN - PAT with repo/admin:org and admin:repo_hook/admin:org_hook scopes
  WEBHOOK_SECRET     - (Optional) Manual webhook secret; auto-generated if not provided
  WEBHOOK_HOST       - (Required for auto-registration) Public URL where this server is reachable
  RUNNER_IMAGE       - Docker image for ephemeral runners (default: ghcr.io/depoll/gh-runner-docker:ephemeral)
  RUNNER_LABELS      - Comma-separated labels for runners (default: self-hosted,linux,x64,ephemeral)
  REQUIRED_LABELS    - Only spawn runners for jobs requesting these labels (optional)
  MAX_RUNNERS        - Maximum concurrent runners (default: 10)
  PORT               - Server port (default: 8080)

Environment Variables (multi-repo mode):
  REPOS_CONFIG_FILE  - Path to JSON config file (e.g., /config/repos.json)
  WEBHOOK_HOST       - (Required for auto-registration) Public URL where this server is reachable
  PORT               - Server port (default: 8080)
"""

import hashlib
import hmac
import http.server
import json
import logging
import os
import platform
import secrets
import subprocess
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global configuration
PORT = int(os.environ.get('PORT', '8080'))
WEBHOOK_HOST = os.environ.get('WEBHOOK_HOST', '')
REPOS_CONFIG_FILE = os.environ.get('REPOS_CONFIG_FILE', '')
DOCKER_NETWORK = os.environ.get('DOCKER_NETWORK', 'gh-runner-network')

# Secret file directory for persistence
SECRETS_DIR = Path('/data/secrets')


@dataclass
class RepoConfig:
    """Configuration for a single repository."""
    id: str
    github_url: str
    github_token: str
    runner_labels: str = 'self-hosted,linux'
    required_labels: str = ''
    max_runners: int = 10
    runner_image: str = 'ghcr.io/depoll/gh-runner-docker:ephemeral'
    webhook_secret: str = ''
    
    # Runtime state (not from config)
    active_runners: dict = field(default_factory=dict)
    runners_lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        # dataclass default_factory handles initialization
        pass


# Global registry of repo configurations
repos: dict[str, RepoConfig] = {}
repos_lock = threading.Lock()


def parse_github_url(url: str) -> tuple[str, Optional[str]]:
    """
    Parse GitHub URL to extract owner and optional repo.
    
    Returns:
        tuple of (owner, repo) where repo may be None for org-level URLs
    """
    # Remove trailing slash and .git suffix
    url = url.rstrip('/').removesuffix('.git')
    
    # Parse the path
    if 'github.com' in url:
        parts = url.split('github.com/')[-1].split('/')
        if len(parts) >= 2:
            return parts[0], parts[1]
        elif len(parts) == 1:
            return parts[0], None
    
    raise ValueError(f"Invalid GitHub URL: {url}")


def get_api_base_url(github_url: str) -> str:
    """Get the GitHub API base URL."""
    if 'github.com' in github_url:
        return 'https://api.github.com'
    # For GitHub Enterprise, extract the base URL
    parts = github_url.split('/')
    return f"{parts[0]}//{parts[2]}/api/v3"


def github_api_request(github_url: str, github_token: str, endpoint: str, 
                       method: str = 'GET', data: dict = None) -> Optional[dict]:
    """Make an authenticated request to the GitHub API."""
    api_base = get_api_base_url(github_url)
    url = f"{api_base}{endpoint}"
    
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'gh-runner-controller'
    }
    
    if data:
        headers['Content-Type'] = 'application/json'
        body = json.dumps(data).encode('utf-8')
    else:
        body = None
    
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status in (200, 201):
                return json.loads(response.read().decode('utf-8'))
            elif response.status == 204:
                return {}
    except urllib.error.HTTPError as e:
        logger.error(f"GitHub API error: {e.code} {e.reason}")
        if e.code != 404:
            try:
                error_body = e.read().decode('utf-8')
                logger.error(f"Error details: {error_body}")
                
                try:
                    error_json = json.loads(error_body)
                    if error_json.get('message') == 'Resource not accessible by personal access token':
                        if 'registration-token' in url:
                            logger.error("HINT: Missing permissions to create runner registration token.")
                            logger.error("      - Fine-grained PAT: Enable 'Administration' (Read and write)")
                            logger.error("      - Classic PAT: Enable 'repo' (private) or 'public_repo' (public)")
                except json.JSONDecodeError:
                    pass
            except Exception as inner_exc:
                logger.error(f"Failed to read or decode error body: {inner_exc}")
        return None
    except Exception as e:
        logger.error(f"GitHub API request failed: {e}")
        return None
    
    return None


def load_or_generate_secret(repo_id: str, env_secret: str = '') -> str:
    """
    Load webhook secret from file, environment, or generate a new one.
    
    Priority:
    1. Provided secret (from config or environment)
    2. Persisted secret in /data/secrets/{repo_id}
    3. Generate new secret and persist it
    """
    # Check provided secret first
    if env_secret:
        logger.info(f"[{repo_id}] Using webhook secret from configuration")
        return env_secret
    
    # Check persisted file
    secret_file = SECRETS_DIR / repo_id
    if secret_file.exists():
        try:
            secret = secret_file.read_text().strip()
            if secret:
                logger.info(f"[{repo_id}] Loaded webhook secret from persisted file")
                return secret
        except Exception as e:
            logger.warning(f"[{repo_id}] Failed to read persisted secret: {e}")
    
    # Generate new secret
    secret = secrets.token_hex(32)
    logger.info(f"[{repo_id}] Generated new webhook secret")
    
    # Try to persist it
    try:
        SECRETS_DIR.mkdir(parents=True, exist_ok=True)
        secret_file.write_text(secret)
        secret_file.chmod(0o600)
        logger.info(f"[{repo_id}] Persisted webhook secret to {secret_file}")
    except Exception as e:
        logger.warning(f"[{repo_id}] Failed to persist webhook secret: {e}")
    
    return secret


def get_webhook_endpoint(github_url: str) -> str:
    """Get the appropriate webhook API endpoint based on GitHub URL."""
    owner, repo = parse_github_url(github_url)
    
    if repo:
        return f"/repos/{owner}/{repo}/hooks"
    else:
        return f"/orgs/{owner}/hooks"


def get_existing_webhook(repo: RepoConfig, webhook_url: str) -> Optional[dict]:
    """Check if a webhook already exists for our URL."""
    endpoint = get_webhook_endpoint(repo.github_url)
    webhooks = github_api_request(repo.github_url, repo.github_token, endpoint)
    
    if not webhooks:
        return None
    
    for hook in webhooks:
        config = hook.get('config', {})
        if config.get('url') == webhook_url:
            return hook
    
    return None


def register_webhook(repo: RepoConfig) -> bool:
    """
    Register or update webhook with GitHub for a specific repo.
    
    Returns True if successful, False otherwise.
    """
    if not WEBHOOK_HOST:
        logger.info(f"[{repo.id}] WEBHOOK_HOST not set, skipping auto-registration")
        return True
    
    # Each repo gets its own webhook path
    webhook_url = f"{WEBHOOK_HOST.rstrip('/')}/webhook/{repo.id}"
    logger.info(f"[{repo.id}] Checking webhook registration for {webhook_url}")
    
    # Check for existing webhook
    existing = get_existing_webhook(repo, webhook_url)
    
    webhook_config = {
        'url': webhook_url,
        'content_type': 'json',
        'secret': repo.webhook_secret,
        'insecure_ssl': '0'
    }
    
    if existing:
        # Update existing webhook
        endpoint = f"{get_webhook_endpoint(repo.github_url)}/{existing['id']}"
        data = {
            'config': webhook_config,
            'events': ['workflow_job'],
            'active': True
        }
        result = github_api_request(repo.github_url, repo.github_token, endpoint, 
                                    method='PATCH', data=data)
        if result:
            logger.info(f"[{repo.id}] Updated existing webhook (ID: {existing['id']})")
            return True
        else:
            logger.error(f"[{repo.id}] Failed to update existing webhook")
            return False
    else:
        # Create new webhook
        endpoint = get_webhook_endpoint(repo.github_url)
        data = {
            'name': 'web',
            'config': webhook_config,
            'events': ['workflow_job'],
            'active': True
        }
        result = github_api_request(repo.github_url, repo.github_token, endpoint, 
                                    method='POST', data=data)
        if result:
            logger.info(f"[{repo.id}] Created new webhook (ID: {result.get('id')})")
            return True
        else:
            logger.error(f"[{repo.id}] Failed to create webhook")
            return False


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify the webhook signature from GitHub."""
    if not secret:
        logger.warning("No webhook secret configured, skipping signature verification")
        return True
    
    if not signature:
        logger.warning("No signature provided in request")
        return False
    
    if not signature.startswith('sha256='):
        logger.warning("Invalid signature format")
        return False
    
    expected_sig = 'sha256=' + hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected_sig)


def get_registration_token(repo: RepoConfig) -> Optional[str]:
    """Get a registration token for the runner."""
    owner, repo_name = parse_github_url(repo.github_url)
    
    if repo_name:
        endpoint = f"/repos/{owner}/{repo_name}/actions/runners/registration-token"
    else:
        endpoint = f"/orgs/{owner}/actions/runners/registration-token"
    
    result = github_api_request(repo.github_url, repo.github_token, endpoint, method='POST')
    
    if result and 'token' in result:
        return result['token']
    
    return None


def spawn_runner(repo: RepoConfig, job_id: int, job_name: str, labels: list[str]) -> bool:
    """Spawn an ephemeral runner container for a job."""
    # Validate job_id
    if not isinstance(job_id, int) or job_id <= 0:
        logger.error(f"[{repo.id}] Invalid job_id: {job_id}")
        return False
    
    with repo.runners_lock:
        if len(repo.active_runners) >= repo.max_runners:
            logger.warning(f"[{repo.id}] Maximum runners ({repo.max_runners}) reached, cannot spawn new runner")
            return False
        
        if job_id in repo.active_runners:
            logger.info(f"[{repo.id}] Runner already exists for job {job_id}")
            return True
        
        # Get registration token inside the lock to prevent race conditions
        token = get_registration_token(repo)
        if not token:
            logger.error(f"[{repo.id}] Failed to get registration token")
            return False
        
        # Re-check runner existence after token acquisition
        if job_id in repo.active_runners:
            logger.info(f"[{repo.id}] Runner already exists for job {job_id} (after token acquisition)")
            return True
    
    # Generate unique runner name
    runner_name = f"ephemeral-{repo.id}-{job_id}-{int(time.time())}"

    # Determine architecture and platform
    platform_args = []
    
    # Detect host architecture
    host_machine = platform.machine().lower()
    is_host_arm = host_machine in ('aarch64', 'arm64')
    
    # Default to host architecture
    if is_host_arm:
        arch_label = 'arm64'
    else:
        arch_label = 'x64'
        
    # Check requested labels for architecture override
    normalized_labels = [l.lower() for l in labels]
    
    if 'arm64' in normalized_labels:
        arch_label = 'arm64'
        if not is_host_arm:
            platform_args = ['--platform', 'linux/arm64']
            logger.info(f"[{repo.id}] Job {job_id} requested arm64 on {host_machine} host, using emulation")
    elif 'x64' in normalized_labels or 'amd64' in normalized_labels:
        arch_label = 'x64'
        if is_host_arm:
            platform_args = ['--platform', 'linux/amd64']
            logger.info(f"[{repo.id}] Job {job_id} requested amd64/x64 on {host_machine} host, using emulation")
    
    # Adjust runner labels to match architecture
    base_labels = [l for l in repo.runner_labels.split(',') if l.lower() not in ('x64', 'amd64', 'arm64')]
    runner_labels = ','.join(base_labels + [arch_label])
    
    # Build docker command
    cmd = [
        'docker', 'run', '-d',
        '--name', runner_name,
        '--rm',  # Auto-remove when stopped
    ] + platform_args + [
        '-e', f'GITHUB_URL={repo.github_url}',
        '-e', f'GITHUB_TOKEN={token}',
        '-e', f'RUNNER_NAME={runner_name}',
        '-e', f'RUNNER_LABELS={runner_labels}',
        '--privileged',  # Required for Docker-in-Docker
        '-v', '/var/run/docker.sock:/var/run/docker.sock',
    ]
    
    # Add network if specified
    if DOCKER_NETWORK:
        cmd.extend(['--network', DOCKER_NETWORK])
    
    cmd.append(repo.runner_image)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            container_id = result.stdout.strip()
            with repo.runners_lock:
                repo.active_runners[job_id] = {
                    'container_id': container_id,
                    'runner_name': runner_name,
                    'job_name': job_name,
                    'started_at': time.time()
                }
            logger.info(f"[{repo.id}] Spawned runner {runner_name} for job {job_id} ({job_name})")
            return True
        else:
            logger.error(f"[{repo.id}] Failed to spawn runner: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        logger.error(f"[{repo.id}] Timeout spawning runner container")
        return False
    except Exception as e:
        logger.error(f"[{repo.id}] Error spawning runner: {e}")
        return False


def cleanup_runner(repo: RepoConfig, job_id: int) -> None:
    """Clean up a runner container after job completion."""
    with repo.runners_lock:
        runner_info = repo.active_runners.pop(job_id, None)
    
    if not runner_info:
        logger.debug(f"[{repo.id}] No runner found for job {job_id}")
        return
    
    runner_name = runner_info['runner_name']
    
    # The container should auto-remove, but force cleanup just in case
    try:
        subprocess.run(
            ['docker', 'stop', runner_name],
            capture_output=True,
            timeout=30
        )
        logger.info(f"[{repo.id}] Stopped runner {runner_name} for job {job_id}")
    except Exception as e:
        logger.debug(f"[{repo.id}] Runner cleanup (may already be stopped): {e}")


def labels_match(job_labels: list[str], required_labels: str) -> bool:
    """Check if job labels match our required labels."""
    if not required_labels:
        return True
    
    required = set(label.strip().lower() for label in required_labels.split(','))
    job_labels_lower = set(label.lower() for label in job_labels)
    
    return required.issubset(job_labels_lower)


def find_repo_by_url(github_url: str) -> Optional[RepoConfig]:
    """Find a repo config by its GitHub URL."""
    # Normalize the URL for comparison
    normalized = github_url.rstrip('/').removesuffix('.git').lower()
    
    with repos_lock:
        for repo in repos.values():
            repo_normalized = repo.github_url.rstrip('/').removesuffix('.git').lower()
            if repo_normalized == normalized:
                return repo
    
    return None


class WebhookHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for GitHub webhooks."""
    
    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.info(f"{self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests (health check, status)."""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            total_runners = 0
            repo_status = {}
            
            with repos_lock:
                for repo_id, repo in repos.items():
                    with repo.runners_lock:
                        count = len(repo.active_runners)
                        total_runners += count
                        repo_status[repo_id] = {
                            'active_runners': count,
                            'max_runners': repo.max_runners
                        }
            
            response = {
                'status': 'healthy',
                'total_active_runners': total_runners,
                'repositories': repo_status
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == '/status':
            # Detailed status endpoint
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            repo_details = {}
            
            with repos_lock:
                for repo_id, repo in repos.items():
                    with repo.runners_lock:
                        runners = []
                        for job_id, info in repo.active_runners.items():
                            runners.append({
                                'job_id': job_id,
                                'runner_name': info['runner_name'],
                                'job_name': info['job_name'],
                                'running_seconds': int(time.time() - info['started_at'])
                            })
                        
                        repo_details[repo_id] = {
                            'github_url': repo.github_url,
                            'active_runners': len(runners),
                            'max_runners': repo.max_runners,
                            'runners': runners
                        }
            
            response = {
                'status': 'healthy',
                'repositories': repo_details
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'GitHub Actions Webhook Controller (Multi-Repo)')
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Handle POST requests (webhook events)."""
        # Parse the path to extract repo_id
        # Supports: /webhook (legacy single-repo), /webhook/{repo_id} (multi-repo)
        # Strip query strings before parsing path
        from urllib.parse import urlparse
        parsed_path = urlparse(self.path).path
        path_parts = parsed_path.strip('/').split('/')
        
        if len(path_parts) == 1 and path_parts[0] == 'webhook':
            # Legacy single-repo mode or auto-detect from payload
            repo_id = None
        elif len(path_parts) == 2 and path_parts[0] == 'webhook':
            repo_id = path_parts[1]
        else:
            self.send_response(404)
            self.end_headers()
            return
        
        # Read payload
        content_length = int(self.headers.get('Content-Length', 0))
        payload = self.rfile.read(content_length)
        
        # Parse payload first to potentially identify repo
        try:
            data = json.loads(payload.decode('utf-8'))
        except json.JSONDecodeError:
            logger.error("Invalid JSON payload")
            self.send_response(400)
            self.end_headers()
            return
        
        # Find the repo config
        repo = None
        
        if repo_id:
            # Direct repo_id from path
            with repos_lock:
                repo = repos.get(repo_id)
            
            if not repo:
                logger.warning(f"Unknown repo_id in webhook path: {repo_id}")
                self.send_response(404)
                self.end_headers()
                return
        else:
            # Try to find repo from payload (legacy mode)
            repository = data.get('repository', {})
            html_url = repository.get('html_url', '')
            
            if html_url:
                repo = find_repo_by_url(html_url)
            
            if not repo:
                # Fall back to single configured repo if only one exists
                with repos_lock:
                    if len(repos) == 1:
                        repo = list(repos.values())[0]
                    else:
                        logger.warning(f"Cannot determine repo for webhook from {html_url}")
                        self.send_response(400)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({
                            'error': 'Cannot determine target repository',
                            'hint': 'Use /webhook/{repo_id} endpoint for multi-repo setups'
                        }).encode())
                        return
        
        # Verify signature
        signature = self.headers.get('X-Hub-Signature-256', '')
        if not verify_signature(payload, signature, repo.webhook_secret):
            logger.warning(f"[{repo.id}] Invalid webhook signature")
            self.send_response(401)
            self.end_headers()
            return
        
        # Check event type
        event_type = self.headers.get('X-GitHub-Event', '')
        if event_type != 'workflow_job':
            logger.debug(f"[{repo.id}] Ignoring event type: {event_type}")
            self.send_response(200)
            self.end_headers()
            return
        
        # Process workflow_job event
        action = data.get('action', '')
        job = data.get('workflow_job', {})
        job_id = job.get('id')
        job_name = job.get('name', 'unknown')
        job_labels = job.get('labels', [])
        
        # Validate job_id is present
        if job_id is None:
            logger.warning(f"[{repo.id}] Missing workflow_job.id in payload")
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'error': 'Missing workflow_job.id in payload'
            }).encode())
            return
        
        logger.info(f"[{repo.id}] Received workflow_job event: action={action}, job_id={job_id}, name={job_name}")
        
        if action == 'queued':
            # Check if labels match
            if not labels_match(job_labels, repo.required_labels):
                logger.info(f"[{repo.id}] Job {job_id} labels {job_labels} don't match required labels, ignoring")
                self.send_response(200)
                self.end_headers()
                return
            
            # Spawn runner in background
            thread = threading.Thread(
                target=spawn_runner,
                args=(repo, job_id, job_name, job_labels)
            )
            thread.start()
        
        elif action == 'completed':
            # Cleanup runner in background
            thread = threading.Thread(target=cleanup_runner, args=(repo, job_id))
            thread.start()
        
        self.send_response(200)
        self.end_headers()


def cleanup_stale_runners():
    """Periodically clean up stale runners that may have been orphaned."""
    while True:
        time.sleep(300)  # Check every 5 minutes
        
        with repos_lock:
            repo_list = list(repos.values())
        
        for repo in repo_list:
            with repo.runners_lock:
                stale_jobs = []
                current_time = time.time()
                
                for job_id, info in repo.active_runners.items():
                    # Consider stale after 6 hours
                    if current_time - info['started_at'] > 21600:
                        stale_jobs.append(job_id)
            
            for job_id in stale_jobs:
                logger.warning(f"[{repo.id}] Cleaning up stale runner for job {job_id}")
                cleanup_runner(repo, job_id)


def load_config_file(config_path: str) -> list[dict]:
    """Load repository configurations from JSON file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Get defaults
        defaults = config.get('defaults', {})
        
        # Process repositories
        repo_configs = []
        for repo_data in config.get('repositories', []):
            # Merge with defaults
            merged = {**defaults, **repo_data}
            repo_configs.append(merged)
        
        return repo_configs
    except Exception as e:
        logger.error(f"Failed to load config file {config_path}: {e}")
        return []


def load_single_repo_config() -> Optional[dict]:
    """Load single repository configuration from environment variables."""
    github_url = os.environ.get('GITHUB_URL', '')
    github_token = os.environ.get('GITHUB_ACCESS_TOKEN', '')
    
    if not github_url or not github_token:
        return None
    
    # Parse URL to create a repo ID
    try:
        owner, repo_name = parse_github_url(github_url)
        repo_id = repo_name if repo_name else owner
    except ValueError:
        repo_id = 'default'
    
    return {
        'id': repo_id,
        'github_url': github_url,
        'github_token': github_token,
        'webhook_secret': os.environ.get('WEBHOOK_SECRET', ''),
        'runner_image': os.environ.get('RUNNER_IMAGE', 'ghcr.io/depoll/gh-runner-docker:ephemeral'),
        'runner_labels': os.environ.get('RUNNER_LABELS', 'self-hosted,linux'),
        'required_labels': os.environ.get('REQUIRED_LABELS', ''),
        'max_runners': int(os.environ.get('MAX_RUNNERS', '10'))
    }


def initialize_repos():
    """Initialize repository configurations from config file or environment."""
    global repos
    
    repo_configs = []
    
    # Try config file first
    if REPOS_CONFIG_FILE:
        logger.info(f"Loading configuration from {REPOS_CONFIG_FILE}")
        repo_configs = load_config_file(REPOS_CONFIG_FILE)
    
    # Fall back to single-repo environment variables
    if not repo_configs:
        single_config = load_single_repo_config()
        if single_config:
            logger.info("Using single-repo configuration from environment variables")
            repo_configs = [single_config]
    
    if not repo_configs:
        logger.error("No repository configuration found. Set REPOS_CONFIG_FILE or GITHUB_URL/GITHUB_ACCESS_TOKEN")
        return False
    
    # Create RepoConfig objects
    with repos_lock:
        for config in repo_configs:
            try:
                repo_id = config['id']
                
                # Load or generate webhook secret
                webhook_secret = load_or_generate_secret(repo_id, config.get('webhook_secret', ''))
                
                # Check for duplicate repo IDs
                if repo_id in repos:
                    logger.error(f"Duplicate repository ID '{repo_id}' found in configuration, skipping")
                    continue
                
                repo = RepoConfig(
                    id=repo_id,
                    github_url=config['github_url'],
                    github_token=config['github_token'],
                    runner_labels=config.get('runner_labels', 'self-hosted,linux'),
                    required_labels=config.get('required_labels', ''),
                    max_runners=int(config.get('max_runners', 10)),
                    runner_image=config.get('runner_image', 'ghcr.io/depoll/gh-runner-docker:ephemeral'),
                    webhook_secret=webhook_secret
                )
                
                repos[repo_id] = repo
                logger.info(f"[{repo_id}] Configured: {repo.github_url}")
                
            except KeyError as e:
                logger.error(f"Missing required field in repo config: {e}")
                continue
            except Exception as e:
                logger.error(f"Error configuring repo: {e}")
                continue
    
    return len(repos) > 0


def register_all_webhooks():
    """Register webhooks for all configured repositories."""
    if not WEBHOOK_HOST:
        logger.info("WEBHOOK_HOST not set, skipping webhook auto-registration")
        return
    
    with repos_lock:
        repo_list = list(repos.values())
    
    for repo in repo_list:
        if not register_webhook(repo):
            logger.warning(f"[{repo.id}] Failed to register webhook, continuing anyway...")


def main():
    """Main entry point."""
    # Initialize repository configurations
    if not initialize_repos():
        logger.error("Failed to initialize any repositories")
        exit(1)
    
    # Register webhooks if WEBHOOK_HOST is set
    register_all_webhooks()
    
    # Log webhook configuration hints if not auto-registering
    if not WEBHOOK_HOST:
        logger.info("Manual webhook configuration required:")
        with repos_lock:
            for repo_id, repo in repos.items():
                logger.info(f"  [{repo_id}] Webhook URL: <your-host>/webhook/{repo_id}")
                logger.info(f"  [{repo_id}] Webhook secret: {repo.webhook_secret}")
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_stale_runners, daemon=True)
    cleanup_thread.start()
    
    # Start server
    server = http.server.HTTPServer(('0.0.0.0', PORT), WebhookHandler)
    logger.info(f"Webhook controller starting on port {PORT}")
    logger.info(f"Configured repositories: {len(repos)}")
    
    with repos_lock:
        for repo_id, repo in repos.items():
            logger.info(f"  [{repo_id}] {repo.github_url} (max {repo.max_runners} runners)")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
