#!/usr/bin/env python3
"""
GitHub Actions Webhook Controller for Autoscaling Ephemeral Runners

This server receives workflow_job webhook events from GitHub and automatically
spawns ephemeral runner containers to handle jobs. It supports:
- Automatic webhook registration with GitHub (generates its own secret)
- Manual webhook secret configuration
- Runner spawning on 'queued' events
- Runner cleanup on 'completed' events
- Label-based filtering

Environment Variables:
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
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == '':
        return default
    try:
        return int(raw.strip())
    except ValueError:
        logger.warning("Invalid %s=%r; using default %s", name, raw, default)
        return default


def _env_csv_ints(name: str, default: list[int]) -> list[int]:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == '':
        return default
    values: list[int] = []
    for part in raw.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            values.append(int(part))
        except ValueError:
            logger.warning("Ignoring invalid %s entry: %r", name, part)
    return values or default

# Configuration
GITHUB_URL = os.environ.get('GITHUB_URL', '')
GITHUB_ACCESS_TOKEN = os.environ.get('GITHUB_ACCESS_TOKEN', '')
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '')
WEBHOOK_HOST = os.environ.get('WEBHOOK_HOST', '')
RUNNER_IMAGE = os.environ.get('RUNNER_IMAGE', 'ghcr.io/depoll/gh-runner-docker:ephemeral')
RUNNER_LABELS = os.environ.get('RUNNER_LABELS', 'self-hosted,linux')
REQUIRED_LABELS = os.environ.get('REQUIRED_LABELS', '')
# Jobs whose labels include any of these will be ignored.
# Default skips macOS and Windows jobs, since this stack provides Linux runners.
UNSUPPORTED_JOB_LABELS = os.environ.get('UNSUPPORTED_JOB_LABELS', 'macos,windows')
# If enabled, the controller will `docker pull` the runner image before spawning.
# This is useful because the runner image is not a docker-compose service, so
# `docker compose pull` won't update it.
PULL_RUNNER_IMAGE = os.environ.get('PULL_RUNNER_IMAGE', 'true').lower() in ('1', 'true', 'yes', 'on')
MAX_RUNNERS = int(os.environ.get('MAX_RUNNERS', '10'))
PORT = int(os.environ.get('PORT', '8080'))
DOCKER_NETWORK = os.environ.get('DOCKER_NETWORK', '')
RUNNER_DOCKER_STORAGE_DRIVER = os.environ.get('RUNNER_DOCKER_STORAGE_DRIVER', '').strip()

# Debug / diagnostics
# If enabled, prints additional spawn diagnostics and tails runner container logs briefly.
DEBUG_SPAWN_LOGS = os.environ.get('DEBUG_SPAWN_LOGS', '').lower() in ('1', 'true', 'yes', 'on')
# If enabled, do not pass --rm to docker run, so failed containers remain inspectable.
DEBUG_KEEP_RUNNER_CONTAINER = os.environ.get('DEBUG_KEEP_RUNNER_CONTAINER', '').lower() in ('1', 'true', 'yes', 'on')

# Debug spawn log sampling controls (only used when DEBUG_SPAWN_LOGS is enabled)
DEBUG_SPAWN_LOG_TAIL_LINES = _env_int('DEBUG_SPAWN_LOG_TAIL_LINES', 400)
DEBUG_SPAWN_LOG_SAMPLE_DELAYS = _env_csv_ints('DEBUG_SPAWN_LOG_SAMPLE_DELAYS', [25, 70])

# Secret file path for persistence
SECRET_FILE = Path('/data/webhook_secret')

# Track active runners
active_runners = {}
runners_lock = threading.Lock()


# Note: This module requires Python 3.10+ for PEP 604 union type syntax (X | Y)
def parse_github_url(url: str) -> tuple[str, str | None]:
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


def get_api_base_url() -> str:
    """Get the GitHub API base URL."""
    if 'github.com' in GITHUB_URL:
        return 'https://api.github.com'
    # For GitHub Enterprise, extract the base URL
    parts = GITHUB_URL.split('/')
    return f"{parts[0]}//{parts[2]}/api/v3"


def github_api_request(endpoint: str, method: str = 'GET', data: dict = None) -> dict | None:
    """Make an authenticated request to the GitHub API."""
    api_base = get_api_base_url()
    url = f"{api_base}{endpoint}"
    
    headers = {
        'Authorization': f'token {GITHUB_ACCESS_TOKEN}',
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
                
                # Attempt to parse JSON for better hints
                try:
                    error_json = json.loads(error_body)
                    if error_json.get('message') == 'Resource not accessible by personal access token':
                        if 'registration-token' in url:
                            logger.error("HINT: Missing permissions to create runner registration token.")
                            logger.error("      - Fine-grained PAT: Enable 'Administration' (Read and write)")
                            logger.error("      - Classic PAT: Enable 'repo' (private) or 'public_repo' (public)")
                except json.JSONDecodeError:
                    # The error body is not valid JSON; safe to ignore in this context.
                    pass
            except Exception as inner_exc:
                logger.error(f"Failed to read or decode error body: {inner_exc}")
        return None
    except Exception as e:
        logger.error(f"GitHub API request failed: {e}")
        return None
    
    return None


def load_or_generate_secret() -> str:
    """
    Load webhook secret from file, environment, or generate a new one.
    
    Priority:
    1. Environment variable WEBHOOK_SECRET
    2. Persisted secret in /data/webhook_secret
    3. Generate new secret and persist it
    """
    global WEBHOOK_SECRET
    
    # Check environment first
    if WEBHOOK_SECRET:
        logger.info("Using webhook secret from environment variable")
        return WEBHOOK_SECRET
    
    # Check persisted file
    if SECRET_FILE.exists():
        try:
            secret = SECRET_FILE.read_text().strip()
            if secret:
                logger.info("Loaded webhook secret from persisted file")
                WEBHOOK_SECRET = secret
                return secret
        except Exception as e:
            logger.warning(f"Failed to read persisted secret: {e}")
    
    # Generate new secret
    secret = secrets.token_hex(32)
    logger.info("Generated new webhook secret")
    
    # Try to persist it
    try:
        SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        SECRET_FILE.write_text(secret)
        SECRET_FILE.chmod(0o600)
        logger.info(f"Persisted webhook secret to {SECRET_FILE}")
    except Exception as e:
        logger.warning(f"Failed to persist webhook secret: {e}")
    
    WEBHOOK_SECRET = secret
    return secret


def get_webhook_endpoint() -> str:
    """Get the appropriate webhook API endpoint based on GITHUB_URL."""
    owner, repo = parse_github_url(GITHUB_URL)
    
    if repo:
        return f"/repos/{owner}/{repo}/hooks"
    else:
        return f"/orgs/{owner}/hooks"


def get_existing_webhook(webhook_url: str) -> dict | None:
    """Check if a webhook already exists for our URL."""
    endpoint = get_webhook_endpoint()
    webhooks = github_api_request(endpoint)
    
    if not webhooks:
        return None
    
    for hook in webhooks:
        config = hook.get('config', {})
        if config.get('url') == webhook_url:
            return hook
    
    return None


def register_webhook(secret: str) -> bool:
    """
    Register or update webhook with GitHub.
    
    Returns True if successful, False otherwise.
    """
    if not WEBHOOK_HOST:
        logger.info("WEBHOOK_HOST not set, skipping auto-registration")
        return True
    
    webhook_url = f"{WEBHOOK_HOST.rstrip('/')}/webhook"
    logger.info(f"Checking webhook registration for {webhook_url}")
    
    # Check for existing webhook
    existing = get_existing_webhook(webhook_url)
    
    webhook_config = {
        'url': webhook_url,
        'content_type': 'json',
        'secret': secret,
        'insecure_ssl': '0'
    }
    
    if existing:
        # Update existing webhook
        endpoint = f"{get_webhook_endpoint()}/{existing['id']}"
        data = {
            'config': webhook_config,
            'events': ['workflow_job'],
            'active': True
        }
        result = github_api_request(endpoint, method='PATCH', data=data)
        if result:
            logger.info(f"Updated existing webhook (ID: {existing['id']})")
            return True
        else:
            logger.error("Failed to update existing webhook")
            return False
    else:
        # Create new webhook
        endpoint = get_webhook_endpoint()
        data = {
            'name': 'web',
            'config': webhook_config,
            'events': ['workflow_job'],
            'active': True
        }
        result = github_api_request(endpoint, method='POST', data=data)
        if result:
            logger.info(f"Created new webhook (ID: {result.get('id')})")
            return True
        else:
            logger.error("Failed to create webhook")
            return False


def verify_signature(payload: bytes, signature: str) -> bool:
    """Verify the webhook signature from GitHub."""
    if not WEBHOOK_SECRET:
        logger.warning("No webhook secret configured, skipping signature verification")
        return True
    
    if not signature:
        logger.warning("No signature provided in request")
        return False
    
    if not signature.startswith('sha256='):
        logger.warning("Invalid signature format")
        return False
    
    expected_sig = 'sha256=' + hmac.new(
        WEBHOOK_SECRET.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected_sig)


def get_registration_token() -> str | None:
    """Get a registration token for the runner."""
    owner, repo = parse_github_url(GITHUB_URL)
    
    if repo:
        endpoint = f"/repos/{owner}/{repo}/actions/runners/registration-token"
    else:
        endpoint = f"/orgs/{owner}/actions/runners/registration-token"
    
    result = github_api_request(endpoint, method='POST')
    
    if result and 'token' in result:
        return result['token']
    
    return None


def spawn_runner(job_id: int, job_name: str, labels: list[str]) -> bool:
    """Spawn an ephemeral runner container for a job."""
    # Validate job_id
    if not isinstance(job_id, int) or job_id <= 0:
        logger.error(f"Invalid job_id: {job_id}")
        return False
    
    with runners_lock:
        if len(active_runners) >= MAX_RUNNERS:
            logger.warning(f"Maximum runners ({MAX_RUNNERS}) reached, cannot spawn new runner")
            return False
        
        if job_id in active_runners:
            logger.info(f"Runner already exists for job {job_id}")
            return True
        
        # Get registration token inside the lock to prevent race conditions
        token = get_registration_token()
        if not token:
            logger.error("Failed to get registration token")
            return False
        
        # Re-check runner existence after token acquisition
        if job_id in active_runners:
            logger.info(f"Runner already exists for job {job_id} (after token acquisition)")
            return True
    
    # Generate unique runner name (moved outside the lock since we have the token)
    runner_name = f"ephemeral-{job_id}-{int(time.time())}"

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
            logger.info(f"Job {job_id} requested arm64 on {host_machine} host, using emulation")
    elif 'x64' in normalized_labels or 'amd64' in normalized_labels:
        arch_label = 'x64'
        if is_host_arm:
            platform_args = ['--platform', 'linux/amd64']
            logger.info(f"Job {job_id} requested amd64/x64 on {host_machine} host, using emulation")

    # Storage driver selection for Docker-in-Docker inside the runner container.
    # When running an amd64 runner under emulation on ARM hosts, overlay2 and fuse-overlayfs
    # are frequently unreliable; vfs is slower but typically the most consistent.
    docker_storage_driver = RUNNER_DOCKER_STORAGE_DRIVER
    if not docker_storage_driver and is_host_arm and platform_args == ['--platform', 'linux/amd64']:
        docker_storage_driver = 'vfs'
    
    # Adjust RUNNER_LABELS to match architecture
    # Remove any existing arch labels from the configured defaults
    base_labels = [l for l in RUNNER_LABELS.split(',') if l.lower() not in ('x64', 'amd64', 'arm64')]
    runner_labels = ','.join(base_labels + [arch_label])

    if DEBUG_SPAWN_LOGS:
        logger.info(
            "Spawn details: job_id=%s job_name=%s requested_labels=%s host_arch=%s selected_arch=%s platform_args=%s runner_labels=%s",
            job_id,
            job_name,
            labels,
            host_machine,
            arch_label,
            ' '.join(platform_args) if platform_args else '(none)',
            runner_labels,
        )

    if PULL_RUNNER_IMAGE:
        try:
            pull = subprocess.run(
                ['docker', 'pull', RUNNER_IMAGE],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if pull.returncode == 0:
                if DEBUG_SPAWN_LOGS:
                    logger.info("Pulled runner image: %s", RUNNER_IMAGE)
            else:
                logger.warning(
                    "Failed to pull runner image %s (continuing with local cache): %s",
                    RUNNER_IMAGE,
                    (pull.stderr or pull.stdout or '').strip(),
                )
        except Exception as e:
            logger.warning("Failed to pull runner image %s (continuing): %s", RUNNER_IMAGE, e)
    
    # Build docker command
    cmd = ['docker', 'run', '-d', '--name', runner_name]
    if not DEBUG_KEEP_RUNNER_CONTAINER:
        cmd += ['--rm']  # Auto-remove when stopped

    # Attach to a specific network if requested (useful for consistent DNS / connectivity).
    if DOCKER_NETWORK:
        cmd += ['--network', DOCKER_NETWORK]

    cmd = cmd + platform_args + [
        '-e', f'GITHUB_URL={GITHUB_URL}',
        '-e', f'GITHUB_TOKEN={token}',
        '-e', f'RUNNER_NAME={runner_name}',
        '-e', f'RUNNER_LABELS={runner_labels}',
        '-e', f'JOB_ID={job_id}',
        '--privileged',  # Required for Docker-in-Docker
        RUNNER_IMAGE
    ]

    if docker_storage_driver:
        cmd = cmd[:-2] + ['-e', f'DOCKER_STORAGE_DRIVER={docker_storage_driver}'] + cmd[-2:]

    if DEBUG_SPAWN_LOGS:
        # Never log the registration token.
        redacted_cmd = []
        for part in cmd:
            if isinstance(part, str) and part.startswith('GITHUB_TOKEN='):
                redacted_cmd.append('GITHUB_TOKEN=<redacted>')
            else:
                redacted_cmd.append(part)
        logger.info("docker run command: %s", ' '.join(redacted_cmd))
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            container_id = result.stdout.strip()
            with runners_lock:
                active_runners[job_id] = {
                    'container_id': container_id,
                    'runner_name': runner_name,
                    'job_name': job_name,
                    'started_at': time.time()
                }
            logger.info(f"Spawned runner {runner_name} for job {job_id} ({job_name})")

            if DEBUG_SPAWN_LOGS:
                # Docker-in-Docker + runner registration can take tens of seconds,
                # especially under emulation. Sample logs a few times.
                start = time.time()
                for delay in (DEBUG_SPAWN_LOG_SAMPLE_DELAYS or [25, 70]):
                    sleep_for = max(0, delay - (time.time() - start))
                    if sleep_for:
                        time.sleep(sleep_for)
                    try:
                        ps = subprocess.run(
                            ['docker', 'ps', '-a', '--filter', f'name={runner_name}', '--format', '{{.Status}}'],
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        status_line = (ps.stdout or '').strip()
                        if status_line:
                            logger.info("Runner container status (@~%ss): %s", int(delay), status_line)

                        logs = subprocess.run(
                            ['docker', 'logs', '--tail', str(DEBUG_SPAWN_LOG_TAIL_LINES), runner_name],
                            capture_output=True,
                            text=True,
                            timeout=15,
                        )
                        if logs.stdout.strip():
                            logger.info("Runner logs (tail @~%ss):\n%s", int(delay), logs.stdout.rstrip())
                        if logs.stderr.strip():
                            logger.info("Runner logs stderr (tail @~%ss):\n%s", int(delay), logs.stderr.rstrip())

                        # If the container is still running, also peek at internal logs
                        # that don't go to stdout (dockerd logs, runner config logs).
                        exec_dockerd = subprocess.run(
                            [
                                'docker', 'exec', runner_name, 'sh', '-lc',
                                'set -e; f=$(ls -1 /tmp/dockerd-*.log 2>/dev/null | head -n 1 || true); '
                                'if [ -n "$f" ]; then echo "=== $f (tail) ==="; tail -n 200 "$f"; fi',
                            ],
                            capture_output=True,
                            text=True,
                            timeout=15,
                        )
                        if exec_dockerd.stdout.strip():
                            logger.info("Runner dockerd log (exec @~%ss):\n%s", int(delay), exec_dockerd.stdout.rstrip())
                        if exec_dockerd.stderr.strip():
                            logger.info("Runner dockerd log stderr (exec @~%ss):\n%s", int(delay), exec_dockerd.stderr.rstrip())

                        exec_config = subprocess.run(
                            [
                                'docker', 'exec', runner_name, 'sh', '-lc',
                                'if [ -f /tmp/runner-config.log ]; then '
                                'echo "=== /tmp/runner-config.log (tail) ==="; tail -n 200 /tmp/runner-config.log; fi',
                            ],
                            capture_output=True,
                            text=True,
                            timeout=15,
                        )
                        if exec_config.stdout.strip():
                            logger.info("Runner config log (exec @~%ss):\n%s", int(delay), exec_config.stdout.rstrip())
                        if exec_config.stderr.strip():
                            logger.info("Runner config log stderr (exec @~%ss):\n%s", int(delay), exec_config.stderr.rstrip())
                    except Exception as log_exc:
                        logger.debug(f"Failed to gather debug logs for {runner_name}: {log_exc}")

            return True
        else:
            logger.error(f"Failed to spawn runner: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        logger.error("Timeout spawning runner container")
        return False
    except Exception as e:
        logger.error(f"Error spawning runner: {e}")
        return False


def cleanup_runner(job_id: int) -> None:
    """Clean up a runner container after job completion."""
    with runners_lock:
        runner_info = active_runners.pop(job_id, None)
    
    if not runner_info:
        logger.debug(f"No runner found for job {job_id}")
        return
    
    runner_name = runner_info['runner_name']
    
    # The container should auto-remove, but force cleanup just in case
    try:
        subprocess.run(
            ['docker', 'stop', runner_name],
            capture_output=True,
            timeout=30
        )
        logger.info(f"Stopped runner {runner_name} for job {job_id}")
    except Exception as e:
        logger.debug(f"Runner cleanup (may already be stopped): {e}")


def labels_match(job_labels: list[str]) -> bool:
    """Check if job labels match our required labels."""
    if not REQUIRED_LABELS:
        return True
    
    required = set(label.strip().lower() for label in REQUIRED_LABELS.split(','))
    job_labels_lower = set(label.lower() for label in job_labels)
    
    return required.issubset(job_labels_lower)


def job_is_supported(job_labels: list[str]) -> tuple[bool, str]:
    """Return (supported, reason).

    This autoscaler provides Linux runner containers. If a workflow_job requests
    macOS or Windows via labels, it can never match these runners, so we skip it.
    """
    labels_lower = {str(label).strip().lower() for label in (job_labels or []) if str(label).strip()}

    unsupported = {
        label.strip().lower()
        for label in (UNSUPPORTED_JOB_LABELS or '').split(',')
        if label.strip()
    }

    if not unsupported:
        return True, ""

    hit = sorted(labels_lower.intersection(unsupported))
    if hit:
        return False, f"requested unsupported labels: {hit}"

    return True, ""


class WebhookHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for GitHub webhooks."""
    
    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.info(f"{self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests (health check)."""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            with runners_lock:
                runner_count = len(active_runners)
            
            response = {
                'status': 'healthy',
                'active_runners': runner_count,
                'max_runners': MAX_RUNNERS
            }
            self.wfile.write(json.dumps(response).encode())
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'GitHub Actions Webhook Controller')
        else:
            self.send_response(404)
            self.end_headers()

    def do_HEAD(self):
        """Handle HEAD requests (used by some probes/validators)."""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        self.send_response(404)
        self.send_header('Content-Length', '0')
        self.end_headers()
    
    def do_POST(self):
        """Handle POST requests (webhook events)."""
        if self.path != '/webhook':
            self.send_response(404)
            self.end_headers()
            return
        
        # Read payload
        content_length = int(self.headers.get('Content-Length', 0))
        payload = self.rfile.read(content_length)
        
        # Verify signature
        signature = self.headers.get('X-Hub-Signature-256', '')
        if not verify_signature(payload, signature):
            logger.warning("Invalid webhook signature")
            self.send_response(401)
            self.end_headers()
            return
        
        # Check event type
        event_type = self.headers.get('X-GitHub-Event', '')
        if event_type != 'workflow_job':
            logger.debug(f"Ignoring event type: {event_type}")
            self.send_response(200)
            self.end_headers()
            return
        
        # Parse payload
        try:
            data = json.loads(payload.decode('utf-8'))
        except json.JSONDecodeError:
            logger.error("Invalid JSON payload")
            self.send_response(400)
            self.end_headers()
            return
        
        # Process workflow_job event
        action = data.get('action', '')
        job = data.get('workflow_job', {})
        job_id = job.get('id')
        job_name = job.get('name', 'unknown')
        job_labels = job.get('labels', [])
        
        logger.info(f"Received workflow_job event: action={action}, job_id={job_id}, name={job_name}")
        
        if action == 'queued':
            supported, reason = job_is_supported(job_labels)
            if not supported:
                logger.info(f"Job {job_id} labels {job_labels} not supported ({reason}); ignoring")
                self.send_response(200)
                self.end_headers()
                return

            # Check if labels match
            if not labels_match(job_labels):
                logger.info(f"Job {job_id} labels {job_labels} don't match required labels, ignoring")
                self.send_response(200)
                self.end_headers()
                return
            
            # Spawn runner in background
            thread = threading.Thread(
                target=spawn_runner,
                args=(job_id, job_name, job_labels)
            )
            thread.start()
        
        elif action == 'completed':
            # Cleanup runner in background
            thread = threading.Thread(target=cleanup_runner, args=(job_id,))
            thread.start()
        
        self.send_response(200)
        self.end_headers()


def cleanup_stale_runners():
    """Periodically clean up stale runners that may have been orphaned."""
    while True:
        time.sleep(300)  # Check every 5 minutes
        
        with runners_lock:
            stale_jobs = []
            current_time = time.time()
            
            for job_id, info in active_runners.items():
                # Consider stale after 6 hours
                if current_time - info['started_at'] > 21600:
                    stale_jobs.append(job_id)
        
        for job_id in stale_jobs:
            logger.warning(f"Cleaning up stale runner for job {job_id}")
            cleanup_runner(job_id)


def main():
    """Main entry point."""
    # Validate configuration
    if not GITHUB_URL:
        logger.error("GITHUB_URL environment variable is required")
        exit(1)
    
    if not GITHUB_ACCESS_TOKEN:
        logger.error("GITHUB_ACCESS_TOKEN environment variable is required")
        exit(1)
    
    # Load or generate webhook secret
    secret = load_or_generate_secret()
    
    # Register webhook if WEBHOOK_HOST is set
    if WEBHOOK_HOST:
        if not register_webhook(secret):
            logger.warning("Failed to register webhook, continuing anyway...")
    else:
        logger.info("WEBHOOK_HOST not set, manual webhook configuration required")
        if not WEBHOOK_SECRET:
            logger.info(f"Auto-generated webhook secret: {secret}")
            logger.info("Configure this secret in your GitHub webhook settings")
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_stale_runners, daemon=True)
    cleanup_thread.start()
    
    # Start server
    server = http.server.HTTPServer(('0.0.0.0', PORT), WebhookHandler)
    logger.info(f"Webhook controller starting on port {PORT}")
    logger.info(f"GitHub URL: {GITHUB_URL}")
    logger.info(f"Runner image: {RUNNER_IMAGE}")
    logger.info(f"Pull runner image before spawn: {PULL_RUNNER_IMAGE}")
    logger.info(f"Max runners: {MAX_RUNNERS}")
    logger.info(f"Docker network for runners: {DOCKER_NETWORK or '(default)'}")
    logger.info(f"DEBUG_SPAWN_LOGS: {DEBUG_SPAWN_LOGS}")
    logger.info(f"DEBUG_KEEP_RUNNER_CONTAINER: {DEBUG_KEEP_RUNNER_CONTAINER}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
