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
  RUNNER_IMAGE       - Docker image for ephemeral runners (default: ghcr.io/yourorg/gh-runner:ephemeral)
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

# Configuration
GITHUB_URL = os.environ.get('GITHUB_URL', '')
GITHUB_ACCESS_TOKEN = os.environ.get('GITHUB_ACCESS_TOKEN', '')
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '')
WEBHOOK_HOST = os.environ.get('WEBHOOK_HOST', '')
RUNNER_IMAGE = os.environ.get('RUNNER_IMAGE', 'ghcr.io/yourorg/gh-runner:ephemeral')
RUNNER_LABELS = os.environ.get('RUNNER_LABELS', 'self-hosted,linux,x64,ephemeral')
REQUIRED_LABELS = os.environ.get('REQUIRED_LABELS', '')
MAX_RUNNERS = int(os.environ.get('MAX_RUNNERS', '10'))
PORT = int(os.environ.get('PORT', '8080'))

# Secret file path for persistence
SECRET_FILE = Path('/data/webhook_secret')

# Track active runners
active_runners = {}
runners_lock = threading.Lock()


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
            except Exception:
                pass
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
    with runners_lock:
        if len(active_runners) >= MAX_RUNNERS:
            logger.warning(f"Maximum runners ({MAX_RUNNERS}) reached, cannot spawn new runner")
            return False
        
        if job_id in active_runners:
            logger.info(f"Runner already exists for job {job_id}")
            return True
    
    # Get registration token
    token = get_registration_token()
    if not token:
        logger.error("Failed to get registration token")
        return False
    
    # Generate unique runner name
    runner_name = f"ephemeral-{job_id}-{int(time.time())}"
    
    # Build docker command
    cmd = [
        'docker', 'run', '-d',
        '--name', runner_name,
        '--rm',  # Auto-remove when stopped
        '-e', f'GITHUB_URL={GITHUB_URL}',
        '-e', f'RUNNER_TOKEN={token}',
        '-e', f'RUNNER_NAME={runner_name}',
        '-e', f'RUNNER_LABELS={RUNNER_LABELS}',
        '-v', '/var/run/docker.sock:/var/run/docker.sock',
        RUNNER_IMAGE
    ]
    
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
    logger.info(f"Max runners: {MAX_RUNNERS}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
