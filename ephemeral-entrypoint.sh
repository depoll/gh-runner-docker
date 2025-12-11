#!/bin/bash

set -e
set -o pipefail

# Ephemeral Runner Entrypoint Script
# This script configures and runs a GitHub Actions runner in ephemeral mode
# The runner processes exactly one job then exits

echo "=== GitHub Actions Ephemeral Runner ==="
echo "Starting at: $(date)"

# Initialize runner_pid to avoid undefined variable in cleanup trap
runner_pid=""

# Function to cleanup on exit
cleanup() {
    local exit_code=$?
    echo "=== Cleanup started (exit code: $exit_code) ==="
    
    # Stop the runner gracefully if running
    if [ -n "$runner_pid" ] && kill -0 "$runner_pid" 2>/dev/null; then
        echo "Stopping runner process..."
        kill -TERM "$runner_pid" 2>/dev/null || true
        wait "$runner_pid" 2>/dev/null || true
    fi
    
    # For ephemeral runners, GitHub auto-deregisters after job completion
    # But we try to clean up anyway in case of early termination
    if [ -f ".runner" ] && [ -n "$REGISTRATION_TOKEN" ]; then
        echo "Attempting to deregister runner..."
        ./config.sh remove --token "${REGISTRATION_TOKEN}" 2>/dev/null || true
    fi
    
    echo "=== Runner cleanup complete ==="
    exit $exit_code
}

# Set trap for cleanup
trap cleanup EXIT SIGTERM SIGINT

# Start containerd first
echo "Starting containerd..."
sudo containerd &
sleep 3

# Start Docker daemon for Docker-in-Docker
echo "Starting Docker daemon..."

# Function to test Docker storage driver
test_docker_storage() {
    local driver=$1
    local opts=$2
    echo "Testing storage driver: $driver"
    
    # Kill any existing dockerd
    sudo pkill dockerd 2>/dev/null || true
    sleep 2
    
    # Try to start with the specified driver
    if [ -n "$opts" ]; then
        sudo dockerd --host=unix:///var/run/docker.sock --storage-driver=$driver $opts &
    else
        sudo dockerd --host=unix:///var/run/docker.sock --storage-driver=$driver &
    fi
    
    local dockerd_pid=$!
    sleep 5
    
    # Check if Docker started successfully
    if docker info >/dev/null 2>&1; then
        echo "Successfully started Docker with $driver storage driver"
        return 0
    else
        echo "Failed to start Docker with $driver storage driver"
        sudo kill $dockerd_pid 2>/dev/null || true
        return 1
    fi
}

# Try different storage drivers in order of preference
if ! test_docker_storage "overlay2" "--storage-opt=overlay2.override_kernel_check=true"; then
    if ! test_docker_storage "fuse-overlayfs" ""; then
        echo "Falling back to vfs storage driver (slower performance)"
        test_docker_storage "vfs" ""
    fi
fi

# Wait for Docker daemon to be ready
echo "Waiting for Docker daemon to start..."
for i in {1..30}; do
    if docker info >/dev/null 2>&1; then
        echo "Docker daemon is ready"
        break
    fi
    echo "Waiting for Docker daemon... ($i/30)"
    sleep 2
done

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon failed to start"
    exit 1
fi

# Validate required environment variables
if [ -z "$GITHUB_URL" ]; then
    echo "Error: GITHUB_URL environment variable is required"
    exit 1
fi

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Error: GITHUB_TOKEN environment variable is required"
    exit 1
fi

# Use provided runner name or generate one
if [ -z "$RUNNER_NAME" ]; then
    RUNNER_NAME="ephemeral-$(hostname | rev | cut -c1-4 | rev)-$(date +%s)"
fi

echo "Runner name: $RUNNER_NAME"
echo "GitHub URL: $GITHUB_URL"
echo "Labels: $RUNNER_LABELS"
echo "Ephemeral mode: enabled"
if [ -n "$JOB_ID" ]; then
    echo "Job ID: $JOB_ID"
fi

# The token passed should already be a registration token
REGISTRATION_TOKEN="$GITHUB_TOKEN"

# Build configuration command with --ephemeral flag
CONFIG_ARGS=(
    "./config.sh" "--url" "$GITHUB_URL"
    "--token" "$REGISTRATION_TOKEN"
    "--name" "$RUNNER_NAME"
    "--work" "$RUNNER_WORKDIR"
    "--ephemeral" "--unattended" "--replace" "--disableupdate"
)

# Add labels if specified
if [ -n "$RUNNER_LABELS" ]; then
    CONFIG_ARGS+=("--labels" "$RUNNER_LABELS")
fi

# Add runner group if specified AND we're registering at org scope.
# Passing --runnergroup for repo-level registration can prevent the runner from registering.
if [ -n "$RUNNER_GROUP" ]; then
    if [[ "$GITHUB_URL" =~ github\.com/[^/]+/[^/]+/?$ ]]; then
        echo "RUNNER_GROUP is set but GITHUB_URL looks like a repo URL; skipping --runnergroup"
    else
        CONFIG_ARGS+=("--runnergroup" "$RUNNER_GROUP")
    fi
fi

# Configure the runner
echo "=== Configuring Ephemeral Runner ==="

config_log="/tmp/runner-config.log"
if ! "${CONFIG_ARGS[@]}" 2>&1 | tee "$config_log"; then
    echo "ERROR: Runner configuration failed. Last 200 lines:" >&2
    tail -n 200 "$config_log" >&2 || true
    exit 1
fi

# Print a small, safe summary of what got registered (if available)
if [ -f ".runner" ]; then
    echo "=== Runner Registration Summary ==="
    if command -v jq >/dev/null 2>&1; then
        jq -r '"runnerId=" + (.runnerId|tostring) + " name=" + .name + " url=" + .gitHubUrl' .runner 2>/dev/null || true
    else
        echo "Registered runner metadata present in .runner"
    fi
else
    echo "WARNING: .runner file not found after config.sh; runner may not have registered" >&2
fi

# Set post-job hook for workspace cleanup
export ACTIONS_RUNNER_HOOK_JOB_COMPLETED="/home/runner/cleanup-workspace.sh"

# Start the runner in foreground (ephemeral mode exits after one job)
echo "=== Starting Ephemeral Runner ==="
echo "Runner will process exactly one job then exit"

./run.sh &
runner_pid=$!

# Wait for runner process to complete
wait $runner_pid
runner_exit_code=$?

echo "=== Runner completed with exit code: $runner_exit_code ==="

# Exit with the runner's exit code
exit $runner_exit_code
