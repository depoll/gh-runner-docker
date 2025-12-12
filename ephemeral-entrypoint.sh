#!/bin/bash

set -e
set -o pipefail

# Ephemeral Runner Entrypoint Script
# This script configures and runs a GitHub Actions runner in ephemeral mode
# The runner processes exactly one job then exits

echo "=== GitHub Actions Ephemeral Runner ==="
echo "Starting at: $(date)"

is_true() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

setup_dotnet_crash_dumps() {
    if ! is_true "${DEBUG_DOTNET_DUMPS:-}"; then
        return 0
    fi

    echo "Enabling .NET crash dumps (DEBUG_DOTNET_DUMPS=true)"
    mkdir -p /tmp/dotnet-dumps >/dev/null 2>&1 || true

    # Best-effort: allow writing core files if the kernel permits it.
    ulimit -c unlimited >/dev/null 2>&1 || true

    # Only set defaults if not already provided.
    : "${COMPlus_DbgEnableMiniDump:=1}"
    : "${COMPlus_DbgMiniDumpType:=1}"
    : "${COMPlus_DbgMiniDumpName:=/tmp/dotnet-dumps/coreclr.%e.%p.%t.dmp}"
    export COMPlus_DbgEnableMiniDump COMPlus_DbgMiniDumpType COMPlus_DbgMiniDumpName
}

configure_iptables_backend() {
    # Best-effort: load common netfilter modules needed for Docker NAT.
    # This only works if the container can access host modules (mount /lib/modules)
    # and has permission to load modules (privileged gives CAP_SYS_MODULE).
    if command -v modprobe >/dev/null 2>&1; then
        modprobe br_netfilter >/dev/null 2>&1 || true
        modprobe nf_conntrack >/dev/null 2>&1 || true
        modprobe nf_nat >/dev/null 2>&1 || true
        modprobe ip_tables >/dev/null 2>&1 || true
        modprobe iptable_nat >/dev/null 2>&1 || true
        modprobe iptable_filter >/dev/null 2>&1 || true
        modprobe ip6_tables >/dev/null 2>&1 || true
        modprobe ip6table_nat >/dev/null 2>&1 || true
        modprobe ip6table_filter >/dev/null 2>&1 || true
        modprobe nf_tables >/dev/null 2>&1 || true
    fi

    # Docker uses iptables to set up networking/NAT. Some environments don't support
    # nftables (iptables-nft), while others don't support legacy iptables (ip_tables).
    # Choose the backend that actually works on this kernel.
    if ! command -v update-alternatives >/dev/null 2>&1; then
        return
    fi

    local iptables_nft
    local iptables_legacy
    iptables_nft="$(command -v iptables-nft 2>/dev/null || true)"
    iptables_legacy="$(command -v iptables-legacy 2>/dev/null || true)"

    # Prefer legacy by default for DinD; nft has been observed to fail in some nested/emulated environments.
    # Override with DOCKER_IPTABLES_BACKEND=nft if you want to force nft.
    local preferred="${DOCKER_IPTABLES_BACKEND:-legacy}"

    if [ "$preferred" = "nft" ]; then
        if [ -n "$iptables_nft" ]; then
            update-alternatives --set iptables "$iptables_nft" >/dev/null 2>&1 || true
            local ip6tables_nft
            ip6tables_nft="$(command -v ip6tables-nft 2>/dev/null || true)"
            if [ -n "$ip6tables_nft" ]; then
                update-alternatives --set ip6tables "$ip6tables_nft" >/dev/null 2>&1 || true
            fi
        fi
    else
        if [ -n "$iptables_legacy" ]; then
            update-alternatives --set iptables "$iptables_legacy" >/dev/null 2>&1 || true
            local ip6tables_legacy
            ip6tables_legacy="$(command -v ip6tables-legacy 2>/dev/null || true)"
            if [ -n "$ip6tables_legacy" ]; then
                update-alternatives --set ip6tables "$ip6tables_legacy" >/dev/null 2>&1 || true
            fi
        fi
    fi

    # Sanity probe: if the chosen backend can't list nat, try the other.
    if ! iptables -t nat -L >/dev/null 2>&1; then
        if [ -n "$iptables_legacy" ] && "$iptables_legacy" -t nat -L >/dev/null 2>&1; then
            update-alternatives --set iptables "$iptables_legacy" >/dev/null 2>&1 || true
        elif [ -n "$iptables_nft" ] && "$iptables_nft" -t nat -L >/dev/null 2>&1; then
            update-alternatives --set iptables "$iptables_nft" >/dev/null 2>&1 || true
        else
            echo "WARNING: Neither iptables backend can access the nat table (seccomp/kernel restriction?)" >&2
        fi
    fi

    local arptables_legacy
    arptables_legacy="$(command -v arptables-legacy 2>/dev/null || true)"
    if [ -n "$arptables_legacy" ]; then
        update-alternatives --set arptables "$arptables_legacy" >/dev/null 2>&1 || true
    fi
    local ebtables_legacy
    ebtables_legacy="$(command -v ebtables-legacy 2>/dev/null || true)"
    if [ -n "$ebtables_legacy" ]; then
        update-alternatives --set ebtables "$ebtables_legacy" >/dev/null 2>&1 || true
    fi
}

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

setup_dotnet_crash_dumps

# Start containerd first
echo "Starting containerd..."
# containerd is noisy; keep logs minimal so we can see runner registration output.
if [ -n "${DOCKER_HOST:-}" ]; then
    echo "Using external Docker daemon via DOCKER_HOST=${DOCKER_HOST} (skipping Docker-in-Docker)"

    echo "Waiting for Docker daemon to be reachable..."
    deadline=$((SECONDS + 60))
    while [ $SECONDS -lt $deadline ]; do
        if timeout 3 docker info >/dev/null 2>&1; then
            echo "Docker daemon is reachable"
            break
        fi
        sleep 2
    done
    if ! timeout 3 docker info >/dev/null 2>&1; then
        echo "ERROR: External Docker daemon is not reachable from runner container" >&2
        exit 1
    fi
elif is_true "${RUNNER_USE_HOST_DOCKER:-}" && [ -S /var/run/docker.sock ]; then
    echo "Using host Docker via /var/run/docker.sock (skipping Docker-in-Docker)"
    export DOCKER_HOST="unix:///var/run/docker.sock"

    echo "Waiting for Docker daemon to be reachable..."
    deadline=$((SECONDS + 30))
    while [ $SECONDS -lt $deadline ]; do
        if timeout 3 docker info >/dev/null 2>&1; then
            echo "Docker daemon is reachable"
            break
        fi
        sleep 2
    done
    if ! timeout 3 docker info >/dev/null 2>&1; then
        echo "ERROR: Host Docker daemon is not reachable from runner container" >&2
        exit 1
    fi
else
    containerd --log-level warn &
    sleep 3

    # Start Docker daemon for Docker-in-Docker
    echo "Starting Docker daemon..."
    configure_iptables_backend

# Function to test Docker storage driver
test_docker_storage() {
    local driver=$1
    local opts=$2
    echo "Testing storage driver: $driver"

    local dockerd_log="/tmp/dockerd-${driver}.log"
    last_dockerd_log="$dockerd_log"
    
    # Kill any existing dockerd
    pkill dockerd 2>/dev/null || true
    sleep 2
    
    # Try to start with the specified driver
    if [ -n "$opts" ]; then
        dockerd --host=unix:///var/run/docker.sock --storage-driver=$driver $opts >"$dockerd_log" 2>&1 &
    else
        dockerd --host=unix:///var/run/docker.sock --storage-driver=$driver >"$dockerd_log" 2>&1 &
    fi
    
    local dockerd_pid=$!

    # Check if Docker started successfully.
    # Under emulation or on slower kernels, dockerd can take a while to become responsive.
    local deadline=$((SECONDS + 45))
    while [ $SECONDS -lt $deadline ]; do
        if timeout 3 docker info >/dev/null 2>&1; then
            echo "Successfully started Docker with $driver storage driver"
            return 0
        fi
        sleep 2
    done

    echo "Failed to start Docker with $driver storage driver"
    echo "Last 120 lines of $dockerd_log:" >&2
    tail -n 120 "$dockerd_log" >&2 || true
    kill $dockerd_pid 2>/dev/null || true
    return 1
}

supports_overlay2() {
    grep -qE '(^|\s)overlay(\s|$)' /proc/filesystems 2>/dev/null || return 1

    # Some kernels report overlay support but still fail to mount it (e.g., missing options).
    # Do a quick real mount probe to avoid repeatedly trying overlay2 when it can't work.
    local base
    base="$(mktemp -d /tmp/overlay-probe.XXXXXX)" || return 1
    local lower="$base/lower"
    local upper="$base/upper"
    local work="$base/work"
    local merged="$base/merged"

    mkdir -p "$lower" "$upper" "$work" "$merged" || { rm -rf "$base"; return 1; }
    echo "probe" >"$lower/file" 2>/dev/null || true

    if mount -t overlay overlay -o "lowerdir=$lower,upperdir=$upper,workdir=$work" "$merged" >/dev/null 2>&1; then
        umount "$merged" >/dev/null 2>&1 || true
        rm -rf "$base" || true
        return 0
    fi

    rm -rf "$base" || true
    return 1
}

# Try different storage drivers in order of preference.
# If DOCKER_STORAGE_DRIVER is set, only attempt that driver.
last_dockerd_log=""
if [ -n "${DOCKER_STORAGE_DRIVER:-}" ]; then
    echo "DOCKER_STORAGE_DRIVER is set: ${DOCKER_STORAGE_DRIVER}"
    test_docker_storage "${DOCKER_STORAGE_DRIVER}" ""
else
    if supports_overlay2; then
        if ! test_docker_storage "overlay2" ""; then
            if ! test_docker_storage "fuse-overlayfs" ""; then
                echo "Falling back to vfs storage driver (slower performance)"
                test_docker_storage "vfs" ""
            fi
        fi
    else
        echo "Overlay mount probe failed; trying fuse-overlayfs then vfs"
        if ! test_docker_storage "fuse-overlayfs" ""; then
            echo "Falling back to vfs storage driver (slower performance)"
            test_docker_storage "vfs" ""
        fi
    fi
fi

# Wait for Docker daemon to be ready
echo "Waiting for Docker daemon to start..."
for i in {1..30}; do
    if timeout 3 docker info >/dev/null 2>&1; then
        echo "Docker daemon is ready"
        break
    fi
    echo "Waiting for Docker daemon... ($i/30)"
    sleep 2
done

    if ! timeout 3 docker info >/dev/null 2>&1; then
        echo "ERROR: Docker daemon failed to start" >&2
        if [ -n "$last_dockerd_log" ]; then
            echo "Last 200 lines of $last_dockerd_log:" >&2
            tail -n 200 "$last_dockerd_log" >&2 || true
        fi
        exit 1
    fi
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
