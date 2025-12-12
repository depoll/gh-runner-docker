#!/bin/bash

set -e
set -o pipefail

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

    # Prefer nft if it can talk to the kernel NAT table.
    if [ -n "$iptables_nft" ] && "$iptables_nft" -t nat -L >/dev/null 2>&1; then
        update-alternatives --set iptables "$iptables_nft" >/dev/null 2>&1 || true
        local ip6tables_nft
        ip6tables_nft="$(command -v ip6tables-nft 2>/dev/null || true)"
        if [ -n "$ip6tables_nft" ]; then
            update-alternatives --set ip6tables "$ip6tables_nft" >/dev/null 2>&1 || true
        fi
    elif [ -n "$iptables_legacy" ] && "$iptables_legacy" -t nat -L >/dev/null 2>&1; then
        update-alternatives --set iptables "$iptables_legacy" >/dev/null 2>&1 || true
        local ip6tables_legacy
        ip6tables_legacy="$(command -v ip6tables-legacy 2>/dev/null || true)"
        if [ -n "$ip6tables_legacy" ]; then
            update-alternatives --set ip6tables "$ip6tables_legacy" >/dev/null 2>&1 || true
        fi
    else
        echo "WARNING: Neither iptables-nft nor iptables-legacy appears functional (nat table unavailable)" >&2
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

# Function to exchange PAT for registration token
exchange_pat_for_token() {
    local github_url="$1"
    local pat="$2"
    
    # Extract owner/repo or org from GitHub URL
    local api_url
    if [[ $github_url =~ github\.com/([^/]+/[^/]+)/?$ ]]; then
        # Repository URL
        local repo_path="${BASH_REMATCH[1]}"
        api_url="https://api.github.com/repos/$repo_path/actions/runners/registration-token"
    elif [[ $github_url =~ github\.com/([^/]+)/?$ ]]; then
        # Organization URL
        local org="${BASH_REMATCH[1]}"
        api_url="https://api.github.com/orgs/$org/actions/runners/registration-token"
    else
        echo "Error: Could not extract repository or organization path from URL: $github_url"
        exit 1
    fi
    
    echo "Exchanging PAT for registration token..." >&2
    local response=$(curl -s -X POST \
        -H "Authorization: token $pat" \
        -H "Accept: application/vnd.github.v3+json" \
        "$api_url")
    
    local token=$(echo "$response" | jq -r '.token // empty' 2>/dev/null)
    
    if [ -z "$token" ]; then
        echo "Error: Failed to obtain registration token" >&2
        echo "Response: $response" >&2
        exit 1
    fi
    
    echo "$token"
}

# Function to cleanup truly stale runners with matching deployment ID
cleanup_offline_runners() {
    if [ -z "$DEPLOYMENT_ID" ]; then
        return
    fi
    
    # Extract owner/repo or org from GitHub URL for API calls
    local api_base_url
    if [[ $GITHUB_URL =~ github\.com/([^/]+/[^/]+)/?$ ]]; then
        # Repository URL
        local repo_path="${BASH_REMATCH[1]}"
        api_base_url="https://api.github.com/repos/$repo_path"
    elif [[ $GITHUB_URL =~ github\.com/([^/]+)/?$ ]]; then
        # Organization URL
        local org="${BASH_REMATCH[1]}"
        api_base_url="https://api.github.com/orgs/$org"
    else
        return
    fi
    
    # Get list of runners and filter for this deployment
    local runners_response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "$api_base_url/actions/runners" 2>/dev/null)
    
    # Only cleanup runners that have been offline for a significant time (more than 10 minutes)
    # Use a file to track when we first saw runners as offline
    local offline_tracker="/tmp/offline_runners"
    local current_time=$(date +%s)
    local cleanup_threshold=600  # 10 minutes in seconds
    
    # Get currently offline runners from this deployment
    local offline_runners=$(echo "$runners_response" | jq -r --arg deployment "$DEPLOYMENT_ID" \
        '.runners[] | select(.labels[]?.name == ("deployment:" + $deployment)) | select(.status == "offline") | .name' 2>/dev/null)
    
    # Update tracker file
    touch "$offline_tracker"
    local temp_tracker=$(mktemp)
    
    # Process each currently offline runner
    while IFS= read -r runner_name; do
        if [ -n "$runner_name" ]; then
            # Check if this runner was already tracked as offline
            local first_offline=$(grep "^$runner_name:" "$offline_tracker" 2>/dev/null | cut -d: -f2)
            
            if [ -z "$first_offline" ]; then
                # First time seeing this runner offline, record the time
                echo "$runner_name:$current_time" >> "$temp_tracker"
            else
                # Runner was already offline, check if it's been long enough
                local offline_duration=$((current_time - first_offline))
                if [ $offline_duration -gt $cleanup_threshold ]; then
                    echo "$(date): Removing stale offline runner: $runner_name (offline for ${offline_duration}s)"
                    # Get a fresh registration token for cleanup
                    local cleanup_token=$(exchange_pat_for_token "$GITHUB_URL" "$GITHUB_TOKEN" 2>/dev/null)
                    if [ -n "$cleanup_token" ]; then
                        ./config.sh remove --token "$cleanup_token" --name "$runner_name" 2>/dev/null || true
                    fi
                else
                    # Still within grace period, keep tracking
                    echo "$runner_name:$first_offline" >> "$temp_tracker"
                fi
            fi
        fi
    done <<< "$offline_runners"
    
    # Update the tracker file with current data
    mv "$temp_tracker" "$offline_tracker"
}

# Background cleanup job that runs every 15 minutes
cleanup_job() {
    while true; do
        sleep 900  # 15 minutes (was 5 minutes)
        cleanup_offline_runners
    done
}

# Health check job that monitors if this runner is still registered
health_check_job() {
    local check_failures=0
    local max_failures=3  # Allow 3 consecutive failures before restarting
    
    while true; do
        sleep 300  # Check every 5 minutes (was 1 minute)
        
        # Skip if runner hasn't been configured yet
        if [ ! -f ".runner" ]; then
            continue
        fi
        
        # Extract owner/repo or org from GitHub URL for API calls
        local api_base_url
        if [[ $GITHUB_URL =~ github\.com/([^/]+/[^/]+)/?$ ]]; then
            # Repository URL
            local repo_path="${BASH_REMATCH[1]}"
            api_base_url="https://api.github.com/repos/$repo_path"
        elif [[ $GITHUB_URL =~ github\.com/([^/]+)/?$ ]]; then
            # Organization URL
            local org="${BASH_REMATCH[1]}"
            api_base_url="https://api.github.com/orgs/$org"
        else
            continue
        fi
        
        # Check if our runner still exists
        local runners_response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
            -H "Accept: application/vnd.github.v3+json" \
            "$api_base_url/actions/runners" 2>/dev/null)
        
        local runner_exists=$(echo "$runners_response" | jq -r --arg name "$RUNNER_NAME" \
            '.runners[] | select(.name == $name) | .name' 2>/dev/null)
        
        if [ -z "$runner_exists" ]; then
            check_failures=$((check_failures + 1))
            echo "$(date): Runner $RUNNER_NAME not found in GitHub (failure $check_failures/$max_failures)"
            
            if [ $check_failures -ge $max_failures ]; then
                echo "$(date): Runner $RUNNER_NAME consistently missing - restarting container"
                exit 1  # Let Docker restart the container
            fi
        else
            # Reset failure counter on successful check
            if [ $check_failures -gt 0 ]; then
                echo "$(date): Runner $RUNNER_NAME found again, resetting failure counter"
                check_failures=0
            fi
        fi
    done
}

# Function to detect if token is PAT or registration token
is_pat_token() {
    local token="$1"
    # PATs start with 'ghp_' (classic) or 'github_pat_' (fine-grained)
    # Registration tokens are typically much longer and don't follow this pattern
    if [[ $token =~ ^(ghp_|github_pat_) ]]; then
        return 0  # true - it's a PAT
    else
        return 1  # false - assume it's a registration token
    fi
}

# Function to generate unique runner name with container ID
generate_runner_name() {
    # Use last 4 characters of container ID for uniqueness
    local container_id=$(hostname | tail -c 5)
    
    echo "${RUNNER_NAME_PREFIX:-runner}-${container_id}"
}

# Function to cleanup on exit
cleanup() {
    echo "Cleaning up runner..."
    
    # Kill the runner process if it's still running
    if [ -n "$runner_pid" ]; then
        echo "Stopping runner process..."
        kill -TERM "$runner_pid" 2>/dev/null || true
        wait "$runner_pid" 2>/dev/null || true
    fi
    
    # Always try to deregister runner from GitHub
    echo "Attempting to deregister runner from GitHub..."
    ./config.sh remove --token "${REGISTRATION_TOKEN}" --name "${RUNNER_NAME}" 2>/dev/null || {
        echo "Failed with registration token, trying with original token..."
        ./config.sh remove --token "${GITHUB_TOKEN}" --name "${RUNNER_NAME}" 2>/dev/null || {
            echo "Failed to deregister runner - it may have already been removed"
        }
    }
    
    exit 0
}

# Set trap for cleanup
trap cleanup SIGTERM SIGINT

# Start containerd first
echo "Starting containerd..."
containerd --log-level warn &
sleep 5

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
    # (Don't pass overlay2.override_kernel_check; it's not supported on all dockerd versions.)
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

sleep 5

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

# Start background cleanup job if DEPLOYMENT_ID is provided
if [ -n "$DEPLOYMENT_ID" ]; then
    echo "Starting cleanup job for deployment: $DEPLOYMENT_ID"
    cleanup_job &
fi

# Start health check job to monitor if runner gets removed
echo "Starting health check job"
health_check_job &


# Validate required environment variables
if [ -z "$GITHUB_URL" ]; then
    echo "Error: GITHUB_URL environment variable is required"
    exit 1
fi

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Error: GITHUB_TOKEN environment variable is required"
    exit 1
fi

# Determine if we need to exchange PAT for registration token
REGISTRATION_TOKEN="$GITHUB_TOKEN"
if is_pat_token "$GITHUB_TOKEN"; then
    echo "PAT detected, exchanging for registration token..."
    REGISTRATION_TOKEN=$(exchange_pat_for_token "$GITHUB_URL" "$GITHUB_TOKEN")
else
    echo "Using provided registration token..."
fi

# Generate unique runner name
RUNNER_NAME=$(generate_runner_name)
echo "Configuring runner: $RUNNER_NAME"

# Build configuration command
CONFIG_CMD="./config.sh --url $GITHUB_URL --token $REGISTRATION_TOKEN --name $RUNNER_NAME --work $RUNNER_WORKDIR --unattended --replace"

# Build labels (include deployment ID if provided)
LABELS="$RUNNER_LABELS"
if [ -n "$DEPLOYMENT_ID" ]; then
    if [ -n "$LABELS" ]; then
        LABELS="$LABELS,deployment:$DEPLOYMENT_ID"
    else
        LABELS="deployment:$DEPLOYMENT_ID"
    fi
fi

# Add labels if any are specified
if [ -n "$LABELS" ]; then
    CONFIG_CMD="$CONFIG_CMD --labels $LABELS"
fi

# Add runner group if specified AND we're registering at org scope.
# Passing --runnergroup for repo-level registration can prevent the runner from registering.
if [ -n "$RUNNER_GROUP" ]; then
    if [[ "$GITHUB_URL" =~ github\.com/[^/]+/[^/]+/?$ ]]; then
        echo "RUNNER_GROUP is set but GITHUB_URL looks like a repo URL; skipping --runnergroup"
    else
        CONFIG_CMD="$CONFIG_CMD --runnergroup $RUNNER_GROUP"
    fi
fi

# Configure the runner
echo "Configuring GitHub Actions Runner..."

# Set post-job hook for workspace cleanup
export ACTIONS_RUNNER_HOOK_JOB_COMPLETED="/home/runner/cleanup-workspace.sh"
echo "Workspace cleanup hook configured: $ACTIONS_RUNNER_HOOK_JOB_COMPLETED"

config_log="/tmp/runner-config.log"
if ! ( eval "$CONFIG_CMD" ) 2>&1 | tee "$config_log"; then
    echo "ERROR: Runner configuration failed. Last 200 lines:" >&2
    tail -n 200 "$config_log" >&2 || true
    exit 1
fi

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

# Start the runner
echo "Starting GitHub Actions Runner..."
./run.sh & runner_pid=$!

# Wait for runner process
wait $runner_pid