#!/bin/bash

set -e

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

# Function to cleanup offline runners with matching deployment ID
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
    
    # Extract runners that match our deployment and are offline
    echo "$runners_response" | jq -r --arg deployment "$DEPLOYMENT_ID" \
        '.runners[] | select(.labels[]?.name == ("deployment:" + $deployment)) | select(.status == "offline") | .name' 2>/dev/null | \
    while read -r runner_name; do
        if [ -n "$runner_name" ]; then
            echo "$(date): Removing offline runner: $runner_name"
            # Get a fresh registration token for cleanup
            local cleanup_token=$(exchange_pat_for_token "$GITHUB_URL" "$GITHUB_TOKEN" 2>/dev/null)
            if [ -n "$cleanup_token" ]; then
                ./config.sh remove --token "$cleanup_token" --name "$runner_name" 2>/dev/null || true
            fi
        fi
    done
}

# Background cleanup job that runs every 5 minutes
cleanup_job() {
    while true; do
        sleep 300  # 5 minutes
        cleanup_offline_runners
    done
}

# Health check job that monitors if this runner is still registered
health_check_job() {
    while true; do
        sleep 60  # Check every minute
        
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
            echo "$(date): Runner $RUNNER_NAME no longer exists in GitHub - restarting container"
            exit 1  # Let Docker restart the container
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

# Start Docker daemon for Docker-in-Docker
echo "Starting Docker daemon..."
sudo dockerd &
sleep 5

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

# Add runner group if specified
if [ -n "$RUNNER_GROUP" ]; then
    CONFIG_CMD="$CONFIG_CMD --runnergroup $RUNNER_GROUP"
fi

# Configure the runner
echo "Configuring GitHub Actions Runner..."
eval $CONFIG_CMD

# Start the runner
echo "Starting GitHub Actions Runner..."
./run.sh & runner_pid=$!

# Wait for runner process
wait $runner_pid