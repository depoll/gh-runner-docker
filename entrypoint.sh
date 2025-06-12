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
    echo "Removing runner..."
    if [ -f ".runner" ]; then
        # Use the registration token for cleanup
        ./config.sh remove --token "${REGISTRATION_TOKEN}"
    fi
    exit 0
}

# Set trap for cleanup
trap cleanup SIGTERM SIGINT

# Start Docker daemon for Docker-in-Docker
echo "Starting Docker daemon..."
sudo dockerd &
sleep 5


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

# Add labels if specified
if [ -n "$RUNNER_LABELS" ]; then
    CONFIG_CMD="$CONFIG_CMD --labels $RUNNER_LABELS"
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