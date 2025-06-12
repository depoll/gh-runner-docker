#!/bin/bash

set -e

# Function to generate unique runner name with instance number
generate_runner_name() {
    local hostname=$(hostname)
    local instance_num=""
    
    # Extract instance number from hostname (Docker Compose adds -1, -2, etc.)
    if [[ $hostname =~ -([0-9]+)$ ]]; then
        instance_num="${BASH_REMATCH[1]}"
    else
        # Fallback: use random number if no instance number found
        instance_num=$(shuf -i 1-9999 -n 1)
    fi
    
    echo "${RUNNER_NAME_PREFIX:-runner}-${instance_num}"
}

# Function to cleanup on exit
cleanup() {
    echo "Removing runner..."
    if [ -f ".runner" ]; then
        ./config.sh remove --token "${GITHUB_TOKEN}"
    fi
    exit 0
}

# Set trap for cleanup
trap cleanup SIGTERM SIGINT

# Validate required environment variables
if [ -z "$GITHUB_URL" ]; then
    echo "Error: GITHUB_URL environment variable is required"
    exit 1
fi

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Error: GITHUB_TOKEN environment variable is required"
    exit 1
fi

# Generate unique runner name
RUNNER_NAME=$(generate_runner_name)
echo "Configuring runner: $RUNNER_NAME"

# Build configuration command
CONFIG_CMD="./config.sh --url $GITHUB_URL --token $GITHUB_TOKEN --name $RUNNER_NAME --work $RUNNER_WORKDIR --unattended --replace"

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