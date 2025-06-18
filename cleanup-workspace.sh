#!/bin/bash

# Workspace cleanup script for GitHub Actions runner
# This script is executed after each job completes to ensure a clean workspace for the next run

set -e

# Get the workspace directory from environment variable or use default
WORKSPACE_DIR="${RUNNER_WORKDIR:-_work}"

echo "$(date): Starting workspace cleanup for directory: $WORKSPACE_DIR"

# Check if workspace directory exists
if [ -d "$WORKSPACE_DIR" ]; then
    # Remove all contents from the workspace directory
    # Use find to handle edge cases like hidden files and preserve the directory itself
    find "$WORKSPACE_DIR" -mindepth 1 -delete 2>/dev/null || {
        echo "$(date): Warning: Some files could not be deleted from $WORKSPACE_DIR"
        # Fallback: try to remove what we can
        rm -rf "$WORKSPACE_DIR"/* "$WORKSPACE_DIR"/.[!.]* "$WORKSPACE_DIR"/..?* 2>/dev/null || true
    }
    echo "$(date): Workspace cleanup completed successfully"
else
    echo "$(date): Workspace directory $WORKSPACE_DIR not found, nothing to clean"
fi

exit 0