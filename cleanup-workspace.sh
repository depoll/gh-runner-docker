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
        echo "$(date): Warning: Some files could not be deleted from $WORKSPACE_DIR, trying with sudo"
        # Fallback: try to remove what we can with regular commands first
        # Safety check to ensure WORKSPACE_DIR is not empty to prevent accidental system damage
        if [ -n "$WORKSPACE_DIR" ] && [ "$WORKSPACE_DIR" != "/" ]; then
            rm -rf "${WORKSPACE_DIR:?}"/* "${WORKSPACE_DIR:?}"/.[!.]* "${WORKSPACE_DIR:?}"/..?* 2>/dev/null || true
        fi
        # Final fallback: use sudo to force removal of stubborn files
        sudo find "$WORKSPACE_DIR" -mindepth 1 -delete 2>/dev/null || {
            echo "$(date): Warning: Some files still could not be deleted even with sudo"
            # Safety check to ensure WORKSPACE_DIR is not empty to prevent accidental system damage
            if [ -n "$WORKSPACE_DIR" ] && [ "$WORKSPACE_DIR" != "/" ]; then
                sudo rm -rf "${WORKSPACE_DIR:?}"/* "${WORKSPACE_DIR:?}"/.[!.]* "${WORKSPACE_DIR:?}"/..?* 2>/dev/null || true
            fi
        }
    }
    echo "$(date): Workspace cleanup completed successfully"
else
    echo "$(date): Workspace directory $WORKSPACE_DIR not found, nothing to clean"
fi

exit 0