#!/bin/bash

# Ensure we're in the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Create essential directories
mkdir -p config lib

# Create default tools.yaml if it doesn't exist
if [ ! -f "config/tools.yaml" ]; then
    mkdir -p config
    cp tools.yaml config/tools.yaml 2>/dev/null || {
        echo "Error: Could not create default configuration"
        exit 1
    }
fi

# Make all scripts executable
chmod +x Setup.sh
find lib -type f -name "*.sh" -exec chmod +x {} \;
find scripts -type f -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

# Run Setup.sh
./Setup.sh "$@"
