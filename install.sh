#!/bin/bash

# Ensure we're in the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -d "$SCRIPT_DIR" ]; then
    echo "Error: Could not determine script directory"
    exit 1
fi
cd "$SCRIPT_DIR" || exit 1

# Create essential directories with error handling
for dir in config lib; do
    mkdir -p "$dir" || {
        echo "Error: Could not create directory: $dir"
        exit 1
    }
done

# Create default tools.yaml if it doesn't exist
if [ ! -f "config/tools.yaml" ]; then
    mkdir -p config || {
        echo "Error: Could not create config directory"
        exit 1
    }
    
    if [ -f "tools.yaml" ]; then
        cp tools.yaml config/tools.yaml || {
            echo "Error: Could not copy tools.yaml to config directory"
            exit 1
        }
    else
        echo "Error: tools.yaml not found in current directory"
        exit 1
    fi
fi

# Make all scripts executable with validation
for script in Setup.sh $(find lib scripts -type f -name "*.sh" 2>/dev/null); do
    if [ -f "$script" ]; then
        chmod +x "$script" || {
            echo "Error: Could not make executable: $script"
            exit 1
        }
    fi
done

# Run Setup.sh with error handling
if [ -x "./Setup.sh" ]; then
    ./Setup.sh "$@"
else
    echo "Error: Setup.sh not found or not executable"
    exit 1
fi
