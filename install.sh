#!/bin/bash

# Simple installer script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing Kali Automator..."

# Make Setup.sh executable
chmod +x "$SCRIPT_DIR/Setup.sh"

# Run Setup.sh
"$SCRIPT_DIR/Setup.sh"
