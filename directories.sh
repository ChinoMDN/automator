#!/bin/bash

# Base directories
BASE_DIRS=(
    "$HOME/pentesting"
    "$HOME/venvs"
    "$HOME/.config/zsh"
    "$HOME/.config/zsh/conf.d"
    "$HOME/.local/share/zsh"
    "$HOME/.cache/zsh"
)

# Pentesting subdirectories
PENTEST_DIRS=(
    "$HOME/pentesting/targets"
    "$HOME/pentesting/tools"
    "$HOME/pentesting/wordlists"
    "$HOME/pentesting/scripts"
    "$HOME/pentesting/reports"
    "$HOME/pentesting/notes"
    "$HOME/pentesting/logs"
    "$HOME/pentesting/config"
)

# Target subdirectories template
TARGET_DIRS=(
    "recon"
    "scans"
    "exploits"
    "loot"
    "screenshots"
    "credentials"
    "evidence"
)

# Tools subdirectories
TOOLS_DIRS=(
    "$HOME/pentesting/tools/custom"
    "$HOME/pentesting/tools/wordlists"
    "$HOME/pentesting/tools/payloads"
    "$HOME/pentesting/tools/scripts"
    "$HOME/pentesting/tools/binaries"
    "$HOME/pentesting/tools/windows"
    "$HOME/pentesting/tools/linux"
    "$HOME/pentesting/tools/web"
)

# Add new tool categories
TOOLS_DIRS+=(
    "$HOME/pentesting/tools/mobile"
    "$HOME/pentesting/tools/cloud"
    "$HOME/pentesting/tools/iot"
    "$HOME/pentesting/tools/forensics"
    "$HOME/pentesting/tools/reversing"
    "$HOME/pentesting/tools/malware-analysis"
)

# Python virtual environments
VENV_DIRS=(
    "$HOME/venvs/pentesting"
    "$HOME/venvs/webapp"
    "$HOME/venvs/osint"
    "$HOME/venvs/mobile"
)

# Add data directories
DATA_DIRS=(
    "$HOME/pentesting/data/payloads"
    "$HOME/pentesting/data/templates"
    "$HOME/pentesting/data/certificates"
    "$HOME/pentesting/data/downloads"
)

create_directory_structure() {
    echo "[+] Creating base directories..."
    for dir in "${BASE_DIRS[@]}"; do
        mkdir -p "$dir"
        chmod 750 "$dir"
    done

    echo "[+] Creating pentesting directories..."
    for dir in "${PENTEST_DIRS[@]}"; do
        mkdir -p "$dir"
        chmod 750 "$dir"
    done

    echo "[+] Creating tools directories..."
    for dir in "${TOOLS_DIRS[@]}"; do
        mkdir -p "$dir"
        chmod 750 "$dir"
    done

    echo "[+] Creating Python virtual environment directories..."
    for dir in "${VENV_DIRS[@]}"; do
        mkdir -p "$dir"
        chmod 750 "$dir"
    done

    echo "[+] Creating data directories..."
    for dir in "${DATA_DIRS[@]}"; do
        mkdir -p "$dir"
        chmod 750 "$dir"
    done

    # Create README files
    echo "[+] Creating documentation files..."
    cat > "$HOME/pentesting/README.md" << 'EOL'
# Pentesting Environment

## Directory Structure
- targets/: Individual target assessments
- tools/: Security tools and scripts
- wordlists/: Password lists and fuzzing dictionaries
- scripts/: Custom automation scripts
- reports/: Assessment reports and documentation
- notes/: General notes and methodologies
- logs/: Tool outputs and session logs
- config/: Tool configurations

## Quick Start
1. Use `pentest` to activate the pentesting Python environment
2. Use `target <name> [IP]` to initialize a new target
3. Check tools/ for installed security tools
4. Use `update-tools` to update all git repositories
EOL

    # Create .gitkeep files to maintain directory structure
    find "$HOME/pentesting" -type d -empty -exec touch {}/.gitkeep \;

    # Create necessary symlinks
    echo "[+] Creating symlinks to system wordlists..."
    ln -sf /usr/share/wordlists "$HOME/pentesting/wordlists/system"
    ln -sf /usr/share/seclists "$HOME/pentesting/wordlists/seclists"

    echo "[+] Directory structure created successfully"
}

# Execute if run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    create_directory_structure
fi
