#!/bin/bash

# Enhanced logging with timestamps and categories
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf '[%s] [%-7s] %s\n' "$timestamp" "$level" "$message" >> "${CONFIG[log_file]}"
}

# Progress bar implementation
show_progress() {
    local current="$1"
    local total="$2"
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))
    
    printf "\rProgress: [%${filled}s%${empty}s] %d%%" \
           | sed 's/ /=/g; s/\s/-/g' \
           "$percentage"
}

# Verify tool installation
verify_installation() {
    local name="$1"
    local install_dir="${CONFIG[install_dir]}/$name"
    
    # Check installation directory
    [[ -d "$install_dir" ]] || return 1
    
    # Check specific files based on tool type
    case "$name" in
        bloodhound)
            [[ -x "$install_dir/BloodHound" ]]
            ;;
        *)
            [[ -d "$install_dir" ]]
            ;;
    esac
}

# Backup existing installation
backup_tool() {
    local name="$1"
    local install_dir="${CONFIG[install_dir]}/$name"
    local backup_dir="${CONFIG[backup_dir]}/$name-$(date +%Y%m%d_%H%M%S)"
    
    [[ -d "$install_dir" ]] || return 0
    
    mkdir -p "$backup_dir"
    cp -r "$install_dir"/* "$backup_dir/" || return 1
    
    log "INFO" "Backed up $name to $backup_dir"
    return 0
}
