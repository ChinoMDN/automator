#!/bin/bash

# Dependency injection for configuration
declare -g -A CONFIG
declare -g -A TOOLS

# Load tool configuration from YAML
load_tool_config() {
    local config_file="$1"
    
    if ! command -v yq &>/dev/null; then
        install_pkg yq || return 1
    fi
    
    # Parse YAML into shell format
    eval "$(yq eval -o=shell "$config_file")"
    
    # Validate required sections
    [[ -z "${tools[*]}" ]] && {
        print_error "No tools defined in configuration"
        return 1
    }
    
    return 0
}

# Install tool with progress and verification
install_tool() {
    local name="$1"
    local -A tool_config
    
    # Get tool configuration
    eval "tool_config=(${tools[$name]})"
    
    print_status "Installing ${tool_config[name]:-$name}..."
    
    # Verify dependencies
    if [[ -n "${tool_config[deps]}" ]]; then
        local IFS=','
        local -a deps=(${tool_config[deps]})
        for dep in "${deps[@]}"; do
            install_pkg "$dep" || return 1
        done
    fi
    
    # Install based on source type
    case "${tool_config[source]}" in
        github|gitlab)
            install_from_git "${tool_config[@]}"
            ;;
        apt|dnf|pacman)
            install_pkg "${tool_config[package]}"
            ;;
        *)
            print_error "Unsupported source: ${tool_config[source]}"
            return 1
            ;;
    esac
    
    # Run post-install commands
    if [[ -n "${tool_config[post_install]}" ]]; then
        local IFS=$'\n'
        local -a commands=(${tool_config[post_install]})
        for cmd in "${commands[@]}"; do
            eval "$cmd" || {
                print_warning "Post-install command failed: $cmd"
                continue
            }
        done
    fi
    
    return 0
}
