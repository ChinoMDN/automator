#!/bin/bash

parse_yaml_config() {
    local config="$1"
    local temp_file
    temp_file=$(mktemp)
    echo "$config" | base64 -d > "$temp_file"
    
    if ! command -v yq &>/dev/null; then
        echo "yq is required for YAML parsing"
        rm "$temp_file"
        return 1
    fi
    
    local parsed
    parsed=$(yq eval -o json "$temp_file")
    rm "$temp_file"
    echo "$parsed"
}

read_tool_config() {
    local config_file="$SCRIPT_DIR/config/tools.yaml"
    if [ ! -f "$config_file" ]; then
        print_error "Configuration file not found: $config_file"
        return 1
    }
    
    if ! command -v yq &>/dev/null; then
        print_status "Installing yq for YAML parsing..."
        install_pkg yq || {
            print_error "Failed to install yq"
            return 1
        }
    }
    
    # Parse and load tool configurations
    while IFS= read -r line; do
        local tool_name
        tool_name=$(echo "$line" | yq e '.name' -)
        TOOL_CONFIGS["$tool_name"]=$(echo "$line" | base64 -w0)
    done < <(yq e -o=json '.tools[]' "$config_file")
}
