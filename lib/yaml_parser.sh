#!/bin/bash

# Function to validate if yq is installed
check_yq() {
    if ! command -v yq &> /dev/null; then
        echo "yq is required but not installed. Installing..."
        wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/local/bin/yq
        chmod +x /usr/local/bin/yq
    fi
}

# Function to parse tool data from YAML
parse_tool() {
    local tool_name="$1"
    local yaml_file="$2"
    
    # Get tool properties using yq
    local source=$(yq e ".tools.$tool_name.source" "$yaml_file")
    local url=$(yq e ".tools.$tool_name.url" "$yaml_file")
    local type=$(yq e ".tools.$tool_name.type" "$yaml_file")
    local dependencies=$(yq e ".tools.$tool_name.dependencies[]" "$yaml_file")
    
    # Export variables for use in main script
    export TOOL_SOURCE="$source"
    export TOOL_URL="$url"
    export TOOL_TYPE="$type"
    export TOOL_DEPENDENCIES="$dependencies"
}

# Function to get all tool names from YAML
get_tool_names() {
    local yaml_file="$1"
    yq e '.tools | keys | .[]' "$yaml_file"
}

parse_yaml() {
    local yaml_file=$1
    local prefix=$2
    local s='[[:space:]]*' w='[a-zA-Z0-9_]*'
    
    sed -ne "s|^\($s\):|\1|" \
        -e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$prefix\2=\"\3\"|p" \
        -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$prefix\2=\"\3\"|p" $yaml_file
}

get_tool_config() {
    local tool_name=$1
    local yaml_file=$2
    eval $(parse_yaml "$yaml_file" "config_")
    echo "${config_tools_${tool_name}_source}"
    echo "${config_tools_${tool_name}_url}"
    echo "${config_tools_${tool_name}_type}"
}
