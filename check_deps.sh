#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_system_deps() {
    local missing_deps=()
    local system_deps=(
        "git" "curl" "wget" "python3" "python3-pip" "nmap"
        "masscan" "gobuster" "ffuf" "tmux" "gcc" "make"
    )

    echo "Checking system dependencies..."
    for dep in "${system_deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}Missing system dependencies: ${missing_deps[*]}${NC}"
        echo "Install with: sudo apt install ${missing_deps[*]}"
        return 1
    fi

    echo -e "${GREEN}All system dependencies are installed${NC}"
    return 0
}

check_python_deps() {
    local req_file="requirements.txt"
    if [ ! -f "$req_file" ]; then
        echo -e "${RED}Requirements file not found: $req_file${NC}"
        return 1
    }

    echo "Checking Python dependencies..."
    if ! pip3 check > /dev/null 2>&1; then
        echo -e "${YELLOW}Installing Python dependencies...${NC}"
        pip3 install -r "$req_file"
    fi
}

check_directory_structure() {
    local base_dirs=(
        "$HOME/pentesting"
        "$HOME/venvs"
        "$HOME/pentesting/tools"
        "$HOME/pentesting/wordlists"
    )

    echo "Checking directory structure..."
    for dir in "${base_dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            echo -e "${RED}Missing directory: $dir${NC}"
            echo "Run: ./directories.sh to create required directories"
            return 1
        fi
    done

    echo -e "${GREEN}Directory structure is correct${NC}"
    return 0
}

main() {
    check_system_deps || exit 1
    check_python_deps || exit 1
    check_directory_structure || exit 1
    echo -e "${GREEN}All dependencies and directories are properly set up${NC}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
