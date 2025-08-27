# Automator 🛠️

**Automated setup script for Kali Linux and other security distributions with focus on web/server pentesting.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Parrot%20OS%20%7C%20BlackArch%20%7C%20Pentoo-brightgreen)](#requirements)
[![Shell](https://img.shields.io/badge/Shell-Bash-89e051.svg)](https://www.gnu.org/software/bash/)

> **Warning**: This tool installs various security testing tools. Use responsibly and only on systems you have explicit permission to test.

## Quick Start 🚀

```bash
git clone https://github.com/ChinoMDN/automator.git
cd automator
chmod +x Setup.sh
./Setup.sh
```

## Features ✨

- 🔄 **Cross-distribution support** - Works on Kali, Parrot OS, BlackArch, and Pentoo
- 🐍 **Python virtual environments** - Isolated environments for security tools
- 🛠️ **Comprehensive toolset** - Essential pentesting tools and custom scripts
- 🖥️ **Modern CLI experience** - Enhanced shell with useful aliases and functions
- 🐋 **Container ready** - Docker support for isolated testing environments
- 📋 **Modular installation** - Interactive menu with selective installation options
- ⚡ **Performance optimized** - Parallel downloads and efficient package management

## Requirements 📋

- **Operating System**: Kali Linux, Parrot OS, BlackArch, or Pentoo
- **User permissions**: Non-root user with sudo privileges
- **Network**: Active internet connection
- **Storage**: Minimum 2GB free space (5GB+ recommended)
- **Memory**: 2GB+ RAM recommended

## Installation Options 🎯

### Interactive Installation
```bash
./Setup.sh
```

### Command Line Options
```bash
./Setup.sh --help                    # Show all available options
./Setup.sh --skip-tools              # Skip tool installation
./Setup.sh --skip-zsh                # Skip ZSH configuration
./Setup.sh --skip-docker             # Skip Docker installation  
./Setup.sh --skip-advanced           # Skip advanced tools
./Setup.sh --minimal                 # Install only essential tools
./Setup.sh --full                    # Install everything (default)
```

### Advanced Usage
```bash
# Custom installation with specific components
./Setup.sh --skip-docker --skip-advanced

# Quiet installation (minimal output)
./Setup.sh --quiet

# Dry run (show what would be installed)
./Setup.sh --dry-run
```

## Directory Structure 📁

The script creates an organized workspace structure in your home directory:

```
~/pentesting/
├── targets/          # Target-specific workspaces
│   ├── example.com/
│   └── 192.168.1.0/
├── tools/            # Custom and compiled tools
│   ├── custom/
│   └── compiled/
├── wordlists/        # Custom and downloaded wordlists
│   ├── discovery/
│   ├── passwords/
│   └── subdomains/
├── scripts/          # Automation and helper scripts
│   ├── recon/
│   ├── exploitation/
│   └── post-exploitation/
├── reports/          # Assessment reports and documentation
│   ├── templates/
│   └── findings/
└── notes/           # Research notes and resources
    ├── methodology/
    └── references/
```

## Included Tools 🔧

### Web Application Testing
- **Burp Suite Community** - Web application security testing
- **Dirsearch** - Web path scanner
- **SQLMap** - Automatic SQL injection tool
- **FFuf** - Fast web fuzzer
- **Nikto** - Web vulnerability scanner
- **Gobuster** - Directory/file brute-forcer
- **Wapiti** - Web application vulnerability scanner

### Network & Infrastructure
- **Nmap** - Network discovery and security auditing
- **Masscan** - Fast port scanner
- **Impacket** - Network protocol toolkit
- **Responder** - LLMNR, NBT-NS and MDNS poisoner
- **CrackMapExec** - Network service exploitation tool
- **BloodHound** - Active Directory reconnaissance

### Exploitation & Post-Exploitation
- **Metasploit Framework** - Penetration testing platform
- **Covenant** - .NET command and control framework
- **Empire** - PowerShell post-exploitation framework
- **LinPEAS/WinPEAS** - Privilege escalation scripts

### OSINT & Reconnaissance
- **TheHarvester** - Email, subdomain and people names harvester
- **Amass** - Attack surface mapping and asset discovery
- **Nuclei** - Vulnerability scanner based on templates
- **Subfinder** - Subdomain discovery tool
- **HTTPx** - HTTP toolkit for security research

### Utilities & Modern CLI Tools
- **Oh My Zsh** - Enhanced shell experience
- **Tmux** - Terminal multiplexer
- **FZF** - Command-line fuzzy finder
- **Bat** - Enhanced cat with syntax highlighting
- **EXA** - Modern replacement for ls
- **Ripgrep** - Fast text search tool

## Aliases & Functions 💻

After installation, you'll have access to these convenient shortcuts:

### Environment Management
```bash
pentest                    # Activate pentesting Python environment
pendir                     # Navigate to pentesting directory
tools                      # Navigate to tools directory
```

### Target Management
```bash
target <name>             # Create and navigate to new target workspace
target list               # List all target workspaces
target clean <name>       # Clean target workspace
```

### Quick Scanning
```bash
qscan <ip>                # Quick TCP port scan (top 1000 ports)
wscan <ip>                # Web-focused port scan (80, 443, 8080, etc.)
fscan <ip>                # Full TCP port scan (all 65535 ports)
uscan <ip>                # UDP scan (top 100 ports)
```

### Payload Generation
```bash
revshell <ip> <port>      # Generate reverse shell payloads
webshell                  # Generate web shell payloads
msfpayload <type>         # Quick MSF payload generation
```

### Reconnaissance
```bash
subenum <domain>          # Comprehensive subdomain enumeration
dirfuzz <url>             # Directory fuzzing with common wordlists
nucleiscan <target>       # Nuclei vulnerability scan
```

## Configuration 🔧

### Python Virtual Environment
The script creates a dedicated Python virtual environment with security-focused packages:
- requests, urllib3
- beautifulsoup4, lxml
- scapy, netaddr
- cryptography, pycrypto
- colorama, termcolor

### ZSH Configuration
If ZSH installation is enabled:
- Oh My Zsh framework
- Syntax highlighting plugin
- Auto-suggestions plugin
- Custom pentesting theme
- Useful aliases and functions

### Docker Setup
Optional Docker configuration includes:
- Latest Docker CE installation
- Docker Compose
- Security-focused container images
- Network isolation templates

## Troubleshooting 🔧

### Common Issues

**Permission errors during installation:**
```bash
sudo chown -R $USER:$USER ~/pentesting/
```

**Python virtual environment issues:**
```bash
rm -rf ~/pentesting/.venv
./Setup.sh --skip-tools  # Recreate environment
```

**Missing tools after installation:**
```bash
./Setup.sh --repair      # Repair broken installation
```

### Getting Help
```bash
./Setup.sh --help        # Show help information
./Setup.sh --version     # Show version information
./Setup.sh --debug       # Run with debug output
```

## Contributing 🤝

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** your feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines
- Follow shell scripting best practices
- Test on multiple distributions
- Update documentation for new features
- Add error handling for edge cases

## Changelog 📝

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

## License 📄

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments 🙏

Special thanks to:
- **Kali Linux Team** - For the excellent penetration testing distribution
- **Open Source Community** - For the amazing security tools
- **Security Researchers** - For continuous innovation in the field
- **Contributors** - Everyone who has contributed to this project

## Security Notice ⚠️

This tool is designed for legitimate security testing and educational purposes only. Users are responsible for:

- Obtaining proper authorization before testing any systems
- Complying with applicable laws and regulations
- Using tools ethically and responsibly
- Respecting the privacy and rights of others

**The authors are not responsible for any misuse of this tool.**

---

<div align="center">
  <p>Made with ❤️ by the security community</p>
  <p><a href="#top">Back to top ⬆️</a></p>
</div>