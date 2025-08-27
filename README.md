# Automator 🛠️

Automated setup script for Kali Linux and other security distributions with focus on web/server pentesting.

## Quick Start 🚀

```bash
git clone https://github.com/ChinoMDN/automator.git
cd automator
chmod +x Setup.sh
./Setup.sh
```

## Features ✨

- 🔄 Cross-distribution package management
- 🐍 Python virtual environments for isolation
- 🛠️ Common pentesting tools and scripts
- 🖥️ Modern CLI tools and configurations
- 🐋 Docker and container support
- 📋 Modular installation with interactive menu

## Requirements 📋

- Kali Linux, Parrot OS, BlackArch, or Pentoo
- Non-root user with sudo privileges
- Internet connection

## Installation Options 🎯

```bash
./Setup.sh          # Interactive installation
./Setup.sh --help   # Show all options
```

Additional flags:

- `--skip-tools`: Skip tool installation
- `--skip-zsh`: Skip ZSH configuration
- `--skip-docker`: Skip Docker installation
- `--skip-advanced`: Skip advanced tools

## Directory Structure 📁

```
~/pentesting/
├── targets/        # Target workspaces
├── tools/          # Custom tools
├── wordlists/      # Custom wordlists
├── scripts/        # Custom scripts
├── reports/        # Reports and documentation
└── notes/          # Notes and resources
```

## Included Tools 🔧

### Web Testing

- Burp Suite
- Dirsearch
- SQLMap
- FFuf
- Nikto

### Network Testing

- Nmap
- Masscan
- Impacket

### Exploitation

- Metasploit
- BloodHound
- Covenant

### OSINT & Recon

- TheHarvester
- Amass
- Nuclei

## Aliases & Functions 💻

Quick reference for commonly used aliases:

```bash
pentest         # Activate pentesting Python environment
pendir          # Go to pentesting directory
tools           # Go to tools directory
target <name>   # Create new target workspace
qscan <ip>      # Quick port scan
wscan <ip>      # Web port scan
revshell        # Generate reverse shell payloads
```

## Contributing 🤝

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## License 📄

This project is licensed under the AGPL-3.0 license - see the LICENSE file for details.

## Acknowledgments 🙏

- Kali Linux Team
- Various open source tool creators
- Pentesting community

## Security Warning ⚠️

This tool installs various security testing tools. Use responsibly and only on systems you have permission to test.
