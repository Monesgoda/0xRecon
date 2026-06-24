# 0xRecon v7.0 🚀

**0xRecon** is an advanced, fully automated reconnaissance framework designed for penetration testing and bug bounty hunting. Built with a refactored architecture in its 7th version, it focuses on speed, modularity, and high-quality output for security professionals.

![0xRecon Banner](https://img.shields.io/badge/Version-7.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)


```markdown
╔═══════════════════════════════════════════════════════════════╗
║    ██████╗ ██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗ ║ 
║   ██╔═████╗╚██╗██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║ ║ 
║   ██║██╔██║ ╚███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║ ║
║   ████╔╝██║ ██╔██╗ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██ ║
║   ╚██████╔╝██╔╝ ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████ ║
║    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝ ║ 
╚═══════════════════════════════════════════════════════════════╝
           [ Automated Reconnaissance Framework v7.0 ]
        
```
---

## 🛠 Features

0xRecon v7.0 is organized into three distinct operational phases to maximize efficiency:

* **Phase 1: Passive Recon (OSINT):** Gathers information via DNS enumeration and OSINT sources without direct interaction with the target.
* **Phase 2: Active Recon:** Performs port scanning, URL collection, and service probing to identify the attack surface.
* **Phase 3: Heavy Vulnerability Scanning:** Leverages the **Nuclei** engine with custom templates to identify critical security vulnerabilities.

### Key Capabilities:
* **Critical Asset Aggregation:** Automatically generates a structured JSON report of critical infrastructure findings.
* **WAF Bypass:** Built-in headers and rotating User-Agent pools.
* **Intelligent Output:** Designed to reduce "noise" by automatically pruning empty files.
* **Self-Healing/Auto-Install:** Automatically detects and installs missing dependencies (`go`, `python3`, `nmap`, `nuclei`, etc.) upon the first run.

---

## 🚀 Getting Started

### Prerequisites
* **OS:** Linux (Debian/Ubuntu).
* **Dependencies:** `go` and `python3` must be installed.

### Installation
```bash
git clone [https://github.com/yourusername/0xRecon.git](https://github.com/yourusername/0xRecon.git)

cd 0xRecon

chmod +x 0xrecon.sh

./0xrecon.sh
