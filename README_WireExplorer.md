<div align="center">

# 🛡️ PriVi-WireExplorer: Developed by PriViSecurity

![PriVi-WireExplorer Dashboard](PriVi-WireExplorer.PNG)

</div>

### Live Packet Forensic Interpreter & Network Analysis Tool
**Developed by Prince Ubebe | [PriViSecurity](https://github.com/Privis40)**

---

## ⚠️ Legal Notice

> **This tool is intended ONLY for use on networks you own or have explicit written authorization to monitor.**
> Unauthorized packet capture and analysis of network traffic you do not own is illegal under the Computer Misuse Act, the CFAA (Computer Fraud and Abuse Act), and equivalent laws worldwide.
> **PriViSecurity accepts no liability for unauthorized or malicious use of this tool.**

---

## What It Does

PriVi-WireExplorer is a live packet forensic interpreter that captures and analyzes network traffic in real time. It surfaces ARP spoofing, plaintext credential exposure, and protocol anomalies through a clean three-panel Rich terminal dashboard — making it practical for both blue team operations and security training environments.

It is designed for:
- Blue teamers and SOC analysts performing live LAN forensics
- Security trainers demonstrating why plaintext protocols (HTTP, FTP, Telnet) are dangerous
- Penetration testers monitoring traffic during authorized network assessments
- Students and researchers studying packet analysis in lab environments

---

## Features

| Feature | Description |
|---|---|
| 📡 Live Packet Capture | Real-time sniffing on any network interface |
| 🕵️ ARP Spoof Detection | Flags IPs seen with multiple MAC addresses — classic ARP poisoning indicator |
| 🏭 MAC Vendor Lookup | Background vendor resolution via macvendors API (rate-limited, cached) |
| 🔍 Deep Packet Inspection | String carving — extracts and highlights sensitive keywords in plaintext traffic |
| 🔑 Credential Keyword Alerts | Flags packets containing: user, pass, login, auth, token, cookie |
| 🌐 HTTP Detection Warning | Alerts on unencrypted HTTP traffic and explains the exposure risk |
| 🖥️ Three-Panel Rich Dashboard | Live packet feed, protocol stats, and alert stream in one view |
| 💾 Session Log Save | Save full session log to file with inline `save` command |
| 🔎 Live Filter | Filter displayed packets by keyword with inline `filter <keyword>` command |

---

## Requirements

```bash
pip install scapy rich requests
```

---

## Installation

```bash
git clone https://github.com/Privis40/PriVi-WireExplorer.git
cd PriVi-WireExplorer
pip install -r requirements.txt
```

---

## Usage

```bash
sudo python3 wire_explorer.py
```

Root is required for raw packet capture.

The tool will prompt for a network interface then launch the live dashboard automatically.

### Inline Commands

While the dashboard is running, type commands directly into the terminal:

| Command | Action |
|---|---|
| `filter <keyword>` | Filter displayed packets to those containing keyword |
| `filter` | Clear active filter — show all packets |
| `save` | Save current session log to a timestamped text file |
| `exit` | Gracefully terminate the session |

### Example Session

```
Interface: eth0

» 14:32:01 | TCP  192.168.1.10 → 93.184.216.34:80  [GET /login HTTP/1.1]
» 14:32:02 | ⚠ KEYWORD: 'password' detected in plaintext payload
» 14:32:05 | ARP SPOOF: 192.168.1.1 seen with new MAC — 00:11:22:33:44:55
» 14:32:08 | TCP  10.0.0.5 → 10.0.0.1:23  [Telnet — plaintext protocol]

filter login
[*] Filter active: 'login'
```

---

## Dashboard Layout

```
┌──────────────────────────────────────────────────────────────┐
│                    WireExplorer Header                        │
├───────────────────────────┬──────────────────────────────────┤
│   Live Packet Feed        │   Protocol Stats & Vendor Intel  │
├───────────────────────────┴──────────────────────────────────┤
│                    Alert Stream                               │
└──────────────────────────────────────────────────────────────┘
```

---

## Detection Logic

**ARP Spoof Detection**
Maintains an IP-to-MAC mapping table. When the same IP is observed with a new MAC address, it fires an alert in the alert stream. This is a reliable indicator of ARP cache poisoning or a rogue device.

**Deep Packet Inspection / String Carving**
Extracts printable strings from raw TCP/UDP payloads and scans for sensitive keywords: `user`, `pass`, `login`, `auth`, `token`, `cookie`. When found, the packet is flagged with the keyword highlighted. This is most impactful on plaintext protocols like HTTP, FTP, and Telnet — and makes an excellent live demonstration of why HTTPS matters.

**MAC Vendor Lookup**
Background thread resolves MAC OUI prefixes to vendor names via the macvendors.com API. Results are cached in memory and rate-limited to one request every 2 seconds to respect the API's limits.

---

## What This Tool Does NOT Do

- ❌ Does **not** inject or modify any network traffic
- ❌ Does **not** block or interfere with connections
- ❌ Does **not** store captured packets to disk automatically
- ❌ Does **not** transmit captured data to external servers

This is a **read-only, passive monitoring tool**.

---

## Tested On

- Kali Linux 2024+
- Ubuntu 22.04 / 24.04
- Python 3.10+

---

## Author & Brand

**Prince Ubebe**
Cybersecurity Analyst | Security Automation Engineer | Founder, PriViSecurity

- GitHub: [github.com/Privis40](https://github.com/Privis40)
- LinkedIn: [linkedin.com/in/prince-ubebe-291573321](https://www.linkedin.com/in/prince-ubebe-291573321)
- YouTube: [@princeubebecyber](https://youtube.com/@princeubebecyber)
- HackerOne / Bugcrowd: Active researcher

---

## License

This tool is released for **authorized security research and professional use only.**
Redistribution or modification for malicious purposes is strictly prohibited.

© 2026 PriViSecurity. All rights reserved.
