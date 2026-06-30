# Network Traffic Audit & Threat Detection System (Wireshark & Python)

[![GitHub License](https://img.shields.io/github/license/abdxl/Network-Traffic-Analysis?style=for-the-badge&color=blue)](LICENSE)
[![Cybersecurity Focus](https://img.shields.io/badge/Security-Blue_Team-navy?style=for-the-badge&logo=shield)](https://github.com/abdxl)
[![Python Version](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Tool Used](https://img.shields.io/badge/Tool-Wireshark_4.x-005B96?style=for-the-badge&logo=wireshark)](https://www.wireshark.org/)

This repository documents a comprehensive, low-level network traffic audit and forensic threat detection exercise completed as part of the Defensive Cybersecurity (Blue Team) Internship at **InlighnTech**. 

The project demonstrates packet-level protocol auditing, plaintext risk identification, DNS query monitoring, and local subnet security validation using a combination of **Wireshark** and a custom **zero-dependency Python PCAP/PCAPNG parser**.

---

## 🛠️ Lab Environment & Infrastructure

- **Operating System:** Windows 11 Home (Samsung Galaxy Book 4)
- **Interface Monitored:** Intel Wi-Fi 6E AX211 Wireless Adapter
- **Capture Engine:** Wireshark v4.6.6 with Npcap driver
- **Threat Intelligence:** OSINT Lookups (VirusTotal API, WHOIS, AbuseIPDB)
- **Execution Script:** `scripts/pcap_analyzer.py` (Pure Python 3, zero third-party requirements)

---

## 📁 Repository Folder Structure

```text
Network-Traffic-Analysis/
├── .gitignore                       # Rules for ignoring local OS and Office caches
├── README.md                        # Master documentation and landing page
├── analysis_results/
│   └── suspicious_ip_list.txt       # Threat Intelligence & IOC Registry
├── packet_captures/
│   └── traffic_capture.pcapng       # Active raw packet log (4,307 Packets)
├── scripts/
│   └── pcap_analyzer.py             # Custom low-level PCAP/PCAPNG parsing tool
├── screenshots/
│   ├── wireshark_startup.png        # System interfaces verification
│   ├── protocol_hierarchy.png       # Captured protocol breakdown
│   ├── http_analysis.png            # Plaintext GET session captures
│   ├── dns_analysis.png             # Query logging captures
│   └── arp_analysis.png             # Local network resolution integrity
└── reports/
    ├── premium_report.html          # High-end printable executive HTML report
    └── traffic_analysis_report.md   # Markdown version of forensic audit findings
```

---

## 🔍 Custom Parser Utility (`scripts/pcap_analyzer.py`)

To verify forensic scale, a custom, low-level Python script was developed to decode raw packet captures without relying on heavy third-party libraries (such as `scapy` or `pyshark`). 

### Key Capabilities:
- Parses both classic **PCAP** and **PCAPNG** global and block headers.
- Decodes Ethernet, IPv4, IPv6, TCP, and UDP layer structures using the native `struct` library.
- Extracts all domain queries requested on UDP Port 53 (DNS).
- Logs and alerts on unencrypted HTTP GET/POST headers on TCP Port 80.
- Collects and lists all contacted external host IP addresses for OSINT mapping.

### How to Run:
Ensure you are in the project root directory, then execute the command:
```cmd
python scripts/pcap_analyzer.py packet_captures/traffic_capture.pcapng
```

### Script Execution Sample Output:
```text
[00:36:45] INFO - Opening network capture file: traffic_capture.pcapng
[00:36:45] INFO - Format detected: PCAP Next Generation (PCAPNG)
============================================================
         INLIGHNTECH NETWORK TRAFFIC ANALYSIS REPORT
============================================================
Target PCAP File:     traffic_capture.pcapng
Total Packets Read:   4307
IPv4 Packets:         729
IPv6 Packets:         1465
TCP Conversations:    1830
UDP Conversations:    342
------------------------------------------------------------
[*] OSINT Target IP Discoveries:
  [+] External Host Connected: 184.28.23.154
  [+] External Host Connected: 172.66.147.243
  ...
[*] DNS Domain Resolution Queries:
  [+] Domain Queried: example.com
  [+] Domain Queried: edge.microsoft.com
  ...
[!] Plaintext HTTP (Port 80) Transmissions:
  [!] HTTP Session Alert from IPv6 to IPv6:
      Request Path: GET /r/r1.crl HTTP/1.1
============================================================
```

---

## 🚨 Key Cybersecurity Audit Findings

### 1. Plaintext HTTP Session Detection (Severity: LOW | CVSS:3.1 Base Score 3.5)
- **Vulnerability:** Transmission of Certificate Revocation Lists (CRL) and test assets via unencrypted HTTP (Port 80).
- **PoC:** Active `GET /r/r1.crl` queries to Google/DigiCert registries and `GET /` to `example.com` logged in plain ASCII.
- **Risk Assessment:** Open to local-link sniffing, credential harvesting, or Man-in-the-Middle (MITM) session modification.

### 2. DNS Query Hygiene Verification (Severity: NONE | Clean Baseline)
- **Assessment:** Zero anomalies detected. Resolved hosts checked out as clean CDN services (Akamai, Cloudflare). No indicators of covert channels, DNS-based tunneling, or Domain Generation Algorithms (DGA).

### 3. Local Routing Stability (Severity: NONE | Clean Baseline)
- **Assessment:** Dynamic ARP mapping validated. Address resolution broadcasts checked out clean with no gateway IP conflicts, ruling out active MAC spoofing or local cache poisoning.

---

## 🔒 Remediation & Hardening Blueprint (NIST CSF Mapped)

1. **Enforce HTTPS (PR.DS-1):** Implement HTTP Strict Transport Security (HSTS) headers across all systems.
2. **Secure DNS Communications (PR.DS-5):** Set client host resolvers to use DNS over HTTPS (DoH) or DNS over TLS (DoT) to prevent resolution sniffing.
3. **Configure Local Switch Security (PR.PT-4):** Deploy Dynamic ARP Inspection (DAI) on switch access ports to block unauthorized ARP spoofing replies.

---

## 🎓 Key Learning Outcomes

1. **Forensics:** Mastering frame structure decodings across Layer 2 (Ethernet), Layer 3 (IP), Layer 4 (TCP/UDP), and Layer 7 (HTTP/DNS).
2. **Network Defenses:** Understanding the severity of plain-text protocols and identifying indicators of network compromise.
3. **Low-level Automation:** Implementing binary file parsers using standard byte unpacking methods to speed up SOC investigations.

---

## 👤 Author Section

- **Name:** abdxl
- **Internship Project:** Project 4 for Blue Team Cybersecurity Pathway
- **Organization:** InlighnTech
- **Date:** June 15, 2026
