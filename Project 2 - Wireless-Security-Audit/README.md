<div align="center">
  <img src="https://img.shields.io/badge/Cybersecurity-Defensive_Security-blue?style=for-the-badge&logo=security" alt="Cybersecurity">
  <img src="https://img.shields.io/badge/Audit-Wireless_Network-orange?style=for-the-badge&logo=wifi" alt="Audit">
  <img src="https://img.shields.io/badge/Status-Completed-success?style=for-the-badge" alt="Status">
</div>

# Wireless Network Security Audit & Rogue Access Point Detection 🛡️

A comprehensive, enterprise-grade Defensive Cybersecurity Project focused on evaluating the security posture of local wireless infrastructure. This project demonstrates practical methodologies for identifying vulnerabilities, monitoring unencrypted wireless traffic, and mapping local network topologies to detect unauthorized entities (Rogue Access Points / Evil Twins).

---

## 📑 Table of Contents
- [Project Overview](#-project-overview)
- [Architecture & Methodology](#-architecture--methodology)
- [Key Features & Objectives](#-key-features--objectives)
- [Technologies & Tools Used](#-technologies--tools-used)
- [Folder Structure](#-folder-structure)
- [Installation & Usage Guide](#-installation--usage-guide)
- [Security Findings & CVSS Scoring](#-security-findings--cvss-scoring)
- [Future Improvements](#-future-improvements)
- [Learning Outcomes](#-learning-outcomes)
- [Author](#-author)

---

## 📖 Project Overview
Organizations rely heavily on wireless networks for daily operations, but these networks are frequently targeted by threat actors exploiting weak configurations (such as WEP/WPA fallback) to perform Man-in-the-Middle (MitM) attacks or packet sniffing.

This project replicates a real-world **Blue Team security assessment**. It systematically audits local networks to verify encryption standards, discovers connected endpoints, intercepts traffic to test for plain-text exposure, and provides a professional vulnerability report mapped to industry standards (NIST, CVSS).

---

## 🏗️ Architecture & Methodology
The assessment follows a structured 3-phase methodology:
1. **RF Reconnaissance:** Passive signal interception to catalog surrounding SSIDs, BSSIDs, and their cryptographic implementations.
2. **Topology Mapping:** Executing ARP/ICMP sweeps on the local subnet to footprint active endpoints and detect disguised unauthorized hardware.
3. **Deep Packet Inspection (DPI):** Intercepting `wlan0` traffic promiscuously to analyze DNS telemetries and application-layer payloads for unencrypted data leakage.

---

## 🎯 Key Features & Objectives
- **Cryptographic Auditing:** Identification of outdated encryption protocols (WEP, WPA-TKIP).
- **Rogue AP Detection:** Mapping BSSIDs and comparing routing tables to locate Evil Twin attacks.
- **Traffic Interception:** Capturing standard TCP handshakes and unencrypted HTTP payloads via `.pcap` forensics.
- **Enterprise Reporting:** Generation of an Executive Security Report complete with CVSS v3.1 severity scores and NIST remediation guidelines.

---

## 🛠️ Technologies & Tools Used
- **Network Discovery:** Nmap, Command-line ARP (`arp -a`)
- **Wireless Scanning:** NetSpot, Airodump-ng (Aircrack-ng suite)
- **Packet Analysis:** Wireshark
- **Reporting:** Markdown, HTML/CSS for enterprise PDF generation

---

## 📂 Folder Structure
```text
Wireless-Security-Audit/
├── reports/
│   ├── wireless_security_audit_report.md     # Professional Markdown Report
│   ├── wireless_security_audit_report.html   # Styled HTML Report (Printable to PDF)
│   └── Wireless Security Audit Report.pdf    # Final Executive Deliverable
├── scans/
│   └── wifi_network_scan.txt                 # Raw output of RF reconnaissance
├── screenshots/
│   ├── screenshot_1_wifi_scan.png.png
│   ├── screenshot_2_device_discovery.png.png
│   └── screenshot_3_wireshark_capture.png.png
├── traffic_analysis/
│   └── packet_captures/
│       └── traffic_capture.pcap              # Raw intercepted network traffic
└── README.md                                 # Project documentation
```

---

## 🚀 Installation & Usage Guide

### Prerequisites
- Wireshark installed with Npcap (for Windows)
- NetSpot (or Kali Linux VM with `airodump-ng` configured)
- Nmap installed or native CLI access

### Step-by-Step Execution
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/Wireless-Security-Audit.git
   cd Wireless-Security-Audit
   ```
2. **Run Wireless Reconnaissance:**
   - Launch NetSpot to map surrounding networks.
   - Export the results to `scans/wifi_network_scan.txt`.
3. **Discover Local Endpoints:**
   - Open Command Prompt and execute an ARP sweep:
     ```bash
     arp -a
     # OR via nmap
     nmap -sn 192.168.1.0/24
     ```
4. **Intercept Wireless Traffic:**
   - Launch Wireshark and bind to your Wi-Fi interface.
   - Capture traffic for 1-2 minutes, focusing on DNS and HTTP filters.
   - Save the payload as `.pcap` in `traffic_analysis/`.
5. **Review the Security Report:**
   - Open `reports/wireless_security_audit_report.html` in your browser to view the finalized vulnerability findings.

---

## 🔒 Security Findings & CVSS Scoring

| Finding | Severity | CVSS v3.1 Score | Mitigation |
|---------|----------|-----------------|------------|
| **Legacy Protocol Support (WPA/WPA2 Mixed Mode)** | Medium | `5.4` (AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N) | Disable TKIP fallback; enforce WPA2-AES or WPA3-SAE strictly. |
| **Unencrypted HTTP/DNS Telemetry** | Low | `3.1` (AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N) | Enforce HSTS and DNS-over-HTTPS (DoH) locally. |

*(Refer to the full PDF report in `/reports` for detailed Root Cause and Business Impact analysis).*

---

## 🔮 Future Improvements
- **Automated Deauthentication Testing:** Utilizing `aireplay-ng` to test client resilience against deauth attacks.
- **WIDS Implementation:** Integrating Snort or Zeek to automatically flag Rogue APs via MAC spoofing heuristics.
- **Credential Cracking Simulation:** Capturing a 4-way WPA handshake and performing an offline dictionary attack using `hashcat` to evaluate password strength.

---

## 🧠 Learning Outcomes
- Practical application of Open Systems Interconnection (OSI) Data Link (Layer 2) and Network (Layer 3) analysis.
- Understanding of cryptographic degradation and downgrade attacks in enterprise environments.
- Proficiency in parsing `.pcap` files for forensic investigation.
- Structuring professional Penetration Testing / Vulnerability Assessment reports aligned with industry standards.

---

## 👤 Author
**Cybersecurity Analyst / Penetration Tester**  
*(Demonstrating 3-5 Years of Technical Proficiency in Defensive Security Auditing)*

---
<div align="center">
  <i>"Securing the invisible layer of the digital infrastructure."</i>
</div>
