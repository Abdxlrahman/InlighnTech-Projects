# 🛡️ Cybersecurity Internship Portfolio — InlighnTech

<div align="center">

![Cybersecurity](https://img.shields.io/badge/Domain-Defensive%20Cybersecurity-blue?style=for-the-badge&logo=shield)
![Projects](https://img.shields.io/badge/Projects-10%20Completed-success?style=for-the-badge)
![Internship](https://img.shields.io/badge/Internship-InlighnTech-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

**A complete portfolio of 10 hands-on defensive cybersecurity projects completed during a professional internship at InlighnTech.**

*Covering Endpoint Security · Network Forensics · Malware Analysis · Web Pentesting · Threat Hunting · Incident Response · SOC Engineering*

</div>

---

## 📂 Repository Structure

| # | Project | Domain | Key Tools |
|---|---------|--------|-----------|
| 01 | [Endpoint Security Hardening](./Project%201%20-%20Endpoint-Security-Hardening/) | Endpoint Security | PowerShell, CIS Benchmarks, GPO |
| 02 | [Wireless Security Audit](./Project%202%20-%20Wireless-Security-Audit/) | Wireless Security | Kali Linux, Wireshark, aircrack-ng |
| 03 | [Malware Investigation](./Project%203%20-%20Malware-Investigation-Project/) | Malware Analysis | VirusTotal, Event Viewer, Netstat |
| 04 | [Network Traffic Analysis](./Project%204%20-%20Network-Traffic-Analysis/) | Network Forensics | Wireshark, Python, PCAP |
| 05 | [Web Security Assessment](./Project%205%20-%20Web-Security-Assessment/) | Web Pentesting | Burp Suite, OWASP Top 10, DVWA |
| 06 | [Log Analysis & SIEM](./Project%206%20-%20Log-Analysis-Project/) | SIEM Engineering | Python, syslog, Custom Dashboard |
| 07 | [Threat Hunting](./project_7_threat_hunting/) | Threat Intelligence | MITRE ATT&CK, Linux Logs |
| 08 | [Malware Traffic Analysis](./Project%208%20-%20Malware-Traffic-Analysis/) | Network Forensics | Wireshark, DPI, PCAPNG |
| 09 | [Incident Response](./Project%209%20-%20Incident-Response-Project/) | Incident Response | NIST IR Lifecycle, Python |
| 10 | [Mini SOC Lab](./Project%2010%20-%20Build%20a%20mini%20security%20operation%20centre%20(SOC)%20Lab/) | SOC Engineering | ELK Stack, Elastic Agent, Hydra, KQL |

---

## 🎯 Project Highlights

### 🔐 Project 1 — Endpoint Security Hardening
Applied CIS Benchmarks to harden a Windows 11 endpoint. Disabled legacy protocols, enforced security policies via Group Policy, and automated the entire process using custom PowerShell scripts. Produced a risk reduction report documenting every control applied.

### 📡 Project 2 — Wireless Network Security Audit
Conducted a full wireless infrastructure audit to detect rogue access points, Evil Twin networks, and weak encryption configurations. Delivered a CVSS-scored professional penetration test report with actionable remediation.

### 🦠 Project 3 — Malware Detection & Investigation
Simulated a SOC Tier-2 malware investigation on Windows 11. Analyzed running processes, Event Logs, and network connections. Submitted file hashes to VirusTotal and documented findings aligned to the NIST Cybersecurity Framework.

### 🌐 Project 4 — Network Traffic Analysis
Captured and dissected live multi-protocol packets using Wireshark. Built a custom zero-dependency Python PCAP/PCAPNG parser to automate forensic extraction of IPs, ports, and payloads. Identified plaintext credential transmissions and suspicious DNS patterns.

### 🕸️ Project 5 — Web Application Security Assessment
Executed a full OWASP Top 10 penetration test against a vulnerable web application (DVWA). Identified SQL Injection, XSS, CSRF, IDOR, and Broken Access Control vulnerabilities. Delivered a professional pentest report with CVSS v3.1 scoring.

### 📊 Project 6 — Log Analysis & SIEM-Based Threat Detection
Built a custom Python SIEM console ("Aegis Console") to ingest and analyze Linux logs. Reconstructed a full APT attack lifecycle (brute force → privilege escalation → persistence) and produced a formal incident report with NIST-aligned hardening guidelines.

### 🔍 Project 7 — Proactive Threat Hunting
Proactively hunted attacker dwell-time behaviors in Linux system telemetry. Mapped all adversarial techniques to the MITRE ATT&CK framework including T1110 (Brute Force), TA0004 (Privilege Escalation), T1105 (Ingress Tool Transfer), and TA0011 (C2).

### 🔬 Project 8 — Malware Traffic Analysis
Performed Level-2 SOC forensic analysis on PCAPNG captures. Used Wireshark Deep Packet Inspection to detect C2 beaconing, DNS tunneling artifacts, and extract network-level Indicators of Compromise (IoCs).

### 🚨 Project 9 — Incident Response Simulation
Executed a complete incident response lifecycle (Detection → Containment → Eradication → Recovery → Post-Incident Review) for an advanced SSH compromise scenario. Produced a formal incident report with attack timeline, IoC list, and lessons learned.

### 🏢 Project 10 — Mini Security Operations Centre (SOC) Lab
Designed and deployed a full virtualized SOC environment using VirtualBox. Installed Elasticsearch 8.19.17 and Kibana, deployed a standalone Elastic Agent to ingest live authentication logs, simulated SSH brute-force attacks from Kali Linux using THC-Hydra, and investigated threats using KQL queries in Kibana. Delivered MITRE ATT&CK-mapped detection rules, Python automation scripts, and a complete SOC engineering report.

---

## 🛠️ Technologies & Tools Used

| Category | Tools |
|----------|-------|
| **Operating Systems** | Windows 11, Ubuntu Linux, Kali Linux |
| **SIEM & Log Management** | Elasticsearch, Kibana, Custom Python SIEM |
| **Network Analysis** | Wireshark, PCAP/PCAPNG, aircrack-ng |
| **Web Security** | Burp Suite, DVWA, OWASP Top 10 |
| **Scripting & Automation** | Python 3.8+, PowerShell, Bash |
| **Attack Simulation** | THC-Hydra, Nmap, Metasploit |
| **Frameworks & Standards** | MITRE ATT&CK, NIST CSF, CIS Benchmarks, CVSS v3.1 |
| **Virtualization** | VirtualBox, NAT Networking, Port Forwarding |

---

## 📈 Learning Outcomes

After completing all 10 projects, the following professional competencies were developed:

- ✅ Configuring and hardening enterprise endpoints to CIS compliance standards
- ✅ Conducting professional wireless and web application penetration tests
- ✅ Performing malware analysis and digital forensic investigations
- ✅ Building and operating a fully functional SIEM threat detection pipeline
- ✅ Proactively hunting advanced threats using the MITRE ATT&CK framework
- ✅ Executing end-to-end incident response engagements
- ✅ Engineering a complete Security Operations Center (SOC) from scratch

---

## 👤 Author

**Cybersecurity Intern — InlighnTech**
*Defensive Cybersecurity | Blue Team Operations | SOC Engineering*

---

<div align="center">

*This repository was completed as part of a professional cybersecurity internship program at InlighnTech.*

</div>
