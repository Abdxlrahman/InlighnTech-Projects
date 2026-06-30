# 🛡️ Cybersecurity Incident Response Simulation

![Cybersecurity Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)
![Security Level](https://img.shields.io/badge/Security-Level_9_Advanced-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

## 📖 Project Overview
This repository contains a comprehensive **Cybersecurity Incident Response Simulation** developed as part of a professional cybersecurity internship. The project meticulously simulates a real-world enterprise cyberattack, demonstrating the full incident response lifecycle from initial detection to containment and remediation.

The simulation specifically models an advanced threat actor exploiting an SSH brute-force vulnerability to gain unauthorized access, deploy a malicious payload, and establish a persistent Command and Control (C2) connection.

## 🎯 Objectives & Scope
- **Detect** and analyze unauthorized access attempts within system logs.
- **Identify** Indicators of Compromise (IoCs) including malicious IPs, domains, and file hashes.
- **Reconstruct** a minute-by-minute timeline of the attack vector.
- **Implement** industry-standard containment protocols (Network isolation, Process termination).
- **Draft** a professional-grade Incident Response Report for executive and technical stakeholders.

## 🏗️ Architecture & Technologies Used
The investigation was conducted using simulated Linux (Ubuntu) server logs and network analysis tools.
- **Log Analysis**: Syslog, Auth.log (`grep`, `tail`, `awk`)
- **Network Monitoring**: `netstat`, simulated Wireshark traffic analysis
- **Threat Intelligence**: IP reputation analysis (simulated), OSINT
- **Documentation**: Markdown, HTML/CSS for professional PDF reporting

## 📂 Folder Structure
```text
Project 9 - Incident-Response-Project/
├── 📁 indicators/
│   └── ioc_list.txt                  # Extracted Indicators of Compromise (IPs, Hashes)
├── 📁 logs/
│   └── system_logs.txt               # Simulated authentication and system execution logs
├── 📁 network_analysis/
│   └── suspicious_connections.txt    # Network state captures showing C2 beacons
├── 📁 reports/
│   └── incident_response_report.html # Final highly-formatted executive report
└── 📄 README.md                      # Project documentation
```

## 🔍 Key Security Findings
1. **Initial Access**: Brute-force attack successful against the `root` account originating from `192.168.1.105`.
2. **Execution**: Unauthorized execution of `wget` to pull `/tmp/sysupdate` (Hash: `e59ff97941044f85df5297e1c302d260`).
3. **Command & Control (C2)**: Outbound persistence established to `203.0.113.50` over TCP port 443.
4. **Persistence**: Creation of rogue backdoor account `support_admin` added to the `sudo` group.

## 🛠️ Usage & Installation Steps
To review the evidence and the final report:
1. Clone this repository: `git clone https://github.com/yourusername/Incident-Response-Project.git`
2. Navigate to the logs: `cd Incident-Response-Project/logs`
3. Analyze the system logs: `cat system_logs.txt | grep "Failed password"`
4. Review the final report: Open `reports/incident_response_report.html` in any modern web browser to view the professionally formatted output (can be saved as PDF).

## 🎓 Learning Outcomes
- Mastery of the **NIST Incident Response Lifecycle** (Preparation, Detection & Analysis, Containment, Eradication & Recovery, Post-Incident Activity).
- Practical experience in log parsing and IoC extraction.
- Professional technical writing and executive reporting skills.

## 👤 Author
**Abdxl**
*Cybersecurity Intern | SOC Analyst*

---
*Disclaimer: All IP addresses, domains, and hashes in this project are simulated for educational purposes and do not represent actual live threats.*
