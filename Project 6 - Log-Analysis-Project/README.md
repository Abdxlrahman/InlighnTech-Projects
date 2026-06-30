# Project 6: Log Analysis & SIEM-Based Threat Detection

[![Status](https://img.shields.io/badge/Status-Complete-green.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](#)
[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](#)
[![Framework](https://img.shields.io/badge/SIEM-Aegis%20Console-purple.svg)](#)

This project demonstrates core competencies in Log Management, Automated Threat Hunting, SIEM Visualization, Incident Reconstruction, and Security Analysis in a Security Operations Center (SOC) simulation environment. It models an advanced persistent threat (APT) scenario targeting a Linux system via SSH brute forcing, leading to a successful account compromise, privilege escalation, and persistence establishment.

## 📖 Table of Contents
- [Project Overview](#-project-overview)
- [Architecture & Workflow](#-architecture--workflow)
- [Interactive SIEM Dashboard](#-interactive-siem-dashboard)
- [Key Features](#-key-features)
- [Project Structure](#-project-structure)
- [Setup & Usage Guide](#-setup--usage-guide)
- [Security Incident Findings Summary](#-security-incident-findings-summary)
- [NIST Alignment & Hardening Guidelines](#-nist-alignment--hardening-guidelines)
- [Learning Outcomes](#-learning-outcomes)
- [License](#-license)

---

## 🔍 Project Overview

In this project, a Linux workstation log parser and a real-time visualization interface were built to parse standard `/var/log/auth.log` records. The analysis chain automatically identifies brute-force patterns, alerts on privilege escalation, reports Indicators of Compromise (IoCs) in both human-readable and JSON format (for ingestion into larger SIEMs like Splunk or ELK), and renders an interactive Cyberpunk-themed local SIEM dashboard.

### Scenario Details
- **Phase 1: Internal Reconnaissance:** Slow brute force targeting `root` from an internal address (`192.168.1.150`).
- **Phase 2: External Credential Stuffing:** High-velocity brute force (80 failed attempts in < 5 mins) from external IP `203.0.113.5`.
- **Phase 3: Compromise:** Attacker succeeds on username `support`.
- **Phase 4: Privilege Escalation:** Sudo policy bypass attempt, culminating in spawning root bash shell (`sudo /bin/bash`).
- **Phase 5: Persistence:** Creation of backdoor account (`backuser`) with UID 1003.

---

## 🛠 Architecture & Workflow

```
+------------------+      +-----------------------+      +-------------------------+
|                  |      |                       |      |                         |
|  generate_logs   | ---> |    collected_logs/    | ---> |      log_analyzer       |
|  (Simulates SSH  |      |     auth_logs.txt     |      |  (Automated Syslog      |
|   Attacks)       |      |                       |      |   Security Parsing)     |
|                  |      +-----------------------+      +-------------------------+
+------------------+                                                  |
                                                                      v
                                                    +----------------------------------+
                                                    | Outputs:                         |
                                                    | - suspicious_login_attempts.txt  |
                                                    | - ioc_report.json                |
                                                    | - dashboard/log_data.js          |
                                                    +----------------------------------+
                                                                      |
                                                                      v
                                                         +-------------------------+
                                                         |  Aegis SIEM Web Console |
                                                         |  (Interactive visual    |
                                                         |   Charts & log feeds)   |
                                                         +-------------------------+
```

---

## 💻 Interactive SIEM Dashboard

The Aegis SIEM Dashboard is a single-page visual analytics workspace written in HTML5, CSS3, and JavaScript utilizing Chart.js for data visualization.

- **KPI Metrics Panel**: Live counters for total logs, failed logins, success logins, and critical incidents.
- **Visual Charts**: Login attempt volume trends over time and a doughnut chart showing the failed-to-success authentication ratio.
- **Incident Feed**: Dynamic panel highlighting critical events, e.g. unauthorized sudo command executions.
- **Log Explorer Terminal**: Color-coded CLI terminal allowing filters on all logs, sudo actions, and failed logins.

---

## ✨ Key Features

- **Automated Security Log Parser**: Configurable via JSON config to check custom brute-force thresholds and watched users.
- **Hypothesis-Driven Threat Hunting**: Built-in `threat_hunter.py` utility targeting off-hours activity, minute-level request spikes, and user probing scans.
- **CVSS Score Integration**: Dynamic risk categorization (Critical, High, Medium, Low) following CVSS standard metrics.
- **Zero-Dependency Core Run**: Python scripts rely completely on standard libraries.

---

## 📂 Project Structure

```
Project 6 - Log-Analysis-Project/
├── configs/
│   └── analyzer_config.json               # Centralized thresholds & watched command configs
├── collected_logs/
│   └── auth_logs.txt                     # Synthetic syslog authentication logs source
├── analysis_results/
│   ├── suspicious_login_attempts.txt     # Human-readable Incident Response Report
│   ├── ioc_report.json                   # Machine-readable JSON IoC details
│   └── threat_hunt_report.txt            # Advanced threat hunt hypothesis output
├── scripts/
│   ├── generate_logs.py                  # Syslog simulation scenario builder
│   ├── log_analyzer.py                   # Parsing engine & main incident generator
│   └── threat_hunter.py                  # Hypothesis-based threat query script
├── dashboard/
│   ├── index.html                        # Interactive SIEM Web Console UI
│   ├── styles.css                        # Cyberpunk dark mode styling sheet
│   ├── app.js                            # Parsing, chart handling, and table filters
│   └── log_data.js                       # Auto-generated JS log data export
├── reports/
│   ├── Log_Analysis_Security_Report.md   # Final Security Investigation Markdown Report
│   ├── Log_Analysis_Security_Report.html # Premium styled HTML version of report
│   └── Log_Analysis_Security_Report.pdf  # Final PDF report export
├── .gitignore                            # Python/OS workspace ignore rules
├── requirements.txt                      # Environment dependencies document
└── README.md                             # Repository homepage and instructions
```

---

## 🚀 Setup & Usage Guide

### Prerequisites
- Python 3.8 or higher installed on your system.
- Standard web browser (Chrome, Firefox, Safari, Edge).

### Running the Analysis Pipeline

1. **Step 1: Clone the Repository & Setup Workspace**
   ```bash
   git clone https://github.com/yourusername/log-analysis-project.git
   cd log-analysis-project
   ```

2. **Step 2: Generate the Simulated Logs**
   Run the generator script to create the synthetic `auth_logs.txt` target file inside `/collected_logs/`.
   ```bash
   python scripts/generate_logs.py
   ```

3. **Step 3: Run the Security Log Analyzer**
   Analyze the logs to output alerts, IoC reports, and JS exports.
   ```bash
   python scripts/log_analyzer.py --json
   ```

4. **Step 4: Run the Advanced Threat Hunter**
   Verify the hypotheses regarding off-hours and high-frequency spike metrics.
   ```bash
   python scripts/threat_hunter.py
   ```

5. **Step 5: View the Visual Dashboard**
   Open `dashboard/index.html` in any web browser to view the visual console.

---

## 📊 Security Incident Findings Summary

Based on logs processed on **June 21, 2026**, the system flagged a high-severity security incident:

| Finding | Metric/Detail | Risk Rating | Recommendation |
|---|---|---|---|
| **Brute Force (External)** | IP `203.0.113.5` (80 failed attempts) | 🔴 CRITICAL | Perimeter Firewall Ingress Block |
| **Brute Force (Internal)** | IP `192.168.1.150` (12 failed attempts) | 🟡 MEDIUM | Isolate & scan target workstation |
| **System Compromise** | Account `support` logged in from external IP | 🔴 CRITICAL | Disable account, rotate SSH keys |
| **Privilege Escalation** | `support` executed `/bin/bash` via sudo | 🔴 CRITICAL | Audit `/etc/sudoers` privilege levels |
| **Backdoor Creation** | Persistence user `backuser` created | 🔴 CRITICAL | Run `userdel -r backuser` immediately |

---

## 🔒 NIST Alignment & Hardening Guidelines

Our remediation guidelines map directly to the **NIST Cybersecurity Framework (CSF)**:

### 1. Identify & Protect
- **SSH Hardening**: Enforce `PasswordAuthentication no` in `/etc/ssh/sshd_config` to force cryptographic keys. Disable direct root log-in via `PermitRootLogin no`.
- **Sudoers Auditing**: Restrict root-level command shells by removing permissive user sudo entries.

### 2. Detect & Respond
- **Fail2ban Integration**: Set up connection bans for IPs exhibiting more than 5 failed connection attempts within a minute.
- **Log Management**: Forward auth logs to centralized log systems using secure rsyslog forwarding.

---

## 🎓 Learning Outcomes
- Hands-on experience in syslog format parsing using regular expressions.
- Automated extraction of Indicators of Compromise (IoCs).
- Building visual metrics dashboards using native JS charts.
- Implementation of threat hunting strategies conforming to NIST security templates.

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
