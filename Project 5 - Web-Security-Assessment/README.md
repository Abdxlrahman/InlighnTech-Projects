# 🛡️ Web Application Security Assessment & Vulnerability Detection

> **Project 5 — Cybersecurity Internship Deliverable**
> Comprehensive web application security assessment performed against a DVWA-equivalent target application using industry-standard penetration testing methodology, OWASP Top 10 framework, and professional documentation standards.

---

## 📋 Table of Contents

1. [Project Overview](#-project-overview)
2. [Features](#-features)
3. [Architecture & Methodology](#-architecture--methodology)
4. [Technologies & Tools Used](#-technologies--tools-used)
5. [Folder Structure](#-folder-structure)
6. [Quick Start — Running the Lab](#-quick-start--running-the-lab)
7. [Vulnerability Modules](#-vulnerability-modules)
8. [Security Findings Summary](#-security-findings-summary)
9. [Evidence Screenshots](#-evidence-screenshots)
10. [Remediation Roadmap](#-remediation-roadmap)
11. [OWASP & Industry Compliance](#-owasp--industry-compliance)
12. [Learning Outcomes](#-learning-outcomes)
13. [Future Improvements](#-future-improvements)
14. [Author](#-author)
15. [Disclaimer](#-disclaimer)

---

## 🎯 Project Overview

This repository contains the complete deliverables for **Project 5: Web Application Security Assessment & Vulnerability Detection**, completed as part of a Cybersecurity Analyst Internship program.

The objective of this engagement was to simulate the perspective of an entry-level web application penetration tester and blue team analyst — identifying critical application security vulnerabilities, producing documented proof-of-concept exploits, and delivering professional-grade remediation recommendations aligned with industry frameworks.

### Assessment Target

A custom **Python-based vulnerable web application** (`app.py`) was engineered to simulate a DVWA (Damn Vulnerable Web Application) equivalent environment, enabling hands-on testing of all vulnerability classes without requiring Docker or external infrastructure.

The application supports a **dual security mode toggle**:
- **🔴 LOW (Vulnerable)** — All vulnerability vectors are active for attack demonstration
- **✅ SECURE (Protected)** — Defensive controls are enabled to demonstrate remediation in action

---

## ✨ Features

| Feature | Details |
|---------|---------|
| 🔬 **5 Vulnerability Modules** | SQLi, Reflected XSS, Stored XSS, Brute Force Auth, Session Mgmt |
| 🔄 **Live Security Toggle** | Switch between vulnerable and secure mode in real time |
| 🛡️ **Secure Mode Demos** | Parameterized queries, HTML encoding, rate limiting, secure cookies |
| 📊 **Professional Reports** | Executive HTML report (PDF-ready) + Markdown technical report |
| 🖼️ **Full Evidence Suite** | 9 screenshots covering all testing phases (01–09) |
| 📄 **4 Vulnerability Findings** | Detailed disclosure reports with CWE/WSTG/CVSS references |
| 🔍 **Scan Artifacts** | Nmap network scan + OWASP ZAP automated scan summaries |
| 📋 **Zero Dependencies** | Pure Python 3 standard library — no pip installs required |

---

## 🏗️ Architecture & Methodology

### Assessment Methodology

```
┌─────────────────────────────────────────────────────────────────┐
│            WEB APPLICATION SECURITY ASSESSMENT FLOW             │
└─────────────────────────────────────────────────────────────────┘

Phase 1: Reconnaissance & Environment Setup
    ├── Network port scan (Nmap -sV -sS)
    ├── Technology fingerprinting (Apache, Python HTTP Server)
    └── Application entry-point mapping (forms, parameters, cookies)

Phase 2: Traffic Interception & Analysis
    ├── HTTP proxy configuration (Burp Suite / Browser DevTools)
    ├── Request/Response header inspection
    └── Cookie attribute audit (HttpOnly, Secure, SameSite)

Phase 3: Vulnerability Testing & Exploitation
    ├── SQL Injection — ' OR 1=1 -- (union-based, error-based)
    ├── Reflected XSS — <script>alert('XSS')</script>
    ├── Stored XSS   — Guestbook persistent script injection
    ├── Brute Force  — Automated credential dictionary attack
    └── Session Mgmt — Cookie flag inspection & hijack chain

Phase 4: Automated Scanning
    ├── OWASP ZAP active + passive scan (14 alerts)
    └── Nmap service version detection

Phase 5: Documentation & Reporting
    ├── 4x Individual finding reports (VULN-01 to VULN-04)
    ├── Nmap & ZAP scan artifacts
    ├── 9x Evidence screenshots (01_env to 09_zap)
    ├── Markdown technical report (web_security_report.md)
    └── Executive HTML/PDF report (executive_security_report.html)
```

### Application Architecture

```
app.py (Python HTTP Server — Port 8080)
├── VulnerableAppHandler (BaseHTTPRequestHandler)
│   ├── do_GET()  → Routes all GET requests
│   ├── do_POST() → Handles guestbook POST
│   └── Module Handlers:
│       ├── handle_dashboard()      → /
│       ├── handle_sqli()           → /sqli
│       ├── handle_xss_reflected()  → /xss_r
│       ├── handle_xss_stored()     → /xss_s
│       ├── handle_xss_stored_post()→ /xss_s_post (POST)
│       ├── handle_brute()          → /brute
│       └── handle_session_info()   → /session_info
├── Security Helpers
│   ├── sanitize_output()     → HTML entity encoding (SECURE mode)
│   ├── is_rate_limited()     → IP-based lockout check
│   ├── record_failed_login() → Failed attempt tracker
│   ├── build_secure_cookie_headers()   → HttpOnly + SameSite
│   └── build_insecure_cookie_headers() → No flags (LOW mode)
└── main() → Server startup with structured logging
```

---

## 🛠️ Technologies & Tools Used

### Core Application
| Technology | Purpose |
|-----------|---------|
| **Python 3.8+** | Lab server runtime (zero external dependencies) |
| **http.server** | HTTP request handling framework |
| **html.escape()** | Output encoding in SECURE mode |
| **logging** | Structured console log output |
| **collections.defaultdict** | Login rate limit tracking |

### Security Assessment Tools
| Tool | Purpose | Version |
|------|---------|---------|
| **Burp Suite** | HTTP proxy, request interception, Intruder brute force | Community Edition |
| **OWASP ZAP** | Automated web vulnerability scanning | v2.14.0 |
| **Nmap** | Network reconnaissance and service enumeration | v7.94 |
| **Browser DevTools** | Cookie inspection, network traffic analysis | Edge / Chrome |

### Frameworks & Standards
| Framework | Application |
|-----------|------------|
| **OWASP Top 10 (2021)** | Vulnerability classification reference |
| **CVSS v3.1** | Severity scoring for all findings |
| **CWE (MITRE)** | Weakness enumeration and classification |
| **WSTG (OWASP)** | Web Security Testing Guide methodology |
| **NIST SP 800-53** | Security control reference |

---

## 📁 Folder Structure

```
Project 5 - Web-Security-Assessment/
│
├── app.py                          # 🐍 Vulnerable lab server (Python 3)
├── README.md                       # 📖 This file
├── requirements.txt                # 📦 Dependency documentation
├── .gitignore                      # 🚫 Git exclusion rules
│
├── findings/                       # 📋 Individual vulnerability disclosure reports
│   ├── sql_injection.txt           #    VULN-01 — SQLi (CVSS 9.8 Critical)
│   ├── xss_vulnerability.txt       #    VULN-02 — XSS Reflected & Stored (CVSS 8.1 High)
│   ├── authentication_weakness.txt #    VULN-03 — Broken Auth (CVSS 7.5 High)
│   └── session_management.txt      #    VULN-04 — Insecure Cookies (CVSS 6.5 Medium)
│
├── reports/                        # 📄 Final security assessment reports
│   ├── web_security_report.md      #    Full Markdown technical report
│   └── executive_security_report.html  # PDF-ready executive report
│
├── vulnerability_scans/            # 🔍 Automated tool scan outputs
│   ├── nmap_scan.txt               #    Network reconnaissance results
│   └── zap_scan_summary.txt        #    OWASP ZAP automated scan (14 alerts)
│
└── screenshots/                    # 🖼️ Evidence screenshots (01–09)
    ├── 01_env_dvwa_dashboard.png        # Lab environment setup
    ├── 02_burp_proxy_intercept.png      # HTTP traffic interception
    ├── 03_sqli_payload_execution.png    # SQL injection payload input
    ├── 04_sqli_data_dump.png            # Database records exposed
    ├── 05_xss_reflected_popup.png       # Reflected XSS alert dialog
    ├── 06_xss_stored_guestbook.png      # Stored XSS guestbook entry
    ├── 07_auth_burp_intruder.png        # Brute force success evidence
    ├── 08_session_devtools_cookies.png  # DevTools cookie flag inspection
    ├── 09_zap_scan_alerts.png           # OWASP ZAP scan alerts dashboard
    └── README.md                        # Screenshot naming convention guide
```

---

## 🚀 Quick Start — Running the Lab

### Prerequisites
- Python 3.8 or higher installed
- Windows 10/11, macOS, or Linux
- Web browser (Microsoft Edge or Google Chrome recommended)

### Step 1: Clone or Download the Repository
```bash
git clone https://github.com/yourusername/web-security-assessment.git
cd "web-security-assessment"
```

### Step 2: Start the Vulnerable Lab Server
```bash
python app.py
```

Expected console output:
```
[2026-06-17 10:00:00] [INFO] ══════════════════════════════════════════════════
[2026-06-17 10:00:00] [INFO] Web Application Security Assessment Lab — Starting
[2026-06-17 10:00:00] [INFO] Target URL    : http://localhost:8080
[2026-06-17 10:00:00] [INFO] Security Level: LOW
[2026-06-17 10:00:00] [INFO] Press CTRL+C to stop the server.
```

### Step 3: Access the Lab in Your Browser
Open: **http://localhost:8080**

### Step 4: Toggle Security Modes
- Click **"Switch to SECURE Mode"** in the sidebar to activate defensive controls
- Click **"Switch to LOW (Vulnerable) Mode"** to restore attack scenarios

### Step 5: Stop the Server
Press `CTRL + C` in the terminal window.

---

## 🔬 Vulnerability Modules

| URL Path | Vulnerability | OWASP | Mode Behavior |
|----------|--------------|-------|---------------|
| `/sqli` | SQL Injection (In-Band) | A03:2021 | LOW: Full DB dump; SECURE: Integer validation + parameterized query |
| `/xss_r` | Reflected XSS | A03:2021 | LOW: Raw input reflected; SECURE: `html.escape()` applied |
| `/xss_s` | Stored XSS (Guestbook) | A03:2021 | LOW: Scripts persist and execute; SECURE: Encoded before render |
| `/brute` | Brute Force Auth | A07:2021 | LOW: Unlimited attempts; SECURE: 5-attempt IP lockout (30s) |
| `/session_info` | Session Cookie Audit | A07:2021 | LOW: No flags; SECURE: HttpOnly + SameSite=Lax |

---

## 🚨 Security Findings Summary

| ID | Vulnerability | OWASP | CVSS v3.1 | Severity | Priority |
|----|--------------|-------|-----------|----------|----------|
| [VULN-01](findings/sql_injection.txt) | SQL Injection (Union-Based) | A03:2021 | **9.8** | 🔴 CRITICAL | P1 — Immediate |
| [VULN-02](findings/xss_vulnerability.txt) | Cross-Site Scripting (Reflected & Stored) | A03:2021 | **8.1** | 🟠 HIGH | P2 — High |
| [VULN-03](findings/authentication_weakness.txt) | Broken Authentication / No Rate Limiting | A07:2021 | **7.5** | 🟠 HIGH | P2 — High |
| [VULN-04](findings/session_management.txt) | Insecure Cookie Attributes (No HttpOnly/Secure) | A07:2021 | **6.5** | 🟡 MEDIUM | P3 — Medium |

**Overall Risk Rating: 🔴 CRITICAL** — Immediate remediation required for VULN-01.

### Attack Chain Demonstration
```
VULN-02 (Stored XSS) ──chain──▶ VULN-04 (No HttpOnly) ──▶ SESSION HIJACK
                                                            Full Account Takeover
                                                            Without Credentials
```

---

## 🖼️ Evidence Screenshots

| # | Screenshot | Description |
|---|-----------|-------------|
| 01 | `01_env_dvwa_dashboard.png` | Lab environment dashboard confirming target app running on port 8080 |
| 02 | `02_burp_proxy_intercept.png` | HTTP traffic interception showing request/response headers |
| 03 | `03_sqli_payload_execution.png` | SQLi payload `' OR 1=1 --` entered in User ID field |
| 04 | `04_sqli_data_dump.png` | All database user records dumped without authentication |
| 05 | `05_xss_reflected_popup.png` | Browser alert dialog confirming Reflected XSS execution |
| 06 | `06_xss_stored_guestbook.png` | Stored XSS payload persisted in guestbook and auto-executing |
| 07 | `07_auth_burp_intruder.png` | Brute force attack result showing valid credentials discovered |
| 08 | `08_session_devtools_cookies.png` | DevTools Cookie panel showing missing HttpOnly/Secure flags |
| 09 | `09_zap_scan_alerts.png` | OWASP ZAP Alerts dashboard with HIGH/MEDIUM risk findings |

---

## 🛠️ Remediation Roadmap

| Phase | Timeline | Priority | Action |
|-------|----------|----------|--------|
| **Phase 1** | 0–7 Days | 🔴 P1 Critical | Replace all SQL queries with PDO Prepared Statements; activate WAF |
| **Phase 2** | 7–30 Days | 🟠 P2 High | Implement HTML output encoding; add CSP header; enforce login rate limiting + CAPTCHA |
| **Phase 3** | 30–60 Days | 🟡 P3 Medium | Set HttpOnly/Secure/SameSite cookie flags; enforce HTTPS/HSTS; implement MFA |

---

## 📐 OWASP & Industry Compliance

This assessment is aligned with the following industry frameworks:

| Standard | Application |
|---------|-------------|
| **OWASP Top 10 (2021)** | All 4 findings mapped to A03:2021 and A07:2021 |
| **CVSS v3.1** | All findings scored with full vector strings |
| **CWE (MITRE)** | CWE-89, CWE-79, CWE-307, CWE-1004, CWE-614 referenced |
| **OWASP WSTG** | WSTG-INPV-05, WSTG-INPV-01/02, WSTG-ATHN-02/03, WSTG-SESS-02/05 |
| **NIST SP 800-53** | SI-10 (Input Validation), IA-5 (Auth Management) |

---

## 📚 Learning Outcomes

Upon completing this project, the following technical competencies were demonstrated:

- ✅ **HTTP Protocol Analysis** — Intercepted and analyzed raw HTTP request/response pairs
- ✅ **SQL Injection** — Identified, exploited (union-based), and remediated using PDO prepared statements
- ✅ **Cross-Site Scripting** — Demonstrated both Reflected and Stored XSS vectors; applied output encoding
- ✅ **Authentication Security** — Conducted brute-force attack; implemented IP-based rate limiting
- ✅ **Session Management** — Audited cookie attributes; demonstrated XSS-to-session-hijack attack chain
- ✅ **Automated Scanning** — Configured and interpreted OWASP ZAP active scan results (14 alerts)
- ✅ **Network Reconnaissance** — Performed Nmap service detection and interpreted scan results
- ✅ **Professional Reporting** — Produced CVSS-scored, CWE-referenced, WSTG-mapped vulnerability reports

---

## 🔮 Future Improvements

- [ ] Add **Command Injection** module (`/cmdi`) for OS-level exploitation demonstration
- [ ] Add **Insecure Direct Object Reference (IDOR)** module mapped to OWASP A01:2021
- [ ] Add **File Upload Vulnerability** module demonstrating unrestricted file execution
- [ ] Integrate **SQLite database** to replace in-memory data structures for a more realistic target
- [ ] Add **JWT Authentication** module to demonstrate token forgery attacks
- [ ] Package as a **Docker container** (`Dockerfile` + `docker-compose.yml`) for one-command deployment
- [ ] Generate automated **HTML scan reports** directly from ZAP API integration
- [ ] Add **HTTPS support** (self-signed TLS certificate) to demonstrate Secure cookie flag behaviour

---

## 👤 Author

**Web Security Analyst Intern**
Cybersecurity Assessment Project — June 17, 2026

---

## ⚠️ Disclaimer

> **EDUCATIONAL USE ONLY**
>
> This project, including the `app.py` vulnerable web application server, was created exclusively for educational and internship assessment purposes within a controlled, isolated local environment.
>
> The techniques demonstrated in this repository **must not** be applied against any system, network, or application without explicit written authorization from the system owner. Unauthorized penetration testing is illegal under the Computer Fraud and Abuse Act (CFAA), the IT Act 2000 (India), and equivalent legislation worldwide.
>
> The author assumes no liability for misuse of any techniques or code contained in this repository.

---

*Web Application Security Assessment — Project 5 | June 17, 2026*
