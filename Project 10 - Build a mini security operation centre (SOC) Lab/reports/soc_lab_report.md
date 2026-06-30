# Professional SOC Laboratory Report
**Mini-SOC Threat Ingestion, Analysis, and Incident Investigation Report**
**Classification: INTERNAL ONLY**
**Version: 1.0.0**

---

## 1. Executive Summary
This document outlines the deployment, optimization, threat simulation, and audit of a virtualized Security Operations Center (SOC) lab infrastructure. As organizations navigate complex environments consisting of web services, database servers, and active domain directories, centralized threat monitoring remains the bedrock of modern cyber defense.

In this project, a centralized SIEM pipeline was implemented using the ELK Stack (Elasticsearch & Kibana) in a virtual network topology. To evaluate the logging configuration's effectiveness, a brute-force SSH attack simulation was executed against the primary server. The attack generated identifiable indicators of compromise (IoCs), which were successfully ingested via the Elastic Agent, structured inside indices, and analyzed inside Kibana. This project demonstrates how defense teams configure log streams, optimize service footprints to bypass system resource constraints, build custom alert correlation rules, and respond to authentication attacks.

---

## 2. Infrastructure & System Design

### 2.1 Topology Map
The environment consists of two virtualized systems running on a restricted virtual network:

```mermaid
graph TD
    subgraph Windows Host OS
        Browser[Kibana Client Browser<br>http://localhost:5601]
        SSH_Client[PowerShell SSH Client<br>Port: 2222]
    end

    subgraph VirtualBox NatNetwork (Subnet: 10.0.2.0/24)
        Kali[Attacker Node: Kali Linux<br>IP: 10.0.2.15]
        SIEM[Target / SIEM: SOC-SIEM-Server-3<br>IP: 10.0.2.4]
    end

    Browser -- "HTTP Navigation" --> SIEM
    SSH_Client -- "Secure Remote Control" --> SIEM
    Kali -- "THC-Hydra Brute-Force" --> SIEM
```

### 2.2 System Configurations & Resource Constraints
*   **Operating Systems:** Ubuntu 26.04 LTS (SIEM/Target), Kali Linux v2026.1 (Attacker).
*   **System Resource Optimizations:** Running a complete SIEM stack alongside databases and system kernels on a single virtual host with 4GB RAM is prone to JVM crashes. The Elasticsearch configuration was hardened by editing `jvm.options.d/memory.options` to restrict maximum heap size:
    - `-Xms1g` (Initial heap allocation)
    - `-Xmx1g` (Maximum heap limits)
    This optimization maintained host stability, successfully preventing kernel out-of-memory (OOM) actions.

---

## 3. SIEM Installation and Log Ingestion Pipeline

### 3.1 ELK Stack Installation Sequence
Deployment was completed using stable repository configurations:
1. **GPG Key Mapping:** Verified Elastic repository authenticity.
2. **APT Source Loading:** Registered the package repository index list.
3. **Daemon Services Initialization:** Enabled and started the backends:
   ```bash
   sudo systemctl enable --now elasticsearch kibana
   ```

### 3.2 Agent Standalone Collection Model
Log shipping was configured using a standalone **Elastic Agent** service model targeting the local authentication (`/var/log/auth.log`) and system message log streams. Connection credentials and SSL certification details were defined in `/etc/elastic-agent/elastic-agent.yml` to redirect records directly to port `9200`.

---

## 4. Threat Simulation (SSH Brute-Force)

### 4.1 Penetration Testing Methodology
To test the threshold capabilities of our detection rules, the attacker simulated a brute-force password spraying campaign using the tool **THC-Hydra**:

```bash
hydra -l soc-admin -P /usr/share/wordlists/fasttrack.txt 10.0.2.4 ssh -t 4
```

### 4.2 Raw Log Signature Evidence
During the attack, the local authentication stream logged a surge of access attempts:
*   *Event Type:* Failed Password
*   *Victim Account:* `soc-admin`
*   *Attacking Source IP:* `10.0.2.15`
*   *Frequency:* 4.5 connection attempts per second.
*   *Pattern:* Incrementing host socket source ports, revealing a multi-threaded automated scanning tool.

---

## 5. Security Detection, KQL Analysis & Investigations

### 5.1 Kibana KQL Query Filter
To audit the threat vector inside the SIEM console, analysts queried the data streams using Kibana Query Language (KQL):
```kql
(message : "Failed password" or message : "Invalid user") and message : "sshd"
```

### 5.2 Indicators of Compromise (IoCs)
1. **Velocity Anomaly:** Unusually high count of login failures within seconds.
2. **Sequential Ports:** Incrementing connection sockets.
3. **Target Username:** Credential brute-force attempts targeting administrative services.

---

## 6. Remediation & Hardening Recommendations
Based on the threat investigation, the following defensive adjustments are required:
1. **Enforce SSH Key-Based Authentication:** Disable password logins entirely inside `/etc/ssh/sshd_config` by setting `PasswordAuthentication no`.
2. **Deploy Fail2ban:** Install the system daemon to block attacking source IPs at the Linux kernel firewall after 3 failures.
3. **Relocate Service Port:** Bind SSH to a non-standard port (e.g., `2244`) instead of port `22`.\n