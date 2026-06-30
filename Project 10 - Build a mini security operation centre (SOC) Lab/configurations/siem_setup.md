# Mini SOC Lab - Installation & Configuration Guide
**Author: Cybersecurity Engineering & Security Operations Center Intern**
**Target Audience: SOC Engineers, Security Analysts, Administrators**
**Standard: NIST SP 800-92 (Guide to Computer Security Log Management)**

---

## 1. Environment & Architecture Overview
This document describes the step-by-step setup of a centralized security logging and threat detection infrastructure. The lab is modeled after enterprise-grade Security Operations Center (SOC) pipelines, implementing secure log shippers, data storage, and analytics.

### Virtual Infrastructure Nodes
1. **VM 1: SOC SIEM Server (Ubuntu 26.04 LTS)**
   - **Role:** Central Log Aggregator, Search Index, Alerting Engine & Visualization Platform.
   - **Services:** Elasticsearch (v8.19.17), Kibana (v8.19.17).
2. **VM 2: Threat Attacker Node (Kali Linux)**
   - **Role:** Automated Brute-Force and Port Scan Simulation.
   - **Services:** THC-Hydra, Nmap.

---

## 2. SIEM Server Deployment (VM 1)
Execute the installation steps in sequential order. 

### 2.1 Package Repositories and GPG Trust Keys
To verify package authenticity and source integrity, import the official Elastic signing key and add the repository:

```bash
# Add the Elastic GPG signing key
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Register the stable Elastic 8.x repository branch
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
```

### 2.2 Software Installation
Update local package caches and install the SIEM software:
```bash
sudo apt-get update -y
sudo apt-get install -y elasticsearch kibana
```

### 2.3 Java Virtual Machine (JVM) Memory Hardening
By default, Elasticsearch attempts to allocate a 2GB heap space, which can result in Kernel Out-of-Memory (OOM) termination on low-resource machines (4GB - 8GB total RAM). Constrain heap allocation to exactly 1GB:

Create a file named `/etc/elasticsearch/jvm.options.d/memory.options`:
```ini
-Xms1g
-Xmx1g
```

### 2.4 Service Enablement & Operations
Enable systemd services to persist across system reboots and start immediately:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now elasticsearch kibana
```

---

## 3. Log Ingestion & Agent Installation
To capture real-time security events, deploy the Elastic Agent in standalone mode directly on the SIEM/Target VM.

### 3.1 SSL Certificate Security Trust
Copy the automatically generated Elasticsearch Certificate Authority (CA) certificate to the Agent's directory to establish a trusted TLS connection:
```bash
sudo cp /etc/elasticsearch/certs/http_ca.crt /etc/elastic-agent/http_ca.crt
sudo chmod 644 /etc/elastic-agent/http_ca.crt
```

### 3.2 Agent Configuration Setup
Generate the configuration file at `/etc/elastic-agent/elastic-agent.yml`:
```yaml
outputs:
  default:
    type: elasticsearch
    hosts: ["https://127.0.0.1:9200"]
    username: "elastic"
    password: "elastic123"
    ssl:
      certificate_authorities: ["/etc/elastic-agent/http_ca.crt"]
      verification_mode: "none"
inputs:
  - type: logfile
    enabled: true
    streams:
      - paths:
          - /var/log/auth.log
          - /var/log/syslog
```

### 3.3 Install and Start the Elastic Agent
From the extracted agent installer directory, run the install script:
```bash
sudo ./elastic-agent install --non-interactive
```

---

## 4. UI Access & Network Configuration
To make the Kibana visual dashboard accessible from the host system, configure Kibana to listen on all interfaces and set up Port Forwarding.

### 4.1 Bind Address Configuration
Edit `/etc/kibana/kibana.yml` to allow inbound connections from outside the local machine:
```yaml
server.host: "0.0.0.0"
```
Restart the Kibana service to apply changes:
```bash
sudo systemctl restart kibana
```

### 4.2 VirtualBox Port Forwarding Rules
In the VirtualBox VM Settings (under Network -> Advanced -> Port Forwarding), add the following mapping rules:
- **Kibana Interface:** Host Port `5601` -> Guest Port `5601` (TCP)
- **SSH Interface:** Host Port `2222` -> Guest Port `22` (TCP)

Access the SIEM web interface by navigating to `http://localhost:5601` in your host browser.\n