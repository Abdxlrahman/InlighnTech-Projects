"""
=============================================================================
threat_hunter.py — Standalone Threat Hunting & Log Query Script
=============================================================================
Project      : Project 6 — Log Analysis & SIEM-Based Threat Detection
Author       : SOC Analyst — Tier 2 | Aegis Cybersecurity
Version      : 1.0.0
Date         : June 21, 2026
Description  : Perform advanced, hypothesis-driven security threat hunting queries
               on syslog logs to detect complex anomalies:
                 1. High-frequency login spikes (DDoS / Credential Stuffing)
                 2. Off-hours/anomalous connection timestamps
                 3. Non-standard target accounts and service probing
               Outputs a professional Threat Hunting Hypothesis & Findings Report.
=============================================================================
"""

import os
import re
import sys
import logging
import argparse
from datetime import datetime
from collections import defaultdict
from typing import List, Dict

# Module Metadata
__version__ = "1.0.0"
__author__ = "Aegis Cybersecurity — SOC Analyst Tier 2"

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s — %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# Standard Working Hours (08:00 to 18:00)
WORK_START = 8
WORK_END = 18

RE_AUTH = re.compile(
    r"(?P<date>\w{3}\s+\d+\s+(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2}))\s+\S+\s+sshd\[\d+\]:\s+(?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>[\d\.]+) port \d+ ssh2"
)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Advanced Threat Hunting Query Utility.")
    parser.add_argument("--log", "-l", default=None, help="Path to auth log file")
    parser.add_argument("--output", "-o", default=None, help="Output file path for hunt report")
    return parser.parse_args()

def perform_threat_hunt(log_path: str, output_path: str) -> None:
    if not os.path.exists(log_path):
        logger.error("Log file not found: %s", log_path)
        sys.exit(1)

    logger.info("Executing Threat Hunting Queries on %s...", log_path)

    off_hours_events: List[Dict] = []
    minute_spikes: Dict[str, List[str]] = defaultdict(list) # minute -> list of IPs
    user_probing: Dict[str, set] = defaultdict(set) # IP -> set of users targetted

    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = RE_AUTH.search(line)
            if m:
                data = m.groupdict()
                h = int(data["hour"])
                # Query 1: Off-hours Access Detection (outside 08:00 - 18:00)
                if h < WORK_START or h >= WORK_END:
                    off_hours_events.append(data)
                
                # Query 2: High-frequency spikes by minute bucket
                minute_key = data["date"][:-3] # Exclude seconds to bucket by minute: "Jun 24 08:05"
                minute_spikes[minute_key].append(data["ip"])

                # Query 3: Target user profiling
                user_probing[data["ip"]].add(data["user"])

    # Analyze Spikes (> 15 attempts in a single minute)
    active_spikes = []
    for minute, ips in minute_spikes.items():
        if len(ips) >= 15:
            ip_counts = defaultdict(int)
            for ip in ips:
                ip_counts[ip] += 1
            major_ip = max(ip_counts, key=ip_counts.get)
            active_spikes.append({
                "minute": minute,
                "count": len(ips),
                "primary_attacker": major_ip,
                "attacker_count": ip_counts[major_ip]
            })

    # Output Threat Hunt report
    with open(output_path, "w", encoding="utf-8") as out:
        out.write("=============================================================================\n")
        out.write("                  AEGIS CYBERSECURITY THREAT HUNTING REPORT                 \n")
        out.write("=============================================================================\n")
        out.write(f"  Target Host  : debian-server\n")
        out.write(f"  Report Date  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write(f"  Scope Source : {log_path}\n")
        out.write("=============================================================================\n\n")

        out.write("HYPOTHESIS 1: Threat actors operate outside standard office working hours.\n")
        out.write("-----------------------------------------------------------------------------\n")
        out.write(f"  [+] Identified {len(off_hours_events)} off-hours SSH authentication events.\n")
        if off_hours_events:
            out.write("  List of abnormal timestamp connections:\n")
            for event in off_hours_events[:15]:
                out.write(f"    - {event['date']} | User: {event['user']:<10} | Source IP: {event['ip']:<15} | Status: {event['status']}\n")
            if len(off_hours_events) > 15:
                out.write(f"    [... truncated {len(off_hours_events) - 15} additional events ...]\n")
        else:
            out.write("  [-] No off-hours events identified.\n")
        out.write("\n")

        out.write("HYPOTHESIS 2: Automated credential-stuffing tools create distinct volume spikes.\n")
        out.write("-----------------------------------------------------------------------------\n")
        out.write(f"  [+] Identified {len(active_spikes)} high-frequency minute spikes (threshold: ≥15/min).\n")
        for spike in active_spikes:
            out.write(f"    - Bucket: {spike['minute']} | Total attempts: {spike['count']:<4} | Dominant IP: {spike['primary_attacker']} ({spike['attacker_count']} attempts)\n")
        out.write("\n")

        out.write("HYPOTHESIS 3: External reconnaissance targets multiple non-standard service accounts.\n")
        out.write("-----------------------------------------------------------------------------\n")
        out.write("  Suspicious IP Account-Probing Profile:\n")
        for ip, users in user_probing.items():
            if len(users) >= 3:
                out.write(f"    - Attacker IP: {ip:<15} | Probed Accounts Count: {len(users):<2} | Users targeted: {', '.join(users)}\n")
        out.write("\n")

        out.write("=============================================================================\n")
        out.write("  Threat Hunt Completed successfully. IOCs mapped to main incident report.\n")
        out.write("=============================================================================\n")

    logger.info("Threat Hunt complete. Findings written to: %s", output_path)

if __name__ == "__main__":
    args = parse_args()
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    
    log = args.log if args.log else os.path.join(project_root, "collected_logs", "auth_logs.txt")
    out_dir = args.output if args.output else os.path.join(project_root, "analysis_results")
    
    os.makedirs(out_dir, exist_ok=True)
    report_file = os.path.join(out_dir, "threat_hunt_report.txt")
    
    perform_threat_hunt(log, report_file)
