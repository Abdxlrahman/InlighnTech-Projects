#!/usr/bin/env python3
"""
SSH Log Ingestion Simulator - Security Operations Center Lab
Author: Technical Lead & Security Architect
Standard: RFC 5424 Log Telemetry Simulation
"""

import time
import sys
import random
from datetime import datetime

ATTACKER_IP = "10.0.2.15"
TARGET_HOSTNAME = "SOC-SIEM-Server-3"
USER_WORDLIST = ["root", "admin", "guest", "ubuntu", "soc-admin", "mysql", "user1"]

def get_syslog_timestamp():
    return datetime.now().strftime("%b %d %H:%M:%S")

def simulate_brute_force(dest_file, num_attempts=10):
    print(f"[*] Simulating SSH brute-force from {ATTACKER_IP}...")
    try:
        with open(dest_file, "a") as f:
            for i in range(num_attempts):
                timestamp = get_syslog_timestamp()
                username = random.choice(USER_WORDLIST)
                port = random.randint(49000, 55000)
                pid = random.randint(7000, 8000)
                if random.choice([True, False]):
                    f.write(f"{timestamp} {TARGET_HOSTNAME} sshd[{pid}]: Invalid user {username} from {ATTACKER_IP} port {port} ssh2\n")
                f.write(f"{timestamp} {TARGET_HOSTNAME} sshd[{pid}]: Failed password for {username} from {ATTACKER_IP} port {port} ssh2\n")
                f.flush()
                time.sleep(0.2)
        print(f"[+] Successfully wrote {num_attempts} attempts to {dest_file}")
    except Exception as e:
        print(f"[-] Error writing: {e}")

def simulate_successful_login(dest_file, user="soc-admin"):
    print(f"[*] Simulating successful login for user '{user}'...")
    try:
        with open(dest_file, "a") as f:
            timestamp = get_syslog_timestamp()
            port = random.randint(49000, 55000)
            pid = random.randint(7000, 8000)
            f.write(f"{timestamp} {TARGET_HOSTNAME} sshd[{pid}]: Accepted password for {user} from {ATTACKER_IP} port {port} ssh2\n")
            f.write(f"{timestamp} {TARGET_HOSTNAME} sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)\n")
            f.flush()
    except Exception as e:
        print(f"[-] Error writing: {e}")

if __name__ == "__main__":
    target_log_file = "auth.log"
    if len(sys.argv) > 1:
        target_log_file = sys.argv[1]
    simulate_brute_force(target_log_file, num_attempts=12)
    time.sleep(1)
    simulate_successful_login(target_log_file, "soc-admin")\n