#!/usr/bin/env python3
"""
Endpoint Discovery & Automation Tool
Part of the Wireless Security Audit & Rogue Access Point Detection Project
Author: Cybersecurity Intern / Analyst
"""

import os
import re
import subprocess
import sys
import json
from datetime import datetime

def check_os():
    if sys.platform != "win32":
        print("[!] Warning: This script is optimized for Windows environments.")

def execute_arp():
    print("[*] Initiating Active Endpoint Discovery via ARP Cache tables...")
    try:
        # Run arp -a command
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Error executing ARP sweep: {e}")
        return None

def parse_arp_output(arp_data):
    if not arp_data:
        return []
    
    devices = []
    # Pattern to match IP Address, Physical Address (MAC), and Type
    pattern = re.compile(r'^\s*(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<mac>[0-9a-fA-F-]{17})\s+(?P<type>\w+)', re.MULTILINE)
    
    for match in pattern.finditer(arp_data):
        ip = match.group('ip')
        mac = match.group('mac').upper().replace('-', ':')
        conn_type = match.group('type')
        
        # Filter out broadcast/multicast IPs
        if not ip.startswith('224.') and not ip.startswith('239.') and not ip.endswith('.255') and ip != '255.255.255.255':
            devices.append({
                "IP Address": ip,
                "MAC Address": mac,
                "Connection Type": conn_type,
                "Audit Status": "Unverified"
            })
            
    return devices

def save_results(devices):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans")
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    output_file = os.path.join(output_dir, f"discovered_endpoints_{timestamp}.json")
    text_file = os.path.join(output_dir, f"discovered_endpoints_{timestamp}.txt")
    
    # Save JSON Report
    with open(output_file, "w") as fj:
        json.dump(devices, fj, indent=4)
        
    # Save Text Report for easy viewing
    with open(text_file, "w") as ft:
        ft.write("=====================================================\n")
        ft.write("         WIRELESS AUDIT - ENDPOINT DISCOVERY REPORT   \n")
        ft.write(f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        ft.write("=====================================================\n\n")
        ft.write(f"{'IP Address':<18}{'MAC Address':<20}{'Type':<12}{'Audit Status':<12}\n")
        ft.write("-" * 62 + "\n")
        for dev in devices:
            ft.write(f"{dev['IP Address']:<18}{dev['MAC Address']:<20}{dev['Connection Type']:<12}{dev['Audit Status']:<12}\n")
            
    print(f"[+] Endpoint discovery logs saved successfully:")
    print(f"    - JSON: {output_file}")
    print(f"    - TXT: {text_file}")

def main():
    check_os()
    raw_data = execute_arp()
    if raw_data:
        devices = parse_arp_output(raw_data)
        if devices:
            print(f"[+] Success: Located {len(devices)} active local endpoints.")
            save_results(devices)
        else:
            print("[-] No active unicast endpoints found in the current ARP cache.")
    else:
        print("[-] Verification failed: Unable to fetch ARP cache table.")

if __name__ == "__main__":
    main()
