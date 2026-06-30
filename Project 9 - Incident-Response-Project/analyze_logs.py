import re
import sys

def analyze_ssh_logs(log_file):
    print("🚀 Starting Automated Log Analysis...")
    print("-" * 40)
    
    failed_logins = {}
    successful_logins = set()
    malicious_processes = []
    
    try:
        with open(log_file, 'r') as file:
            for line in file:
                # Detect Failed SSH Logins
                if "Failed password for root" in line:
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        failed_logins[ip] = failed_logins.get(ip, 0) + 1
                        
                # Detect Successful SSH Logins
                elif "Accepted password for root" in line:
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        successful_logins.add(ip_match.group(1))
                        
                # Detect suspicious process execution (e.g., wget downloading payload)
                elif "COMMAND=/usr/bin/wget" in line:
                    malicious_processes.append(line.strip())
                    
    except FileNotFoundError:
        print(f"❌ Error: {log_file} not found.")
        sys.exit(1)

    print("\n🔍 FINDINGS REPORT:")
    print("===================")
    
    if failed_logins:
        print("\n[!] Brute Force Attempts Detected:")
        for ip, count in failed_logins.items():
            print(f"  - IP: {ip} | Failed Attempts: {count}")
    
    if successful_logins:
        print("\n[!] Successful Unauthorized Logins:")
        for ip in successful_logins:
            print(f"  - IP: {ip} (WARNING: Correlate with failed logins)")
            
    if malicious_processes:
        print("\n[!] Suspicious Process Executions (C2/Payloads):")
        for proc in malicious_processes:
            print(f"  - {proc}")
            
    print("\n✅ Log Analysis Complete.")

if __name__ == "__main__":
    analyze_ssh_logs("logs/system_logs.txt")
