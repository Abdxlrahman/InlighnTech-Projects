"""
================================================================================
Web Security Assessment — Automated Target Data Collection Script
================================================================================
Project     : Project 5 — Web Application Security Assessment
Author      : Web Security Analyst Intern
Date        : June 17, 2026
Version     : 1.0

Description : An automated Python script to collect baseline endpoint
              configuration and vulnerability data from the local DVWA target
              (app.py). This simulates the reconnaissance phase of a web app
              security assessment, generating an automated JSON report.

Dependencies: Python 3.8+ (Standard Library Only)
Usage       : python collect_endpoint_data.py
================================================================================
"""

import urllib.request
import urllib.error
import json
import socket
import time
from datetime import datetime

# Configuration
TARGET_HOST = "localhost"
TARGET_PORT = 8080
TARGET_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"
REPORT_FILE = "automated_recon_report.json"

def ping_target():
    """Verify the target server is online and accessible."""
    print(f"[*] Pinging target server {TARGET_URL}...")
    try:
        start = time.time()
        with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=3):
            latency = (time.time() - start) * 1000
            print(f"[+] Target is ONLINE (Latency: {latency:.2f}ms)")
            return True
    except (socket.timeout, ConnectionRefusedError):
        print("[-] Target is OFFLINE. Ensure app.py is running.")
        return False

def fetch_headers(path="/"):
    """Fetch and analyze HTTP response headers from a specific path."""
    print(f"[*] Fetching HTTP headers for {path}...")
    try:
        req = urllib.request.Request(TARGET_URL + path, method="GET")
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = dict(response.headers)
            print(f"[+] Headers retrieved successfully (Status: {response.status})")
            return headers, response.status
    except urllib.error.URLError as e:
        status = getattr(e, 'code', 'Connection Error')
        print(f"[-] Failed to retrieve headers: {status}")
        return getattr(e, 'headers', {}), status

def analyze_security_headers(headers):
    """Analyze the presence of standard security headers."""
    print("[*] Analyzing security headers...")
    standard_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": ["SAMEORIGIN", "DENY"],
        "Content-Security-Policy": None,
        "Strict-Transport-Security": None,
        "Referrer-Policy": None
    }
    
    analysis = {}
    for header, expected in standard_headers.items():
        if header in headers:
            val = headers[header]
            if expected is None:
                analysis[header] = {"status": "Present", "value": val}
            elif isinstance(expected, list) and val in expected:
                 analysis[header] = {"status": "Present (Secure)", "value": val}
            elif val == expected:
                 analysis[header] = {"status": "Present (Secure)", "value": val}
            else:
                 analysis[header] = {"status": "Present (Warning)", "value": val}
        else:
            analysis[header] = {"status": "Missing", "value": None}
            
    return analysis

def analyze_cookies(headers):
    """Analyze Set-Cookie headers for security flags."""
    print("[*] Analyzing session cookie configuration...")
    cookies_analysis = []
    
    # urllib groups multiple Set-Cookie headers into a single comma-separated string sometimes,
    # or keeps them in a list if accessed via get_all.
    set_cookies = headers.get_all('Set-Cookie') if hasattr(headers, 'get_all') else []
    
    if not set_cookies and 'Set-Cookie' in headers:
        set_cookies = [headers['Set-Cookie']]
        
    for cookie_str in set_cookies:
        parts = [p.strip() for p in cookie_str.split(';')]
        cookie_name = parts[0].split('=')[0]
        
        flags = {
            "HttpOnly": "HttpOnly" in parts,
            "Secure": "Secure" in parts,
            "SameSite": None
        }
        
        for part in parts:
            if part.lower().startswith("samesite="):
                flags["SameSite"] = part.split('=')[1]
                
        cookies_analysis.append({
            "name": cookie_name,
            "flags": flags,
            "is_secure": flags["HttpOnly"] and flags["Secure"]
        })
        
    return cookies_analysis

def generate_report():
    """Run all checks and generate a JSON report."""
    print("=" * 60)
    print("Automated Reconnaissance Script Initiated")
    print("=" * 60)
    
    if not ping_target():
        return
        
    report_data = {
        "scan_metadata": {
            "target_url": TARGET_URL,
            "scan_time": datetime.now().isoformat(),
            "scanner": "Custom Python Recon Script v1.0"
        },
        "endpoints": {}
    }
    
    # Check default dashboard
    headers_root, status_root = fetch_headers("/")
    
    # Check session info page to force cookie generation (if any logic varies)
    headers_session, status_session = fetch_headers("/session_info")
    
    report_data["endpoints"]["/"] = {
        "status_code": status_root,
        "server_banner": headers_root.get("Server", "Unknown"),
        "security_headers": analyze_security_headers(headers_root),
        "cookies": analyze_cookies(headers_root)
    }
    
    print("\n[*] Writing JSON report to disk...")
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
        
    print(f"[+] Automated reconnaissance complete. Report saved to: {REPORT_FILE}")
    print("=" * 60)

if __name__ == "__main__":
    generate_report()
