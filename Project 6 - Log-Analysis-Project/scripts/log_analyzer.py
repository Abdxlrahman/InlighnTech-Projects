"""
=============================================================================
log_analyzer.py — SSH Authentication Log Security Analyzer
=============================================================================
Project      : Project 6 — Log Analysis & SIEM-Based Threat Detection
Author       : SOC Analyst — Tier 2 | Aegis Cybersecurity
Version      : 2.0.0
Date         : June 21, 2026
Description  : Parses a Linux auth.log file and performs multi-stage
               threat detection including:
                 - SSH brute-force source identification
                 - Compromised account cross-referencing
                 - High-risk sudo command flagging
                 - Backdoor user account detection
                 - Indicators of Compromise (IoC) extraction
                 - CVSS-aligned severity classification
               Outputs:
                 - analysis_results/suspicious_login_attempts.txt (human-readable)
                 - analysis_results/ioc_report.json (machine-readable SIEM export)
                 - dashboard/log_data.js (raw log payload for the web dashboard)
Usage        : python scripts/log_analyzer.py [--log PATH] [--output DIR]
                                               [--threshold N] [--json] [--verbose]
=============================================================================
"""

import os
import re
import sys
import json
import logging
import argparse
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Module Metadata
# ---------------------------------------------------------------------------
__version__ = "2.0.0"
__author__ = "Aegis Cybersecurity — SOC Analyst Tier 2"

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s — %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity Classification (CVSS-aligned)
# ---------------------------------------------------------------------------
SEVERITY_MAP = {
    "CRITICAL": {"score": "9.0–10.0", "color": "RED",    "nist": "RESPOND"},
    "HIGH":     {"score": "7.0–8.9",  "color": "ORANGE", "nist": "DETECT"},
    "MEDIUM":   {"score": "4.0–6.9",  "color": "YELLOW", "nist": "PROTECT"},
    "LOW":      {"score": "0.1–3.9",  "color": "GREEN",  "nist": "IDENTIFY"},
    "INFO":     {"score": "0.0",      "color": "BLUE",   "nist": "IDENTIFY"},
}

# High-risk commands that indicate post-exploitation activity
HIGH_RISK_COMMANDS: List[str] = [
    "/bin/bash", "/bin/sh", "/usr/bin/python", "/usr/bin/python3",
    "cat /etc/shadow", "cat /etc/passwd", "useradd", "usermod",
    "chmod 777", "wget ", "curl ", "nc ", "ncat ", "/tmp/"
]

# Known legitimate administrative accounts (baseline)
TRUSTED_USERS: List[str] = ["webdev", "deploy", "backup", "monitor"]


# ---------------------------------------------------------------------------
# Compiled Regular Expressions
# ---------------------------------------------------------------------------

# Failed SSH login: "Failed password for <user> from <ip> port <port> ssh2"
RE_FAILED = re.compile(
    r"(?P<date>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd\[\d+\]:\s+Failed password for (?P<user>\S+) from "
    r"(?P<ip>[\d\.]+) port \d+ ssh2"
)

# Successful SSH login: "Accepted password for <user> from <ip> port <port> ssh2"
RE_SUCCESS = re.compile(
    r"(?P<date>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd\[\d+\]:\s+Accepted password for (?P<user>\S+) from "
    r"(?P<ip>[\d\.]+) port \d+ ssh2"
)

# Sudo activity: captures user and the full sudo details string
RE_SUDO = re.compile(
    r"(?P<date>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sudo:\s+\s*(?P<user>\S+)\s*:(?P<details>.*)"
)

# Backdoor user creation: "useradd: new user: name=<user>"
RE_USERADD = re.compile(
    r"(?P<date>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"useradd:\s+new user:\s+name=(?P<username>\S+?),.*"
)


# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze SSH auth logs for security threats and generate incident reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python log_analyzer.py --threshold 5 --json --verbose"
    )
    parser.add_argument(
        "--log", "-l",
        default=None,
        help="Path to the auth log file (default: ../collected_logs/auth_logs.txt)"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Directory for output reports (default: ../analysis_results/)"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=10,
        help="Minimum failed attempts to classify as brute force (default: 10)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="export_json",
        help="Export IoC data as ioc_report.json alongside the text report"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug output"
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Parsing Functions
# ---------------------------------------------------------------------------

def parse_log_file(log_path: str) -> Tuple[List, List, List, List]:
    """
    Parse the auth log file and extract security-relevant events.

    Args:
        log_path: Absolute path to the auth.log file.

    Returns:
        Tuple of (failed_attempts, successful_logins, sudo_attempts, useradd_events)
        Each element is a list of dict objects with parsed fields.

    Raises:
        FileNotFoundError: If the log file does not exist.
        OSError: If the file cannot be read.
    """
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")

    failed_attempts: List[Dict] = []
    successful_logins: List[Dict] = []
    sudo_attempts: List[Dict] = []
    useradd_events: List[Dict] = []
    total_lines = 0

    logger.info("Parsing log file: %s", log_path)

    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            total_lines += 1
            line = line.strip()
            if not line:
                continue

            # Check for failed SSH login
            m = RE_FAILED.search(line)
            if m:
                failed_attempts.append(m.groupdict())
                continue

            # Check for successful SSH login
            m = RE_SUCCESS.search(line)
            if m:
                successful_logins.append(m.groupdict())
                continue

            # Check for sudo activity
            m = RE_SUDO.search(line)
            if m:
                sudo_attempts.append(m.groupdict())
                continue

            # Check for new user creation (backdoor detection)
            m = RE_USERADD.search(line)
            if m:
                useradd_events.append(m.groupdict())

    logger.info(
        "Parsing complete — %d lines read | %d failed | %d success | %d sudo | %d useradd",
        total_lines, len(failed_attempts), len(successful_logins),
        len(sudo_attempts), len(useradd_events)
    )
    return failed_attempts, successful_logins, sudo_attempts, useradd_events


# ---------------------------------------------------------------------------
# Analysis Functions
# ---------------------------------------------------------------------------

def detect_brute_force(
    failed_attempts: List[Dict],
    threshold: int = 10
) -> Tuple[Dict, Dict]:
    """
    Identify brute-force source IPs exceeding the failure threshold.

    Args:
        failed_attempts: List of parsed failed login dicts.
        threshold:       Minimum failed attempt count to flag an IP.

    Returns:
        Tuple of (failed_counts_by_ip, brute_force_sources).
        failed_counts_by_ip: {ip: count}
        brute_force_sources: {ip: {"count": n, "targeted_users": [...]}}
    """
    failed_counts: Dict[str, int] = defaultdict(int)
    targeted_users: Dict[str, set] = defaultdict(set)

    for attempt in failed_attempts:
        ip = attempt["ip"]
        failed_counts[ip] += 1
        targeted_users[ip].add(attempt["user"])

    brute_force_sources = {
        ip: {"count": count, "targeted_users": sorted(targeted_users[ip])}
        for ip, count in failed_counts.items()
        if count >= threshold
    }

    logger.info(
        "Brute force detection — %d IPs exceeded threshold of %d failures.",
        len(brute_force_sources), threshold
    )
    return dict(failed_counts), brute_force_sources


def detect_compromised_accounts(
    successful_logins: List[Dict],
    brute_force_sources: Dict
) -> List[Dict]:
    """
    Cross-reference successful logins against brute-force source IPs
    to identify confirmed account compromises.

    Args:
        successful_logins:   Parsed successful login events.
        brute_force_sources: Dict of known attacker IPs.

    Returns:
        List of confirmed compromised session dicts.
    """
    compromised = [
        login for login in successful_logins
        if login["ip"] in brute_force_sources
    ]
    logger.info("Compromised accounts detected: %d", len(compromised))
    return compromised


def detect_high_risk_sudo(sudo_attempts: List[Dict]) -> List[Dict]:
    """
    Scan sudo events for high-risk or denied commands indicating
    post-exploitation or privilege escalation activity.

    Severity Logic:
      - CRITICAL: Command succeeded AND matches a known high-risk pattern.
      - HIGH:     Command was denied by sudo policy.

    Args:
        sudo_attempts: List of parsed sudo event dicts.

    Returns:
        List of flagged sudo event dicts with added 'severity' field.
    """
    flagged: List[Dict] = []

    for sudo in sudo_attempts:
        details: str = sudo["details"]
        is_denied: bool = "command not allowed" in details
        is_high_risk: bool = any(cmd in details for cmd in HIGH_RISK_COMMANDS)

        if is_denied or is_high_risk:
            severity = "CRITICAL" if (is_high_risk and not is_denied) else "HIGH"
            flagged.append({
                "date":     sudo["date"],
                "user":     sudo["user"],
                "details":  details.strip(),
                "denied":   is_denied,
                "severity": severity,
                "cvss_range": SEVERITY_MAP[severity]["score"],
                "nist_function": SEVERITY_MAP[severity]["nist"],
            })

    logger.info("High-risk sudo events flagged: %d", len(flagged))
    return flagged


def detect_backdoor_accounts(
    useradd_events: List[Dict],
    trusted_users: List[str] = None
) -> List[Dict]:
    """
    Flag unexpected user account creation events as potential backdoor installations.
    Any account created outside the known trusted user list is flagged.

    Args:
        useradd_events: Parsed useradd log events.
        trusted_users:  List of expected/legitimate usernames.

    Returns:
        List of suspicious useradd events.
    """
    if trusted_users is None:
        trusted_users = TRUSTED_USERS

    suspicious = [
        event for event in useradd_events
        if event["username"] not in trusted_users
    ]
    logger.info("Suspicious user creations detected: %d", len(suspicious))
    return suspicious


# ---------------------------------------------------------------------------
# Report Writers
# ---------------------------------------------------------------------------

REPORT_HEADER = """
=============================================================================
        SECURITY LOG ANALYSIS — INCIDENT REPORT
=============================================================================
  Organization  : Aegis Cybersecurity — Threat Intelligence Division
  Incident Ref  : INC-2026-0621
  Report Date   : {date}
  Analyst       : SOC Analyst — Tier 2
  Hostname      : debian-server
  Log Source    : /var/log/auth.log
  Analyzer Ver  : {version}
=============================================================================

"""

DIVIDER = "-" * 77 + "\n"


def write_text_report(
    output_path: str,
    failed_attempts: List[Dict],
    successful_logins: List[Dict],
    sudo_attempts: List[Dict],
    failed_counts: Dict,
    brute_force_sources: Dict,
    compromised_sessions: List[Dict],
    high_risk_sudo: List[Dict],
    backdoor_accounts: List[Dict]
) -> None:
    """
    Write the full human-readable security analysis report to a text file.

    Args:
        output_path: Path to the output .txt file.
        (remaining): Parsed analysis data structures.
    """
    with open(output_path, "w", encoding="utf-8") as out:
        # Header
        out.write(REPORT_HEADER.format(
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            version=__version__
        ))

        # Section 1: Summary Metrics
        out.write("SECTION 1 — SUMMARY METRICS\n")
        out.write(DIVIDER)
        out.write(f"  Total Log Lines Parsed              : {len(failed_attempts) + len(successful_logins) + len(sudo_attempts)}\n")
        out.write(f"  Total Failed SSH Login Attempts     : {len(failed_attempts)}\n")
        out.write(f"  Total Successful SSH Logins         : {len(successful_logins)}\n")
        out.write(f"  Total Sudo Executions / Requests    : {len(sudo_attempts)}\n")
        out.write(f"  Unique Attacking IP Addresses       : {len(failed_counts)}\n")
        out.write(f"  Brute Force Sources (Threshold ≥10) : {len(brute_force_sources)}\n")
        out.write(f"  Confirmed Account Compromises       : {len(compromised_sessions)}\n")
        out.write(f"  High-Risk / Denied Sudo Events      : {len(high_risk_sudo)}\n")
        out.write(f"  Suspected Backdoor Accounts         : {len(backdoor_accounts)}\n\n")

        # Section 2: Brute Force Sources
        out.write("SECTION 2 — BRUTE FORCE SOURCES DETECTED\n")
        out.write(DIVIDER)
        if brute_force_sources:
            for ip, info in sorted(brute_force_sources.items(),
                                   key=lambda x: x[1]["count"], reverse=True):
                out.write(f"  Attacker IP       : {ip}\n")
                out.write(f"  Failed Attempts   : {info['count']}\n")
                out.write(f"  Targeted Accounts : {', '.join(info['targeted_users'])}\n")
                out.write(f"  Risk Rating       : CRITICAL\n")
                out.write(f"  CVSS Score Range  : {SEVERITY_MAP['CRITICAL']['score']}\n")
                out.write(f"  NIST Function     : {SEVERITY_MAP['CRITICAL']['nist']}\n")
                out.write(f"  Recommended Action: Block IP at perimeter firewall immediately.\n\n")
        else:
            out.write("  No brute-force sources detected above threshold.\n\n")

        # Section 3: Compromised Accounts
        out.write("SECTION 3 — CONFIRMED ACCOUNT COMPROMISES\n")
        out.write(DIVIDER)
        if compromised_sessions:
            for session in compromised_sessions:
                out.write(f"  Compromised Account : {session['user']}\n")
                out.write(f"  Attacking Source IP : {session['ip']}\n")
                out.write(f"  Compromise Timestamp: {session['date']}\n")
                out.write(f"  Severity            : CRITICAL\n")
                out.write(f"  Status              : Host Compromised — Immediate Incident Response Required\n")
                out.write(f"  Recommended Action  : Disable account, kill sessions, rotate credentials.\n\n")
        else:
            out.write("  No confirmed compromises detected.\n\n")

        # Section 4: Backdoor Accounts
        out.write("SECTION 4 — SUSPECTED BACKDOOR ACCOUNTS\n")
        out.write(DIVIDER)
        if backdoor_accounts:
            for acct in backdoor_accounts:
                out.write(f"  Username          : {acct['username']}\n")
                out.write(f"  Creation Timestamp: {acct['date']}\n")
                out.write(f"  Severity          : CRITICAL\n")
                out.write(f"  NIST Function     : RESPOND\n")
                out.write(f"  Recommended Action: userdel -r {acct['username']} — investigate immediately.\n\n")
        else:
            out.write("  No unexpected user account creations detected.\n\n")

        # Section 5: High-Risk Sudo
        out.write("SECTION 5 — HIGH-RISK & DENIED SUDO EVENTS\n")
        out.write(DIVIDER)
        if high_risk_sudo:
            for entry in high_risk_sudo:
                status = "DENIED" if entry["denied"] else "PERMITTED"
                out.write(f"  Timestamp         : {entry['date']}\n")
                out.write(f"  Actor             : {entry['user']}\n")
                out.write(f"  Status            : {status}\n")
                out.write(f"  Command Details   : {entry['details']}\n")
                out.write(f"  Severity          : {entry['severity']}\n")
                out.write(f"  CVSS Score Range  : {entry['cvss_range']}\n")
                out.write(f"  NIST Function     : {entry['nist_function']}\n\n")
        else:
            out.write("  No high-risk or denied sudo events detected.\n\n")

        # Section 6: IoC List
        out.write("SECTION 6 — INDICATORS OF COMPROMISE (IoC LIST)\n")
        out.write(DIVIDER)
        for ip, count in sorted(failed_counts.items(), key=lambda x: x[1], reverse=True):
            rating = "CRITICAL" if ip in brute_force_sources else "MEDIUM"
            out.write(f"  IP: {ip:<20} | Failed Attempts: {count:<5} | Rating: {rating}\n")
        out.write("\n")

        # Section 7: Recommendations
        out.write("SECTION 7 — REMEDIATION RECOMMENDATIONS\n")
        out.write(DIVIDER)
        recommendations = [
            "[CRITICAL] Isolate the affected host immediately from the network.",
            "[CRITICAL] Remove backdoor account(s): userdel -r <username>",
            "[CRITICAL] Disable and lock compromised account(s): usermod -L <user>",
            "[HIGH]     Block attacker IPs at the perimeter firewall.",
            "[HIGH]     Set PermitRootLogin no in /etc/ssh/sshd_config.",
            "[HIGH]     Disable PasswordAuthentication — enforce SSH key pairs only.",
            "[HIGH]     Audit /etc/sudoers — remove /bin/bash from allowed commands.",
            "[MEDIUM]   Deploy Fail2ban: auto-ban IPs after 5 failed SSH attempts.",
            "[MEDIUM]   Relocate SSH service to a non-standard port (e.g., 22022).",
            "[MEDIUM]   Implement geo-IP blocking on SSH ingress rules.",
            "[LOW]      Enable real-time log forwarding to a centralized SIEM platform.",
            "[LOW]      Schedule automated log analysis using this script via cron.",
        ]
        for rec in recommendations:
            out.write(f"  {rec}\n")
        out.write("\n")

        # Footer
        out.write("=============================================================================\n")
        out.write(f"  END OF REPORT — Generated by log_analyzer.py v{__version__}\n")
        out.write(f"  Aegis Cybersecurity — SOC | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write("=============================================================================\n")

    logger.info("Text report written: %s", output_path)


def write_json_report(
    output_path: str,
    failed_counts: Dict,
    brute_force_sources: Dict,
    compromised_sessions: List[Dict],
    high_risk_sudo: List[Dict],
    backdoor_accounts: List[Dict]
) -> None:
    """
    Export a structured JSON IoC report for SIEM platform ingestion.

    Args:
        output_path: Path to the output .json file.
        (remaining): Parsed analysis data structures.
    """
    report = {
        "metadata": {
            "report_type": "IoC Export — SSH Auth Log Analysis",
            "incident_reference": "INC-2026-0621",
            "analyst": __author__,
            "generated_at": datetime.now().isoformat(),
            "analyzer_version": __version__,
            "hostname": "debian-server",
            "log_source": "/var/log/auth.log"
        },
        "summary": {
            "total_failed_logins": sum(failed_counts.values()),
            "brute_force_sources": len(brute_force_sources),
            "compromised_accounts": len(compromised_sessions),
            "high_risk_sudo_events": len(high_risk_sudo),
            "backdoor_accounts_detected": len(backdoor_accounts)
        },
        "brute_force_sources": [
            {
                "ip": ip,
                "failed_attempts": info["count"],
                "targeted_users": info["targeted_users"],
                "severity": "CRITICAL",
                "cvss_score_range": SEVERITY_MAP["CRITICAL"]["score"],
                "nist_function": SEVERITY_MAP["CRITICAL"]["nist"],
                "recommended_action": "Block at perimeter firewall"
            }
            for ip, info in brute_force_sources.items()
        ],
        "compromised_accounts": [
            {
                "username": s["user"],
                "source_ip": s["ip"],
                "timestamp": s["date"],
                "severity": "CRITICAL",
                "recommended_action": "Disable account and rotate credentials"
            }
            for s in compromised_sessions
        ],
        "backdoor_accounts": [
            {
                "username": a["username"],
                "created_at": a["date"],
                "severity": "CRITICAL",
                "recommended_action": f"userdel -r {a['username']}"
            }
            for a in backdoor_accounts
        ],
        "high_risk_sudo_events": [
            {
                "timestamp": e["date"],
                "user": e["user"],
                "details": e["details"],
                "denied": e["denied"],
                "severity": e["severity"],
                "cvss_score_range": e["cvss_range"],
                "nist_function": e["nist_function"]
            }
            for e in high_risk_sudo
        ],
        "ioc_ip_list": [
            {"ip": ip, "failed_attempts": count,
             "classification": "CRITICAL" if ip in brute_force_sources else "MEDIUM"}
            for ip, count in sorted(failed_counts.items(), key=lambda x: x[1], reverse=True)
        ]
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=4)

    logger.info("JSON IoC report written: %s", output_path)


def export_dashboard_data(log_path: str, dashboard_dir: str) -> None:
    """
    Read the raw auth log and export it as a JavaScript template literal
    for direct loading into the SIEM web dashboard without a web server.

    Args:
        log_path:      Path to the raw auth log file.
        dashboard_dir: Path to the dashboard/ directory.
    """
    js_path = os.path.join(dashboard_dir, "log_data.js")
    os.makedirs(dashboard_dir, exist_ok=True)

    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    # Escape characters unsafe inside a JS template literal
    escaped = (
        content
        .replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("${", "\\${")
    )

    with open(js_path, "w", encoding="utf-8") as fh:
        fh.write(f"// Auto-generated by log_analyzer.py v{__version__}\n")
        fh.write(f"// Generated: {datetime.now().isoformat()}\n")
        fh.write(f"// Source: {log_path}\n\n")
        fh.write(f"const rawLogData = `\n{escaped}`;\n")

    logger.info("Dashboard log_data.js exported: %s", js_path)


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def analyze_logs(
    log_path: str = None,
    output_dir: str = None,
    threshold: int = 10,
    export_json: bool = True,
    verbose: bool = False
) -> None:
    """
    Orchestrate the full security log analysis pipeline.

    Args:
        log_path:    Path to auth log file.
        output_dir:  Directory for output reports.
        threshold:   Brute-force detection threshold.
        export_json: Whether to write a JSON IoC report.
        verbose:     Enable debug logging.
    """
    if verbose:
        logger.setLevel(logging.DEBUG)

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    if log_path is None:
        log_path = os.path.join(project_root, "collected_logs", "auth_logs.txt")
    if output_dir is None:
        output_dir = os.path.join(project_root, "analysis_results")

    os.makedirs(output_dir, exist_ok=True)
    dashboard_dir = os.path.join(project_root, "dashboard")

    logger.info("=" * 60)
    logger.info("Aegis Cybersecurity — Log Analyzer v%s", __version__)
    logger.info("Incident Reference : INC-2026-0621")
    logger.info("Log Source         : %s", log_path)
    logger.info("=" * 60)

    # -- Parse --
    try:
        failed, successful, sudo_events, useradd_events = parse_log_file(log_path)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        logger.error("Run generate_logs.py first to create the log file.")
        sys.exit(1)

    # -- Analyze --
    failed_counts, brute_force_sources = detect_brute_force(failed, threshold)
    compromised_sessions = detect_compromised_accounts(successful, brute_force_sources)
    high_risk_sudo = detect_high_risk_sudo(sudo_events)
    backdoor_accounts = detect_backdoor_accounts(useradd_events)

    # -- Write text report --
    txt_path = os.path.join(output_dir, "suspicious_login_attempts.txt")
    write_text_report(
        txt_path, failed, successful, sudo_events,
        failed_counts, brute_force_sources, compromised_sessions,
        high_risk_sudo, backdoor_accounts
    )

    # -- Write JSON IoC report --
    if export_json:
        json_path = os.path.join(output_dir, "ioc_report.json")
        write_json_report(
            json_path, failed_counts, brute_force_sources,
            compromised_sessions, high_risk_sudo, backdoor_accounts
        )

    # -- Export dashboard data --
    try:
        export_dashboard_data(log_path, dashboard_dir)
    except OSError as exc:
        logger.warning("Dashboard export failed (non-critical): %s", exc)

    # -- Final Summary --
    logger.info("=" * 60)
    logger.info("ANALYSIS COMPLETE")
    logger.info("  Failed Logins Detected      : %d", len(failed))
    logger.info("  Brute Force IPs             : %d", len(brute_force_sources))
    logger.info("  Compromised Accounts        : %d", len(compromised_sessions))
    logger.info("  High-Risk Sudo Events       : %d", len(high_risk_sudo))
    logger.info("  Backdoor Accounts Detected  : %d", len(backdoor_accounts))
    logger.info("  Reports written to          : %s", output_dir)
    logger.info("=" * 60)


if __name__ == "__main__":
    args = parse_args()
    analyze_logs(
        log_path=args.log,
        output_dir=args.output,
        threshold=args.threshold,
        export_json=args.export_json,
        verbose=args.verbose
    )
