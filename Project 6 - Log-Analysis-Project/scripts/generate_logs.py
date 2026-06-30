"""
=============================================================================
generate_logs.py — Synthetic SSH Auth Log Generator
=============================================================================
Project      : Project 6 — Log Analysis & SIEM-Based Threat Detection
Author       : SOC Analyst — Tier 2 | Aegis Cybersecurity
Version      : 2.0.0
Date         : June 21, 2026
Description  : Generates a realistic synthetic Linux authentication log
               (auth.log) containing five distinct scenarios:
                 1. Normal daily SSH operations (legitimate admin sessions)
                 2. Internal low-rate brute force (reconnaissance phase)
                 3. External high-velocity brute force (credential stuffing)
                 4. Account compromise and privilege escalation
                 5. Backdoor persistence account creation
               Output is used by log_analyzer.py and the SIEM dashboard.
Usage        : python scripts/generate_logs.py [--output PATH] [--verbose]
=============================================================================
"""

import os
import sys
import random
import logging
import argparse
from datetime import datetime, timedelta
from typing import List

# ---------------------------------------------------------------------------
# Module Metadata
# ---------------------------------------------------------------------------
__version__ = "2.0.0"
__author__ = "Aegis Cybersecurity — SOC Analyst Tier 2"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
HOSTNAME = "debian-server"
NORMAL_USER = "webdev"
NORMAL_IP = "192.168.1.100"
SLOW_ATTACK_IP = "192.168.1.150"
RAPID_ATTACK_IP = "203.0.113.5"
COMPROMISED_USER = "support"
BACKDOOR_USER = "backuser"

ATTACK_USERNAMES: List[str] = [
    "root", "admin", "administrator", "user", "test",
    "support", "guest", "oracle", "mysql"
]

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
# Helper Functions
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate synthetic Linux SSH auth.log for security analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python generate_logs.py --output ../collected_logs/auth_logs.txt"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to write the generated log file (default: ../collected_logs/auth_logs.txt)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output showing each generated event"
    )
    return parser.parse_args()


def format_log_entry(timestamp: datetime, process: str, message: str) -> str:
    """
    Format a single syslog-style log entry.

    Args:
        timestamp: The datetime for the log event.
        process:   The process name and PID (e.g., 'sshd[1234]').
        message:   The log message body.

    Returns:
        A formatted syslog string.
    """
    ts = timestamp.strftime("%b %d %H:%M:%S")
    return f"{ts} {HOSTNAME} {process}: {message}"


def make_pid(low: int = 1000, high: int = 9999) -> str:
    """Generate a random PID string."""
    return str(random.randint(low, high))


# ---------------------------------------------------------------------------
# Scenario Generators
# ---------------------------------------------------------------------------

def generate_normal_sessions(base_time: datetime, verbose: bool) -> List[str]:
    """
    Scenario 1: Generate 5 legitimate SSH sessions from a trusted admin user.
    Each session includes a sudo apt-get update operation.

    Args:
        base_time: Starting timestamp for this scenario.
        verbose:   If True, logs each event to stdout.

    Returns:
        List of formatted log line strings.
    """
    logs: List[str] = []
    current_time = base_time + timedelta(hours=2)

    for session_num in range(1, 6):
        pid = make_pid(1000, 9999)
        port = random.randint(50000, 65000)

        entries = [
            (current_time, f"sshd[{pid}]",
             f"Connection from {NORMAL_IP} port {port} on ipv4"),
            (current_time + timedelta(seconds=2), f"sshd[{pid}]",
             f"Accepted password for {NORMAL_USER} from {NORMAL_IP} port {port} ssh2"),
            (current_time + timedelta(seconds=3), "systemd-logind",
             f"New session {session_num} of user {NORMAL_USER}."),
            (current_time + timedelta(seconds=3), f"sshd[{pid}]",
             f"pam_unix(sshd:session): session opened for user {NORMAL_USER} by (uid=0)"),
            # Legitimate sudo activity
            (current_time + timedelta(minutes=15), "sudo",
             f"  {NORMAL_USER} : TTY=pts/0 ; PWD=/home/{NORMAL_USER} ; "
             "USER=root ; COMMAND=/usr/bin/apt-get update"),
            (current_time + timedelta(minutes=15), "sudo",
             "pam_unix(sudo:session): session opened for user root by (uid=0)"),
            (current_time + timedelta(minutes=15, seconds=12), "sudo",
             "pam_unix(sudo:session): session closed for user root"),
            (current_time + timedelta(hours=1), f"sshd[{pid}]",
             f"pam_unix(sshd:session): session closed for user {NORMAL_USER}"),
        ]

        for ts, proc, msg in entries:
            line = format_log_entry(ts, proc, msg)
            logs.append(line)
            if verbose:
                logger.debug("  + %s", line)

        current_time += timedelta(hours=2)

    logger.info("Scenario 1 — Normal sessions: %d log lines generated.", len(logs))
    return logs


def generate_slow_bruteforce(base_time: datetime, verbose: bool) -> List[str]:
    """
    Scenario 2: Simulate a slow internal brute-force attack against 'root'.
    12 attempts spaced 10 minutes apart to evade rate-limit detection.

    Args:
        base_time: Starting timestamp reference.
        verbose:   If True, logs each event.

    Returns:
        List of formatted log line strings.
    """
    logs: List[str] = []
    attack_time = base_time + timedelta(hours=4)

    for attempt in range(1, 13):
        pid = make_pid(10000, 15000)
        port = random.randint(40000, 55000)

        logs.append(format_log_entry(
            attack_time, f"sshd[{pid}]",
            f"Connection from {SLOW_ATTACK_IP} port {port} on ipv4"
        ))
        attack_time += timedelta(seconds=1)
        logs.append(format_log_entry(
            attack_time, f"sshd[{pid}]",
            f"Failed password for root from {SLOW_ATTACK_IP} port {port} ssh2"
        ))
        if verbose:
            logger.debug("  [Slow BF] Attempt %d/12 recorded.", attempt)
        attack_time += timedelta(minutes=10)

    logger.info("Scenario 2 — Slow brute force: %d log lines generated.", len(logs))
    return logs


def generate_rapid_bruteforce(base_time: datetime, verbose: bool) -> List[str]:
    """
    Scenario 3: Simulate a high-velocity automated credential-stuffing attack.
    80 failed attempts in under 5 minutes across 9 target accounts.

    Args:
        base_time: Starting timestamp reference.
        verbose:   If True, logs each event.

    Returns:
        List of formatted log line strings.
    """
    logs: List[str] = []
    attack_time = base_time + timedelta(hours=8)

    for attempt in range(1, 81):
        pid = make_pid(15000, 20000)
        target_user = random.choice(ATTACK_USERNAMES)
        src_port = random.randint(30000, 60000)

        logs.append(format_log_entry(
            attack_time, f"sshd[{pid}]",
            f"Connection from {RAPID_ATTACK_IP} port {src_port} on ipv4"
        ))
        attack_time += timedelta(milliseconds=random.randint(500, 3000))
        logs.append(format_log_entry(
            attack_time, f"sshd[{pid}]",
            f"Failed password for {target_user} from {RAPID_ATTACK_IP} port {src_port} ssh2"
        ))
        if verbose and attempt % 10 == 0:
            logger.debug("  [Rapid BF] %d/80 attempts recorded.", attempt)

    logger.info("Scenario 3 — Rapid brute force: %d log lines generated.", len(logs))
    return logs


def generate_compromise_and_escalation(base_time: datetime, verbose: bool) -> List[str]:
    """
    Scenario 4 & 5: Simulate successful account compromise, privilege escalation,
    and backdoor persistence installation.

    Phases:
      4a — Successful authentication as 'support' from the attacker IP.
      4b — Unauthorized sudo attempts (denied) then successful root shell.
      5  — Root-level useradd for backdoor account 'backuser'.

    Args:
        base_time: Starting timestamp reference.
        verbose:   If True, logs each event.

    Returns:
        List of formatted log line strings.
    """
    logs: List[str] = []
    c_time = base_time + timedelta(hours=8, minutes=5)
    pid = make_pid(20000, 22000)

    # -- Phase 4a: Successful login --
    logs.extend([
        format_log_entry(c_time, f"sshd[{pid}]",
                         f"Connection from {RAPID_ATTACK_IP} port 55431 on ipv4"),
        format_log_entry(c_time + timedelta(seconds=2), f"sshd[{pid}]",
                         f"Accepted password for {COMPROMISED_USER} from {RAPID_ATTACK_IP} port 55431 ssh2"),
        format_log_entry(c_time + timedelta(seconds=2), "systemd-logind",
                         "New session 42 of user support."),
        format_log_entry(c_time + timedelta(seconds=2), f"sshd[{pid}]",
                         f"pam_unix(sshd:session): session opened for user {COMPROMISED_USER} by (uid=0)"),
    ])

    # -- Phase 4b: Privilege escalation attempts --
    esc_time = c_time + timedelta(minutes=2)
    logs.extend([
        # Denied: read shadow file
        format_log_entry(esc_time, "sudo",
                         f"  {COMPROMISED_USER} : command not allowed ; TTY=pts/2 ; "
                         "PWD=/home/support ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"),
        # Denied: add user
        format_log_entry(esc_time + timedelta(seconds=45), "sudo",
                         f"  {COMPROMISED_USER} : command not allowed ; TTY=pts/2 ; "
                         "PWD=/home/support ; USER=root ; COMMAND=/usr/bin/useradd -m backuser"),
        # Granted: root shell via /bin/bash (misconfigured sudoers)
        format_log_entry(esc_time + timedelta(minutes=1), "sudo",
                         f"  {COMPROMISED_USER} : TTY=pts/2 ; PWD=/home/support ; "
                         "USER=root ; COMMAND=/bin/bash"),
        format_log_entry(esc_time + timedelta(minutes=1), "sudo",
                         "pam_unix(sudo:session): session opened for user root by (uid=0)"),
    ])

    # -- Phase 5: Backdoor account creation --
    persist_time = esc_time + timedelta(minutes=6)
    logs.append(format_log_entry(
        persist_time, "useradd",
        f"new user: name={BACKDOOR_USER}, UID=1003, GID=1003, "
        f"home=/home/{BACKDOOR_USER}, shell=/bin/bash"
    ))

    # -- Session cleanup --
    close_time = persist_time + timedelta(minutes=10)
    logs.extend([
        format_log_entry(close_time, "sudo",
                         "pam_unix(sudo:session): session closed for user root"),
        format_log_entry(close_time + timedelta(seconds=5), f"sshd[{pid}]",
                         f"pam_unix(sshd:session): session closed for user {COMPROMISED_USER}"),
    ])

    if verbose:
        logger.debug("  [Compromise] All escalation events recorded.")
    logger.info("Scenarios 4 & 5 — Compromise + Persistence: %d log lines generated.", len(logs))
    return logs


def generate_post_incident_sessions(base_time: datetime, verbose: bool) -> List[str]:
    """
    Scenario 6: Normal background activity resuming after the incident.
    Simulates 3 legitimate webdev sessions post-compromise (for baseline contrast).

    Args:
        base_time: Starting timestamp reference.
        verbose:   If True, logs each event.

    Returns:
        List of formatted log line strings.
    """
    logs: List[str] = []
    post_time = base_time + timedelta(hours=10)

    for i in range(3):
        pid = make_pid(25000, 29000)
        port = random.randint(50000, 65000)

        logs.extend([
            format_log_entry(post_time, f"sshd[{pid}]",
                             f"Connection from {NORMAL_IP} port {port} on ipv4"),
            format_log_entry(post_time + timedelta(seconds=3), f"sshd[{pid}]",
                             f"Accepted password for {NORMAL_USER} from {NORMAL_IP} port {port} ssh2"),
            format_log_entry(post_time + timedelta(minutes=30), f"sshd[{pid}]",
                             f"pam_unix(sshd:session): session closed for user {NORMAL_USER}"),
        ])
        if verbose:
            logger.debug("  [Post-Incident] Session %d recorded.", i + 1)
        post_time += timedelta(hours=2)

    logger.info("Scenario 6 — Post-incident baseline: %d log lines generated.", len(logs))
    return logs


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def generate_logs(output_path: str = None, verbose: bool = False) -> None:
    """
    Orchestrate all log generation scenarios and write the combined output
    to the specified file path, sorted chronologically.

    Args:
        output_path: File path to write the generated auth log.
        verbose:     Enable per-event debug logging.
    """
    if output_path is None:
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        output_path = os.path.join(project_root, "collected_logs", "auth_logs.txt")

    output_dir = os.path.dirname(output_path)
    os.makedirs(output_dir, exist_ok=True)

    if verbose:
        logger.setLevel(logging.DEBUG)

    logger.info("Starting synthetic auth log generation...")
    logger.info("Output target: %s", output_path)

    base_time = datetime.now() - timedelta(days=1)
    all_logs: List[str] = []

    try:
        all_logs += generate_normal_sessions(base_time, verbose)
        all_logs += generate_slow_bruteforce(base_time, verbose)
        all_logs += generate_rapid_bruteforce(base_time, verbose)
        all_logs += generate_compromise_and_escalation(base_time, verbose)
        all_logs += generate_post_incident_sessions(base_time, verbose)
    except Exception as exc:
        logger.error("Log generation failed: %s", exc)
        sys.exit(1)

    # Sort all events chronologically by timestamp
    try:
        all_logs.sort(key=lambda entry: datetime.strptime(entry[:15], "%b %d %H:%M:%S"))
    except ValueError as exc:
        logger.warning("Timestamp sort failed (non-critical): %s", exc)

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(all_logs) + "\n")
    except OSError as exc:
        logger.error("Failed to write log file: %s", exc)
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("Log generation complete!")
    logger.info("  Total events generated : %d", len(all_logs))
    logger.info("  Output file            : %s", output_path)
    logger.info("=" * 60)
    logger.info("Next step: python scripts/log_analyzer.py")


if __name__ == "__main__":
    args = parse_args()
    generate_logs(output_path=args.output, verbose=args.verbose)
