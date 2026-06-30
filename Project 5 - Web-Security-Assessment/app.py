"""
================================================================================
Web Application Security Assessment — Vulnerable Lab Target Server
================================================================================
Project     : Project 5 — Web Application Security Assessment & Vulnerability Detection
Author      : Web Security Analyst Intern
Date        : June 17, 2026
Version     : 2.0 (Professional Edition)
Description : A zero-dependency Python HTTP server simulating a deliberately
              vulnerable web application (DVWA-equivalent) for security testing
              practice. Demonstrates SQL Injection, Reflected XSS, Stored XSS,
              Insecure Authentication, and Session Management weaknesses.

              Supports a dual Security Level toggle:
                - LOW  : All vulnerabilities active (for attack demonstration)
                - SECURE: Defensive controls enabled (for remediation demonstration)

Usage       : python app.py
              Then visit: http://localhost:8080
================================================================================
EDUCATIONAL USE ONLY — DO NOT DEPLOY ON PRODUCTION SYSTEMS
================================================================================
"""

import html
import http.server
import logging
import socketserver
import time
import urllib.parse
from collections import defaultdict
from typing import Dict, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

PORT: int = 8080
HOST: str = ""
LOG_FORMAT: str = "[%(asctime)s] [%(levelname)s] %(message)s"
LOG_DATE_FMT: str = "%Y-%m-%d %H:%M:%S"

# Brute-force rate limiting (used in SECURE mode)
MAX_FAILED_ATTEMPTS: int = 5
LOCKOUT_SECONDS: int = 30

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt=LOG_DATE_FMT)
logger = logging.getLogger("VulnLabServer")

# ─────────────────────────────────────────────────────────────────────────────
# IN-MEMORY STATE
# ─────────────────────────────────────────────────────────────────────────────

# Simulated database users (vulnerable mode - passwords in plaintext)
USERS_DB: Dict[str, str] = {
    "admin": "password",
    "gordonb": "abc123",
    "smithy": "password",
}

# Guestbook entries for Stored XSS module
guestbook_messages: List[Dict[str, str]] = [
    {"name": "Admin", "message": "Welcome to the Vulnerability Lab Assessment Target!"}
]

# Failed login tracker: {ip_address: [timestamp, ...]}
failed_login_tracker: Dict[str, List[float]] = defaultdict(list)

# Active security level: "low" or "secure"
security_level: str = "low"


# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def sanitize_output(user_input: str) -> str:
    """Encode HTML special characters to prevent XSS. Used in SECURE mode."""
    return html.escape(user_input, quote=True)


def is_rate_limited(ip: str) -> bool:
    """
    Check if the given IP has exceeded the maximum allowed failed login
    attempts within the lockout window. Used in SECURE mode only.
    """
    now = time.time()
    # Filter attempts within the lockout window
    recent = [t for t in failed_login_tracker[ip] if now - t < LOCKOUT_SECONDS]
    failed_login_tracker[ip] = recent
    return len(recent) >= MAX_FAILED_ATTEMPTS


def record_failed_login(ip: str) -> None:
    """Record a failed login attempt from the given IP address."""
    failed_login_tracker[ip].append(time.time())
    logger.warning(
        "[SECURITY ALERT] Failed login attempt from IP: %s | Total recent failures: %d",
        ip,
        len(failed_login_tracker[ip]),
    )


def build_secure_cookie_headers() -> List[tuple]:
    """
    Return secure cookie attributes for SECURE mode:
    - HttpOnly : Prevents JavaScript access (mitigates XSS session theft)
    - SameSite=Lax : Protects against CSRF attacks
    Note: 'Secure' flag requires HTTPS; omitted here as we run plain HTTP.
    """
    return [
        ("Set-Cookie", "PHPSESSID=9a8b7c6d5e4f3a2b1c0d; Path=/; HttpOnly; SameSite=Lax"),
        ("Set-Cookie", f"security={security_level}; Path=/; HttpOnly; SameSite=Lax"),
    ]


def build_insecure_cookie_headers() -> List[tuple]:
    """
    Return insecure cookie headers for LOW (vulnerable) mode.
    Deliberately omits HttpOnly and Secure flags for demonstration purposes.
    """
    return [
        ("Set-Cookie", "PHPSESSID=9a8b7c6d5e4f3a2b1c0d; Path=/"),
        ("Set-Cookie", f"security={security_level}; Path=/"),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# HTML PAGE TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────

def get_page_header(active_path: str = "/") -> str:
    """Return the shared HTML header and navigation sidebar for all pages."""
    mode_badge = (
        '<span style="background:#ef4444;color:#fff;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700;">⚠ LOW (Vulnerable)</span>'
        if security_level == "low"
        else '<span style="background:#10b981;color:#fff;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700;">✅ SECURE (Protected)</span>'
    )

    toggle_url = "/set_security?level=secure" if security_level == "low" else "/set_security?level=low"
    toggle_label = "Switch to SECURE Mode" if security_level == "low" else "Switch to LOW (Vulnerable) Mode"
    toggle_color = "#10b981" if security_level == "low" else "#ef4444"

    nav_links = [
        ("/", "🏠 Dashboard"),
        ("/sqli", "💉 SQL Injection"),
        ("/xss_r", "⚡ XSS (Reflected)"),
        ("/xss_s", "💾 XSS (Stored)"),
        ("/brute", "🔑 Brute Force Auth"),
        ("/session_info", "🍪 Session Info"),
    ]

    nav_html = "\n".join(
        f'<a href="{url}" class="{"active" if url == active_path else ""}">{label}</a>'
        for url, label in nav_links
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Security Assessment Lab — {active_path}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
        .header {{ background: linear-gradient(90deg,#1e293b,#0f172a); padding: 14px 24px; border-bottom: 2px solid #2563eb; display: flex; justify-content: space-between; align-items: center; }}
        .header h1 {{ font-size: 18px; color: #93c5fd; font-weight: 700; }}
        .header .meta {{ display: flex; align-items: center; gap: 12px; font-size: 13px; }}
        .container {{ display: flex; min-height: calc(100vh - 56px); }}
        .sidebar {{ width: 220px; background: #1e293b; padding: 20px 12px; border-right: 1px solid #334155; flex-shrink: 0; }}
        .sidebar a {{ display: block; color: #94a3b8; padding: 10px 14px; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin-bottom: 4px; transition: all 0.15s; }}
        .sidebar a:hover {{ background: #334155; color: #e2e8f0; }}
        .sidebar a.active {{ background: #2563eb; color: #fff; }}
        .sidebar .divider {{ border-top: 1px solid #334155; margin: 12px 0; }}
        .sidebar .toggle-btn {{ display: block; margin-top: 16px; padding: 10px 14px; background: {toggle_color}22; color: {toggle_color}; border: 1px solid {toggle_color}44; border-radius: 6px; text-align: center; font-size: 13px; font-weight: 600; text-decoration: none; transition: all 0.15s; }}
        .sidebar .toggle-btn:hover {{ background: {toggle_color}33; }}
        .content {{ flex: 1; padding: 30px; }}
        .card {{ background: #1e293b; padding: 24px; border-radius: 10px; border: 1px solid #334155; margin-bottom: 20px; }}
        .card h2 {{ font-size: 20px; font-weight: 700; color: #f1f5f9; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid #334155; }}
        input[type=text], input[type=password], textarea {{ width: 100%; max-width: 400px; padding: 9px 12px; margin: 6px 0 12px; border: 1px solid #475569; background: #0f172a; color: #e2e8f0; border-radius: 6px; font-size: 14px; font-family: inherit; }}
        input[type=submit], button[type=submit] {{ background: #2563eb; color: white; padding: 9px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 600; font-family: inherit; }}
        input[type=submit]:hover {{ background: #1d4ed8; }}
        .vuln-box {{ background: #0f172a; padding: 16px; border-left: 4px solid #ef4444; margin-top: 16px; font-family: 'Courier New', monospace; font-size: 13px; border-radius: 0 6px 6px 0; }}
        .secure-box {{ background: #0f172a; padding: 16px; border-left: 4px solid #10b981; margin-top: 16px; border-radius: 0 6px 6px 0; font-size: 14px; }}
        .alert-info {{ background: #1e3a5f; border: 1px solid #2563eb; padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; font-size: 13.5px; color: #93c5fd; }}
        .alert-warn {{ background: #431407; border: 1px solid #ef4444; padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; font-size: 13.5px; color: #fca5a5; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
        code {{ background: #0f172a; padding: 2px 7px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; color: #60a5fa; }}
        .tag-vuln {{ background: #7f1d1d; color: #fca5a5; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
        .tag-secure {{ background: #14532d; color: #86efac; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
        .footer {{ padding: 16px 30px; background: #1e293b; border-top: 1px solid #334155; text-align: center; font-size: 12px; color: #475569; }}
    </style>
</head>
<body>
<div class="header">
    <h1>🛡️ Web Security Assessment Lab Target</h1>
    <div class="meta">
        {mode_badge}
        <span style="color:#475569;font-size:12px;">PHPSESSID: 9a8b7c6d...1c0d</span>
    </div>
</div>
<div class="container">
    <div class="sidebar">
        {nav_html}
        <div class="divider"></div>
        <a href="{toggle_url}" class="toggle-btn">{toggle_label}</a>
    </div>
    <div class="content">
"""


def get_page_footer() -> str:
    """Return shared HTML footer and closing tags for all pages."""
    return """
    </div><!-- /content -->
</div><!-- /container -->
<div class="footer">
    🔒 Web Security Assessment Lab Target — For Educational Purposes Only | Project 5 — June 17, 2026
</div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST HANDLER
# ─────────────────────────────────────────────────────────────────────────────

class VulnerableAppHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP request handler for the Vulnerable Web Application Lab.
    Routes GET and POST requests to the appropriate vulnerability module pages.
    Supports a dual security level: 'low' (vulnerable) and 'secure' (protected).
    """

    server_version = "VulnLabServer/2.0"
    sys_version = ""  # Suppress Python version from Server header

    def log_message(self, fmt: str, *args) -> None:
        """Override default logging to use structured logger."""
        logger.info("REQUEST | %s | %s", self.address_string(), fmt % args)

    def send_page(self, content: str, path: str = "/") -> None:
        """Helper to send a complete HTML page response with appropriate security headers."""
        full_html = get_page_header(path) + content + get_page_footer()
        body = full_html.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))

        # Set cookies based on current security level
        cookie_headers = (
            build_secure_cookie_headers()
            if security_level == "secure"
            else build_insecure_cookie_headers()
        )
        for header_name, header_value in cookie_headers:
            self.send_header(header_name, header_value)

        # Security headers (always applied)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        """Handle all incoming HTTP GET requests and route to the appropriate handler."""
        global security_level

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        try:
            if path in ("/", "/login"):
                self.handle_dashboard()
            elif path == "/sqli":
                self.handle_sqli(query)
            elif path == "/xss_r":
                self.handle_xss_reflected(query)
            elif path == "/xss_s":
                self.handle_xss_stored()
            elif path == "/brute":
                self.handle_brute(query)
            elif path == "/session_info":
                self.handle_session_info()
            elif path == "/set_security":
                level = query.get("level", ["low"])[0]
                if level in ("low", "secure"):
                    security_level = level
                    logger.info("Security level changed to: %s", security_level.upper())
                self.send_redirect("/")
            else:
                self.handle_404()
        except Exception as exc:
            logger.error("Unhandled exception for path %s: %s", path, exc)
            self.send_error(500, "Internal Server Error")

    def do_POST(self) -> None:
        """Handle POST requests (used by the Stored XSS guestbook module)."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")
            params = urllib.parse.parse_qs(post_data)

            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == "/xss_s_post":
                self.handle_xss_stored_post(params)
            else:
                self.send_error(404, "Not Found")
        except Exception as exc:
            logger.error("POST handler error: %s", exc)
            self.send_error(500, "Internal Server Error")

    def send_redirect(self, location: str) -> None:
        """Send an HTTP 302 redirect response."""
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    # ─────────────────────────────────────────────────────────────────────────
    # PAGE HANDLERS
    # ─────────────────────────────────────────────────────────────────────────

    def handle_dashboard(self) -> None:
        """Render the main dashboard / environment setup page."""
        mode_info = (
            '<span class="tag-vuln">LOW SECURITY — Vulnerabilities Active</span>'
            if security_level == "low"
            else '<span class="tag-secure">SECURE MODE — Defenses Enabled</span>'
        )
        content = f"""
        <div class="card">
            <h2>🏠 DVWA Dashboard &amp; Environment Setup</h2>
            <div class="alert-info">
                <strong>Lab Status:</strong> ✅ Target Application Running on
                <code>http://localhost:{PORT}</code> — Security Level: {mode_info}
            </div>
            <p>Welcome to the <strong>Web Application Security Assessment Lab</strong>.
            This environment simulates a deliberately vulnerable web application based on the
            <strong>DVWA (Damn Vulnerable Web Application)</strong> model.</p>
            <br>
            <p>Use the sidebar navigation to access each vulnerability module, execute
            test payloads, and capture screenshot evidence for your assessment report.</p>
            <br>
            <table>
                <tr><th>Module</th><th>Vulnerability</th><th>OWASP</th><th>Severity</th></tr>
                <tr><td>SQL Injection</td><td>In-Band / Union-Based SQLi</td><td>A03:2021</td><td><span class="tag-vuln">CRITICAL</span></td></tr>
                <tr><td>XSS Reflected</td><td>Reflected Cross-Site Scripting</td><td>A03:2021</td><td><span class="tag-vuln">HIGH</span></td></tr>
                <tr><td>XSS Stored</td><td>Stored Cross-Site Scripting</td><td>A03:2021</td><td><span class="tag-vuln">HIGH</span></td></tr>
                <tr><td>Brute Force</td><td>Missing Rate Limiting / Lockout</td><td>A07:2021</td><td><span class="tag-vuln">HIGH</span></td></tr>
                <tr><td>Session Mgmt</td><td>Insecure Cookie Attributes</td><td>A07:2021</td><td><span class="tag-vuln">MEDIUM</span></td></tr>
            </table>
        </div>"""
        self.send_page(content, "/")

    def handle_sqli(self, query: dict) -> None:
        """
        SQL Injection Module.
        LOW: Directly reflects raw user input and simulates vulnerable query output.
        SECURE: Validates input type (integer) and sanitizes output.
        """
        user_id = query.get("id", [""])[0]
        result_html = ""

        if user_id:
            if security_level == "low":
                # Simulate vulnerable SQL execution path
                if any(p in user_id for p in ("' OR", "OR '1'='1", "1' OR", "--", "UNION")):
                    logger.warning(
                        "[SECURITY ALERT] SQL Injection payload detected: %s", user_id
                    )
                    result_html = """
                    <div class="vuln-box">
                        <p><strong>[!] SQL Injection Successful — All Records Exposed:</strong></p>
                        <p>ID: ' OR 1=1 -- &nbsp;| First name: <strong>admin</strong> | Surname: <strong>admin</strong></p>
                        <p>ID: ' OR 1=1 -- &nbsp;| First name: <strong>Gordon</strong> | Surname: <strong>Brown</strong></p>
                        <p>ID: ' OR 1=1 -- &nbsp;| First name: <strong>Hack</strong> | Surname: <strong>Me</strong></p>
                        <p>ID: ' OR 1=1 -- &nbsp;| First name: <strong>Pablo</strong> | Surname: <strong>Escobar</strong></p>
                        <p>ID: ' OR 1=1 -- &nbsp;| First name: <strong>Bob</strong> | Surname: <strong>Smith</strong></p>
                    </div>"""
                elif user_id == "1":
                    result_html = """
                    <div class="vuln-box">
                        <p>ID: 1 | First name: <strong>admin</strong> | Surname: <strong>admin</strong></p>
                    </div>"""
                else:
                    result_html = f'<div class="vuln-box"><p>ID: {user_id} — not found or SQL syntax error.</p></div>'
            else:
                # Secure mode: strict integer validation
                if not user_id.isdigit():
                    result_html = """
                    <div class="secure-box">
                        <p>✅ <strong>Input Rejected:</strong> User ID must be a positive integer.
                        Parameterized queries are enforced — SQL injection is not possible.</p>
                    </div>"""
                elif user_id == "1":
                    safe_id = sanitize_output(user_id)
                    result_html = f"""
                    <div class="secure-box">
                        <p>✅ <strong>Query executed safely using parameterized statement:</strong></p>
                        <code>SELECT first_name, last_name FROM users WHERE user_id = {safe_id}</code>
                        <p style="margin-top:10px;">ID: {safe_id} | First name: admin | Surname: admin</p>
                    </div>"""
                else:
                    result_html = '<div class="secure-box"><p>✅ No records found for that ID.</p></div>'

        mode_note = (
            '<div class="alert-warn">⚠️ <strong>LOW Security Mode:</strong> '
            'Input is directly interpolated into SQL. Try: <code>\' OR 1=1 --</code></div>'
            if security_level == "low"
            else '<div class="alert-info">✅ <strong>SECURE Mode:</strong> '
            'Input is validated and passed via parameterized query (PDO). SQL injection is prevented.</div>'
        )

        safe_user_id = sanitize_output(user_id)
        content = f"""
        <div class="card">
            <h2>💉 Vulnerability: SQL Injection (SQLi)</h2>
            {mode_note}
            <form action="/sqli" method="GET">
                <label>User ID:</label><br>
                <input type="text" name="id" value="{safe_user_id}" placeholder="Try: 1  or  ' OR 1=1 --"><br>
                <input type="submit" value="Submit Query">
            </form>
            {result_html}
        </div>"""
        self.send_page(content, "/sqli")

    def handle_xss_reflected(self, query: dict) -> None:
        """
        Reflected XSS Module.
        LOW: Raw user input is reflected directly into the DOM, enabling script injection.
        SECURE: Output is HTML-encoded before rendering using html.escape().
        """
        name = query.get("name", [""])[0]
        result_html = ""

        if name:
            if security_level == "low":
                logger.warning("[SECURITY ALERT] Reflected XSS input received: %s", name[:80])
                result_html = (
                    f'<div class="vuln-box"><p>Hello {name}</p>'
                    f"<script>alert('XSS Reflected Vulnerability Confirmed — Input: ' + decodeURIComponent('{urllib.parse.quote(name)}'));</script></div>"
                )
            else:
                safe_name = sanitize_output(name)
                result_html = f"""
                <div class="secure-box">
                    <p>✅ <strong>Output safely encoded:</strong> Hello, {safe_name}</p>
                    <p style="font-size:13px;color:#64748b;">
                    Input was sanitized using <code>html.escape()</code> before rendering.
                    </p>
                </div>"""

        mode_note = (
            '<div class="alert-warn">⚠️ <strong>LOW Security Mode:</strong> '
            'User input is reflected without encoding. Try: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></div>'
            if security_level == "low"
            else '<div class="alert-info">✅ <strong>SECURE Mode:</strong> '
            'Output is HTML-entity encoded. XSS scripts are neutralized.</div>'
        )

        safe_name_attr = sanitize_output(name)
        content = f"""
        <div class="card">
            <h2>⚡ Vulnerability: Cross-Site Scripting (Reflected XSS)</h2>
            {mode_note}
            <form action="/xss_r" method="GET">
                <label>What is your name?</label><br>
                <input type="text" name="name" value="{safe_name_attr}"
                    placeholder="&lt;script&gt;alert('XSS')&lt;/script&gt;"><br>
                <input type="submit" value="Submit">
            </form>
            {result_html}
        </div>"""
        self.send_page(content, "/xss_r")

    def handle_xss_stored(self) -> None:
        """
        Stored XSS Module — Guestbook.
        LOW: Guestbook entries are stored and rendered without sanitization.
        SECURE: Stored content is HTML-encoded before display.
        """
        entries_html = ""
        for entry in guestbook_messages:
            if security_level == "low":
                # Render raw (dangerous)
                name_display = entry["name"]
                msg_display = entry["message"]
            else:
                # Encode stored content before rendering (safe)
                name_display = sanitize_output(entry["name"])
                msg_display = sanitize_output(entry["message"])
            entries_html += (
                f"<p><strong>{name_display}:</strong> {msg_display}</p><hr style='border-color:#334155'>"
            )

        mode_note = (
            '<div class="alert-warn">⚠️ <strong>LOW Security Mode:</strong> '
            'Guestbook entries are stored and rendered without sanitization. '
            'Try: Name=Attacker, Message=<code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></div>'
            if security_level == "low"
            else '<div class="alert-info">✅ <strong>SECURE Mode:</strong> '
            'All stored content is HTML-encoded before rendering. Stored XSS is prevented.</div>'
        )

        content = f"""
        <div class="card">
            <h2>💾 Vulnerability: Cross-Site Scripting (Stored XSS)</h2>
            {mode_note}
            <form action="/xss_s_post" method="POST">
                <label>Name:</label><br>
                <input type="text" name="name" placeholder="Your name"><br>
                <label>Message:</label><br>
                <input type="text" name="message" placeholder="Your message or payload"><br>
                <input type="submit" value="Sign Guestbook">
            </form>
        </div>
        <div class="card">
            <h2>📋 Guestbook Entries</h2>
            <div class="vuln-box" style="border-color:#{'ef4444' if security_level == 'low' else '10b981'}">
                {entries_html}
            </div>
        </div>"""
        self.send_page(content, "/xss_s")

    def handle_xss_stored_post(self, params: dict) -> None:
        """Process Stored XSS guestbook POST submission."""
        name = params.get("name", ["Anonymous"])[0][:100]  # Limit length
        message = params.get("message", [""])[0][:500]  # Limit length
        guestbook_messages.append({"name": name, "message": message})
        logger.info("Guestbook entry added | Name: %s | Length: %d chars", name[:20], len(message))
        self.send_redirect("/xss_s")

    def handle_brute(self, query: dict) -> None:
        """
        Brute Force Authentication Module.
        LOW: No rate limiting — unlimited login attempts allowed.
        SECURE: IP-based lockout after 5 failed attempts within 30 seconds.
        """
        username = query.get("username", [""])[0]
        password = query.get("password", [""])[0]
        result_html = ""
        client_ip = self.client_address[0]

        if username and password:
            if security_level == "low":
                # No rate limiting — direct credential check
                if username in USERS_DB and USERS_DB[username] == password:
                    logger.warning(
                        "[SECURITY ALERT] Successful brute force — credentials valid: %s", username
                    )
                    result_html = (
                        '<div class="vuln-box" style="border-color:#10b981">'
                        f"<p>✅ <strong>Welcome back, {sanitize_output(username)}!</strong> — Login successful.</p>"
                        "<p style='color:#ef4444;margin-top:8px;'>⚠ No rate limiting was enforced. Brute force attack succeeded.</p></div>"
                    )
                else:
                    result_html = '<div class="vuln-box"><p>❌ Username and/or password incorrect.</p></div>'
            else:
                # Secure mode: enforce rate limiting
                if is_rate_limited(client_ip):
                    result_html = f"""
                    <div class="secure-box">
                        <p>🔒 <strong>Account Temporarily Locked</strong></p>
                        <p>Too many failed attempts detected from your IP address.
                        Please wait {LOCKOUT_SECONDS} seconds before retrying.</p>
                    </div>"""
                elif username in USERS_DB and USERS_DB[username] == password:
                    failed_login_tracker[client_ip].clear()
                    result_html = f"""
                    <div class="secure-box">
                        <p>✅ <strong>Login successful</strong> — Welcome, {sanitize_output(username)}!</p>
                        <p style="font-size:13px;color:#64748b;">Rate limiting and lockout policies are active in SECURE mode.</p>
                    </div>"""
                else:
                    record_failed_login(client_ip)
                    attempts = len(failed_login_tracker[client_ip])
                    remaining = MAX_FAILED_ATTEMPTS - attempts
                    result_html = f"""
                    <div class="secure-box">
                        <p>❌ Invalid credentials. <strong>{remaining} attempt(s) remaining</strong>
                        before temporary IP lockout ({LOCKOUT_SECONDS}s).</p>
                    </div>"""

        mode_note = (
            '<div class="alert-warn">⚠️ <strong>LOW Security Mode:</strong> '
            'No rate limiting enforced. Try credentials: <code>admin / password</code> — '
            'unlimited attempts permitted.</div>'
            if security_level == "low"
            else '<div class="alert-info">✅ <strong>SECURE Mode:</strong> '
            f'IP-based lockout active: {MAX_FAILED_ATTEMPTS} failed attempts triggers a {LOCKOUT_SECONDS}s lockout.</div>'
        )

        content = f"""
        <div class="card">
            <h2>🔑 Vulnerability: Insecure Authentication (Brute Force)</h2>
            {mode_note}
            <form action="/brute" method="GET">
                <label>Username:</label><br>
                <input type="text" name="username" placeholder="admin"><br>
                <label>Password:</label><br>
                <input type="password" name="password" placeholder="password"><br>
                <input type="submit" value="Login">
            </form>
            {result_html}
        </div>"""
        self.send_page(content, "/brute")

    def handle_session_info(self) -> None:
        """
        Session Information & Cookie Inspection Module.
        Displays current cookie headers so users can verify security flag presence/absence.
        """
        if security_level == "low":
            cookie_str = "PHPSESSID=9a8b7c6d5e4f3a2b1c0d; Path=/"
            flags_info = """
            <tr><td><code>PHPSESSID</code></td><td><span style="color:#ef4444">❌ Missing</span></td>
                <td><span style="color:#ef4444">❌ Missing</span></td>
                <td><span style="color:#ef4444">❌ None</span></td>
                <td><span class="tag-vuln">VULNERABLE</span></td></tr>"""
            note = '<div class="alert-warn">⚠️ Session cookie has no HttpOnly, Secure, or SameSite flags. It can be stolen via XSS.</div>'
        else:
            cookie_str = "PHPSESSID=9a8b7c6d5e4f3a2b1c0d; Path=/; HttpOnly; SameSite=Lax"
            flags_info = """
            <tr><td><code>PHPSESSID</code></td>
                <td><span style="color:#10b981">✅ Set</span></td>
                <td><span style="color:#fbbf24">⚠ HTTP only</span></td>
                <td><span style="color:#10b981">✅ Lax</span></td>
                <td><span class="tag-secure">PROTECTED</span></td></tr>"""
            note = '<div class="alert-info">✅ Cookie is protected with HttpOnly and SameSite=Lax flags. (Secure flag requires HTTPS.)</div>'

        content = f"""
        <div class="card">
            <h2>🍪 Session Management — Cookie Security Inspection</h2>
            {note}
            <p><strong>Raw Set-Cookie Header:</strong></p>
            <div class="vuln-box" style="border-color:#{'ef4444' if security_level == 'low' else '10b981'}">
                <code>{sanitize_output(cookie_str)}</code>
            </div>
            <br>
            <table>
                <tr>
                    <th>Cookie Name</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th><th>Status</th>
                </tr>
                {flags_info}
            </table>
            <br>
            <p style="font-size:13.5px;color:#94a3b8;">
                To inspect cookie flags in the browser: Press <code>F12</code> →
                Application tab → Cookies → <code>http://localhost:{PORT}</code>
            </p>
        </div>"""
        self.send_page(content, "/session_info")

    def handle_404(self) -> None:
        """Return a styled 404 Not Found page."""
        content = """
        <div class="card">
            <h2>404 — Page Not Found</h2>
            <p>The requested resource does not exist on this server.</p>
        </div>"""
        body = (get_page_header("/") + content + get_page_footer()).encode("utf-8")
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ─────────────────────────────────────────────────────────────────────────────
# SERVER ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Start the vulnerable lab HTTP server and handle shutdown gracefully."""
    logger.info("=" * 70)
    logger.info("Web Application Security Assessment Lab — Server Starting")
    logger.info("=" * 70)
    logger.info("Target URL    : http://localhost:%d", PORT)
    logger.info("Security Level: %s", security_level.upper())
    logger.info("Mode          : EDUCATIONAL — DO NOT USE IN PRODUCTION")
    logger.info("=" * 70)
    logger.info("Available Modules:")
    logger.info("  /          → Dashboard")
    logger.info("  /sqli      → SQL Injection (SQLi)")
    logger.info("  /xss_r     → Reflected XSS")
    logger.info("  /xss_s     → Stored XSS (Guestbook)")
    logger.info("  /brute     → Brute Force Authentication")
    logger.info("  /session_info → Session Cookie Inspection")
    logger.info("=" * 70)
    logger.info("Press CTRL+C to stop the server.")

    try:
        with socketserver.TCPServer((HOST, PORT), VulnerableAppHandler) as httpd:
            httpd.allow_reuse_address = True
            httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested. Stopping gracefully...")
    except OSError as exc:
        logger.error("Failed to bind to port %d: %s", PORT, exc)
        logger.error("Ensure the port is not already in use and retry.")


if __name__ == "__main__":
    main()
