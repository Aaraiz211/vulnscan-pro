# 📖 VulnScan Pro — Usage Guide

This document covers everything you need to install, configure, and use VulnScan Pro effectively — from first run to exporting your final report.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation](#installation)
  - [Windows](#windows)
  - [Linux / Kali](#linux--kali)
  - [macOS](#macos)
- [Starting the Tool](#starting-the-tool)
- [First Run — Authorization Gate](#first-run--authorization-gate)
- [Running a Scan](#running-a-scan)
  - [Step 1 — Enter Target](#step-1--enter-target)
  - [Step 2 — Select Modules](#step-2--select-modules)
  - [Step 3 — Start Scan](#step-3--start-scan)
  - [Step 4 — Read the Scan Log](#step-4--read-the-scan-log)
  - [Step 5 — Review Findings](#step-5--review-findings)
- [Exporting Reports](#exporting-reports)
- [Module Reference](#module-reference)
- [Interpreting Findings](#interpreting-findings)
- [Troubleshooting](#troubleshooting)
- [Recommended Lab Targets](#recommended-lab-targets)

---

## System Requirements

| Requirement | Minimum |
|-------------|---------|
| Python | 3.8 or higher |
| pip | Any recent version |
| RAM | 512 MB free |
| Network | Internet or LAN access to target |
| Browser | Chrome, Firefox, or Edge (modern version) |
| OS | Windows 10+, Kali Linux, Ubuntu, macOS |

---

## Installation

### Windows

**Step 1 — Install Python**

Download Python 3.x from [python.org/downloads](https://www.python.org/downloads/).

> ⚠️ During installation, tick **"Add python.exe to PATH"** — this is critical.

**Step 2 — Verify installation**

Open PowerShell and run:
```powershell
python --version
```
You should see `Python 3.x.x`.

**Step 3 — Clone or download the repository**

```powershell
# Option A — Git clone
git clone https://github.com/Aaraiz211/vulnscan-pro.git
cd vulnscan-pro

# Option B — Download ZIP from GitHub
# Extract the ZIP, then cd into the folder
```

**Step 4 — Install dependencies**

```powershell
python -m pip install -r requirements.txt
```

> If `pip` is not found, use `python -m pip` instead of `pip` directly.

**Step 5 — Run**

```powershell
python app.py
```

---

### Linux / Kali

```bash
# Clone the repo
git clone https://github.com/Aaraiz211/vulnscan-pro.git
cd vulnscan-pro

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python3 app.py
```

---

### macOS

```bash
# Install Python if needed
brew install python3

# Clone and install
git clone https://github.com/Aaraiz211/vulnscan-pro.git
cd vulnscan-pro
pip3 install -r requirements.txt

# Run
python3 app.py
```

---

## Starting the Tool

When you run `python app.py`, you will see the startup banner:

```
=======================================================
  VulnScan Pro v1.0.0
  Author : Aaraiz Tahir | Air University BS CYS
  For authorized penetration testing only.
=======================================================
  Starting server → http://127.0.0.1:5000
=======================================================
```

Open your browser and navigate to:

```
http://127.0.0.1:5000
```

The top-right corner of the interface will show a **teal pulsing dot** confirming the server is online.

> Keep the terminal window open while using the tool — closing it shuts down the backend.

---

## First Run — Authorization Gate

Every session begins with a mandatory authorization modal. This cannot be skipped.

1. Read the authorization requirements carefully
2. Tick the checkbox: **"I confirm I have written authorization to scan the target"**
3. Click **Accept & Continue**

> If you do not have written authorization from the target system owner, click **Exit** and do not proceed.

---

## Running a Scan

### Step 1 — Enter Target

In the **Target URL or IP Address** field, enter your target in any of these formats:

```
https://example.com
http://192.168.1.10
192.168.1.10
http://localhost:8080
```

The tool will automatically resolve hostnames to IP addresses for port scanning.

---

### Step 2 — Select Modules

Check or uncheck the scan modules based on your engagement scope:

| Module | Tag | What it does |
|--------|-----|--------------|
| ✅ Port Scan | NET | Scans 20 common TCP ports |
| ✅ HTTP Headers | SAST | Checks security response headers |
| ✅ SSL / TLS | NET | Inspects certificate and encryption config |
| ✅ Dir Enum | DAST | Probes for exposed paths and files |
| ✅ Injection Points | DAST | Passively detects SQLi/XSS risk fields |

All modules are selected by default. Deselect any you don't need to speed up the scan.

---

### Step 3 — Start Scan

Click the **▶ Start Scan** button.

- The button changes to **⏳ Scanning...**
- A progress bar appears showing percentage completion
- The **Scan Log** terminal begins printing timestamped output in real time

Typical scan duration: **30–90 seconds** depending on target responsiveness and modules selected.

---

### Step 4 — Read the Scan Log

The scan log uses color-coded output:

| Color | Prefix | Meaning |
|-------|--------|---------|
| 🔵 Cyan | `[INFO]` | Module started, action taken |
| 🟢 Green | `[ OK ]` | Check passed, no issue |
| 🟡 Yellow | `[WARN]` | Potential issue detected |
| 🔴 Red | `[ERR ]` | Problem found or connection failed |
| ⬜ Dim | `[SYS ]` | System/backend message |

Example log output:
```
01:48:43 [INFO] Starting real scan: http://10.135.136.5
01:48:43 [INFO] Modules: port, header, ssl, dir, injection
01:48:45 [INFO] Resolved 10.135.136.5 → 10.135.136.5
01:48:46 [WARN] Open port: 23/Telnet
01:48:46 [ERR ] Open port: 23 — CRITICAL risk
01:48:50 [ OK ] Scan complete. 3 findings.
```

---

### Step 5 — Review Findings

Once the scan completes, all findings appear in the **Findings** table sorted by severity:

| Column | Description |
|--------|-------------|
| # | Finding number (zero-padded) |
| Severity | CRITICAL / HIGH / MEDIUM / LOW / INFO badge |
| Module | Which scanner found this |
| Finding | Short finding name |
| Description | What the issue means and its risk |
| Reference | CWE identifier |
| Detail | Specific remediation or follow-up action |

The **Severity Breakdown** chart on the right updates to show counts per severity level.

---

## Exporting Reports

After a scan completes, two export buttons appear at the bottom of the Findings panel:

### ⬇ Export HTML Report

Downloads a standalone `.html` file — a dark-themed formal penetration test report containing:
- Tool name, author, target, date, modules run
- Executive summary with severity counts
- Full findings table with all columns
- Suitable for sharing with a client or including in a portfolio

Open the downloaded file in any browser. No internet connection required to view it.

### ⬇ Export JSON

Downloads a `.json` file with this structure:

```json
{
  "tool": "VulnScan Pro v1.0.0",
  "target": "http://10.135.136.5",
  "scan_date": "2026-06-06T20:55:00Z",
  "modules_run": ["port", "ssl"],
  "summary": { "critical": 1, "high": 1, "low": 1 },
  "findings": [
    {
      "severity": "critical",
      "module": "Port Scanner",
      "name": "Open Port: 23 (Telnet)",
      "description": "Telnet is unencrypted. Disable immediately.",
      "reference": "CWE-319",
      "detail": "Host: 10.135.136.5 | Port: 23 | Service: Telnet"
    }
  ]
}
```

Useful for programmatic processing or SIEM ingestion.

---

## Module Reference

### Port Scanner

Scans using Python's `socket` library with a `ThreadPoolExecutor` for parallel scanning. Each port attempt has a 1-second timeout. Results are enriched from an internal risk database.

**Risk levels by port:**

| Port | Service | Risk |
|------|---------|------|
| 23 | Telnet | CRITICAL — plaintext protocol |
| 445 | SMB | CRITICAL — ransomware target |
| 6379 | Redis | CRITICAL — often unauthenticated |
| 27017 | MongoDB | CRITICAL — often unauthenticated |
| 3306 | MySQL | HIGH — DB exposed to network |
| 3389 | RDP | HIGH — brute force target |
| 22 | SSH | LOW — ensure key-based auth |
| 80/443 | HTTP/S | INFO — verify config |

---

### Header Analyzer

Makes a live HTTP GET request to the target and inspects response headers. Falls back from HTTPS to HTTP automatically if SSL fails.

**Required security headers:**

| Header | Severity if Missing | Purpose |
|--------|-------------------|---------|
| Strict-Transport-Security | MEDIUM | Enforce HTTPS |
| Content-Security-Policy | MEDIUM | Prevent XSS |
| X-Frame-Options | MEDIUM | Prevent clickjacking |
| X-Content-Type-Options | LOW | Prevent MIME sniffing |
| Referrer-Policy | LOW | Control referrer leakage |
| Permissions-Policy | LOW | Restrict browser features |
| X-XSS-Protection | LOW | Legacy XSS filter |

---

### SSL/TLS Checker

Connects via Python's `ssl` module and inspects the live TLS session. Certificate parsing uses the `cryptography` library.

**What is checked:**
- Certificate expiry (CRITICAL if expired, HIGH if <15 days, MEDIUM if <30 days)
- Self-signed detection
- Negotiated protocol version (TLS 1.0/1.1 = HIGH)
- Cipher suite strength (RC4/3DES/NULL = HIGH)
- HSTS header presence (MEDIUM if missing)

---

### Directory Enumerator

Sends `HEAD` or `GET` requests to 40+ common paths concurrently (20 threads). HTTP 200, 301, 302, and 403 responses are all recorded as findings with context-aware severity.

**High-value paths:**

```
/.env              → CRITICAL (credentials)
/.git/config       → CRITICAL (source code)
/wp-config.php     → CRITICAL (WordPress DB)
/backup.sql        → CRITICAL (database dump)
/phpinfo.php       → HIGH (server info)
/phpmyadmin        → HIGH (DB management)
/admin             → MEDIUM (admin panel)
/swagger-ui.html   → INFO (API docs)
```

---

### Injection Detector

Fetches the target page HTML and parses it using Python's built-in `html.parser`. No payloads are sent. Findings are flagged for manual follow-up.

**Detection logic:**
- URL parameters matching risk patterns → flagged for SQLi and/or XSS
- Form input `name` attributes matching risk patterns → flagged
- Password fields in `method="GET"` forms → HIGH finding
- `innerHTML`, `document.write`, `eval()` in page JS → LOW finding

**Follow-up tools for flagged points:**
```bash
# SQLi — use SQLMap
sqlmap -u "http://target.com/page?id=1" --dbs

# XSS — use Burp Suite or manual testing
# Inject: <script>alert(1)</script> in flagged fields
```

---

## Interpreting Findings

| Severity | Action |
|----------|--------|
| 🔴 CRITICAL | Fix immediately. Exploit risk is direct and high-impact. |
| 🟠 HIGH | Fix before deployment. Significant risk to confidentiality/integrity. |
| 🟡 MEDIUM | Fix in next patch cycle. Risk exists but requires specific conditions. |
| 🟢 LOW | Fix when convenient. Minimal direct risk but contributes to attack surface. |
| 🔵 INFO | Informational. Review and decide based on context. |

---

## Troubleshooting

### `pip` not recognized on Windows
```powershell
python -m pip install -r requirements.txt
```

### `No module named pip`
```powershell
python -m ensurepip --upgrade
python -m pip install -r requirements.txt
```

### Server shows offline in browser
- Make sure `python app.py` is still running in the terminal
- Check you are visiting `http://127.0.0.1:5000` (not HTTPS)
- Try restarting the server

### Scan times out on target
- The target may be blocking your requests (firewall, rate limiting)
- Try a different test target from the recommended list below
- Check your network connection to the target

### SSL module errors on Windows
```powershell
pip install --upgrade cryptography
```

---

## Recommended Lab Targets

> These are intentionally vulnerable systems. Only use them in a lab environment.

| Target | How to set up |
|--------|---------------|
| DVWA (Docker) | `docker run -d -p 8080:80 vulnerables/web-dvwa` then scan `http://localhost:8080` |
| DVWA (XAMPP) | Install XAMPP → drop DVWA in `htdocs/dvwa` → scan `http://localhost/dvwa` |
| Metasploitable 2 | Run in VMware/VirtualBox → scan its IP |
| Your own router | Scan your gateway IP (e.g. `192.168.1.1`) — you own it |
| testphp.vulnweb.com | Public Acunetix demo site (network access required) |

---

<div align="center">
<sub>VulnScan Pro v1.0.0 | Aaraiz Tahir | BS Cybersecurity — Air University | For authorized use only</sub>
</div>
