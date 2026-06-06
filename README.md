# 🔍 VulnScan Pro — Web Vulnerability Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.3+-green?style=for-the-badge&logo=flask)
![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)
![CEH](https://img.shields.io/badge/CEH-Aligned-red?style=for-the-badge)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-orange?style=for-the-badge)

**A real-time, modular web vulnerability scanner with an IBM QRadar-inspired dark GUI.**
Built for authorized penetration testing engagements by security professionals and students.

[Features](#features) • [Screenshots](#screenshots) • [Installation](#installation) • [Usage](#usage) • [Modules](#modules) • [Reports](#reports) • [Author](#author)

</div>

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized penetration testing only.**
> Only scan systems you own or have explicit **written permission** to test.
> Unauthorized scanning is illegal under the CFAA (US), Computer Misuse Act (UK), PECA (Pakistan), and equivalent laws worldwide.
> The author accepts **no responsibility** for misuse of this tool.

VulnScan Pro enforces this through a mandatory **authorization gate** that must be acknowledged before every scan session.

---

## Overview

VulnScan Pro is a full-stack, self-contained vulnerability assessment tool that combines a **Python Flask backend** scanning engine with a **browser-based IBM QRadar-inspired GUI**. It performs live reconnaissance across five attack surface categories and produces professional-grade reports mapped to OWASP Top 10 and CWE identifiers.

Unlike most open-source scanners that are either too narrow in scope or require complex setup, VulnScan Pro packages five distinct scanning modules into a single application that runs on any machine with Python installed — no cloud dependency, no subscription, no compromise on depth.

---

## Features

| Feature | Description |
|---------|-------------|
| 🔌 Port Scanner | Scans 20 common TCP ports, identifies services, and maps risk levels |
| 📋 Header Analyzer | Checks 7 critical security headers + cookie flags + server info disclosure |
| 🔐 SSL/TLS Checker | Validates certificates, TLS versions, cipher suites, and HSTS enforcement |
| 📁 Dir Enumeration | Probes 40+ sensitive paths — admin panels, config files, backups, Git repos |
| 💉 Injection Detector | Passively identifies SQLi/XSS-prone fields and dangerous JS sinks |
| 📊 Live Dashboard | Real-time severity breakdown chart and timestamped scan log terminal |
| 📄 Report Export | One-click HTML and JSON report export with CWE references |
| 🛡️ Auth Gate | Mandatory authorization confirmation before every scan |
| 🌐 Cross-Platform | Runs on Windows, Linux (Kali), and macOS |

---

## Screenshots

### Authorization Gate
Every session begins with a mandatory authorization modal. Scanning is locked until the user explicitly confirms written permission.

![Authorization Gate](docs/screenshots/auth_gate.png)

### Main Dashboard
IBM QRadar-inspired dark interface with module selector, severity chart, and live log terminal.

![Dashboard](docs/screenshots/dashboard.png)

### Scan in Progress
Real-time progress bar and timestamped log output during active scanning.

![Scan Progress](docs/screenshots/scan_progress.png)

### Findings Table
Color-coded severity findings with CWE references and remediation details.

![Findings](docs/screenshots/findings.png)

### Exported HTML Report
Standalone dark-themed report ready to share as a pen test deliverable.

![Report](docs/screenshots/html_report.png)

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- A modern web browser (Chrome, Firefox, Edge)

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/Aaraiz211/vulnscan-pro.git
cd vulnscan-pro

# 2. (Recommended) Create a virtual environment
python -m venv venv

# Activate on Linux/macOS:
source venv/bin/activate

# Activate on Windows:
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the server
python app.py
```

### 5. Open in browser

```
http://127.0.0.1:5000
```

That's it. No configuration files. No API keys required for core functionality.

---

## Modules

### 🔌 Port Scanner (`modules/port_scanner.py`)
Uses concurrent Python `socket` connections to scan 20 high-value TCP ports. Each open port is assessed against a built-in risk database and enriched with service identification, risk severity, and CWE mapping.

**Ports covered:** 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 143 (IMAP), 443 (HTTPS), 445 (SMB), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 5900 (VNC), 6379 (Redis), 8080, 8443, 27017 (MongoDB), 9200 (Elasticsearch), 11211 (Memcached)

### 📋 Header Analyzer (`modules/header_analyzer.py`)
Fetches live HTTP response headers and checks for the presence and correct configuration of critical security headers. Also inspects cookie flags and server fingerprinting headers.

**Headers checked:** `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection`

**Also detects:** `Server`, `X-Powered-By`, `X-AspNet-Version` disclosure and insecure cookie flags (`Secure`, `HttpOnly`).

### 🔐 SSL/TLS Checker (`modules/ssl_checker.py`)
Establishes a live TLS handshake with the target and inspects the full certificate chain, protocol version negotiation, cipher suite strength, and HSTS header enforcement.

**Checks:** Certificate expiry, self-signed detection, TLS 1.0/1.1 support, weak cipher suites (RC4, 3DES, NULL, EXPORT), HSTS presence.

### 📁 Directory Enumerator (`modules/dir_enum.py`)
Sends concurrent HTTP requests to 40+ known sensitive paths. Findings are enriched with context-aware severity — a `.env` file exposure is `CRITICAL`, a `403 Forbidden` on `/admin` is `LOW`.

**Paths probed:** `/.env`, `/.git/config`, `/wp-config.php`, `/backup.zip`, `/db.sql`, `/phpinfo.php`, `/phpmyadmin`, `/actuator/env`, `/swagger-ui.html`, and 30+ more.

### 💉 Injection Point Detector (`modules/injection_detector.py`)
Passively parses the target page HTML — **no attack payloads are sent**. Identifies form fields and URL parameters matching known SQLi/XSS risk patterns. Also scans inline JavaScript for dangerous sinks.

**Detects:** Risky form input names (`id`, `username`, `search`, `query`), reflected URL parameters, password fields submitted via GET, and JS sinks (`innerHTML`, `document.write`, `eval()`).

> **Why passive only?** Firing injection payloads against a live target without a controlled scope is irresponsible. Identified points are flagged for manual follow-up with tools like SQLMap or Burp Suite — the correct methodology for a real engagement.

---

## Reports

VulnScan Pro generates two report formats after every scan:

### HTML Report
A standalone dark-themed document matching the tool's visual identity. Opens in any browser. Includes:
- Executive summary with severity count breakdown
- Full findings table with severity badges, module attribution, descriptions, and CWE references
- Author, institution, target, date, and modules run
- Suitable as a formal penetration test deliverable

### JSON Report
A structured machine-readable format following this schema:

```json
{
  "tool": "VulnScan Pro v1.0.0",
  "author": "Aaraiz Tahir | BS Cybersecurity — Air University",
  "target": "https://example.com",
  "scan_date": "2026-06-06T20:55:00Z",
  "modules_run": ["port", "header", "ssl", "dir", "injection"],
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 1,
    "info": 0
  },
  "total_findings": 7,
  "findings": [...]
}
```

Can be ingested by SIEM platforms or processed programmatically.

---

## Project Structure

```
vulnscan_pro/
├── app.py                    ← Flask backend + REST API
├── requirements.txt          ← Python dependencies
├── README.md
├── USAGE.md
├── modules/
│   ├── __init__.py
│   ├── port_scanner.py       ← TCP port scanning
│   ├── header_analyzer.py    ← HTTP security headers
│   ├── ssl_checker.py        ← SSL/TLS inspection
│   ├── dir_enum.py           ← Directory enumeration
│   ├── injection_detector.py ← Passive injection detection
│   └── reporter.py           ← HTML + JSON report generation
└── templates/
    └── index.html            ← QRadar-inspired frontend
```

---

## API Reference

VulnScan Pro exposes a simple REST API:

### `POST /api/scan`

```json
{
  "target": "https://example.com",
  "modules": ["port", "header", "ssl", "dir", "injection"],
  "authorized": true
}
```

**Response:**
```json
{
  "findings": [...],
  "logs": [...],
  "report_json": {...},
  "report_html": "..."
}
```

### `GET /api/health`

Returns server status. Used by the frontend to show the connection indicator.

---

## Recommended Test Targets

> Only scan targets you own or have permission to test.

| Target | Description |
|--------|-------------|
| `http://testphp.vulnweb.com` | Acunetix intentionally vulnerable PHP app |
| `http://localhost/dvwa` | DVWA (requires local XAMPP/Docker setup) |
| `http://localhost:8080` | DVWA via Docker (`docker run -d -p 8080:80 vulnerables/web-dvwa`) |
| Your own server | Any system you own or have written authorization to test |

---

## Methodology

VulnScan Pro follows the **CEH (Certified Ethical Hacker)** penetration testing methodology and maps all findings to:

- **OWASP Top 10** — A01 through A10 coverage
- **CWE** — Common Weakness Enumeration identifiers on every finding
- **Manual testing guidance** — flagged injection points include SQLMap and Burp Suite follow-up instructions

---

## Author

**Aaraiz Tahir**
BS Cybersecurity (4th Semester) — Air University, Islamabad
CEH Certified | OpenSSF LFD121 Certified | IBM QRadar SOAR Certified

- 🐙 GitHub: [github.com/Aaraiz211](https://github.com/Aaraiz211)
- 💼 LinkedIn: [linkedin.com/in/aaraiz-tahir](https://www.linkedin.com/in/aaraiz-tahir-a87621375)

---

## License

MIT License — free to use, modify, and distribute with attribution.

```
Copyright (c) 2026 Aaraiz Tahir

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. Ensure any new scanning modules follow the existing `run(target) -> (findings, logs)` interface pattern.

---

<div align="center">
<sub>Built with Python, Flask, and a lot of caffeine ☕ | Air University — BS Cybersecurity 2026</sub>
</div>
