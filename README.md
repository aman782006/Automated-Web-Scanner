# Automated Web Security Scanner

![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Tests](https://img.shields.io/badge/tests-162%20passed-brightgreen)
![Scope](https://img.shields.io/badge/Audit-Read--Only-informational)

A modular, lightweight Python-based web security auditing tool that analyzes authorized websites for HTTP security header misconfigurations, potentially unsafe Cross-Origin Resource Sharing (CORS) policies, and HTTPS/redirect vulnerabilities. Built with Flask, featuring a clean analytical dashboard and PDF/JSON reporting.

> **Authorized Use Only** — Only scan targets and systems you own or are explicitly authorized to audit. See [SECURITY.md](SECURITY.md) for details.

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Objectives](#objectives)
- [System Architecture](#system-architecture)
- [Technology Stack](#technology-stack)
- [Features](#features)
- [Folder Structure](#folder-structure)
- [Installation & Setup](#installation--setup)
  - [Prerequisites](#prerequisites)
  - [1. Clone Repository](#1-clone-repository)
  - [2. Environment Configuration](#2-environment-configuration)
  - [3. Setup Virtual Environment](#3-setup-virtual-environment)
- [Running the Application](#running-the-application)
- [How to Use the Scanner](#how-to-use-the-scanner)
- [Running Tests](#running-tests)
- [Exporting Reports](#exporting-reports)
- [Known Limitations](#known-limitations)
- [Security & Responsible Disclosure](#security--responsible-disclosure)
- [Contributing](#contributing)
- [License](#license)

---

## Problem Statement

Many modern web applications inadvertently deploy without vital HTTP defensive headers, configure overly permissive CORS origins with credentials enabled, or mishandle TLS redirect chains. These misconfigurations can expose users to Cross-Site Scripting (XSS), clickjacking, sensitive data leakage, and adversary-in-the-middle attacks.

Auditing these configurations manually via command-line tools is tedious. This project provides a dedicated, safe, read-only analysis layer and an intuitive web UI to help security students, software engineers, and auditors inspect defensive configurations in seconds.

---

## Objectives

- **Safe Header Analysis**: Inspect HTTP responses without sending malicious payloads or mutating state.
- **Header Auditing**: Detect missing or misconfigured security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy).
- **CORS Misconfiguration Analysis**: Validate CORS headers against dangerous patterns (wildcard with credentials, reflected origins, `null` origin trust).
- **HTTPS & TLS Checks**: Validate HTTPS enforcement, redirect chains, and certificate validity.
- **Risk Classification Engine**: Categorize findings by severity (`Critical`, `High`, `Medium`, `Low`, `Informational`) with concrete remediation steps.
- **Reporting Engine**: Download executive-ready PDF audit reports and machine-readable JSON exports.
- **SSRF Prevention**: Enforce strict target URL and IP address validation (blocking loopback, private RFC 1918 ranges, link-local, and cloud metadata endpoints).

---

## System Architecture

```
Browser ──► Flask (app.py)
              │
              ├── scanner/validator.py    ← URL + IP validation, SSRF prevention
              ├── scanner/http_client.py  ← Safe HTTP client (no body storage)
              ├── scanner/headers.py      ← HTTP security header analyzer
              ├── scanner/cors.py         ← CORS misconfiguration analyzer
              ├── scanner/https.py        ← HTTPS + redirect analyzer
              ├── scanner/rules.py        ← Risk classification engine
              ├── scanner/engine.py       ← Scan orchestrator
              │
              ├── reports/json_report.py  ← JSON export
              └── reports/pdf_report.py   ← PDF export (ReportLab)
```

**In-memory storage model**: Scan results are held in an `OrderedDict` protected by a `threading.Lock`. The system runs entirely database-free for zero-overhead local deployment.

---

## Technology Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.10+, Flask 3, Flask-WTF, python-dotenv |
| **HTTP Client** | Requests |
| **PDF Generation** | ReportLab |
| **Frontend** | HTML5, Bootstrap 5, Bootstrap Icons, JavaScript |
| **Charts** | Chart.js 4 |
| **Testing** | pytest, pytest-mock (162 unit tests) |
| **CI/CD** | GitHub Actions (Matrix testing across Python 3.10-3.12 on Linux & Windows) |

---

## Features

| Module | What it checks |
|---|---|
| **Headers Analyzer** | Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| **CORS Analyzer** | Wildcard origin with `Access-Control-Allow-Credentials: true`, `null` origin acceptance, missing `Vary: Origin`, unsafe HTTP methods |
| **HTTPS Analyzer** | Plain HTTP vs HTTPS, automatic redirect to HTTPS, certificate validity, HSTS on TLS, redirect loop detection |
| **Orchestration Engine** | Finding deduplication, partial-failure tolerance, timeout handling, strict rate limiting |
| **Reporting** | Executive-summary PDF generation with severity charts, machine-readable JSON report export |
| **Web Dashboard** | Severity breakdown pie charts, recent scan history, search and filter by category/severity |

---

## Folder Structure

```
automated-web-scanner/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/
│       └── ci.yml             # GitHub Actions CI matrix
├── .env.example               # Template for environment settings
├── .gitattributes             # Line ending normalization
├── .gitignore                 # Comprehensive Python & OS ignore rules
├── CONTRIBUTING.md            # Guidelines for contributors
├── LICENSE                    # MIT License
├── README.md                  # Project documentation
├── SECURITY.md                # Responsible disclosure & authorized use policy
├── app.py                     # Flask application entry point & routes
├── config.py                  # Environment-based configuration & limits
├── requirements.txt           # Python dependencies
├── scanner/
│   ├── __init__.py
│   ├── validator.py           # Target validation & SSRF prevention
│   ├── http_client.py         # Safe, bounded HTTP client
│   ├── headers.py             # Security header analyzer
│   ├── cors.py                # CORS analyzer
│   ├── https.py               # HTTPS & redirect analyzer
│   ├── rules.py               # Risk classification & finding models
│   └── engine.py              # Scan orchestrator
├── reports/
│   ├── __init__.py
│   ├── json_report.py         # JSON report generation
│   └── pdf_report.py          # PDF generation via ReportLab
├── templates/
│   ├── base.html              # Layout shell with navbar and footer
│   ├── index.html             # Scanner dashboard & submission form
│   ├── results.html           # Scan results & severity filters
│   ├── finding_details.html   # Detailed finding explanation & remediation
│   └── error.html             # Custom HTTP error page
├── static/
│   ├── css/style.css          # Custom styling and glassmorphism elements
│   └── js/app.js              # Dashboard client logic & Chart.js rendering
└── tests/
    ├── __init__.py
    ├── test_validator.py      # IP blocking & URL validation tests
    ├── test_http_client.py    # HTTP client safety & timeout tests
    ├── test_headers.py        # Header rule tests
    ├── test_cors.py           # CORS misconfiguration tests
    ├── test_https.py          # HTTPS & redirect tests
    ├── test_rules.py          # Severity mapping tests
    ├── test_routes.py         # Flask route tests
    ├── test_json_report.py    # JSON exporter tests
    └── test_pdf_report.py     # PDF generation tests
```

---

## Installation & Setup

### Prerequisites

- **Python 3.10 or later** ([python.org](https://www.python.org/downloads/))
- **Git** ([git-scm.com](https://git-scm.com/))

### 1. Clone Repository

```bash
git clone https://github.com/<your-username>/automated-web-scanner.git
cd automated-web-scanner
```

### 2. Environment Configuration

Copy the example environment configuration:

```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

### 3. Setup Virtual Environment

#### On Windows:
```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

#### On Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Running the Application

With your virtual environment activated:

```bash
python app.py
```

The application will start at **http://127.0.0.1:5000**.

> To run on a custom port or host:
> ```bash
> PORT=8080 python app.py
> ```

---

## How to Use the Scanner

1. Open **http://127.0.0.1:5000** in your browser.
2. Enter the target URL you are **authorized to test** (e.g. `https://example.com`).
3. Click **Scan**.
4. The scanner evaluates security headers, CORS response headers, TLS parameters, and redirect behaviors.
5. Review findings categorized by severity (`Critical`, `High`, `Medium`, `Low`, `Informational`).
6. Click any finding to inspect:
   - **Risk explanation**
   - **Raw evidence headers**
   - **Remediation advice and recommended values**
7. Click **Export JSON** or **Export PDF** to download the audit report.

---

## Running Tests

The test suite contains **162 tests** covering SSRF validation, HTTP client timeouts, security header analysis, CORS edge-cases, PDF generation, and web routes. All tests use mocked network responses—no external requests are made.

Run all tests:
```bash
pytest tests/ -v
```

Run a specific module:
```bash
pytest tests/test_headers.py -v
```

Run with test coverage:
```bash
pip install pytest-cov
pytest tests/ -v --cov=scanner --cov=reports --cov-report=term-missing
```

---

## Exporting Reports

From any scan's results page:
- **Export JSON** — Generates a timestamped JSON file containing structured findings, target metadata, and severity totals.
- **Export PDF** — Builds a ReportLab PDF document with an executive summary, severity matrix, and individual finding breakdowns.

---

## Known Limitations

| Limitation | Detail |
|---|---|
| **Header-only analysis** | Deep application logic, authentication states, and SQLi/XSS fuzzing are intentionally out of scope. |
| **TLS Depth** | Cipher suites and certificate chain validity are verified via standard TLS handshake; deep cipher ranking is not performed. |
| **Unauthenticated** | Scans run without session credentials. |
| **Ephemeral Storage** | Scan results are stored in memory and reset upon application restart. |
| **Redirect Boundaries** | Redirect validation restricts cross-domain chaining to avoid unintended third-party scans. |

---

## Security & Responsible Disclosure

This tool is designed strictly for defensive and educational security research. Please review [SECURITY.md](SECURITY.md) for full terms, legal notices, and instructions on reporting security issues.

---

## Contributing

Contributions, bug reports, and rule improvements are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for contribution workflows and code style guidelines.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
