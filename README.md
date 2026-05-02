<div align="center">

```
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓██████████████▓▒░  ░▒▓████████▓▒░ ░▒▓███████▓▒░  
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░    G R 3 Y       ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓████████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░
```

# 🛡️ S!M0N — Web Vulnerability Scanner

**Automated. Threaded. Ruthless.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Kali%20%7C%20Linux-red?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/r4hul-s3thi/Simon_vs)
[![Version](https://img.shields.io/badge/Version-2.0-orange?style=for-the-badge)](https://github.com/r4hul-s3thi/Simon_vs/releases)
[![Made By](https://img.shields.io/badge/Made%20by-GR3Y-purple?style=for-the-badge)](https://github.com/r4hul-s3thi)

*A Python-based web vulnerability scanner built for bug bounty hunters, ethical hackers, and security researchers.*  
*Detects 15+ real-world web vulnerabilities, classifies them by severity, and generates a professional PDF report.*

[🚀 Quick Start](#-quick-start) · [🔍 Vulnerabilities](#-vulnerabilities-detected) · [⚙️ Usage](#️-usage) · [🧪 Test Targets](#-safe-test-targets) · [📄 Report](#-pdf-report-output)

---

</div>

## 🚀 Quick Start

> **Prerequisites:** Python 3.8+, Git

<details>
<summary><b>🐧 Kali Linux / Linux</b></summary>

```bash
# Clone the repo
git clone https://github.com/r4hul-s3thi/Simon_vs.git
cd Simon_vs

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run your first scan
python3 simon.py -d http://testphp.vulnweb.com -o report.pdf
```

> If `python3-venv` is missing: `sudo apt install python3-venv -y`

</details>

<details>
<summary><b>🪟 Windows</b></summary>

```powershell
# Clone the repo
git clone https://github.com/r4hul-s3thi/Simon_vs.git
cd Simon_vs

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run your first scan
python simon.py -d http://testphp.vulnweb.com -o report.pdf
```

> Make sure Python is added to PATH during installation.

</details>

---

## 🔍 Vulnerabilities Detected

S!M0N checks for **18 vulnerability classes** across 4 severity levels:

<details open>
<summary><b>🔴 Critical</b></summary>

| Vulnerability | Description |
|---|---|
| **SQL Injection** | Detects error-based SQLi via parameter fuzzing with payload files |
| **Cross-Site Scripting (XSS)** | Reflected XSS via URL parameters using custom payloads |
| **Path Traversal** | Attempts `../` sequences to read `/etc/passwd` or `win.ini` |
| **Command Injection** | Tests for OS command execution via `;`, `\|`, `` ` `` patterns |
| **XXE Injection** | Sends malicious XML to detect external entity processing |

</details>

<details>
<summary><b>🟠 Medium</b></summary>

| Vulnerability | Description |
|---|---|
| **CORS Misconfiguration** | Tests wildcard/credentialed cross-origin access |
| **Open Redirect** | Fuzzes common redirect params (`url=`, `next=`, `goto=`, etc.) |
| **Insecure Cookies** | Checks for missing `Secure`, `HttpOnly`, `SameSite` flags |
| **Dangerous HTTP Methods** | Tests `PUT`, `DELETE`, `TRACE`, `CONNECT` availability |

</details>

<details>
<summary><b>🟡 Low / Info</b></summary>

| Vulnerability | Description |
|---|---|
| **Server Version Disclosure** | Detects version info in `Server` / `X-Powered-By` headers |
| **Missing Security Headers** | Checks for CSP, HSTS, X-Frame-Options, Referrer-Policy, etc. |
| **Clickjacking** | Missing `X-Frame-Options` or CSP `frame-ancestors` |
| **Directory Listing** | Probes common paths for open directory indexing |
| **Internal IP Disclosure** | Regex scan for private IPs leaked in HTML |
| **Verbose Error Messages** | Triggers errors to detect stack traces / debug output |
| **Technology Detection** | Fingerprints WordPress, Laravel, React, Drupal, etc. |

</details>

---

## ⚙️ Usage

```
python3 simon.py -d <target> [options]
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `-d`, `--domain` | **Required.** Target URL | — |
| `-o`, `--output` | Output PDF filename | `vulnerability_report.pdf` |
| `-l`, `--level` | Crawl depth level | `2` |
| `-t`, `--threads` | Concurrent threads | `5` |
| `--subdomains` | Expand scope to subdomains | Off |
| `--no-crawl` | Skip crawling, scan base URL only | Off |

### Examples

```bash
# Basic scan
python3 simon.py -d http://testphp.vulnweb.com

# Deep scan with more threads
python3 simon.py -d http://testphp.vulnweb.com -l 3 -t 15 -o deep_scan.pdf

# Fast surface scan (no crawl)
python3 simon.py -d http://target.com --no-crawl -o quick.pdf

# Include subdomains
python3 simon.py -d http://target.com --subdomains -l 2 -t 10 -o full.pdf
```

---

## 🧪 Safe Test Targets

> ✅ These are **intentionally vulnerable** sites made for testing. Legal to scan.

| Target | Notable Vulns |
|---|---|
| `http://testphp.vulnweb.com` | SQLi, XSS, Path Traversal |
| `http://testfire.net` | Auth bypass, XSS, Info disclosure |
| `http://zero.webappsecurity.com` | CSRF, Open Redirect |
| `http://hackyourselffirst.troyhunt.com` | Multiple high-severity vulns |

---

## 📄 PDF Report Output

Every scan auto-generates a professional PDF with:

- 🎯 **Target URL & scan timestamp**
- 📊 **Executive summary** — total counts per severity
- 📋 **Detailed findings** — type, affected URL, and description for every finding
- 🔢 **Severity-ordered sections** — Critical → High → Medium → Low → Info

```
[*] Generating PDF: report.pdf...
[+] Report saved: report.pdf
```

Open with any PDF viewer — `evince` / `xdg-open` on Linux, any viewer on Windows.

---

## 📁 Project Structure

```
Simon_vs/
├── simon.py            # Main scanner
├── requirements.txt    # Dependencies
├── payloads/
│   ├── sqli.txt        # SQL injection payloads
│   ├── xss.txt         # XSS payloads
│   ├── traversal.txt   # Path traversal payloads
│   └── open_redirect.txt
└── README.md
```

Payload files are loaded automatically — add your own lines to extend coverage.

---

## ⚠️ Disclaimer

> This tool is for **educational purposes and authorized security testing only.**  
> **Do NOT** use it against any system without **explicit written permission.**  
> The author is not responsible for any misuse or damage caused by this tool.

---

<div align="center">

**Built with 🔥 by [GR3Y](https://github.com/r4hul-s3thi)**

*Star ⭐ the repo if it helped you.*

</div>
