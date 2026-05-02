<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=32&pause=1000&color=FF0000&center=true&vCenter=true&width=600&lines=S!M0N+%E2%80%94+Web+Vulnerability+Scanner;Automated.+Threaded.+Ruthless.;Hunt+Bugs.+Not+Excuses." alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Kali%20%7C%20Linux-red?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/r4hul-s3thi/Simon_vs)
[![Version](https://img.shields.io/badge/Version-2.0-orange?style=for-the-badge)](https://github.com/r4hul-s3thi/Simon_vs/releases)
[![Made By](https://img.shields.io/badge/Made%20by-GR3Y-purple?style=for-the-badge)](https://github.com/r4hul-s3thi)
[![Stars](https://img.shields.io/github/stars/r4hul-s3thi/Simon_vs?style=for-the-badge&color=yellow)](https://github.com/r4hul-s3thi/Simon_vs/stargazers)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-black?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/www-project-top-ten/)

<br/>

> 🔍 A Python-based web vulnerability scanner built for **bug bounty hunters**, **ethical hackers**, and **security researchers**.
> Covers the full **OWASP Top 10 (2021)**, detects **18+ vulnerability classes**, and generates a **professional PDF report**.

<br/>

[⚡ Quick Start](#-quick-start) • [🛡️ Vulnerabilities](#%EF%B8%8F-vulnerabilities-detected) • [📦 Payload Coverage](#-payload-coverage) • [🔧 Usage](#-usage) • [🎯 Test Targets](#-safe-test-targets) • [📄 PDF Report](#-pdf-report-output)

</div>

---

## ⚡ Quick Start

> **Prerequisites:** Python 3.8+, Git

<details>
<summary><b>🐧 Kali Linux / Linux</b></summary>

```bash
git clone https://github.com/r4hul-s3thi/Simon_vs.git
cd Simon_vs
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 simon.py -d http://testphp.vulnweb.com -o report.pdf
```

> Missing `python3-venv`? Run: `sudo apt install python3-venv -y`

</details>

<details>
<summary><b>🪟 Windows</b></summary>

```powershell
git clone https://github.com/r4hul-s3thi/Simon_vs.git
cd Simon_vs
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
python simon.py -d http://testphp.vulnweb.com -o report.pdf
```

> Make sure Python is added to PATH during installation.

</details>

---

## 🛡️ Vulnerabilities Detected

S!M0N scans for **18 vulnerability classes** across 4 severity levels:

<details open>
<summary><b>🔴 Critical</b></summary>

| Vulnerability | How It Works |
|---|---|
| **SQL Injection** | Error-based, Union, Blind, Time-based, OOB via payload fuzzing |
| **Cross-Site Scripting (XSS)** | Reflected XSS via URL params — WAF bypass, polyglot, DOM-based |
| **Path Traversal / LFI** | `../` sequences, PHP wrappers, null byte, double encoding |
| **Command Injection** | OS command execution via `;`, `\|`, `` ` ``, `$()` patterns |
| **XXE Injection** | Malicious XML to detect external entity processing |
| **SSRF** | Cloud metadata, internal services, protocol handlers |
| **Insecure Deserialization** | Java, PHP, Python, Node.js gadget chains + SSTI |

</details>

<details>
<summary><b>🟠 High / Medium</b></summary>

| Vulnerability | How It Works |
|---|---|
| **Broken Access Control** | IDOR, admin panel discovery, forced browsing, role bypass |
| **CORS Misconfiguration** | Tests wildcard / credentialed cross-origin access |
| **Open Redirect** | Fuzzes `url=`, `next=`, `goto=` and 30+ similar params |
| **Insecure Cookies** | Checks for missing `Secure`, `HttpOnly`, `SameSite` flags |
| **Dangerous HTTP Methods** | Tests `PUT`, `DELETE`, `TRACE`, `CONNECT` availability |
| **Auth Failures** | Default creds, SQLi bypass, MFA bypass, session abuse |

</details>

<details>
<summary><b>🟡 Low / Info</b></summary>

| Vulnerability | How It Works |
|---|---|
| **Server Version Disclosure** | Detects version info in `Server` / `X-Powered-By` headers |
| **Missing Security Headers** | Checks CSP, HSTS, X-Frame-Options, Referrer-Policy |
| **Clickjacking** | Missing `X-Frame-Options` or CSP `frame-ancestors` |
| **Directory Listing** | Probes common paths for open directory indexing |
| **Internal IP Disclosure** | Regex scan for private IPs leaked in HTML |
| **Verbose Error Messages** | Triggers errors to detect stack traces / debug output |
| **Technology Detection** | Fingerprints WordPress, Laravel, React, Drupal, etc. |
| **Security Misconfiguration** | Exposed `.git`, actuator endpoints, debug pages, API docs |
| **Vulnerable Components** | CVE fingerprinting for Log4Shell, Spring4Shell, Shellshock + more |

</details>

---

## 📦 Payload Coverage

S!M0N ships with **13 payload files** covering the full **OWASP Top 10 (2021)**:

| File | OWASP | Coverage |
|---|---|---|
| `sqli.txt` | A03 | Error-based, Union, Boolean/Time blind, OOB, NoSQL, WAF bypass, Auth bypass |
| `xss.txt` | A03 | Reflected, DOM, Stored probes, WAF bypass, Polyglot, SSTI→XSS, CSP bypass |
| `traversal.txt` | A03 | `../` chains, URL/double encoded, Unicode, null byte, PHP wrappers, absolute paths |
| `lfi.txt` | A03 | Local file inclusion — Linux/Windows targets, log poisoning, wrappers |
| `open_redirect.txt` | A01 | Protocol bypass, slash bypass, encoding, whitelist bypass, SSRF-chained |
| `ssrf.txt` | A10 | AWS/GCP/Azure/DO metadata, internal services, IP encoding, protocol handlers |
| `broken_access_control.txt` | A01 | IDOR, admin paths, role param bypass, JWT manipulation, sensitive file paths |
| `auth_failures.txt` | A07 | 60+ default creds, SQLi bypass, MFA bypass, account enumeration, session abuse |
| `crypto_failures.txt` | A02 | Exposed `.env`/keys/certs, cloud credential endpoints, JWT none-algo |
| `security_misconfig.txt` | A05 | Actuator endpoints, `.git`/`.svn`, CI/CD files, API docs, directory listing |
| `insecure_deserialization.txt` | A08 | Java/PHP/Python/Node.js deserialization, SSTI (Jinja2/Twig/Freemarker/ERB), prototype pollution |
| `vulnerable_components.txt` | A06 | CVE paths for WordPress, Laravel, Spring Boot, Log4Shell, Shellshock, ProxyShell |
| `insecure_design.txt` | A04 | Mass assignment, business logic, race condition endpoints, file upload bypass |
| `extra_injections.txt` | A03/A09 | LDAP, XPath, NoSQL, CRLF, Host header, HTTP request smuggling, log injection |

> 💡 All payload files are loaded automatically. Add your own lines to extend coverage.

---

## 🔧 Usage

```bash
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

## 🎯 Safe Test Targets

> ✅ These are **intentionally vulnerable** sites made for testing. Legal to scan.

| Target | Notable Vulns |
|---|---|
| `http://testphp.vulnweb.com` | SQLi, XSS, Path Traversal, LFI |
| `http://testfire.net` | Auth Bypass, XSS, Info Disclosure |
| `http://zero.webappsecurity.com` | CSRF, Open Redirect |
| `http://hackyourselffirst.troyhunt.com` | Multiple High-Severity Vulns |
| `https://juice-shop.herokuapp.com` | Full OWASP Top 10 |
| `http://dvwa.co.uk` | SQLi, XSS, CSRF, File Upload |

---

## 📄 PDF Report Output

Every scan auto-generates a professional PDF with:

- 🎯 **Target URL & scan timestamp**
- 📊 **Executive summary** — total counts per severity
- 🔍 **Detailed findings** — type, affected URL, and description per finding
- 🗂️ **Severity-ordered sections** — Critical → High → Medium → Low → Info

```
[*] Generating PDF: report.pdf...
[+] Report saved: report.pdf
```

---

## 📂 Project Structure

```
Simon_vs/
├── simon.py                      # Main scanner
├── requirements.txt              # Dependencies
├── payloads/
│   ├── sqli.txt                  # SQL injection
│   ├── xss.txt                   # Cross-site scripting
│   ├── traversal.txt             # Path traversal
│   ├── lfi.txt                   # Local file inclusion
│   ├── open_redirect.txt         # Open redirect
│   ├── ssrf.txt                  # Server-side request forgery
│   ├── broken_access_control.txt # A01 - Broken access control
│   ├── auth_failures.txt         # A07 - Auth failures
│   ├── crypto_failures.txt       # A02 - Cryptographic failures
│   ├── security_misconfig.txt    # A05 - Security misconfiguration
│   ├── insecure_deserialization.txt # A08 - Deserialization / SSTI
│   ├── vulnerable_components.txt # A06 - Vulnerable components / CVEs
│   ├── insecure_design.txt       # A04 - Insecure design
│   └── extra_injections.txt      # LDAP, XPath, CRLF, Host header
└── README.md
```

---

## ⚠️ Disclaimer

> This tool is for **educational purposes and authorized security testing only.**
> **Do NOT** use it against any system without **explicit written permission.**
> The author is **not responsible** for any misuse or damage caused by this tool.

---

<div align="center">

**Built with 🖤 by [GR3Y](https://github.com/r4hul-s3thi)**

*If S!M0N helped you find a bug, drop a ⭐ — it means a lot.*

[![GitHub](https://img.shields.io/badge/GitHub-r4hul--s3thi-181717?style=for-the-badge&logo=github)](https://github.com/r4hul-s3thi)

</div>
