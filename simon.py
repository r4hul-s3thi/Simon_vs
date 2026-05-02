#!/usr/bin/env python3
"""
S!M0N vuln-scanner v2: Enhanced Web vulnerability scanner with PDF reporting.
"""

import sys
import os
import argparse
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from colorama import Fore, Style, init
from tqdm import tqdm
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)

PAYLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads")


def print_banner():
    banner = f"""
{Fore.GREEN}
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓██████████████▓▒░  ░▒▓████████▓▒░ ░▒▓███████▓▒░  
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░ G R 3 Y ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓████████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░
{Style.RESET_ALL}
"""
    subtitle = f"{Fore.BLUE}--- Enhanced Automated Web Vulnerability Scanner v2.0 by GR3Y ---{Style.RESET_ALL}"
    print(banner)
    print(subtitle.center(50, "-"))
    print("\n")


class EnhancedVulnerabilityScanner:

    def __init__(self, target_url, max_threads=5, crawl_depth=2, enable_subdomains=False):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []
        self.session = requests.Session()
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        self.discovered_urls = set()
        self.max_threads = max_threads
        self.crawl_depth = crawl_depth
        self.enable_subdomains = enable_subdomains
        self.forms = []

    def load_payloads(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            return []

    def crawl_site(self):
        max_depth = self.crawl_depth
        print(f"{Fore.CYAN}[*] Crawling website (depth={max_depth}) to discover endpoints...{Style.RESET_ALL}")
        to_visit = [(self.target_url, 0)]
        visited = set()
        base_netloc = urlparse(self.target_url).netloc

        while to_visit:
            url, depth = to_visit.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            try:
                resp = self.session.get(url, headers=self.headers, timeout=10)
                self.discovered_urls.add(url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                for form in soup.find_all('form'):
                    self.forms.append({
                        'url': url,
                        'action': form.get('action', ''),
                        'method': form.get('method', 'get').lower(),
                        'inputs': [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                    })
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(url, link['href'])
                    next_netloc = urlparse(next_url).netloc
                    same_domain = (next_netloc == base_netloc)
                    subdomain_match = self.enable_subdomains and next_netloc.endswith('.' + base_netloc)
                    if (same_domain or subdomain_match) and next_url not in visited:
                        to_visit.append((next_url, depth + 1))
            except Exception:
                continue

        print(f"{Fore.GREEN}[+] Discovered {len(self.discovered_urls)} URLs and {len(self.forms)} forms{Style.RESET_ALL}")

    def _run_threaded(self, fn, items, desc, color="white"):
        results = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(fn, item): item for item in items}
            for future in tqdm(as_completed(futures), total=len(futures), desc=desc, ncols=100, colour=color):
                try:
                    r = future.result()
                    if r:
                        results.extend(r if isinstance(r, list) else [r])
                except Exception:
                    pass
        return results

    def scan(self, skip_crawl=False):
        print(f"{Fore.YELLOW}[*] Starting comprehensive vulnerability scan...{Style.RESET_ALL}\n")

        if not skip_crawl:
            self.crawl_site()
        else:
            self.discovered_urls.add(self.target_url)

        self.check_server_version_disclosure()
        self.check_technology_detection()
        self.check_security_headers()
        self.check_clickjacking()
        self.check_directory_listing()
        self.check_internal_ip_disclosure()
        self.check_verbose_error_messages()
        self.check_cors_misconfiguration()
        self.check_open_redirect()
        self.check_insecure_cookies()
        self.check_http_methods()
        self.check_sql_injection()
        self.check_xss()
        self.check_path_traversal()
        self.check_command_injection()
        self.check_xxe()

        return self.categorize_vulnerabilities()

    def categorize_vulnerabilities(self):
        severity_map = {
            'Server Version Disclosure': 'Low',
            'Technology Detection': 'Info',
            'Security Headers Missing': 'Low',
            'Clickjacking': 'Low',
            'Directory Listing': 'Low',
            'Internal IP Disclosure': 'Low',
            'Verbose Error Messages': 'Low',
            'CORS Misconfiguration': 'Medium',
            'Open Redirect': 'Medium',
            'Insecure Cookies': 'Medium',
            'Dangerous HTTP Methods': 'Medium',
            'SQL Injection': 'Critical',
            'Cross-Site Scripting (XSS)': 'Critical',
            'Path Traversal': 'Critical',
            'Command Injection': 'Critical',
            'XXE Injection': 'Critical',
        }
        categorized = {'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Info': []}
        for vuln in self.vulnerabilities:
            severity = severity_map.get(vuln['type'], 'Low')
            categorized[severity].append(vuln)
        return categorized

    def check_technology_detection(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            tech_stack = []
            if 'X-Powered-By' in resp.headers:
                tech_stack.append(resp.headers['X-Powered-By'])
            patterns = {
                'WordPress': r'wp-content|wp-includes',
                'Joomla': r'com_content|Joomla',
                'Drupal': r'Drupal\.settings|drupal\.js',
                'Laravel': r'laravel_session',
                'React': r'react',
                'Vue': r'vue',
                'Angular': r'ng-version'
            }
            for tech, pattern in patterns.items():
                if re.search(pattern, resp.text, re.IGNORECASE):
                    tech_stack.append(tech)
            if tech_stack:
                self.vulnerabilities.append({
                    'type': 'Technology Detection',
                    'url': self.target_url,
                    'description': f'Detected technologies: {", ".join(set(tech_stack))}'
                })
        except Exception:
            pass

    def check_security_headers(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            resp_header_keys = [k.lower() for k in resp.headers.keys()]
            security_headers = [
                'Strict-Transport-Security', 'Content-Security-Policy',
                'X-Content-Type-Options', 'X-Frame-Options',
                'X-XSS-Protection', 'Referrer-Policy', 'Permissions-Policy'
            ]
            missing = [h for h in security_headers if h.lower() not in resp_header_keys]
            if missing:
                self.vulnerabilities.append({
                    'type': 'Security Headers Missing',
                    'url': self.target_url,
                    'description': f'Missing security headers: {", ".join(missing)}'
                })
        except Exception:
            pass

    def check_server_version_disclosure(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            if resp.headers.get('Server'):
                self.vulnerabilities.append({'type': 'Server Version Disclosure', 'url': self.target_url,
                                             'description': f'Server header reveals: {resp.headers["Server"]}'})
            if resp.headers.get('X-Powered-By'):
                self.vulnerabilities.append({'type': 'Server Version Disclosure', 'url': self.target_url,
                                             'description': f'X-Powered-By reveals: {resp.headers["X-Powered-By"]}'})
        except Exception:
            pass

    def check_clickjacking(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            keys = [h.lower() for h in resp.headers.keys()]
            if 'x-frame-options' not in keys and 'content-security-policy' not in keys:
                self.vulnerabilities.append({'type': 'Clickjacking', 'url': self.target_url,
                                             'description': 'No X-Frame-Options or CSP frame-ancestors set'})
        except Exception:
            pass

    def check_cors_misconfiguration(self):
        try:
            for origin in ['https://evil.com', 'null']:
                h = self.headers.copy()
                h['Origin'] = origin
                resp = self.session.get(self.target_url, headers=h, timeout=10)
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                if (acao == origin or acao == '*') and acac.lower() == 'true':
                    self.vulnerabilities.append({'type': 'CORS Misconfiguration', 'url': self.target_url,
                                                 'description': f'CORS allows credentials from: {origin}'})
        except Exception:
            pass

    def check_http_methods(self):
        for method in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
            try:
                resp = self.session.request(method, self.target_url, headers=self.headers, timeout=10)
                if resp.status_code not in [405, 501]:
                    self.vulnerabilities.append({'type': 'Dangerous HTTP Methods', 'url': self.target_url,
                                                 'description': f'{method} allowed (status {resp.status_code})'})
            except Exception:
                pass

    def check_directory_listing(self):
        for dir_path in ['/', '/uploads/', '/images/', '/files/', '/backup/', '/admin/']:
            try:
                resp = self.session.get(self.target_url + dir_path, headers=self.headers, timeout=10)
                if any(x in resp.text for x in ["Index of", "Directory listing", "Parent Directory"]):
                    self.vulnerabilities.append({'type': 'Directory Listing',
                                                 'url': self.target_url + dir_path,
                                                 'description': f'Directory listing at: {dir_path}'})
            except Exception:
                continue

    def check_internal_ip_disclosure(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            matches = re.findall(r'\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}\b', resp.text)
            if matches:
                self.vulnerabilities.append({'type': 'Internal IP Disclosure', 'url': self.target_url,
                                             'description': f'Internal IPs found: {", ".join(set(matches))}'})
        except Exception:
            pass

    def check_verbose_error_messages(self):
        for path in ['/thispagedoesnotexist', '/%00', '/..%2f..%2f']:
            try:
                resp = self.session.get(self.target_url + path, headers=self.headers, timeout=10)
                if any(e in resp.text.lower() for e in ['exception', 'traceback', 'stack trace',
                                                         'mysqli', 'postgresql', 'warning:', 'fatal error']):
                    self.vulnerabilities.append({'type': 'Verbose Error Messages',
                                                 'url': self.target_url + path,
                                                 'description': 'Stack trace or verbose error exposed'})
                    break
            except Exception:
                continue

    def check_open_redirect(self):
        file_payloads = self.load_payloads(os.path.join(PAYLOAD_DIR, "open_redirect.txt"))
        targets = file_payloads[:5] if file_payloads else ['https://evil.com', '//evil.com']
        keys = ['url', 'redirect', 'next', 'return', 'goto', 'dest']
        test_urls = [f"{self.target_url}?{k}={p}" for k in keys for p in targets[:2]]

        for test_url in tqdm(test_urls, desc="[Open Redirect]", ncols=100, colour="yellow"):
            try:
                resp = self.session.get(test_url, allow_redirects=False, headers=self.headers, timeout=10)
                location = resp.headers.get('Location', '')
                if resp.status_code in (301, 302, 303, 307, 308) and ('evil.com' in location):
                    self.vulnerabilities.append({'type': 'Open Redirect', 'url': test_url,
                                                 'description': f'Open redirect to: {location}'})
            except Exception:
                continue

    def check_insecure_cookies(self):
        """FIX: Parse Set-Cookie raw header to correctly detect HttpOnly/SameSite."""
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            # Get raw Set-Cookie header text
            raw_set_cookie = resp.headers.get('Set-Cookie', '')

            for cookie in resp.cookies:
                issues = []
                if not cookie.secure:
                    issues.append('Missing Secure flag')
                # Search the raw header string (case-insensitive)
                cookie_segment = ''
                for part in raw_set_cookie.split(','):
                    if f'{cookie.name}=' in part:
                        cookie_segment = part.lower()
                        break
                if not cookie_segment:
                    cookie_segment = raw_set_cookie.lower()

                if 'httponly' not in cookie_segment:
                    issues.append('Missing HttpOnly flag')
                if 'samesite' not in cookie_segment:
                    issues.append('Missing SameSite attribute')

                if issues:
                    self.vulnerabilities.append({'type': 'Insecure Cookies', 'url': self.target_url,
                                                 'description': f'Cookie "{cookie.name}": {", ".join(issues)}'})
        except Exception:
            pass

    # ---- HIGH RISK (threaded) ----

    def _sqli_check_url(self, url):
        found = []
        payloads = self.load_payloads(os.path.join(PAYLOAD_DIR, "sqli.txt")) or \
                   ["'", "1' OR '1'='1", "' OR 1=1--", "1' UNION SELECT NULL--"]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        sql_errors = ['syntax error', 'mysql', 'mysqli', 'postgresql', 'odbc',
                      'sql syntax', 'sqlite', 'oracle', 'mssql', 'unclosed quotation']
        for param in params:
            for payload in payloads[:10]:
                np = params.copy()
                np[param] = [payload]
                test_url = parsed._replace(query=urlencode(np, doseq=True)).geturl()
                try:
                    resp = self.session.get(test_url, headers=self.headers, timeout=10)
                    if any(e in resp.text.lower() for e in sql_errors):
                        found.append({'type': 'SQL Injection', 'url': test_url,
                                      'description': f'SQLi in param: {param}'})
                        break
                except Exception:
                    continue
        return found

    def check_sql_injection(self):
        urls = [u for u in list(self.discovered_urls)[:20] if '?' in u]
        if not urls:
            return
        results = self._run_threaded(self._sqli_check_url, urls, "[SQL Injection]", "red")
        self.vulnerabilities.extend(results)

    def _xss_check_url(self, url):
        found = []
        payloads = self.load_payloads(os.path.join(PAYLOAD_DIR, "xss.txt")) or \
                   ['<script>alert(1)</script>', '"><script>alert(1)</script>',
                    '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>']
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            for payload in payloads[:8]:
                np = params.copy()
                np[param] = [payload]
                test_url = parsed._replace(query=urlencode(np, doseq=True)).geturl()
                try:
                    resp = self.session.get(test_url, headers=self.headers, timeout=10)
                    if payload in resp.text:
                        found.append({'type': 'Cross-Site Scripting (XSS)', 'url': test_url,
                                      'description': f'Reflected XSS in param: {param}'})
                        break
                except Exception:
                    continue
        return found

    def check_xss(self):
        urls = [u for u in list(self.discovered_urls)[:20] if '?' in u]
        if not urls:
            return
        results = self._run_threaded(self._xss_check_url, urls, "[XSS]", "red")
        self.vulnerabilities.extend(results)

    def _traversal_check_task(self, args):
        url, payload = args
        found = []
        for test_url in [f"{url}?file={payload}", f"{url}?path={payload}", f"{url}?page={payload}"]:
            try:
                resp = self.session.get(test_url, headers=self.headers, timeout=10)
                if re.search(r'root:.*:0:0:', resp.text):
                    found.append({'type': 'Path Traversal', 'url': test_url,
                                  'description': 'Path traversal - read /etc/passwd'})
                    break
                if '[extensions]' in resp.text.lower() or '[fonts]' in resp.text.lower():
                    found.append({'type': 'Path Traversal', 'url': test_url,
                                  'description': 'Path traversal - read win.ini'})
                    break
            except Exception:
                continue
        return found

    def check_path_traversal(self):
        payloads = self.load_payloads(os.path.join(PAYLOAD_DIR, "traversal.txt")) or \
                   ['../../../etc/passwd', '....//....//....//etc/passwd', '..%2F..%2Fetc%2Fpasswd']
        urls = list(self.discovered_urls)[:10]
        tasks = [(url, p) for url in urls for p in payloads[:6]]
        results = self._run_threaded(self._traversal_check_task, tasks, "[Path Traversal]", "red")
        self.vulnerabilities.extend(results)

    def check_command_injection(self):
        cmd_payloads = ['; ls', '| whoami', '`id`', '$(whoami)', '; id;']
        urls = [u for u in list(self.discovered_urls)[:10] if '?' in u]
        for url in tqdm(urls, desc="[Cmd Injection]", ncols=100, colour="red"):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload in cmd_payloads:
                    np = params.copy()
                    np[param] = [payload]
                    test_url = parsed._replace(query=urlencode(np, doseq=True)).geturl()
                    try:
                        resp = self.session.get(test_url, headers=self.headers, timeout=10)
                        if any(x in resp.text.lower() for x in ['uid=', 'gid=', 'root:', 'www-data']):
                            self.vulnerabilities.append({'type': 'Command Injection', 'url': test_url,
                                                         'description': f'Cmd injection in param: {param}'})
                            break
                    except Exception:
                        continue

    def check_xxe(self):
        xxe_payload = ('<?xml version="1.0" encoding="ISO-8859-1"?>'
                       '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                       '<foo>&xxe;</foo>')
        for url in list(self.discovered_urls)[:5]:
            try:
                h = self.headers.copy()
                h['Content-Type'] = 'application/xml'
                resp = self.session.post(url, data=xxe_payload, headers=h, timeout=10)
                if 'root:' in resp.text:
                    self.vulnerabilities.append({'type': 'XXE Injection', 'url': url,
                                                 'description': 'XXE - XML parser reads external entities'})
            except Exception:
                continue


def generate_report(filename, findings, target_url):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    heading = styles['Heading2']
    heading.alignment = TA_CENTER
    elements = []

    elements.append(Paragraph("Security Vulnerability Assessment Report", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"<b>Target:</b> {target_url}", styles['BodyText']))
    elements.append(Paragraph(f"<b>Scan Date:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}", styles['BodyText']))
    elements.append(Spacer(1, 20))

    total = sum(len(v) for v in findings.values())
    elements.append(Paragraph("Executive Summary", heading))
    elements.append(Paragraph(f"Total vulnerabilities found: <b>{total}</b>", styles['BodyText']))
    for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        count = len(findings.get(sev, []))
        if count:
            elements.append(Paragraph(f"{sev}: {count}", styles['BodyText']))
    elements.append(Spacer(1, 20))

    for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        if findings.get(sev):
            elements.append(Paragraph(f"{sev} Risk Findings", heading))
            elements.append(Spacer(1, 12))
            for vuln in findings[sev]:
                elements.append(Paragraph(f"<b>Type:</b> {vuln['type']}", styles['Heading3']))
                elements.append(Paragraph(f"<b>URL:</b> {vuln['url']}", styles['BodyText']))
                elements.append(Paragraph(f"<b>Description:</b> {vuln['description']}", styles['BodyText']))
                elements.append(Spacer(1, 12))

    if not any(findings.values()):
        elements.append(Paragraph("No vulnerabilities found.", styles['BodyText']))

    doc.build(elements)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="S!M0N vuln-scanner v2: Enhanced web vulnerability scanner with PDF reporting."
    )
    parser.add_argument('-d', '--domain', required=True, help='Target URL (e.g., http://example.com)')
    parser.add_argument('-o', '--output', default="vulnerability_report.pdf", help='Output PDF filename')
    parser.add_argument('-l', '--level', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Threads (default: 5)')
    parser.add_argument('--subdomains', action='store_true', help='Include subdomains in scope')
    parser.add_argument('--no-crawl', action='store_true', help='Skip crawling, scan only the target URL')

    args = parser.parse_args()

    print(f"{Fore.CYAN}[*] Target:   {args.domain}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Output:   {args.output}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Depth:    {args.level}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Threads:  {args.threads}{Style.RESET_ALL}")
    if args.subdomains:
        print(f"{Fore.CYAN}[*] Subdomain scope: ENABLED{Style.RESET_ALL}")
    print()

    scanner = EnhancedVulnerabilityScanner(
        args.domain,
        max_threads=args.threads,
        crawl_depth=args.level,
        enable_subdomains=args.subdomains
    )
    findings = scanner.scan(skip_crawl=args.no_crawl)

    total = sum(len(v) for v in findings.values())
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Scan Complete!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Total Vulnerabilities Found: {total}{Style.RESET_ALL}")
    for sev, vulns in findings.items():
        if vulns:
            color = Fore.RED if sev in ['Critical', 'High'] else Fore.YELLOW if sev == 'Medium' else Fore.BLUE
            print(f"{color}    - {sev}: {len(vulns)}{Style.RESET_ALL}")

    try:
        print(f"\n{Fore.CYAN}[*] Generating PDF: {args.output}...{Style.RESET_ALL}")
        generate_report(args.output, findings, args.domain)
        print(f"{Fore.GREEN}[+] Report saved: {args.output}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Report failed: {e}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)
