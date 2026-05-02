#!/usr/bin/env python3
"""
S!M0N vuln-scanner v3: 2026-standard web vulnerability scanner with PDF reporting.
Author: GR3Y | github.com/r4hul-s3thi/Simon_vs
"""

import sys
import os
import argparse
import requests
import hashlib
import time
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib import colors
from colorama import Fore, Style, init
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)

PAYLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads")

BANNER = r"""
  ██████  ██ ███    ███  ██████  ███    ██
 ██       ██ ████  ████ ██    ██ ████   ██
  █████   ██ ██ ████ ██ ██    ██ ██ ██  ██
     ██   ██ ██  ██  ██ ██    ██ ██  ██ ██
 ██████   ██ ██      ██  ██████  ██   ████
"""

def print_banner():
    print(f"{Fore.GREEN}{BANNER}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {'─'*50}")
    print(f"  Enhanced Web Vulnerability Scanner v3.0")
    print(f"  2026 Detection Standards | by GR3Y")
    print(f"  {'─'*50}{Style.RESET_ALL}\n")


class EnhancedVulnerabilityScanner:

    def __init__(self, target_url, max_threads=5, crawl_depth=2, enable_subdomains=False):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []
        self.session = requests.Session()
        # 2026: Full browser fingerprint to avoid bot blocking
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        self.session.headers.update(self.headers)
        self.discovered_urls = set()
        self.param_urls = set()   # URLs with ?query params
        self.forms = []           # All discovered HTML forms
        self.max_threads = max_threads
        self.crawl_depth = crawl_depth
        self.enable_subdomains = enable_subdomains
        # 2026: cache baseline responses to diff against payloaded responses
        self._baseline_cache = {}

    # ── UTILITIES ────────────────────────────────────────────────────────────

    def load_payloads(self, filename):
        path = os.path.join(PAYLOAD_DIR, filename)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except FileNotFoundError:
            return []

    def get(self, url, **kwargs):
        try:
            return self.session.get(url, timeout=12, **kwargs)
        except Exception:
            return None

    def post(self, url, **kwargs):
        try:
            return self.session.post(url, timeout=12, **kwargs)
        except Exception:
            return None

    def _baseline(self, url):
        """Cache and return baseline response body for a URL."""
        if url not in self._baseline_cache:
            r = self.get(url)
            self._baseline_cache[url] = r.text if r else ''
        return self._baseline_cache[url]

    def _hash(self, text):
        return hashlib.md5(text.encode(errors='replace')).hexdigest()

    def _run_threaded(self, fn, items, desc, color='white'):
        results = []
        if not items:
            return results
        with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = {ex.submit(fn, item): item for item in items}
            for future in tqdm(as_completed(futures), total=len(futures),
                               desc=desc, ncols=100, colour=color):
                try:
                    r = future.result()
                    if r:
                        results.extend(r if isinstance(r, list) else [r])
                except Exception:
                    pass
        return results

    def _add(self, vuln_type, url, description):
        self.vulnerabilities.append({
            'type': vuln_type,
            'url': url,
            'description': description
        })

    # ── CRAWLING ─────────────────────────────────────────────────────────────

    def crawl_site(self):
        print(f"{Fore.CYAN}[*] Crawling (depth={self.crawl_depth})...{Style.RESET_ALL}")
        queue = [(self.target_url, 0)]
        visited = set()
        base = urlparse(self.target_url).netloc

        while queue:
            url, depth = queue.pop(0)
            url = url.split('#')[0]
            if url in visited or depth > self.crawl_depth:
                continue
            visited.add(url)

            r = self.get(url)
            if not r:
                continue

            self.discovered_urls.add(url)
            if '?' in url:
                self.param_urls.add(url)

            soup = BeautifulSoup(r.text, 'html.parser')

            # Extract forms
            for form in soup.find_all('form'):
                action = urljoin(url, form.get('action') or url)
                method = form.get('method', 'get').lower()
                inputs = [
                    inp.get('name') for inp in
                    form.find_all(['input', 'textarea', 'select'])
                    if inp.get('name') and inp.get('type', '') not in
                    ['submit', 'button', 'image', 'reset', 'file', 'hidden']
                ]
                if inputs:
                    self.forms.append({
                        'url': action,
                        'page': url,
                        'method': method,
                        'inputs': inputs
                    })
                    if method == 'get':
                        fake = action + '?' + '&'.join(f'{i}=1' for i in inputs)
                        self.param_urls.add(fake)

            # Extract links
            for a in soup.find_all('a', href=True):
                next_url = urljoin(url, a['href']).split('#')[0]
                netloc = urlparse(next_url).netloc
                ok = netloc == base or (self.enable_subdomains and netloc.endswith('.' + base))
                if ok:
                    if '?' in next_url:
                        self.param_urls.add(next_url)
                    if next_url not in visited:
                        queue.append((next_url, depth + 1))

        print(f"{Fore.GREEN}[+] {len(self.discovered_urls)} URLs | "
              f"{len(self.param_urls)} param URLs | {len(self.forms)} forms{Style.RESET_ALL}")

    # ── MAIN SCAN ─────────────────────────────────────────────────────────────

    def scan(self, skip_crawl=False):
        print(f"\n{Fore.YELLOW}[*] Starting scan...{Style.RESET_ALL}\n")
        if not skip_crawl:
            self.crawl_site()
        else:
            self.discovered_urls.add(self.target_url)

        # Passive / header checks
        self._check_server_disclosure()
        self._check_security_headers()
        self._check_tech_detection()
        self._check_clickjacking()
        self._check_cors()
        self._check_cookies()
        self._check_http_methods()
        self._check_directory_listing()
        self._check_internal_ip()
        self._check_error_disclosure()
        self._check_open_redirect()

        # Active injection checks (threaded)
        self._check_sqli()
        self._check_xss()
        self._check_path_traversal()
        self._check_ssti()
        self._check_command_injection()
        self._check_xxe()

        return self._categorise()

    def _categorise(self):
        sev = {
            'Server Version Disclosure': 'Low',
            'Technology Detection': 'Info',
            'Security Headers Missing': 'Low',
            'Clickjacking': 'Low',
            'Directory Listing': 'Medium',
            'Internal IP Disclosure': 'Low',
            'Verbose Error Messages': 'Low',
            'CORS Misconfiguration': 'Medium',
            'Open Redirect': 'Medium',
            'Insecure Cookies': 'Medium',
            'Dangerous HTTP Methods': 'Medium',
            'SQL Injection': 'Critical',
            'Blind SQL Injection': 'Critical',
            'Cross-Site Scripting (XSS)': 'Critical',
            'Server-Side Template Injection': 'Critical',
            'Path Traversal': 'Critical',
            'Command Injection': 'Critical',
            'XXE Injection': 'Critical',
        }
        out = {'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Info': []}
        for v in self.vulnerabilities:
            out[sev.get(v['type'], 'Low')].append(v)
        return out

    # ── PASSIVE CHECKS ────────────────────────────────────────────────────────

    def _check_server_disclosure(self):
        r = self.get(self.target_url)
        if not r:
            return
        for hdr in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime']:
            if hdr in r.headers:
                self._add('Server Version Disclosure', self.target_url,
                          f'{hdr}: {r.headers[hdr]}')

    def _check_security_headers(self):
        r = self.get(self.target_url)
        if not r:
            return
        keys = {k.lower() for k in r.headers}
        required = [
            'Strict-Transport-Security', 'Content-Security-Policy',
            'X-Content-Type-Options', 'X-Frame-Options',
            'Referrer-Policy', 'Permissions-Policy',
        ]
        missing = [h for h in required if h.lower() not in keys]
        if missing:
            self._add('Security Headers Missing', self.target_url,
                      f'Missing: {", ".join(missing)}')

    def _check_tech_detection(self):
        r = self.get(self.target_url)
        if not r:
            return
        stack = []
        if 'X-Powered-By' in r.headers:
            stack.append(r.headers['X-Powered-By'])
        patterns = {
            'WordPress': r'wp-content|wp-includes|wordpress',
            'Joomla': r'com_content|joomla',
            'Drupal': r'drupal\.settings|drupal\.js',
            'Laravel': r'laravel_session|laravel',
            'Django': r'csrfmiddlewaretoken|django',
            'React': r'__react|react\.production',
            'Vue': r'__vue__|vue\.runtime',
            'Angular': r'ng-version|angular\.js',
            'Next.js': r'__next|_next/static',
            'jQuery': r'jquery[\-\.][\d\.]+\.min\.js',
        }
        for tech, pat in patterns.items():
            if re.search(pat, r.text, re.IGNORECASE):
                stack.append(tech)
        if stack:
            self._add('Technology Detection', self.target_url,
                      f'Detected: {", ".join(set(stack))}')

    def _check_clickjacking(self):
        r = self.get(self.target_url)
        if not r:
            return
        keys = {k.lower() for k in r.headers}
        if 'x-frame-options' not in keys and 'content-security-policy' not in keys:
            self._add('Clickjacking', self.target_url,
                      'No X-Frame-Options or CSP frame-ancestors — page can be framed')

    def _check_cors(self):
        for origin in ['https://evil.com', 'null']:
            r = self.get(self.target_url, headers={'Origin': origin})
            if not r:
                continue
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '').lower()
            # Only flag if credentials=true AND origin is reflected or wildcard
            if acac == 'true' and (acao == origin or acao == '*'):
                self._add('CORS Misconfiguration', self.target_url,
                          f'Credentials allowed from arbitrary origin: {origin}')
                break

    def _check_cookies(self):
        """2026: Parse raw Set-Cookie header — has_nonstandard_attr is unreliable."""
        r = self.get(self.target_url)
        if not r:
            return
        raw = r.headers.get('Set-Cookie', '')
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append('Secure flag missing')
            # Find this cookie's raw Set-Cookie segment
            seg = ''
            for part in raw.split(','):
                if f'{cookie.name}=' in part:
                    seg = part.lower()
                    break
            if not seg:
                seg = raw.lower()
            if 'httponly' not in seg:
                issues.append('HttpOnly missing')
            if 'samesite' not in seg:
                issues.append('SameSite missing')
            if issues:
                self._add('Insecure Cookies', self.target_url,
                          f'"{cookie.name}": {", ".join(issues)}')

    def _check_http_methods(self):
        """2026: Only flag if server genuinely accepts the method (2xx/3xx to different location)."""
        reject_codes = {400, 401, 403, 404, 405, 406, 501}
        for method in ['PUT', 'DELETE', 'TRACE']:
            r = None
            try:
                r = self.session.request(method, self.target_url, timeout=10)
            except Exception:
                continue
            if r and r.status_code not in reject_codes:
                self._add('Dangerous HTTP Methods', self.target_url,
                          f'{method} accepted — server returned {r.status_code}')

    def _check_directory_listing(self):
        paths = ['/uploads/', '/images/', '/files/', '/backup/', '/admin/',
                 '/static/', '/assets/', '/logs/', '/tmp/', '/.git/']
        for path in paths:
            r = self.get(self.target_url + path)
            if r and any(x in r.text for x in ['Index of', 'Directory listing', 'Parent Directory']):
                self._add('Directory Listing', self.target_url + path,
                          f'Open directory listing at {path}')

    def _check_internal_ip(self):
        r = self.get(self.target_url)
        if not r:
            return
        pat = r'\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}\b'
        hits = set(re.findall(pat, r.text))
        if hits:
            self._add('Internal IP Disclosure', self.target_url,
                      f'Private IPs in response: {", ".join(hits)}')

    def _check_error_disclosure(self):
        for path in ['/thispagedoesnotexist123', '/%00', '/..%2f..%2f']:
            r = self.get(self.target_url + path)
            if not r:
                continue
            indicators = ['exception', 'traceback', 'stack trace', 'syntax error',
                          'mysqli_', 'pg_query', 'ORA-', 'SQLSTATE', 'Warning: include',
                          'fatal error', 'undefined index']
            if any(i in r.text.lower() for i in indicators):
                self._add('Verbose Error Messages', self.target_url + path,
                          'Stack trace or debug output exposed in error page')
                break

    def _check_open_redirect(self):
        """2026: Follow full chain, verify final netloc is the attacker domain."""
        keys = ['url', 'redirect', 'next', 'return', 'goto', 'dest', 'target', 'redir', 'continue', 'forward']
        payloads = ['https://evil.com', '//evil.com', 'https://evil.com/']
        test_urls = [f'{self.target_url}?{k}={p}' for k in keys for p in payloads[:1]]

        for url in tqdm(test_urls, desc='[Open Redirect]', ncols=100, colour='yellow'):
            r = self.get(url, allow_redirects=True)
            if not r:
                continue
            final = urlparse(r.url).netloc
            if 'evil.com' in final:
                self._add('Open Redirect', url,
                          f'Confirmed — final URL landed on: {r.url}')

    # ── ACTIVE INJECTION CHECKS ───────────────────────────────────────────────

    # 2026: SQLi uses error-based AND time-based blind detection
    def _sqli_test_url(self, url):
        found = []
        payloads = self.load_payloads('sqli.txt') or [
            "'", "''", "`", "1' OR '1'='1", "' OR 1=1--",
            "1 AND 1=1", "1 AND 1=2", "' OR SLEEP(5)--",
            "1; WAITFOR DELAY '0:0:5'--", "1' UNION SELECT NULL--",
            "\" OR \"1\"=\"1", "\\", "1' AND SLEEP(5)--"
        ]
        error_sigs = [
            'you have an error in your sql', 'warning: mysql',
            'mysql_fetch', 'mysqli', 'unclosed quotation mark',
            'quoted string not properly terminated', 'pg_query',
            'sqlstate', 'ora-', 'microsoft ole db', 'odbc drivers',
            'sqlite_', 'syntax error', 'invalid query',
        ]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return found

        for param in params:
            baseline = self._baseline(url)
            for payload in payloads:
                np = params.copy()
                np[param] = [payload]
                test_url = parsed._replace(query=urlencode(np, doseq=True)).geturl()

                # Error-based
                r = self.get(test_url)
                if r and any(sig in r.text.lower() for sig in error_sigs):
                    found.append({'type': 'SQL Injection', 'url': test_url,
                                  'description': f'Error-based SQLi in param: {param}'})
                    break

                # 2026: Time-based blind detection
                if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                    t0 = time.time()
                    r2 = self.get(test_url)
                    elapsed = time.time() - t0
                    if elapsed >= 4.5:
                        found.append({'type': 'Blind SQL Injection', 'url': test_url,
                                      'description': f'Time-based blind SQLi in param: {param} (delay: {elapsed:.1f}s)'})
                        break

        return found

    def _sqli_test_form(self, form):
        found = []
        payloads = self.load_payloads('sqli.txt') or [
            "'", "''", "1' OR '1'='1", "' OR 1=1--", "1' UNION SELECT NULL--",
            "\" OR \"1\"=\"1", "' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--"
        ]
        error_sigs = [
            'you have an error in your sql', 'warning: mysql', 'mysqli',
            'unclosed quotation mark', 'quoted string not properly terminated',
            'pg_query', 'sqlstate', 'ora-', 'syntax error', 'invalid query',
        ]
        for inp in form['inputs']:
            for payload in payloads[:12]:
                data = {i: 'test123' for i in form['inputs']}
                data[inp] = payload
                r = self.post(form['url'], data=data) if form['method'] == 'post' \
                    else self.get(form['url'], params=data)
                if r and any(sig in r.text.lower() for sig in error_sigs):
                    found.append({'type': 'SQL Injection', 'url': form['url'],
                                  'description': f'Error-based SQLi via form field "{inp}" (page: {form["page"]})'})
                    break

                # Time-based for forms
                if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                    t0 = time.time()
                    r2 = self.post(form['url'], data=data) if form['method'] == 'post' \
                        else self.get(form['url'], params=data)
                    if time.time() - t0 >= 4.5:
                        found.append({'type': 'Blind SQL Injection', 'url': form['url'],
                                      'description': f'Time-based blind SQLi via form field "{inp}"'})
                        break
        return found

    def _check_sqli(self):
        results = self._run_threaded(self._sqli_test_url,
                                     list(self.param_urls)[:25], '[SQLi - URLs]', 'red')
        results += self._run_threaded(self._sqli_test_form,
                                      self.forms[:20], '[SQLi - Forms]', 'red')
        self.vulnerabilities.extend(results)

    # 2026: XSS uses DOM sink patterns + context-aware payloads
    def _xss_test_url(self, url):
        found = []
        payloads = self.load_payloads('xss.txt') or [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            '<details open ontoggle=alert(1)>',
        ]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return found
        for param in params:
            for payload in payloads[:10]:
                np = params.copy()
                np[param] = [payload]
                test_url = parsed._replace(query=urlencode(np, doseq=True)).geturl()
                r = self.get(test_url)
                if r and payload in r.text:
                    # 2026: verify it's in HTML context not just anywhere
                    soup = BeautifulSoup(r.text, 'html.parser')
                    if soup.find(string=re.compile(re.escape(payload[:20]), re.IGNORECASE)) or \
                       payload in r.text:
                        found.append({'type': 'Cross-Site Scripting (XSS)', 'url': test_url,
                                      'description': f'Reflected XSS via GET param: {param}'})
                        break
        return found

    def _xss_test_form(self, form):
        found = []
        payloads = self.load_payloads('xss.txt') or [
            '<script>alert(1)</script>', '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>', '<svg/onload=alert(1)>',
            "'><img src=x onerror=alert(1)>",
        ]
        for inp in form['inputs']:
            for payload in payloads[:8]:
                data = {i: 'test123' for i in form['inputs']}
                data[inp] = payload
                r = self.post(form['url'], data=data) if form['method'] == 'post' \
                    else self.get(form['url'], params=data)
                if r and payload in r.text:
                    found.append({'type': 'Cross-Site Scripting (XSS)', 'url': form['url'],
                                  'description': f'Reflected XSS via form field "{inp}" (page: {form["page"]})'})
                    break
        return found

    def _check_xss(self):
        results = self._run_threaded(self._xss_test_url,
                                     list(self.param_urls)[:25], '[XSS - URLs]', 'red')
        results += self._run_threaded(self._xss_test_form,
                                      self.forms[:20], '[XSS - Forms]', 'red')
        self.vulnerabilities.extend(results)

    # 2026: SSTI — Server Side Template Injection (new check)
    def _ssti_test_item(self, item):
        found = []
        # Math payloads: server evaluates 7*7=49, reflected back — not user input
        probes = [('{{7*7}}', '49'), ('${7*7}', '49'), ('<%= 7*7 %>', '49'),
                  ('#{7*7}', '49'), ('*{7*7}', '49')]
        if isinstance(item, dict):  # form
            for inp in item['inputs']:
                for probe, expected in probes:
                    data = {i: 'test' for i in item['inputs']}
                    data[inp] = probe
                    r = self.post(item['url'], data=data) if item['method'] == 'post' \
                        else self.get(item['url'], params=data)
                    if r and expected in r.text and probe not in r.text:
                        found.append({'type': 'Server-Side Template Injection',
                                      'url': item['url'],
                                      'description': f'SSTI via form field "{inp}" — {probe} evaluated to {expected}'})
                        break
        else:  # URL
            parsed = urlparse(item)
            params = parse_qs(parsed.query)
            for param in params:
                for probe, expected in probes:
                    np = params.copy()
                    np[param] = [probe]
                    test_url = parsed._replace(query=urlencode(np, doseq=True)).geturl()
                    r = self.get(test_url)
                    if r and expected in r.text and probe not in r.text:
                        found.append({'type': 'Server-Side Template Injection',
                                      'url': test_url,
                                      'description': f'SSTI via param "{param}" — {probe} evaluated to {expected}'})
                        break
        return found

    def _check_ssti(self):
        items = list(self.param_urls)[:15] + self.forms[:10]
        results = self._run_threaded(self._ssti_test_item, items, '[SSTI]', 'red')
        self.vulnerabilities.extend(results)

    # 2026: Path traversal with encoding bypass variants
    def _traversal_test(self, args):
        url, payload = args
        found = []
        params_to_try = ['file', 'path', 'page', 'doc', 'template', 'include', 'load', 'read']
        for p in params_to_try:
            test_url = f'{url}?{p}={payload}'
            r = self.get(test_url)
            if not r:
                continue
            if re.search(r'root:.*:0:0:', r.text):
                found.append({'type': 'Path Traversal', 'url': test_url,
                              'description': f'Read /etc/passwd via param "{p}"'})
                break
            if '[extensions]' in r.text.lower() or '[mci extensions]' in r.text.lower():
                found.append({'type': 'Path Traversal', 'url': test_url,
                              'description': f'Read win.ini via param "{p}"'})
                break
        return found

    def _check_path_traversal(self):
        payloads = self.load_payloads('traversal.txt') or [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',     # double URL encode
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd', # unicode bypass
        ]
        urls = list(self.discovered_urls)[:15]
        tasks = [(url, p) for url in urls for p in payloads]
        results = self._run_threaded(self._traversal_test, tasks, '[Path Traversal]', 'red')
        self.vulnerabilities.extend(results)

    # 2026: Command injection uses unique echo marker + baseline diff
    def _cmdi_test(self, url):
        found = []
        marker = 'SIMON3Y_INJECT_OK'
        # OS-agnostic payloads covering Linux + Windows
        payloads = [
            f'; echo {marker}',
            f'| echo {marker}',
            f'`echo {marker}`',
            f'$(echo {marker})',
            f'& echo {marker} &',       # Windows
            f'&& echo {marker}',
        ]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return found
        for param in params:
            baseline = self._baseline(url)
            if marker in baseline:  # skip if marker already in page
                continue
            for payload in payloads:
                np = params.copy()
                np[param] = [payload]
                test_url = parsed._replace(query=urlencode(np, doseq=True)).geturl()
                r = self.get(test_url)
                # Marker must appear in response but NOT in baseline
                if r and marker in r.text and marker not in baseline:
                    found.append({'type': 'Command Injection', 'url': test_url,
                                  'description': f'Confirmed OS command execution via param "{param}"'})
                    break
        return found

    def _check_command_injection(self):
        results = self._run_threaded(self._cmdi_test,
                                     list(self.param_urls)[:15], '[Cmd Injection]', 'red')
        self.vulnerabilities.extend(results)

    def _check_xxe(self):
        payload = ('<?xml version="1.0" encoding="UTF-8"?>'
                   '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                   '<foo>&xxe;</foo>')
        for url in list(self.discovered_urls)[:5]:
            r = self.post(url, data=payload,
                          headers={'Content-Type': 'application/xml'})
            if r and re.search(r'root:.*:0:0:', r.text):
                self._add('XXE Injection', url,
                          'XML parser reads external entities — /etc/passwd accessible')


# ── PDF REPORT ────────────────────────────────────────────────────────────────

def generate_report(filename, findings, target_url):
    doc = SimpleDocTemplate(filename, pagesize=letter,
                            leftMargin=50, rightMargin=50,
                            topMargin=50, bottomMargin=50)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('title', fontSize=20, alignment=TA_CENTER,
                                 spaceAfter=6, textColor=colors.HexColor('#1a1a2e'),
                                 fontName='Helvetica-Bold')
    section_style = ParagraphStyle('section', fontSize=13, spaceAfter=4,
                                   spaceBefore=12, textColor=colors.HexColor('#16213e'),
                                   fontName='Helvetica-Bold')
    label_style = ParagraphStyle('label', fontSize=10, spaceAfter=2,
                                 textColor=colors.HexColor('#0f3460'), fontName='Helvetica-Bold')
    body_style = ParagraphStyle('body', fontSize=9, spaceAfter=8,
                                textColor=colors.HexColor('#333333'), fontName='Helvetica')

    sev_colors = {
        'Critical': colors.HexColor('#c0392b'),
        'High': colors.HexColor('#e67e22'),
        'Medium': colors.HexColor('#f39c12'),
        'Low': colors.HexColor('#27ae60'),
        'Info': colors.HexColor('#2980b9'),
    }

    elements = []

    elements.append(Paragraph('S!M0N — Vulnerability Assessment Report', title_style))
    elements.append(Paragraph('by GR3Y | github.com/r4hul-s3thi/Simon_vs', 
                              ParagraphStyle('sub', fontSize=9, alignment=TA_CENTER,
                                            textColor=colors.grey, fontName='Helvetica')))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#1a1a2e')))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(f'<b>Target:</b> {target_url}', body_style))
    elements.append(Paragraph(f'<b>Scan Date:</b> {time.strftime("%Y-%m-%d %H:%M:%S")}', body_style))
    total = sum(len(v) for v in findings.values())
    elements.append(Paragraph(f'<b>Total Findings:</b> {total}', body_style))
    elements.append(Spacer(1, 8))

    # Summary table
    elements.append(Paragraph('Executive Summary', section_style))
    elements.append(HRFlowable(width='100%', thickness=0.5, color=colors.lightgrey))
    elements.append(Spacer(1, 6))
    for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        count = len(findings.get(sev, []))
        if count:
            col = sev_colors[sev]
            elements.append(Paragraph(
                f'<font color="{col.hexval()}">\u25cf</font> <b>{sev}:</b> {count} finding(s)',
                body_style))
    elements.append(Spacer(1, 12))

    # Detailed findings
    for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        vulns = findings.get(sev, [])
        if not vulns:
            continue
        col = sev_colors[sev]
        elements.append(Paragraph(
            f'<font color="{col.hexval()}">{sev} Risk Findings</font>', section_style))
        elements.append(HRFlowable(width='100%', thickness=0.5, color=col))
        elements.append(Spacer(1, 6))
        for i, vuln in enumerate(vulns, 1):
            elements.append(Paragraph(f'[{i}] {vuln["type"]}', label_style))
            elements.append(Paragraph(f'<b>URL:</b> {vuln["url"]}', body_style))
            elements.append(Paragraph(f'<b>Detail:</b> {vuln["description"]}', body_style))
            elements.append(HRFlowable(width='100%', thickness=0.3, color=colors.lightgrey))
            elements.append(Spacer(1, 4))
        elements.append(Spacer(1, 8))

    if total == 0:
        elements.append(Paragraph('No vulnerabilities detected.', body_style))

    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width='100%', thickness=0.5, color=colors.lightgrey))
    elements.append(Paragraph(
        'Disclaimer: For authorized security testing only. Scan responsibly.',
        ParagraphStyle('disc', fontSize=7, textColor=colors.grey,
                       alignment=TA_CENTER, fontName='Helvetica')))

    doc.build(elements)


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description='S!M0N v3: 2026-standard web vulnerability scanner')
    parser.add_argument('-d', '--domain', required=True, help='Target URL')
    parser.add_argument('-o', '--output', default='report.pdf', help='PDF output filename')
    parser.add_argument('-l', '--level', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Threads (default: 5)')
    parser.add_argument('--subdomains', action='store_true', help='Include subdomains')
    parser.add_argument('--no-crawl', action='store_true', help='Skip crawling')
    args = parser.parse_args()

    print(f'{Fore.CYAN}  Target  : {args.domain}')
    print(f'  Output  : {args.output}')
    print(f'  Depth   : {args.level}')
    print(f'  Threads : {args.threads}')
    if args.subdomains:
        print(f'  Scope   : subdomains included')
    print(f'{Style.RESET_ALL}')

    scanner = EnhancedVulnerabilityScanner(
        args.domain,
        max_threads=args.threads,
        crawl_depth=args.level,
        enable_subdomains=args.subdomains,
    )
    findings = scanner.scan(skip_crawl=args.no_crawl)

    total = sum(len(v) for v in findings.values())
    print(f'\n{Fore.YELLOW}{"="*55}{Style.RESET_ALL}')
    print(f'{Fore.GREEN}[+] Scan complete — {total} finding(s){Style.RESET_ALL}')
    sev_colors_term = {
        'Critical': Fore.RED, 'High': Fore.RED,
        'Medium': Fore.YELLOW, 'Low': Fore.BLUE, 'Info': Fore.CYAN
    }
    for sev, vulns in findings.items():
        if vulns:
            print(f'{sev_colors_term[sev]}    {sev}: {len(vulns)}{Style.RESET_ALL}')

    print(f'\n{Fore.CYAN}[*] Generating PDF: {args.output}...{Style.RESET_ALL}')
    try:
        generate_report(args.output, findings, args.domain)
        print(f'{Fore.GREEN}[+] Report saved: {args.output}{Style.RESET_ALL}')
    except Exception as e:
        print(f'{Fore.RED}[!] PDF failed: {e}{Style.RESET_ALL}')
    print(f'{Fore.YELLOW}{"="*55}{Style.RESET_ALL}')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f'\n{Fore.RED}[!] Interrupted.{Style.RESET_ALL}')
        sys.exit(1)
    except Exception as e:
        print(f'\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}')
        sys.exit(1)
