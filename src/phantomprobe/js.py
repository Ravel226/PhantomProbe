#!/usr/bin/env python3
"""
JavaScript analysis: discover API endpoints, exposed secrets and hidden paths
in the client-side assets a target serves.
"""

import hashlib
import re
import ssl
from datetime import datetime
from html.parser import HTMLParser
from typing import List, Optional, Set, Tuple
from urllib.request import Request

from .http_client import safe_urlopen

from .constants import BROWSER_USER_AGENT
from .models import Finding, Severity


class ScriptTagParser(HTMLParser):
    """HTML parser to extract script src URLs"""
    
    def __init__(self):
        super().__init__()
        self.script_urls: List[str] = []
    
    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            for attr, value in attrs:
                if attr == 'src' and value:
                    self.script_urls.append(value)


class JSEngine:
    """JavaScript analysis for endpoint and secret discovery"""

    # Regex patterns for API endpoints
    ENDPOINT_PATTERNS = [
        r'["\']/(api|v[0-9]+|rest|graphql|query)/[a-zA-Z0-9_/-]+["\']',
        r'["\'][a-zA-Z0-9_/-]+:[a-zA-Z0-9_/-]+["\']',  # GraphQL-style
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'\.ajax\([^)]*url:\s*["\']([^"\']+)["\']',
    ]

    # Regex patterns for secrets
    SECRET_PATTERNS = [
        (r'(?i)["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'API Key'),
        (r'(?i)["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'Secret Key'),
        (r'(?i)["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_.-]{20,})["\']', 'Auth Token'),
        (r'(?i)["\']?bearer["\']?\s*[:=]\s*["\']([a-zA-Z0-9_.-]{20,})["\']', 'Bearer Token'),
        (r'(?i)["\']?access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_.-]{20,})["\']', 'Access Token'),
        (r'(?i)aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key'),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'AWS Secret Key'),
        (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI API Key'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Token'),
        (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
        (r'ghu_[a-zA-Z0-9]{36}', 'GitHub User Token'),
        (r'ghs_[a-zA-Z0-9]{36}', 'GitHub Server Token'),
        (r'xox[baprs]-[0-9]{10,}-[a-zA-Z0-9]{24}', 'Slack Token'),
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'JWT Token'),
        (r'(?i)["\']?private[_-]?key["\']?\s*[:=]\s*["\']-----BEGIN[^"\']+["\']', 'Private Key'),
    ]

    # Regex patterns for hidden paths
    PATH_PATTERNS = [
        r'["\']/(admin|config|backup|test|dev|staging|api|debug|console|dashboard)/[a-zA-Z0-9_/-]*["\']',
        r'["\']\.(php|asp|aspx|jsp|cgi|json|xml|yaml|yml|env|conf|config|log)["\']',
    ]

    def __init__(self, target: str):
        self.target = target
        self.findings: List[Finding] = []
        self.js_urls: Set[str] = set()
        self.endpoints: Set[str] = set()
        self.secrets: List[Tuple[str, str, str]] = []  # (type, value, file)
        self.hidden_paths: Set[str] = set()

    def fetch_page(self, url: str) -> Optional[str]:
        """Fetch HTML page content"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = Request(url, headers={'User-Agent': BROWSER_USER_AGENT})
            with safe_urlopen(req, context=ctx, timeout=15) as response:
                return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return None

    def fetch_js(self, url: str) -> Optional[str]:
        """Fetch JavaScript file content"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Handle relative URLs
            if url.startswith('//'):
                url = f'https:{url}'
            elif url.startswith('/'):
                url = f'https://{self.target}{url}'
            elif not url.startswith('http'):
                url = f'https://{self.target}/{url}'

            req = Request(url, headers={'User-Agent': BROWSER_USER_AGENT})
            with safe_urlopen(req, context=ctx, timeout=15) as response:
                return response.read().decode('utf-8', errors='ignore')
        except Exception:
            return None

    def extract_js_urls(self, html: str) -> List[str]:
        """Extract JavaScript URLs from HTML"""
        parser = ScriptTagParser()
        try:
            parser.feed(html)
        except Exception:
            pass
        
        # Also find inline script tags and other JS sources
        patterns = [
            r'<script[^>]+src=["\']([^"\']+)["\']',
            r'import\s+.*?from\s+["\']([^"\']+\.js)["\']',
        ]
        
        urls = set(parser.script_urls)
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            urls.update(matches)
        
        return list(urls)

    def analyze_js(self, js_content: str, js_url: str) -> None:
        """Analyze JavaScript content for endpoints and secrets"""
        
        # Extract API endpoints
        for pattern in self.ENDPOINT_PATTERNS:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[1] if len(match) > 1 else None
                if match and len(match) > 3:
                    self.endpoints.add(match.strip('\'"'))

        # Extract secrets
        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and len(match) >= 10:
                    # Mask the secret for reporting
                    masked = match[:4] + '*' * (len(match) - 8) + match[-4:] if len(match) > 12 else '****'
                    self.secrets.append((secret_type, masked, js_url))

        # Extract hidden paths
        for pattern in self.PATH_PATTERNS:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match:
                    self.hidden_paths.add(match.strip('\'"'))

    def run(self) -> List[Finding]:
        """Run JavaScript analysis"""
        print(f"[*] Analyzing JavaScript files...")

        # Fetch main page
        main_url = f"https://{self.target}"
        html = self.fetch_page(main_url)
        
        if not html:
            # Try HTTP
            main_url = f"http://{self.target}"
            html = self.fetch_page(main_url)

        if not html:
            print(f"[!] Could not fetch main page")
            return []

        # Extract JS URLs
        js_urls = self.extract_js_urls(html)
        print(f"[*] Found {len(js_urls)} JavaScript files")

        # Fetch and analyze each JS file
        for js_url in js_urls[:20]:  # Limit to 20 files
            js_content = self.fetch_js(js_url)
            if js_content:
                self.analyze_js(js_content, js_url)

        # Create findings from discovered items
        
        # Endpoints
        for endpoint in sorted(self.endpoints)[:30]:
            self.findings.append(Finding(
                id=f"JS-ENDPOINT-{hashlib.sha256(endpoint.encode()).hexdigest()[:8]}",
                title="API Endpoint Discovered",
                description=f"Potential API endpoint found: {endpoint}",
                severity=Severity.INFORMATIONAL,
                category="JavaScript Analysis",
                evidence=f"Endpoint: {endpoint}",
                remediation="Review if endpoint should be publicly accessible",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        # Secrets (more severe)
        for secret_type, masked_value, source in self.secrets:
            self.findings.append(Finding(
                id=f"JS-SECRET-{hashlib.sha256(masked_value.encode()).hexdigest()[:8]}",
                title=f"Potential {secret_type} Exposed",
                description=f"Potential {secret_type} found in JavaScript: {masked_value}",
                severity=Severity.HIGH,
                category="Information Disclosure",
                evidence=f"Type: {secret_type}\nValue: {masked_value}\nSource: {source}",
                remediation="Remove secrets from client-side code. Use environment variables or secret management.",
                references=["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_GET_request"],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        # Hidden paths
        for path in sorted(self.hidden_paths)[:20]:
            self.findings.append(Finding(
                id=f"JS-PATH-{hashlib.sha256(path.encode()).hexdigest()[:8]}",
                title="Hidden Path Discovered",
                description=f"Potential hidden path found: {path}",
                severity=Severity.LOW,
                category="JavaScript Analysis",
                evidence=f"Path: {path}",
                remediation="Verify path doesn't expose sensitive functionality",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        # Summary finding
        if self.findings:
            summary = f"Analyzed {len(js_urls)} JS files\n"
            summary += f"Found {len(self.endpoints)} endpoints\n"
            summary += f"Found {len(self.secrets)} potential secrets\n"
            summary += f"Found {len(self.hidden_paths)} hidden paths"
            
            self.findings.append(Finding(
                id="JS-SUMMARY",
                title="JavaScript Analysis Summary",
                description=summary,
                severity=Severity.INFORMATIONAL,
                category="JavaScript Analysis",
                evidence=summary,
                remediation="Review findings and verify if sensitive data is exposed",
                references=[],
                discovered_at=datetime.now().isoformat(),
                target=self.target
            ))

        print(f"[+] JavaScript analysis: {len(self.findings)} findings")
        return self.findings

