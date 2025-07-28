"""
Web Vulnerability Scanner - Security Headers Plugin

This plugin checks for the presence and proper configuration of security-related HTTP headers, including:
1. Content-Security-Policy
2. X-XSS-Protection
3. X-Content-Type-Options
4. X-Frame-Options
5. Strict-Transport-Security
6. Referrer-Policy
7. Feature-Policy/Permissions-Policy
8. Cache-Control and other cache-related headers
9. Deprecated security headers

It evaluates header strength and provides specific recommendations for improvement.
"""

import logging
import re
from typing import Dict, List, Any, Set, Tuple, Optional
import json

from plugins.base import Plugin
from scanner.http_client import HttpClient
from scanner.reporter import Finding, Severity, Reporter

# Configure logging
logger = logging.getLogger('plugins.security_headers')

class SecurityHeadersPlugin(Plugin):
    """
    Plugin for checking HTTP security headers.
    """
    
    name = "security_headers"
    description = "Checks for the presence and proper configuration of security-related HTTP headers"
    
    # Required security headers and their recommended values
    REQUIRED_HEADERS = {
        'content-security-policy': {
            'severity': Severity.HIGH,
            'cwe': '1021',  # CWE-1021: Improper Restriction of Rendered UI Layers or Frames
            'description': "Helps prevent Cross-Site Scripting (XSS) and data injection attacks",
            'recommendation': "Implement a strong Content-Security-Policy that restricts sources of executable scripts, objects, frames, etc.",
            'reference': "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            'check': lambda v: not any(x in v.lower() for x in ['unsafe-inline', 'unsafe-eval', '*']) or 'report-only' in v.lower()
        },
        'x-content-type-options': {
            'severity': Severity.MEDIUM,
            'cwe': '16',  # CWE-16: Configuration
            'description': "Prevents MIME type sniffing",
            'recommendation': "Set X-Content-Type-Options to 'nosniff'",
            'reference': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            'check': lambda v: v.lower() == 'nosniff'
        },
        'x-frame-options': {
            'severity': Severity.MEDIUM,
            'cwe': '1021',  # CWE-1021: Improper Restriction of Rendered UI Layers or Frames
            'description': "Prevents clickjacking attacks",
            'recommendation': "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'",
            'reference': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            'check': lambda v: v.upper() in ['DENY', 'SAMEORIGIN']
        },
        'strict-transport-security': {
            'severity': Severity.MEDIUM,
            'cwe': '319',  # CWE-319: Cleartext Transmission of Sensitive Information
            'description': "Ensures the browser only connects to the server over HTTPS",
            'recommendation': "Set Strict-Transport-Security with max-age of at least 31536000 (1 year) and include subdomains",
            'reference': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            'check': lambda v: ('max-age=' in v.lower() and 
                              int(re.search(r'max-age=(\d+)', v.lower()).group(1)) >= 31536000 and 
                              'includesubdomains' in v.lower())
        },
        'x-xss-protection': {
            'severity': Severity.LOW,  # Considered less important in modern browsers
            'cwe': '79',  # CWE-79: Improper Neutralization of Input During Web Page Generation
            'description': "Enables browser's built-in XSS filtering",
            'recommendation': "Set X-XSS-Protection to '1; mode=block'",
            'reference': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
            'check': lambda v: v.lower() == '1; mode=block'
        },
        'referrer-policy': {
            'severity': Severity.LOW,
            'cwe': '200',  # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
            'description': "Controls how much referrer information is included with requests",
            'recommendation': "Set Referrer-Policy to 'no-referrer' or 'strict-origin-when-cross-origin'",
            'reference': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
            'check': lambda v: v.lower() in ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin', 
                                           'strict-origin-when-cross-origin', 'same-origin']
        },
        'permissions-policy': {
            'severity': Severity.LOW,
            'cwe': '16',  # CWE-16: Configuration
            'description': "Controls which browser features and APIs can be used in the document",
            'recommendation': "Implement a Permissions-Policy to restrict access to sensitive features like camera, microphone, geolocation",
            'reference': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
            'check': lambda v: True  # Any value is better than none, detailed checking is complex
        },
    }
    
    # Handle Feature-Policy as an alias of Permissions-Policy (older name)
    REQUIRED_HEADERS['feature-policy'] = REQUIRED_HEADERS['permissions-policy'].copy()
    
    # Cache-related headers to check
    CACHE_HEADERS = {
        'cache-control': {
            'severity': Severity.LOW,
            'cwe': '524',  # CWE-524: Use of Cache Containing Sensitive Information
            'description': "Controls how pages are cached by browsers and proxies",
            'recommendation': "For sensitive pages, set Cache-Control to 'no-store, no-cache, must-revalidate, max-age=0'",
            'reference': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
            'check': lambda v: any(x in v.lower() for x in ['no-store', 'no-cache', 'private'])
        },
        'pragma': {
            'severity': Severity.INFO,
            'cwe': '524',
            'description': "Legacy header for controlling caching",
            'recommendation': "Consider using Cache-Control instead, but for maximum compatibility include 'Pragma: no-cache'",
            'reference': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma",
            'check': lambda v: v.lower() == 'no-cache'
        },
        'expires': {
            'severity': Severity.INFO,
            'cwe': '524',
            'description': "Sets the date/time after which the response is considered stale",
            'recommendation': "For sensitive pages, set Expires to a date in the past or '0'",
            'reference': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires",
            'check': lambda v: True  # Complex to check exact date format, presence is enough
        }
    }
    
    # Deprecated/problematic headers to check for
    PROBLEMATIC_HEADERS = {
        'server': {
            'severity': Severity.LOW,
            'cwe': '200',
            'description': "Reveals server software information",
            'recommendation': "Remove or customize the Server header to avoid revealing software details",
            'reference': "https://owasp.org/www-project-secure-headers/#server"
        },
        'x-powered-by': {
            'severity': Severity.LOW,
            'cwe': '200',
            'description': "Reveals technology stack information",
            'recommendation': "Remove the X-Powered-By header to avoid revealing technology details",
            'reference': "https://owasp.org/www-project-secure-headers/#x-powered-by"
        },
        'x-aspnet-version': {
            'severity': Severity.LOW,
            'cwe': '200',
            'description': "Reveals ASP.NET version information",
            'recommendation': "Remove the X-AspNet-Version header",
            'reference': "https://owasp.org/www-project-secure-headers/"
        },
        'x-aspnetmvc-version': {
            'severity': Severity.LOW,
            'cwe': '200',
            'description': "Reveals ASP.NET MVC version information",
            'recommendation': "Remove the X-AspNetMvc-Version header",
            'reference': "https://owasp.org/www-project-secure-headers/"
        }
    }
    
    # Missing security header templates
    MISSING_HEADER_TEMPLATES = {
        'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; img-src 'self' data:; connect-src 'self';",
        'x-content-type-options': "nosniff",
        'x-frame-options': "DENY",
        'strict-transport-security': "max-age=31536000; includeSubDomains; preload",
        'x-xss-protection': "1; mode=block",
        'referrer-policy': "strict-origin-when-cross-origin",
        'permissions-policy': "camera=(), microphone=(), geolocation=(), interest-cohort=()",
        'feature-policy': "camera 'none'; microphone 'none'; geolocation 'none'; interest-cohort 'none'",
        'cache-control': "no-store, no-cache, must-revalidate, max-age=0",
        'pragma': "no-cache"
    }
    
    def __init__(self, reporter: Reporter = None):
        """Initialize the security headers plugin."""
        super().__init__(reporter)
        self.tested_urls: Set[str] = set()
    
    def scan(self, target_url: str, http_client: HttpClient) -> List[Finding]:
        """
        Scan for missing or misconfigured security headers.
        
        Args:
            target_url: URL to scan
            http_client: HTTP client for making requests
            
        Returns:
            List[Finding]: List of findings
        """
        findings = []
        
        # Skip if already tested
        if target_url in self.tested_urls:
            return findings
        
        # Add to tested URLs
        self.tested_urls.add(target_url)
        
        self.logger.info(f"Scanning {target_url} for security header issues")
        
        try:
            # Send request and get headers
            response = http_client.get(target_url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Check for missing required headers
            missing_header_findings = self._check_missing_headers(headers, target_url)
            findings.extend(missing_header_findings)
            
            # Check for misconfigured headers
            misconfigured_header_findings = self._check_misconfigured_headers(headers, target_url)
            findings.extend(misconfigured_header_findings)
            
            # Check for problematic headers
            problematic_header_findings = self._check_problematic_headers(headers, target_url)
            findings.extend(problematic_header_findings)
            
            # Check for cookie issues
            cookie_findings = self._check_cookie_security(response.cookies, target_url)
            findings.extend(cookie_findings)
            
        except Exception as e:
            self.logger.error(f"Error scanning {target_url} for security headers: {e}")
        
        # Report findings
        for finding in findings:
            self.report_finding(finding)
        
        return findings
    
    def _check_missing_headers(self, headers: Dict[str, str], url: str) -> List[Finding]:
        """
        Check for missing security headers.
        
        Args:
            headers: Response headers
            url: Target URL
            
        Returns:
            List[Finding]: List of findings for missing headers
        """
        findings = []
        
        # Check required security headers
        for header_name, header_info in self.REQUIRED_HEADERS.items():
            # Skip if this header or an equivalent is present
            if header_name in headers:
                continue
            
            # Special case for Feature-Policy vs Permissions-Policy (they're alternatives)
            if header_name == 'feature-policy' and 'permissions-policy' in headers:
                continue
            if header_name == 'permissions-policy' and 'feature-policy' in headers:
                continue
            
            # Create finding for missing header
            finding = Finding(
                title=f"Missing {self._format_header_name(header_name)} Header",
                description=(
                    f"The {self._format_header_name(header_name)} header is missing. "
                    f"{header_info['description']}."
                ),
                url=url,
                severity=header_info['severity'],
                plugin_name=self.name,
                evidence=f"No {self._format_header_name(header_name)} header was found in the response",
                request_data={"url": url, "method": "GET"},
                response_data={"headers": headers},
                remediation=(
                    f"{header_info['recommendation']}. "
                    f"Suggested value: {self.MISSING_HEADER_TEMPLATES.get(header_name, 'See reference')}\n\n"
                    f"Reference: {header_info['reference']}"
                ),
                cwe_id=header_info['cwe']
            )
            findings.append(finding)
        
        # Check cache-related headers for sensitive pages
        # We check if any of the cache headers are present
        # If none are present, suggest adding them
        has_any_cache_header = any(cache_header in headers for cache_header in self.CACHE_HEADERS.keys())
        
        if not has_any_cache_header:
            # Suggest adding Cache-Control
            cache_info = self.CACHE_HEADERS['cache-control']
            finding = Finding(
                title="Missing Cache-Control Header",
                description=(
                    "No cache control headers were found. "
                    "Without proper cache controls, sensitive information might be cached "
                    "by browsers or proxies, potentially exposing it to unauthorized users."
                ),
                url=url,
                severity=cache_info['severity'],
                plugin_name=self.name,
                evidence="No Cache-Control, Pragma, or Expires headers were found in the response",
                request_data={"url": url, "method": "GET"},
                response_data={"headers": headers},
                remediation=(
                    "Add appropriate cache control headers to prevent caching of sensitive information.\n"
                    f"Suggested value: Cache-Control: {self.MISSING_HEADER_TEMPLATES['cache-control']}\n\n"
                    f"Reference: {cache_info['reference']}"
                ),
                cwe_id=cache_info['cwe']
            )
            findings.append(finding)
        
        return findings
    
    def _check_misconfigured_headers(self, headers: Dict[str, str], url: str) -> List[Finding]:
        """
        Check for misconfigured security headers.
        
        Args:
            headers: Response headers
            url: Target URL
            
        Returns:
            List[Finding]: List of findings for misconfigured headers
        """
        findings = []
        
        # Check each security header against its recommended configuration
        for header_name, header_info in self.REQUIRED_HEADERS.items():
            # Skip if header is not present
            if header_name not in headers:
                continue
            
            # Skip if check function is not defined
            if 'check' not in header_info:
                continue
            
            # Check if header value meets recommendations
            header_value = headers[header_name]
            check_result = header_info['check'](header_value)
            
            if not check_result:
                finding = Finding(
                    title=f"Misconfigured {self._format_header_name(header_name)} Header",
                    description=(
                        f"The {self._format_header_name(header_name)} header is present but not configured optimally. "
                        f"{header_info['description']}."
                    ),
                    url=url,
                    severity=header_info['severity'],
                    plugin_name=self.name,
                    evidence=f"{self._format_header_name(header_name)}: {header_value}",
                    request_data={"url": url, "method": "GET"},
                    response_data={"headers": {header_name: header_value}},
                    remediation=(
                        f"{header_info['recommendation']}. "
                        f"Current value: {header_value}\n"
                        f"Suggested value: {self.MISSING_HEADER_TEMPLATES.get(header_name, 'See reference')}\n\n"
                        f"Reference: {header_info['reference']}"
                    ),
                    cwe_id=header_info['cwe']
                )
                findings.append(finding)
        
        # Check cache headers
        for header_name, header_info in self.CACHE_HEADERS.items():
            # Skip if header is not present
            if header_name not in headers:
                continue
            
            # Skip if check function is not defined
            if 'check' not in header_info:
                continue
            
            # Check if header value meets recommendations
            header_value = headers[header_name]
            check_result = header_info['check'](header_value)
            
            if not check_result:
                finding = Finding(
                    title=f"Suboptimal {self._format_header_name(header_name)} Header",
                    description=(
                        f"The {self._format_header_name(header_name)} header is present but not configured optimally "
                        f"for security. {header_info['description']}."
                    ),
                    url=url,
                    severity=header_info['severity'],
                    plugin_name=self.name,
                    evidence=f"{self._format_header_name(header_name)}: {header_value}",
                    request_data={"url": url, "method": "GET"},
                    response_data={"headers": {header_name: header_value}},
                    remediation=(
                        f"{header_info['recommendation']}. "
                        f"Current value: {header_value}\n"
                        f"Suggested value: {self.MISSING_HEADER_TEMPLATES.get(header_name, 'See reference')}\n\n"
                        f"Reference: {header_info['reference']}"
                    ),
                    cwe_id=header_info['cwe']
                )
                findings.append(finding)
        
        # Special check for Content-Security-Policy
        if 'content-security-policy' in headers:
            csp_value = headers['content-security-policy']
            csp_findings = self._check_content_security_policy(csp_value, url)
            findings.extend(csp_findings)
        
        return findings
    
    def _check_content_security_policy(self, csp_value: str, url: str) -> List[Finding]:
        """
        Check Content-Security-Policy for weak configurations.
        
        Args:
            csp_value: CSP header value
            url: Target URL
            
        Returns:
            List[Finding]: List of findings for CSP issues
        """
        findings = []
        csp_lower = csp_value.lower()
        
        # Check for unsafe directives
        unsafe_directives = []
        
        if "unsafe-inline" in csp_lower:
            unsafe_directives.append("'unsafe-inline'")
        
        if "unsafe-eval" in csp_lower:
            unsafe_directives.append("'unsafe-eval'")
            
        if "data:" in csp_lower and "img-src" not in csp_lower:
            unsafe_directives.append("data: (without proper scope)")
            
        # Check for wildcard sources
        wildcard_directives = []
        
        for directive in ["script-src", "object-src", "frame-src", "frame-ancestors", "connect-src", "form-action"]:
            directive_pattern = rf"{directive}\s+[^;]*\*[^;]*"
            if re.search(directive_pattern, csp_lower):
                wildcard_directives.append(f"{directive} *")
        
        # Report findings if unsafe or wildcard directives are found
        if unsafe_directives or wildcard_directives:
            finding_items = []
            
            if unsafe_directives:
                finding_items.append(f"Unsafe directives: {', '.join(unsafe_directives)}")
            
            if wildcard_directives:
                finding_items.append(f"Wildcard sources: {', '.join(wildcard_directives)}")
            
            finding = Finding(
                title="Weak Content-Security-Policy Configuration",
                description=(
                    "The Content-Security-Policy header contains potentially insecure directives "
                    "or overly permissive wildcard sources that may reduce its effectiveness against XSS attacks."
                ),
                url=url,
                severity=Severity.MEDIUM,
                plugin_name=self.name,
                evidence=f"Content-Security-Policy: {csp_value}\n\n{', '.join(finding_items)}",
                request_data={"url": url, "method": "GET"},
                response_data={"headers": {"content-security-policy": csp_value}},
                remediation=(
                    "1. Avoid using 'unsafe-inline' and 'unsafe-eval' directives\n"
                    "2. Avoid wildcard (*) sources in critical directives\n"
                    "3. Use nonces or hashes instead of 'unsafe-inline'\n"
                    "4. Specify trusted domains explicitly rather than using wildcards\n"
                    "5. Consider using a strict CSP like:\n"
                    f"{self.MISSING_HEADER_TEMPLATES['content-security-policy']}\n\n"
                    "Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
                ),
                cwe_id="1021"  # CWE-1021: Improper Restriction of Rendered UI Layers or Frames
            )
            findings.append(finding)
        
        return findings
    
    def _check_problematic_headers(self, headers: Dict[str, str], url: str) -> List[Finding]:
        """
        Check for problematic headers that may leak information.
        
        Args:
            headers: Response headers
            url: Target URL
            
        Returns:
            List[Finding]: List of findings for problematic headers
        """
        findings = []
        
        # Check for each problematic header
        for header_name, header_info in self.PROBLEMATIC_HEADERS.items():
            if header_name in headers:
                header_value = headers[header_name]
                
                # Skip Server header if it doesn't reveal specific information
                if header_name == 'server' and header_value.lower() in ['apache', 'nginx', 'iis', 'cloudflare', 'server']:
                    continue
                
                finding = Finding(
                    title=f"Information Leakage in {self._format_header_name(header_name)} Header",
                    description=(
                        f"The {self._format_header_name(header_name)} header reveals potentially sensitive information. "
                        f"{header_info['description']}."
                    ),
                    url=url,
                    severity=header_info['severity'],
                    plugin_name=self.name,
                    evidence=f"{self._format_header_name(header_name)}: {header_value}",
                    request_data={"url": url, "method": "GET"},
                    response_data={"headers": {header_name: header_value}},
                    remediation=(
                        f"{header_info['recommendation']}.\n\n"
                        f"Reference: {header_info['reference']}"
                    ),
                    cwe_id=header_info['cwe']
                )
                findings.append(finding)
        
        return findings
    
    def _check_cookie_security(self, cookies, url: str) -> List[Finding]:
        """
        Check cookies for security issues.
        
        Args:
            cookies: Response cookies
            url: Target URL
            
        Returns:
            List[Finding]: List of findings for cookie security issues
        """
        findings = []
        
        # Skip if no cookies
        if not cookies:
            return findings
        
        # Check if URL is HTTPS
        is_https = url.startswith('https://')
        
        # Check each cookie
        for cookie in cookies:
            cookie_issues = []
            
            # Check if cookie is missing secure flag
            if is_https and not cookie.secure:
                cookie_issues.append("Missing Secure flag")
            
            # Check if cookie is missing HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly'):
                cookie_issues.append("Missing HttpOnly flag")
            
            # Check if SameSite attribute is missing or set to 'None'
            samesite = cookie.get_nonstandard_attr('SameSite')
            if not samesite:
                cookie_issues.append("Missing SameSite attribute")
            elif samesite.lower() == 'none' and (not cookie.secure):
                cookie_issues.append("SameSite=None without Secure flag")
            
            # If any issues, create a finding
            if cookie_issues:
                finding = Finding(
                    title=f"Insecure Cookie: {cookie.name}",
                    description=(
                        f"The cookie '{cookie.name}' has security issues: {', '.join(cookie_issues)}. "
                        "This could potentially lead to cookie theft, session hijacking, or CSRF attacks."
                    ),
                    url=url,
                    severity=Severity.MEDIUM,
                    plugin_name=self.name,
                    evidence=f"Cookie: {cookie.name}={cookie.value}; " + 
                             f"Secure={cookie.secure}; " + 
                             f"HttpOnly={cookie.has_nonstandard_attr('HttpOnly')}; " + 
                             f"SameSite={cookie.get_nonstandard_attr('SameSite') or 'Not Set'}",
                    request_data={"url": url, "method": "GET"},
                    response_data={"cookies": {cookie.name: cookie.value}},
                    remediation=(
                        "Set appropriate security attributes on cookies:\n"
                        "1. Set Secure flag for HTTPS cookies\n"
                        "2. Set HttpOnly flag for cookies not needed by JavaScript\n"
                        "3. Set SameSite=Strict or SameSite=Lax attribute (not None)\n"
                        "4. If SameSite=None is necessary, ensure the Secure flag is also set\n\n"
                        "Reference: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies"
                    ),
                    cwe_id="614"  # CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
                )
                findings.append(finding)
        
        return findings
    
    def _format_header_name(self, header_name: str) -> str:
        """
        Format header name for display.
        
        Args:
            header_name: Name of the header
            
        Returns:
            str: Formatted header name
        """
        # Split by hyphens and capitalize each part
        parts = header_name.split('-')
        capitalized_parts = [part.capitalize() for part in parts]
        return '-'.join(capitalized_parts)
