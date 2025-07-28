"""
Web Vulnerability Scanner - Open Redirect Plugin

This plugin tests for open redirect vulnerabilities by:
1. Identifying URL-related parameters in URLs and forms
2. Testing each parameter with redirect payloads
3. Detecting if the application redirects to those external domains
"""

import logging
import re
from typing import Dict, List, Any, Set
from urllib.parse import urlparse, parse_qs, urlencode, unquote

import requests
from bs4 import BeautifulSoup

from plugins.base import Plugin
from scanner.http_client import HttpClient
from scanner.parser import HtmlParser, FormData
from scanner.reporter import Finding, Severity, Reporter

# Configure logging
logger = logging.getLogger('plugins.open_redirect')

class OpenRedirectPlugin(Plugin):
    """
    Plugin for detecting open redirect vulnerabilities.
    """
    
    name = "open_redirect"
    description = "Tests for open redirect vulnerabilities in parameters and forms"
    
    # Open redirect test payloads - malicious domains for testing
    REDIRECT_PAYLOADS = [
        # Basic payloads
        "https://evil.com",
        "//evil.com",
        "https://evil-example.com",
        "//evil-example.com",
        
        # Encoded payloads
        "https%3A%2F%2Fevil.com",
        "%2F%2Fevil.com",
        
        # Double encoded payloads
        "https%253A%252F%252Fevil.com",
        "%252F%252Fevil.com",
        
        # With path
        "https://evil.com/path/to/page",
        "//evil.com/path/to/page",
        
        # With protocol bypass attempts
        "javascript://evil.com/%0Aalert(1)",
        "data://evil.com/,alert(1)",
        
        # With @ character
        "https://target.com@evil.com",
        "https://@evil.com",
        
        # Bypassing filters
        "https://evil.com?q=https://target.com",
        "https://evil.com#https://target.com",
        "https://target.com.evil.com",
        "https://evil.com/target.com/",
        
        # Unicode encoding bypasses
        "https://evil.com/%e2%80%ae",
        
        # Null byte
        "https://evil.com%00https://target.com",
        
        # Whitelisting bypasses
        "https://target.com.evil.com",
        "https://evil.com?target.com",
        "https://evil.com/target.com"
    ]
    
    # Parameters that are commonly vulnerable to open redirect
    COMMON_VULNERABLE_PARAMS = {
        'redirect', 'redirect_uri', 'redirect_url', 'url', 'link', 'goto', 
        'return', 'return_url', 'return_to', 'destination', 'dest', 
        'next', 'next_url', 'to', 'path', 'site', 'location', 'back', 'target',
        'continue', 'continue_to', 'redir', 'out', 'view', 'dir', 'show',
        'navigation', 'returnurl', 'returnto', 'exit', 'file', 'forward',
        'reference', 'ref', 'r', 'jump'
    }
    
    def __init__(self, reporter: Reporter = None):
        """Initialize the open redirect plugin."""
        super().__init__(reporter)
        self.tested_urls: Set[str] = set()  # Track already tested URLs to avoid duplication
        self.malicious_domains = [
            urlparse(p).netloc for p in self.REDIRECT_PAYLOADS 
            if p.startswith(('http://', 'https://', '//')) and '//' in p
        ]
        self.malicious_domains = [d for d in self.malicious_domains if d]  # Filter empty domains
    
    def scan(self, target_url: str, http_client: HttpClient) -> List[Finding]:
        """
        Scan for open redirect vulnerabilities.
        
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
        
        self.logger.info(f"Scanning {target_url} for open redirect vulnerabilities")
        
        try:
            # Get the target domain for comparison
            target_domain = urlparse(target_url).netloc
            
            # Test URL parameters
            url_findings = self._test_url_parameters(target_url, http_client, target_domain)
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
            form_findings = self._test_forms(forms, http_client, target_domain)
            findings.extend(form_findings)
            
        except Exception as e:
            self.logger.error(f"Error scanning {target_url} for open redirect: {e}")
        
        # Report findings
        for finding in findings:
            self.report_finding(finding)
        
        return findings
    
    def _test_url_parameters(self, url: str, http_client: HttpClient, target_domain: str) -> List[Finding]:
        """
        Test URL parameters for open redirect vulnerabilities.
        
        Args:
            url: URL to test
            http_client: HTTP client for making requests
            target_domain: Original domain of the target site
            
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
            # Skip testing if param doesn't seem vulnerable
            if not self._is_likely_vulnerable(param):
                continue
                
            # Original value
            original_value = values[0] if values else ""
            
            # Test each payload
            for payload in self.REDIRECT_PAYLOADS:
                # Create a new URL with the redirect payload
                new_params = query_params.copy()
                new_params[param] = [payload]
                query_string = urlencode(new_params, doseq=True)
                
                path = parsed_url.path or '/'
                new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{query_string}"
                
                try:
                    # Send the request with the payload and check for redirects
                    response = http_client.get(
                        new_url, 
                        allow_redirects=False,  # Don't follow redirects automatically
                        timeout=10
                    )
                    
                    # Check if response is a redirect
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location_header = response.headers.get('location', '')
                        
                        # Check if redirects to one of our malicious domains
                        if self._is_redirect_to_malicious_site(location_header, target_domain):
                            finding = Finding(
                                title=f"Open Redirect in URL parameter '{param}'",
                                description=(
                                    f"The parameter '{param}' appears to be vulnerable to open redirect. "
                                    f"The application redirects to arbitrary external domains without proper validation."
                                ),
                                url=url,
                                severity=Severity.MEDIUM,
                                plugin_name=self.name,
                                evidence=(
                                    f"Payload: {payload}\n"
                                    f"Response status code: {response.status_code}\n"
                                    f"Location header: {location_header}"
                                ),
                                request_data={"url": new_url, "method": "GET"},
                                response_data={
                                    "status": response.status_code, 
                                    "headers": dict(response.headers)
                                },
                                remediation=(
                                    "1. Implement a whitelist of allowed redirect destinations.\n"
                                    "2. Use relative URLs for internal redirects when possible.\n"
                                    "3. If full URLs are needed, validate the domain against an allowed list.\n"
                                    "4. Consider implementing indirect reference maps for redirects.\n"
                                    "5. Always validate that redirect URLs begin with a forward slash (/) "
                                    "for internal redirects."
                                ),
                                cwe_id="601"  # CWE-601: URL Redirection to Untrusted Site
                            )
                            findings.append(finding)
                            
                            # Stop testing this parameter after finding a vulnerability
                            break
                        
                except Exception as e:
                    self.logger.error(f"Error testing {new_url} with payload {payload}: {e}")
        
        return findings
    
    def _test_forms(self, forms: List[FormData], http_client: HttpClient, target_domain: str) -> List[Finding]:
        """
        Test forms for open redirect vulnerabilities.
        
        Args:
            forms: List of forms to test
            http_client: HTTP client for making requests
            target_domain: Original domain of the target site
            
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
            vulnerable_fields = []
            
            for input_name, attrs in form.inputs.items():
                # Skip non-text inputs
                input_type = attrs.get('type', 'text').lower()
                if input_type in ['checkbox', 'radio', 'button', 'submit', 'image', 'file']:
                    continue
                
                # Add empty value
                form_data[input_name] = ''
                
                # Mark as vulnerable if it seems likely
                if self._is_likely_vulnerable(input_name):
                    vulnerable_fields.append(input_name)
            
            # Skip if no vulnerable fields
            if not vulnerable_fields:
                continue
            
            # Test each vulnerable field
            for input_name in vulnerable_fields:
                # Test each payload
                for payload in self.REDIRECT_PAYLOADS:
                    # Create new form data with the payload
                    test_data = form_data.copy()
                    test_data[input_name] = payload
                    
                    try:
                        # Send the request with the payload
                        if form.method.upper() == 'POST':
                            response = http_client.post(
                                form.action, 
                                data=test_data,
                                allow_redirects=False,
                                timeout=10
                            )
                        else:
                            query_string = urlencode(test_data)
                            url = f"{form.action}?{query_string}" if '?' not in form.action else f"{form.action}&{query_string}"
                            response = http_client.get(
                                url,
                                allow_redirects=False,
                                timeout=10
                            )
                        
                        # Check if response is a redirect
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location_header = response.headers.get('location', '')
                            
                            # Check if redirects to one of our malicious domains
                            if self._is_redirect_to_malicious_site(location_header, target_domain):
                                finding = Finding(
                                    title=f"Open Redirect in form field '{input_name}'",
                                    description=(
                                        f"The form field '{input_name}' on {form.action} appears to be vulnerable "
                                        f"to open redirect. The application redirects to arbitrary external domains "
                                        f"without proper validation."
                                    ),
                                    url=form.action,
                                    severity=Severity.MEDIUM,
                                    plugin_name=self.name,
                                    evidence=(
                                        f"Form method: {form.method}\n"
                                        f"Field: {input_name}\n"
                                        f"Payload: {payload}\n"
                                        f"Response status code: {response.status_code}\n"
                                        f"Location header: {location_header}"
                                    ),
                                    request_data={"url": form.action, "method": form.method, "data": test_data},
                                    response_data={
                                        "status": response.status_code, 
                                        "headers": dict(response.headers)
                                    },
                                    remediation=(
                                        "1. Implement a whitelist of allowed redirect destinations.\n"
                                        "2. Use relative URLs for internal redirects when possible.\n"
                                        "3. If full URLs are needed, validate the domain against an allowed list.\n"
                                        "4. Consider implementing indirect reference maps for redirects.\n"
                                        "5. Always validate that redirect URLs begin with a forward slash (/) "
                                        "for internal redirects."
                                    ),
                                    cwe_id="601"  # CWE-601: URL Redirection to Untrusted Site
                                )
                                findings.append(finding)
                                
                                # Stop testing this field after finding a vulnerability
                                break
                                
                    except Exception as e:
                        self.logger.error(f"Error testing form {form.action} field {input_name} with payload {payload}: {e}")
        
        return findings
    
    def _is_redirect_to_malicious_site(self, location: str, target_domain: str) -> bool:
        """
        Check if the redirect location points to a potentially malicious site.
        
        Args:
            location: Redirect location URL
            target_domain: Original domain of the target site
            
        Returns:
            bool: True if redirects to a malicious site, False otherwise
        """
        # No location header
        if not location:
            return False
        
        # Handle relative URLs
        if location.startswith('/'):
            return False
        
        try:
            # Handle protocol-relative URLs
            if location.startswith('//'):
                location = f"http:{location}"
                
            # Parse location URL
            parsed_location = urlparse(location)
            location_domain = parsed_location.netloc.lower()
            
            # No domain in location
            if not location_domain:
                return False
                
            # Same domain as target (internal redirect)
            if location_domain == target_domain.lower():
                return False
                
            # Check if location domain is one of our malicious domains
            for malicious_domain in self.malicious_domains:
                if malicious_domain.lower() in location_domain:
                    return True
                    
            # Check for potentially dangerous protocols
            if parsed_location.scheme in ['javascript', 'data', 'vbscript']:
                return True
                
            # If URL has our malicious domain anywhere in it
            for malicious_domain in ['evil.com', 'evil-example.com']:
                if malicious_domain in location.lower():
                    return True
            
        except Exception as e:
            self.logger.error(f"Error parsing redirect location {location}: {e}")
            
        return False
    
    def _is_likely_vulnerable(self, param_name: str) -> bool:
        """
        Determine if a parameter is likely vulnerable to open redirect.
        
        Args:
            param_name: Name of the parameter
            
        Returns:
            bool: True if parameter is likely vulnerable, False otherwise
        """
        param_lower = param_name.lower()
        
        # Common vulnerable parameter names
        if param_lower in self.COMMON_VULNERABLE_PARAMS:
            return True
            
        # Parameters that often contain URLs/locations
        if any(name in param_lower for name in ['url', 'link', 'redirect', 'goto', 'next', 'return', 'target']):
            return True
            
        # Default to non-vulnerable for other parameters
        return False
