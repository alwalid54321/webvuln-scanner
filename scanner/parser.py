"""
Web Vulnerability Scanner - Parser Module

This module provides HTML parsing functionality to extract:
- Links and URLs
- Forms and input fields
- JavaScript files
- Static resources
- Comments and potential sensitive information
"""

import logging
import re
from typing import List, Dict, Set, Any, Optional
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('scanner.parser')

@dataclass
class FormData:
    """Data class to store information about an HTML form."""
    action: str  # Form submission URL
    method: str  # Form method (GET, POST)
    inputs: Dict[str, Dict[str, str]]  # Dictionary of input fields with their attributes
    id: Optional[str] = None  # Form ID if available
    name: Optional[str] = None  # Form name if available
    enctype: str = 'application/x-www-form-urlencoded'  # Form encoding type


class HtmlParser:
    """Parser for extracting elements from HTML content."""
    
    def __init__(self, base_url: str):
        """
        Initialize the HTML parser.
        
        Args:
            base_url: Base URL for resolving relative links
        """
        self.base_url = base_url
        
    def parse_html(self, html_content: str) -> BeautifulSoup:
        """
        Parse HTML content into a BeautifulSoup object.
        
        Args:
            html_content: Raw HTML content to parse
            
        Returns:
            BeautifulSoup: Parsed HTML
        """
        return BeautifulSoup(html_content, 'html.parser')
        
    def extract_links(self, soup: BeautifulSoup, base_url: Optional[str] = None) -> Set[str]:
        """
        Extract all links from the HTML content.
        
        Args:
            soup: BeautifulSoup object of parsed HTML
            base_url: Base URL to resolve relative links (defaults to self.base_url)
            
        Returns:
            Set[str]: Set of absolute URLs found in the HTML
        """
        if base_url is None:
            base_url = self.base_url
            
        links = set()
        
        # Extract anchor links
        for anchor in soup.find_all('a'):
            href = anchor.get('href')
            if href:
                absolute_url = self._make_absolute_url(href, base_url)
                if absolute_url:
                    links.add(absolute_url)
                    
        # Extract links from other elements (img, script, link)
        for tag in soup.find_all(['img', 'script', 'link']):
            # Check for src attribute (img, script)
            src = tag.get('src')
            if src:
                absolute_url = self._make_absolute_url(src, base_url)
                if absolute_url:
                    links.add(absolute_url)
            
            # Check for href attribute (link)
            href = tag.get('href')
            if href:
                absolute_url = self._make_absolute_url(href, base_url)
                if absolute_url:
                    links.add(absolute_url)
        
        # Look for URLs in inline JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Look for URLs in JavaScript strings
                urls = re.findall(r'(https?://[^\s\'"]+)', script.string)
                for url in urls:
                    # Clean up URL if it has trailing quotes or punctuation
                    url = re.sub(r'[\'",;\)]$', '', url)
                    links.add(url)
                    
                # Look for relative URLs in JavaScript strings
                rel_urls = re.findall(r'[\'"](/[^\s\'"]+)[\'"]', script.string)
                for rel_url in rel_urls:
                    absolute_url = self._make_absolute_url(rel_url, base_url)
                    if absolute_url:
                        links.add(absolute_url)
        
        return links
        
    def extract_forms(self, soup: BeautifulSoup, base_url: Optional[str] = None) -> List[FormData]:
        """
        Extract all forms and their input fields from the HTML.
        
        Args:
            soup: BeautifulSoup object of parsed HTML
            base_url: Base URL to resolve relative form action URLs
            
        Returns:
            List[FormData]: List of form data objects
        """
        if base_url is None:
            base_url = self.base_url
            
        forms_data = []
        
        for form in soup.find_all('form'):
            # Get form attributes
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            form_id = form.get('id')
            name = form.get('name')
            enctype = form.get('enctype', 'application/x-www-form-urlencoded')
            
            # Resolve action URL
            action_url = self._make_absolute_url(action, base_url) if action else base_url
            
            # Get all input fields
            inputs = {}
            for input_field in form.find_all(['input', 'select', 'textarea']):
                field_name = input_field.get('name', '')
                if not field_name:
                    continue  # Skip inputs without name
                    
                field_attrs = {}
                for attr in input_field.attrs:
                    field_attrs[attr] = input_field.get(attr)
                
                # For select fields, get options
                if input_field.name == 'select':
                    options = []
                    for option in input_field.find_all('option'):
                        option_value = option.get('value', '')
                        options.append(option_value)
                    field_attrs['options'] = options
                    
                inputs[field_name] = field_attrs
                
            form_data = FormData(
                action=action_url,
                method=method,
                inputs=inputs,
                id=form_id,
                name=name,
                enctype=enctype
            )
            forms_data.append(form_data)
            
        return forms_data
        
    def extract_comments(self, html_content: str) -> List[str]:
        """
        Extract HTML comments from the page.
        
        Args:
            html_content: Raw HTML content
            
        Returns:
            List[str]: List of comments found
        """
        return re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
        
    def extract_javascript_files(self, soup: BeautifulSoup, base_url: Optional[str] = None) -> List[str]:
        """
        Extract JavaScript file URLs from the HTML.
        
        Args:
            soup: BeautifulSoup object of parsed HTML
            base_url: Base URL to resolve relative script URLs
            
        Returns:
            List[str]: List of JavaScript file URLs
        """
        if base_url is None:
            base_url = self.base_url
            
        js_files = []
        
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                absolute_url = self._make_absolute_url(src, base_url)
                if absolute_url and absolute_url.endswith('.js'):
                    js_files.append(absolute_url)
                    
        return js_files
        
    def extract_meta_tags(self, soup: BeautifulSoup) -> Dict[str, str]:
        """
        Extract meta tags from HTML head.
        
        Args:
            soup: BeautifulSoup object of parsed HTML
            
        Returns:
            Dict[str, str]: Dictionary of meta tags (name/property -> content)
        """
        meta_tags = {}
        
        for tag in soup.find_all('meta'):
            name = tag.get('name')
            property = tag.get('property')
            content = tag.get('content')
            
            if name and content:
                meta_tags[name] = content
            elif property and content:
                meta_tags[property] = content
                
        return meta_tags
        
    def extract_headers(self, response: requests.Response) -> Dict[str, str]:
        """
        Extract HTTP headers from response.
        
        Args:
            response: Requests response object
            
        Returns:
            Dict[str, str]: Dictionary of HTTP headers
        """
        return dict(response.headers)
        
    def _make_absolute_url(self, url: str, base_url: str) -> Optional[str]:
        """
        Convert a relative URL to an absolute URL.
        
        Args:
            url: URL to convert (may be relative or absolute)
            base_url: Base URL for resolving relative URLs
            
        Returns:
            str or None: Absolute URL, or None if invalid
        """
        # Skip URLs that are not http/https
        if url.startswith(('javascript:', 'mailto:', 'tel:', 'data:', '#')):
            return None
            
        # Make relative URL absolute
        try:
            absolute_url = urljoin(base_url, url)
            
            # Validate URL
            parsed = urlparse(absolute_url)
            if parsed.scheme in ('http', 'https') and parsed.netloc:
                return absolute_url
                
        except Exception as e:
            logger.warning(f"Failed to parse URL {url}: {e}")
            
        return None
        
    @staticmethod
    def extract_potential_sensitive_info(html_content: str) -> Dict[str, List[str]]:
        """
        Extract potentially sensitive information from HTML content.
        
        Args:
            html_content: Raw HTML content
            
        Returns:
            Dict[str, List[str]]: Dictionary of sensitive data patterns found
        """
        findings = {}
        
        # Patterns to look for
        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'api_key': r'(?i)(api[_-]?key|apikey|app[_-]?key|appkey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'token': r'(?i)(access|auth|jwt|oauth|refresh)[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.=]+)["\']',
        }
        
        for name, pattern in patterns.items():
            matches = re.findall(pattern, html_content)
            if matches:
                # Clean up matches based on pattern type
                if name == 'api_key' or name == 'token':
                    # Extract just the key part from tuples
                    matches = [match[1] for match in matches if isinstance(match, tuple)]
                findings[name] = matches
                
        return findings
