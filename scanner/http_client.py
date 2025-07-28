"""
Web Vulnerability Scanner - HTTP Client Module

This module provides a robust HTTP client for the scanner with features including:
- Session management and cookie handling
- Request retries and timeouts
- Proxy support
- Custom headers and user agent
- TLS/SSL configuration options
"""

import logging
import time
import random
from typing import Dict, Optional, Union, List, Any, Tuple
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .safety import get_safety_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('scanner.http_client')

# Common realistic user agents for stealth
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
]

class HttpClient:
    """
    HTTP Client for making web requests with built-in security and resilience features.
    Wraps the requests library with additional functionality.
    """
    
    def __init__(
        self,
        user_agent: str = "WebVulnScanner/0.1.0",
        timeout: int = 10,
        max_retries: int = 3,
        verify_ssl: bool = True,
        proxy: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        allow_redirects: bool = True,
        max_redirects: int = 5,
        rotate_user_agents: bool = False
    ):
        """
        Initialize the HTTP client with configuration parameters.
        
        Args:
            user_agent: User-Agent string to use for requests
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
            verify_ssl: Whether to verify SSL certificates
            proxy: Proxy settings (e.g., {'http': 'http://proxy:8080', 'https': 'https://proxy:8080'})
            cookies: Initial cookies to use for requests
            headers: Additional headers to include in requests
            auth: HTTP Basic Authentication credentials (username, password)
            allow_redirects: Whether to follow redirects
            max_redirects: Maximum number of redirects to follow
            rotate_user_agents: Whether to rotate user agents for stealth
        """
        # Initialize safety manager for host protection
        self.safety_manager = get_safety_manager()
        
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.allow_redirects = allow_redirects
        self.max_redirects = max_redirects
        self.auth = auth
        self.rotate_user_agents = rotate_user_agents
        
        # Create session
        self.session = requests.Session()
        
        # Configure retries
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Configure session parameters
        default_headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Store original user agent for rotation
        self.original_user_agent = self.user_agent
        
        if headers:
            default_headers.update(headers)
            
        self.session.headers.update(default_headers)
        
        if cookies:
            self.session.cookies.update(cookies)
            
        if proxy:
            self.session.proxies.update(proxy)
            
    def get(self, url: str, **kwargs) -> requests.Response:
        """
        Make a GET request to the specified URL.
        
        Args:
            url: Target URL
            **kwargs: Additional arguments to pass to requests.get()
            
        Returns:
            requests.Response: Response object
        """
        return self._request("GET", url, **kwargs)
        
    def post(self, url: str, data: Optional[Dict[str, Any]] = None, json: Optional[Dict[str, Any]] = None, **kwargs) -> requests.Response:
        """
        Make a POST request to the specified URL.
        
        Args:
            url: Target URL
            data: Form data to send
            json: JSON data to send
            **kwargs: Additional arguments to pass to requests.post()
            
        Returns:
            requests.Response: Response object
        """
        return self._request("POST", url, data=data, json=json, **kwargs)
        
    def head(self, url: str, **kwargs) -> requests.Response:
        """
        Make a HEAD request to the specified URL.
        
        Args:
            url: Target URL
            **kwargs: Additional arguments to pass to requests.head()
            
        Returns:
            requests.Response: Response object
        """
        return self._request("HEAD", url, **kwargs)
        
    def options(self, url: str, **kwargs) -> requests.Response:
        """
        Make an OPTIONS request to the specified URL.
        
        Args:
            url: Target URL
            **kwargs: Additional arguments to pass to requests.options()
            
        Returns:
            requests.Response: Response object
        """
        return self._request("OPTIONS", url, **kwargs)
        
    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Generic method to make HTTP requests with common error handling.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            **kwargs: Additional arguments to pass to requests
            
        Returns:
            requests.Response: Response object
        """
        # Safety validation - block unsafe URLs
        if not self.safety_manager.validate_url(url):
            raise ValueError(f"Unsafe URL blocked by security policy: {url}")
        
        # Set default options if not explicitly provided
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('allow_redirects', self.allow_redirects)
        
        if self.auth and 'auth' not in kwargs:
            kwargs['auth'] = self.auth
        
        # Rotate user agent if enabled
        if self.rotate_user_agents:
            random_ua = random.choice(USER_AGENTS)
            self.session.headers.update({'User-Agent': random_ua})
            logger.debug(f"Using user agent: {random_ua}")
            
        start_time = time.time()
        domain = urlparse(url).netloc
        
        try:
            logger.debug(f"Making {method} request to {url}")
            response = self.session.request(method, url, **kwargs)
            elapsed = time.time() - start_time
            
            # Log response details
            logger.debug(f"{method} {url} - {response.status_code} - {len(response.content)} bytes - {elapsed:.2f}s")
            
            # Track cookies if any were set
            if response.cookies:
                cookie_names = [name for name in response.cookies]
                logger.debug(f"Cookies set in response: {', '.join(cookie_names)}")
                
            return response
            
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error for {url}: {str(e)}")
            raise
            
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {url}: {str(e)}")
            raise
            
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout error for {url}: {str(e)}")
            raise
            
        except requests.exceptions.RequestException as e:
            # Check for specific HTTP status codes that indicate blocking/rate limiting
            if hasattr(e, 'response') and e.response is not None:
                status_code = e.response.status_code
                if status_code == 503:
                    logger.warning(f"Service unavailable (503) for {url} - possible rate limiting or server overload")
                elif status_code == 429:
                    logger.warning(f"Rate limited (429) for {url} - too many requests")
                elif status_code == 403:
                    logger.warning(f"Forbidden (403) for {url} - possible WAF/security blocking")
                elif status_code == 401:
                    logger.warning(f"Unauthorized (401) for {url} - authentication required")
                else:
                    logger.error(f"HTTP {status_code} error for {url}: {str(e)}")
            else:
                logger.error(f"Request error for {url}: {str(e)}")
            raise
            
    def get_session(self) -> requests.Session:
        """
        Get the underlying requests session for advanced usage.
        
        Returns:
            requests.Session: The session object
        """
        return self.session
        
    def clear_cookies(self) -> None:
        """Clear all cookies in the session."""
        self.session.cookies.clear()
        
    def update_headers(self, headers: Dict[str, str]) -> None:
        """
        Update the default headers used for requests.
        
        Args:
            headers: Headers to update
        """
        self.session.headers.update(headers)
        
    def set_cookie(self, name: str, value: str, domain: str = None) -> None:
        """
        Set a specific cookie in the session.
        
        Args:
            name: Cookie name
            value: Cookie value
            domain: Cookie domain (optional)
        """
        if domain:
            self.session.cookies.set(name, value, domain=domain)
        else:
            self.session.cookies.set(name, value)
            
    def close(self) -> None:
        """Close the session and free up resources."""
        self.session.close()
        
    def __enter__(self):
        """Support for context manager usage."""
        return self
        
    def __exit__(self, exc_type, exc_value, traceback):
        """Clean up resources when exiting context manager."""
        self.close()
