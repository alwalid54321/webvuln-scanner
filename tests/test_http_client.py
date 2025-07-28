"""
Unit tests for the HTTP client module.
"""

import unittest
from unittest.mock import patch, MagicMock
import requests
import os
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner.http_client import HttpClient, RequestError

class TestHttpClient(unittest.TestCase):
    """Test cases for HttpClient class."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = HttpClient(timeout=10, max_retries=2, verify_ssl=True)
    
    @patch('requests.Session')
    def test_get_request(self, mock_session_class):
        """Test GET request functionality."""
        # Setup mock
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.ok = True
        mock_response.text = "<html><body>Test</body></html>"
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        # Create client with mocked session
        client = HttpClient(timeout=10, max_retries=2, verify_ssl=True)
        
        # Test GET request
        response = client.get("https://example.com")
        
        # Verify
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "<html><body>Test</body></html>")
        mock_session.get.assert_called_with(
            "https://example.com", 
            timeout=10, 
            verify=True,
            allow_redirects=True,
            headers={'User-Agent': 'WebVulnScanner/1.0'}
        )

    @patch('requests.Session')
    def test_post_request(self, mock_session_class):
        """Test POST request functionality."""
        # Setup mock
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.ok = True
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        # Create client with mocked session
        client = HttpClient(timeout=10, max_retries=2, verify_ssl=True)
        
        # Test POST request
        data = {"username": "test", "password": "password"}
        response = client.post("https://example.com/login", data=data)
        
        # Verify
        self.assertEqual(response.status_code, 200)
        mock_session.post.assert_called_with(
            "https://example.com/login", 
            data=data,
            json=None,
            timeout=10, 
            verify=True,
            allow_redirects=True,
            headers={'User-Agent': 'WebVulnScanner/1.0'}
        )

    @patch('requests.Session')
    def test_set_headers(self, mock_session_class):
        """Test setting custom headers."""
        # Setup mock
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        
        # Create client with mocked session
        client = HttpClient(timeout=10, max_retries=2, verify_ssl=True)
        
        # Set custom headers
        custom_headers = {
            "X-Custom-Header": "Value",
            "Authorization": "Bearer token"
        }
        client.set_headers(custom_headers)
        
        # Test that headers were set correctly
        self.assertEqual(client.headers["X-Custom-Header"], "Value")
        self.assertEqual(client.headers["Authorization"], "Bearer token")
        self.assertEqual(client.headers["User-Agent"], "WebVulnScanner/1.0")  # Default still present

    @patch('requests.Session')
    def test_set_proxy(self, mock_session_class):
        """Test setting proxy."""
        # Setup mock
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        
        # Create client with mocked session
        client = HttpClient(timeout=10, max_retries=2, verify_ssl=True)
        
        # Set proxy
        proxies = {
            "http": "http://proxy:8080",
            "https": "https://proxy:8080"
        }
        client.set_proxy(proxies)
        
        # Verify proxy was set on session
        self.assertEqual(mock_session.proxies, proxies)

    @patch('requests.Session')
    def test_set_cookies(self, mock_session_class):
        """Test setting cookies."""
        # Setup mock
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        
        # Create client with mocked session
        client = HttpClient(timeout=10, max_retries=2, verify_ssl=True)
        
        # Set cookies
        cookies = {
            "sessionid": "abc123",
            "user": "testuser"
        }
        client.set_cookies(cookies)
        
        # Verify cookies were set
        for key, value in cookies.items():
            self.assertEqual(mock_session.cookies[key], value)

    @patch('requests.Session')
    def test_error_handling(self, mock_session_class):
        """Test error handling in requests."""
        # Setup mock to raise ConnectionError
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError("Connection refused")
        mock_session_class.return_value = mock_session
        
        # Create client with mocked session
        client = HttpClient(timeout=5, max_retries=1, verify_ssl=True)
        
        # Test error handling
        with self.assertRaises(RequestError):
            client.get("https://example.com")
    
    @patch('requests.Session')
    def test_retry_mechanism(self, mock_session_class):
        """Test retry mechanism works correctly."""
        # Setup mock to raise ConnectionError first time, then succeed
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.ok = True
        
        # First call raises exception, second call succeeds
        mock_session.get.side_effect = [
            requests.exceptions.ConnectionError("Connection refused"),
            mock_response
        ]
        mock_session_class.return_value = mock_session
        
        # Create client with mocked session
        client = HttpClient(timeout=5, max_retries=2, verify_ssl=True)
        
        # Test retry mechanism
        response = client.get("https://example.com")
        
        # Verify we got the successful response after retry
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_session.get.call_count, 2)  # Called twice due to retry

if __name__ == '__main__':
    unittest.main()
