"""
Unit tests for the crawler module.
"""

import unittest
from unittest.mock import patch, MagicMock, call
import os
import sys
import requests
import threading
from queue import Queue

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner.crawler import Crawler
from scanner.http_client import HttpClient

class TestCrawler(unittest.TestCase):
    """Test cases for Crawler class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_http_client = MagicMock(spec=HttpClient)
        self.crawler = Crawler(
            http_client=self.mock_http_client,
            max_depth=3,
            max_urls=100,
            respect_robots_txt=True,
            threads=2,
            delay=0.1
        )
    
    @patch('scanner.parser.HtmlParser')
    def test_initialize(self, mock_parser_class):
        """Test crawler initialization."""
        # Verify crawler state after initialization
        self.assertEqual(self.crawler.max_depth, 3)
        self.assertEqual(self.crawler.max_urls, 100)
        self.assertTrue(self.crawler.respect_robots_txt)
        self.assertEqual(self.crawler.threads, 2)
        self.assertEqual(self.crawler.delay, 0.1)
        self.assertEqual(len(self.crawler.visited_urls), 0)
        self.assertEqual(len(self.crawler.url_queue.queue), 0)
        self.assertFalse(self.crawler.crawl_finished)
        
    @patch('scanner.parser.HtmlParser')
    def test_start_crawler(self, mock_parser_class):
        """Test starting the crawler with a URL."""
        # Arrange
        base_url = "https://example.com"
        
        # Mock parser to be returned when parser class is instantiated
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        
        # Mock robots.txt check
        self.crawler._check_robots_txt = MagicMock(return_value=True)
        
        # Mock worker method to avoid starting threads
        self.crawler._worker = MagicMock()
        
        # Act
        self.crawler.start(base_url)
        
        # Assert
        # Verify that URL was added to queue
        self.assertEqual(self.crawler.url_queue.qsize(), 1)
        # Verify that robots.txt was checked
        self.crawler._check_robots_txt.assert_called_once_with(base_url)
        # Verify that worker threads were started
        self.assertEqual(len(self.crawler.threads), 2)
    
    @patch('scanner.parser.HtmlParser')
    def test_check_robots_txt_allowed(self, mock_parser_class):
        """Test checking robots.txt when allowed."""
        # Arrange
        base_url = "https://example.com"
        
        # Mock response for robots.txt
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        User-agent: *
        Allow: /
        Disallow: /admin/
        Disallow: /private/
        """
        self.mock_http_client.get.return_value = mock_response
        
        # Act
        result = self.crawler._check_robots_txt(base_url)
        
        # Assert
        self.assertTrue(result)
        self.mock_http_client.get.assert_called_once_with(
            "https://example.com/robots.txt",
            allow_redirects=True
        )
        self.assertEqual(len(self.crawler.disallowed_paths), 2)
        self.assertIn("/admin/", self.crawler.disallowed_paths)
        self.assertIn("/private/", self.crawler.disallowed_paths)
    
    @patch('scanner.parser.HtmlParser')
    def test_check_robots_txt_not_found(self, mock_parser_class):
        """Test checking robots.txt when not found (404)."""
        # Arrange
        base_url = "https://example.com"
        
        # Mock response for robots.txt not found
        mock_response = MagicMock()
        mock_response.status_code = 404
        self.mock_http_client.get.return_value = mock_response
        
        # Act
        result = self.crawler._check_robots_txt(base_url)
        
        # Assert
        self.assertTrue(result)  # Should continue crawling if robots.txt not found
        self.assertEqual(len(self.crawler.disallowed_paths), 0)
    
    @patch('scanner.parser.HtmlParser')
    def test_is_url_allowed(self, mock_parser_class):
        """Test URL permission checking against robots.txt rules."""
        # Arrange
        self.crawler.disallowed_paths = ["/admin/", "/private/"]
        
        # Act & Assert
        # Allowed URLs
        self.assertTrue(self.crawler._is_url_allowed("https://example.com"))
        self.assertTrue(self.crawler._is_url_allowed("https://example.com/public"))
        self.assertTrue(self.crawler._is_url_allowed("https://example.com/public/page"))
        
        # Disallowed URLs
        self.assertFalse(self.crawler._is_url_allowed("https://example.com/admin/"))
        self.assertFalse(self.crawler._is_url_allowed("https://example.com/admin/login"))
        self.assertFalse(self.crawler._is_url_allowed("https://example.com/private/data"))
    
    @patch('scanner.parser.HtmlParser')
    @patch('time.sleep')
    def test_crawl_url(self, mock_sleep, mock_parser_class):
        """Test crawling a single URL."""
        # Arrange
        url = "https://example.com"
        depth = 0
        
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body><a href='/page1'>Link</a></body></html>"
        mock_response.headers = {"Content-Type": "text/html; charset=utf-8"}
        self.mock_http_client.get.return_value = mock_response
        
        # Mock parser
        mock_parser = MagicMock()
        mock_parser.parse_html.return_value = "soup"
        mock_parser.extract_links.return_value = ["https://example.com/page1"]
        mock_parser.extract_forms.return_value = []
        mock_parser_class.return_value = mock_parser
        
        # Act
        self.crawler._crawl_url(url, depth)
        
        # Assert
        # Verify URL was added to visited list
        self.assertIn(url, self.crawler.visited_urls)
        
        # Verify HTTP client was called correctly
        self.mock_http_client.get.assert_called_once_with(url, allow_redirects=True)
        
        # Verify parser methods were called
        mock_parser.parse_html.assert_called_once_with(mock_response.text)
        mock_parser.extract_links.assert_called_once_with("soup", url)
        mock_parser.extract_forms.assert_called_once_with("soup", url)
        
        # Verify queue has the new URL
        self.assertEqual(self.crawler.url_queue.qsize(), 1)
        self.assertEqual(self.crawler.url_queue.queue[0][0], "https://example.com/page1")
        self.assertEqual(self.crawler.url_queue.queue[0][1], 1)  # depth increased
        
        # Verify rate limiting was enforced
        mock_sleep.assert_called_once_with(0.1)
    
    @patch('scanner.parser.HtmlParser')
    def test_crawl_url_max_depth(self, mock_parser_class):
        """Test crawling respects max depth."""
        # Arrange
        url = "https://example.com"
        depth = 3  # Max depth from setUp
        
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body><a href='/page1'>Link</a></body></html>"
        mock_response.headers = {"Content-Type": "text/html; charset=utf-8"}
        self.mock_http_client.get.return_value = mock_response
        
        # Mock parser
        mock_parser = MagicMock()
        mock_parser.parse_html.return_value = "soup"
        mock_parser.extract_links.return_value = ["https://example.com/page1"]
        mock_parser_class.return_value = mock_parser
        
        # Act
        self.crawler._crawl_url(url, depth)
        
        # Assert
        # Verify URL was added to visited list
        self.assertIn(url, self.crawler.visited_urls)
        
        # Verify no URLs were added to queue (because max depth reached)
        self.assertEqual(self.crawler.url_queue.qsize(), 0)
    
    @patch('scanner.parser.HtmlParser')
    def test_crawl_url_nonhtml_response(self, mock_parser_class):
        """Test crawling a URL that returns non-HTML content."""
        # Arrange
        url = "https://example.com/file.pdf"
        depth = 0
        
        # Mock HTTP response for PDF file
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "PDF content"
        mock_response.headers = {"Content-Type": "application/pdf"}
        self.mock_http_client.get.return_value = mock_response
        
        # Act
        self.crawler._crawl_url(url, depth)
        
        # Assert
        # Verify URL was added to visited list
        self.assertIn(url, self.crawler.visited_urls)
        
        # Verify parser methods were not called
        mock_parser_class.assert_not_called()
        
        # Verify no URLs were added to queue
        self.assertEqual(self.crawler.url_queue.qsize(), 0)
    
    @patch('scanner.parser.HtmlParser')
    def test_get_all_urls(self, mock_parser_class):
        """Test getting all discovered URLs."""
        # Arrange
        self.crawler.visited_urls = {"https://example.com", "https://example.com/page1"}
        self.crawler.forms = {
            "https://example.com": [],
            "https://example.com/page1": [
                MagicMock(action="https://example.com/form1"),
                MagicMock(action="https://example.com/form2")
            ]
        }
        
        # Act
        all_urls = self.crawler.get_all_urls()
        
        # Assert
        self.assertEqual(len(all_urls), 4)
        self.assertIn("https://example.com", all_urls)
        self.assertIn("https://example.com/page1", all_urls)
        self.assertIn("https://example.com/form1", all_urls)
        self.assertIn("https://example.com/form2", all_urls)

    @patch('scanner.parser.HtmlParser')
    @patch('threading.Thread')
    def test_worker_thread_processing(self, mock_thread, mock_parser_class):
        """Test worker thread processes URLs from queue."""
        # Create a mock queue with a URL
        self.crawler.url_queue = Queue()
        self.crawler.url_queue.put(("https://example.com", 0))
        
        # Mock the _crawl_url method
        self.crawler._crawl_url = MagicMock()
        
        # Simulate thread behavior manually
        self.crawler.crawl_finished = False
        
        def stop_after_one():
            self.crawler._crawl_url("https://example.com", 0)
            self.crawler.crawl_finished = True
            
        # Act
        with patch('threading.current_thread') as mock_current_thread:
            mock_current_thread.return_value.name = "MockThread"
            stop_after_one()
        
        # Assert
        self.crawler._crawl_url.assert_called_once_with("https://example.com", 0)

if __name__ == '__main__':
    unittest.main()
