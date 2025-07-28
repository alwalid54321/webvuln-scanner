"""
Unit tests for the HTML parser module.
"""

import unittest
import os
import sys
from bs4 import BeautifulSoup

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner.parser import HtmlParser, FormData

class TestHtmlParser(unittest.TestCase):
    """Test cases for HtmlParser class."""

    def setUp(self):
        """Set up test fixtures."""
        self.base_url = "https://example.com"
        self.parser = HtmlParser(self.base_url)
        
        # Sample HTML for testing
        self.html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Page</title>
            <meta name="description" content="Test page for unit tests">
            <meta name="keywords" content="test, unit, parser">
            <meta http-equiv="refresh" content="30">
            <script src="/js/script.js"></script>
            <script>
                // Inline script
                var sensitive = "password123";
                var apiKey = "api_key_12345";
            </script>
        </head>
        <body>
            <h1>Test Page</h1>
            <p>This is a test page.</p>
            
            <!-- This is a comment with potentially sensitive info: admin:password -->
            
            <a href="/page1">Link 1</a>
            <a href="/page2">Link 2</a>
            <a href="https://external.com/page3">External Link</a>
            <a href="javascript:void(0)">JavaScript Link</a>
            <a href="#section">Hash Link</a>
            <a href="/page4.pdf">PDF Link</a>
            
            <form action="/login" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="hidden" name="csrf_token" value="abc123">
                <button type="submit">Login</button>
            </form>
            
            <form action="https://external.com/submit" method="GET">
                <input type="text" name="query">
                <input type="checkbox" name="option1" value="yes">
                <input type="radio" name="choice" value="a">
                <input type="radio" name="choice" value="b">
                <select name="dropdown">
                    <option value="1">Option 1</option>
                    <option value="2">Option 2</option>
                </select>
                <input type="submit" value="Search">
            </form>
        </body>
        </html>
        """
        
        self.soup = self.parser.parse_html(self.html_content)
    
    def test_parse_html(self):
        """Test HTML parsing."""
        # Verify soup is created
        self.assertIsInstance(self.soup, BeautifulSoup)
        # Verify basic elements
        self.assertEqual(self.soup.title.text, "Test Page")
        self.assertEqual(len(self.soup.find_all("form")), 2)
        self.assertEqual(len(self.soup.find_all("a")), 6)
    
    def test_extract_links(self):
        """Test link extraction."""
        links = self.parser.extract_links(self.soup, self.base_url)
        
        # Verify number of valid links (excluding javascript and hash links)
        self.assertEqual(len(links), 4)  # 3 internal + 1 external
        
        # Verify links are normalized
        self.assertIn("https://example.com/page1", links)
        self.assertIn("https://example.com/page2", links)
        self.assertIn("https://external.com/page3", links)
        self.assertIn("https://example.com/page4.pdf", links)
        
        # Verify javascript and hash links are excluded
        self.assertNotIn("javascript:void(0)", links)
        self.assertNotIn("https://example.com/#section", links)
        self.assertNotIn("#section", links)
    
    def test_extract_forms(self):
        """Test form extraction."""
        forms = self.parser.extract_forms(self.soup, self.base_url)
        
        # Verify number of forms
        self.assertEqual(len(forms), 2)
        
        # Verify first form
        form1 = next(form for form in forms if form.action == "https://example.com/login")
        self.assertEqual(form1.method, "POST")
        self.assertEqual(len(form1.inputs), 3)
        self.assertIn("username", form1.inputs)
        self.assertIn("password", form1.inputs)
        self.assertIn("csrf_token", form1.inputs)
        self.assertEqual(form1.inputs["csrf_token"]["value"], "abc123")
        
        # Verify second form
        form2 = next(form for form in forms if form.action == "https://external.com/submit")
        self.assertEqual(form2.method, "GET")
        self.assertEqual(len(form2.inputs), 5)  # text, checkbox, 2 radios, select
        self.assertIn("query", form2.inputs)
        self.assertIn("option1", form2.inputs)
        self.assertIn("choice", form2.inputs)
        self.assertIn("dropdown", form2.inputs)
    
    def test_extract_js_files(self):
        """Test JavaScript file extraction."""
        js_files = self.parser.extract_js_files(self.soup, self.base_url)
        
        # Verify JS files
        self.assertEqual(len(js_files), 1)
        self.assertEqual(js_files[0], "https://example.com/js/script.js")
    
    def test_extract_comments(self):
        """Test comment extraction."""
        comments = self.parser.extract_comments(self.soup)
        
        # Verify comments
        self.assertEqual(len(comments), 1)
        self.assertIn("admin:password", comments[0])
    
    def test_extract_meta_tags(self):
        """Test meta tag extraction."""
        meta_tags = self.parser.extract_meta_tags(self.soup)
        
        # Verify meta tags
        self.assertEqual(len(meta_tags), 3)
        
        # Check specific meta tags
        description_tag = next((tag for tag in meta_tags if tag.get('name') == 'description'), None)
        self.assertIsNotNone(description_tag)
        self.assertEqual(description_tag.get('content'), "Test page for unit tests")
        
        # Check refresh tag
        refresh_tag = next((tag for tag in meta_tags if tag.get('http-equiv') == 'refresh'), None)
        self.assertIsNotNone(refresh_tag)
        self.assertEqual(refresh_tag.get('content'), "30")
    
    def test_extract_sensitive_patterns(self):
        """Test extraction of sensitive patterns."""
        patterns = self.parser.extract_sensitive_patterns(self.html_content)
        
        # Verify patterns
        self.assertGreaterEqual(len(patterns), 2)
        
        # Check for specific sensitive data
        found_password = False
        found_api_key = False
        
        for pattern in patterns:
            if "password123" in pattern:
                found_password = True
            if "api_key_12345" in pattern:
                found_api_key = True
        
        self.assertTrue(found_password)
        self.assertTrue(found_api_key)
    
    def test_normalize_url(self):
        """Test URL normalization."""
        # Test relative URLs
        self.assertEqual(
            self.parser.normalize_url("/page", self.base_url),
            "https://example.com/page"
        )
        
        # Test absolute URLs
        self.assertEqual(
            self.parser.normalize_url("https://example.org/page", self.base_url),
            "https://example.org/page"
        )
        
        # Test relative URL with base path
        parser = HtmlParser("https://example.com/subdir/")
        self.assertEqual(
            parser.normalize_url("page", "https://example.com/subdir/"),
            "https://example.com/subdir/page"
        )
        
        # Test handling of double slashes
        self.assertEqual(
            self.parser.normalize_url("//page", self.base_url),
            "https://page"
        )
        
        # Test query parameters
        self.assertEqual(
            self.parser.normalize_url("/page?param=value", self.base_url),
            "https://example.com/page?param=value"
        )

    def test_form_data_class(self):
        """Test FormData dataclass."""
        form_data = FormData(
            action="https://example.com/submit",
            method="POST",
            inputs={
                "username": {"type": "text", "name": "username"},
                "password": {"type": "password", "name": "password"}
            }
        )
        
        self.assertEqual(form_data.action, "https://example.com/submit")
        self.assertEqual(form_data.method, "POST")
        self.assertEqual(len(form_data.inputs), 2)
        self.assertEqual(form_data.inputs["username"]["type"], "text")
        self.assertEqual(form_data.inputs["password"]["type"], "password")

if __name__ == '__main__':
    unittest.main()
