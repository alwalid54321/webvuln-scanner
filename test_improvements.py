#!/usr/bin/env python3
"""
Test script to verify the improvements made to the Web Vulnerability Scanner.
This script tests the enhanced error handling, user-agent rotation, and stealth features.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.http_client import HttpClient
import time

def test_user_agent_rotation():
    """Test the user-agent rotation functionality."""
    print("Testing user-agent rotation...")
    
    # Create client with rotation enabled
    client = HttpClient(rotate_user_agents=True, timeout=10)
    
    # Make a few requests to see different user agents
    test_url = "https://httpbin.org/user-agent"
    
    print("Making requests with user-agent rotation:")
    for i in range(3):
        try:
            response = client.get(test_url)
            if response.status_code == 200:
                print(f"Request {i+1}: {response.json()['user-agent']}")
            else:
                print(f"Request {i+1}: HTTP {response.status_code}")
        except Exception as e:
            print(f"Request {i+1}: Error - {e}")
        
        time.sleep(1)  # Small delay between requests
    
    client.close()

def test_error_handling():
    """Test the improved error handling."""
    print("\nTesting error handling...")
    
    client = HttpClient(timeout=5, max_retries=1)
    
    # Test with a URL that should return 503 or similar
    test_urls = [
        "https://httpstat.us/503",  # Returns 503 Service Unavailable
        "https://httpstat.us/429",  # Returns 429 Too Many Requests
        "https://httpstat.us/403",  # Returns 403 Forbidden
    ]
    
    for url in test_urls:
        try:
            print(f"Testing {url}...")
            response = client.get(url)
            print(f"  Response: {response.status_code}")
        except Exception as e:
            print(f"  Caught exception: {type(e).__name__}: {e}")
    
    client.close()

if __name__ == "__main__":
    print("Web Vulnerability Scanner - Improvements Test")
    print("=" * 50)
    
    test_user_agent_rotation()
    test_error_handling()
    
    print("\nTest completed!")
