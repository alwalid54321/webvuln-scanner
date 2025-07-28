#!/usr/bin/env python3
"""
Connectivity test script to diagnose connection issues with targets.
This helps identify timeout, DNS, or network connectivity problems.
"""

import sys
import os
import requests
import time
import socket
from urllib.parse import urlparse

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_dns_resolution(hostname):
    """Test DNS resolution for the hostname."""
    try:
        ip = socket.gethostbyname(hostname)
        print(f"[OK] DNS Resolution: {hostname} -> {ip}")
        return True, ip
    except socket.gaierror as e:
        print(f"[FAIL] DNS Resolution Failed: {hostname} - {e}")
        return False, None

def test_tcp_connection(hostname, port, timeout=10):
    """Test TCP connection to hostname:port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((hostname, port))
        sock.close()
        
        if result == 0:
            print(f"[OK] TCP Connection: {hostname}:{port} is reachable")
            return True
        else:
            print(f"[FAIL] TCP Connection: {hostname}:{port} is not reachable (error {result})")
            return False
    except Exception as e:
        print(f"[ERROR] TCP Connection Error: {hostname}:{port} - {e}")
        return False

def test_http_request(url, timeout=30):
    """Test HTTP request with various configurations."""
    print(f"\n[HTTP] Testing HTTP Request to: {url}")
    
    # Test with different user agents
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'WebVulnScanner/1.0',
        'curl/7.68.0'
    ]
    
    for i, ua in enumerate(user_agents, 1):
        try:
            print(f"  {i}. Testing with User-Agent: {ua[:50]}...")
            headers = {'User-Agent': ua}
            start_time = time.time()
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            elapsed = time.time() - start_time
            
            print(f"     [OK] Success: {response.status_code} ({elapsed:.2f}s) - {len(response.content)} bytes")
            return True, response
            
        except requests.exceptions.ConnectTimeout:
            print(f"     [FAIL] Connection Timeout ({timeout}s)")
        except requests.exceptions.ReadTimeout:
            print(f"     [FAIL] Read Timeout ({timeout}s)")
        except requests.exceptions.ConnectionError as e:
            print(f"     [FAIL] Connection Error: {e}")
        except requests.exceptions.SSLError as e:
            print(f"     [FAIL] SSL Error: {e}")
        except Exception as e:
            print(f"     [ERROR] Other Error: {e}")
    
    return False, None

def diagnose_target(url):
    """Comprehensive diagnosis of target connectivity."""
    print(f"[DIAG] Diagnosing connectivity to: {url}")
    print("=" * 60)
    
    # Parse URL
    parsed = urlparse(url)
    hostname = parsed.netloc
    port = 443 if parsed.scheme == 'https' else 80
    
    # Test DNS resolution
    dns_ok, ip = test_dns_resolution(hostname)
    if not dns_ok:
        return False
    
    # Test TCP connection
    tcp_ok = test_tcp_connection(hostname, port)
    if not tcp_ok:
        return False
    
    # Test HTTP request
    http_ok, response = test_http_request(url)
    
    if http_ok:
        print(f"\n[SUCCESS] Target is accessible!")
        print(f"[INFO] Response Headers:")
        for key, value in response.headers.items():
            print(f"   {key}: {value}")
    else:
        print(f"\n[FAIL] Target is not accessible via HTTP")
        print(f"\n[TIPS] Suggestions:")
        print(f"   • Try increasing timeout: --timeout 60")
        print(f"   • Check if target requires specific headers")
        print(f"   • Verify target is not behind a firewall/WAF")
        print(f"   • Test with different user-agent")
    
    return http_ok

def main():
    """Main function."""
    if len(sys.argv) != 2:
        print("Usage: python test_connectivity.py <URL>")
        print("Example: python test_connectivity.py https://testphp.vulnweb.com")
        sys.exit(1)
    
    url = sys.argv[1]
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    success = diagnose_target(url)
    
    if success:
        print(f"\n[SUCCESS] You can now scan this target with:")
        print(f"   python console.py -u {url} --verbose")
    else:
        print(f"\n[TIPS] Try these scanner options for problematic targets:")
        print(f"   python console.py -u {url} --timeout 60 --delay 2.0 --threads 1")

if __name__ == "__main__":
    main()
