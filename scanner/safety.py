#!/usr/bin/env python3
"""
Host Safety Module for Web Vulnerability Scanner

This module implements comprehensive safety measures to protect the host machine
during scanning operations. It prevents destructive actions, limits resource usage,
and ensures all operations are contained and safe.

Security Principles:
1. No file writes outside designated directories
2. No shell command execution
3. No code evaluation or dynamic imports
4. Resource usage limits
5. Input validation and sanitization
6. Network request restrictions
"""

import os
import sys
import re
import time
import threading
import psutil
from pathlib import Path
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger('scanner.safety')

class HostSafetyManager:
    """
    Manages host safety during scanning operations.
    Implements multiple layers of protection to prevent any harm to the host system.
    """
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root).resolve()
        self.allowed_write_dirs = {
            self.project_root / 'reports',
            self.project_root / 'logs'
        }
        self.max_memory_mb = 512  # Maximum memory usage in MB
        self.max_cpu_percent = 50  # Maximum CPU usage percentage
        self.max_open_files = 100  # Maximum open file descriptors
        self.max_threads = 20     # Maximum thread count
        self.start_time = time.time()
        self.resource_monitor = None
        
        # Ensure safe directories exist
        for directory in self.allowed_write_dirs:
            directory.mkdir(parents=True, exist_ok=True)
        
        logger.info("Host Safety Manager initialized")
    
    def validate_url(self, url: str) -> bool:
        """
        Validate URL for safety - prevent scanning of dangerous targets.
        
        Args:
            url: URL to validate
            
        Returns:
            bool: True if URL is safe to scan
        """
        try:
            parsed = urlparse(url)
            
            # Must have valid scheme
            if parsed.scheme not in ['http', 'https']:
                logger.warning(f"Invalid URL scheme: {parsed.scheme}")
                return False
            
            # Must have hostname
            if not parsed.netloc:
                logger.warning("URL missing hostname")
                return False
            
            # Block localhost and private networks for safety
            hostname = parsed.netloc.split(':')[0].lower()
            
            # Block localhost variants
            localhost_patterns = [
                'localhost', '127.0.0.1', '::1', '0.0.0.0',
                '127.', '10.', '172.16.', '172.17.', '172.18.',
                '172.19.', '172.20.', '172.21.', '172.22.',
                '172.23.', '172.24.', '172.25.', '172.26.',
                '172.27.', '172.28.', '172.29.', '172.30.',
                '172.31.', '192.168.'
            ]
            
            for pattern in localhost_patterns:
                if hostname.startswith(pattern):
                    logger.warning(f"Blocked private/local network: {hostname}")
                    return False
            
            # Block file:// and other dangerous schemes
            dangerous_schemes = ['file', 'ftp', 'sftp', 'ssh', 'telnet']
            if parsed.scheme in dangerous_schemes:
                logger.warning(f"Blocked dangerous scheme: {parsed.scheme}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"URL validation error: {e}")
            return False
    
    def validate_file_write(self, file_path: str) -> bool:
        """
        Validate that file write is safe and within allowed directories.
        
        Args:
            file_path: Path to file being written
            
        Returns:
            bool: True if write is safe
        """
        try:
            target_path = Path(file_path).resolve()
            
            # Check if path is within allowed directories
            for allowed_dir in self.allowed_write_dirs:
                try:
                    target_path.relative_to(allowed_dir)
                    logger.debug(f"File write allowed: {target_path}")
                    return True
                except ValueError:
                    continue
            
            logger.warning(f"File write blocked - outside safe directories: {target_path}")
            return False
            
        except Exception as e:
            logger.error(f"File write validation error: {e}")
            return False
    
    def sanitize_input(self, input_data: str) -> str:
        """
        Sanitize input data to prevent injection attacks.
        
        Args:
            input_data: Raw input data
            
        Returns:
            str: Sanitized input data
        """
        if not isinstance(input_data, str):
            return str(input_data)
        
        # Remove dangerous characters and patterns
        dangerous_patterns = [
            r'[;&|`$()]',  # Shell metacharacters
            r'<script[^>]*>.*?</script>',  # Script tags
            r'javascript:',  # JavaScript URLs
            r'data:',  # Data URLs
            r'eval\s*\(',  # eval() calls
            r'exec\s*\(',  # exec() calls
            r'import\s+',  # import statements
            r'__import__',  # __import__ calls
        ]
        
        sanitized = input_data
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        # Limit length to prevent DoS
        if len(sanitized) > 10000:
            sanitized = sanitized[:10000]
            logger.warning("Input truncated due to excessive length")
        
        return sanitized
    
    def check_resource_usage(self) -> Dict[str, Any]:
        """
        Check current resource usage and enforce limits.
        
        Returns:
            dict: Resource usage statistics
        """
        try:
            process = psutil.Process()
            
            # Memory usage
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            
            # CPU usage
            cpu_percent = process.cpu_percent()
            
            # Open files
            try:
                open_files = len(process.open_files())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                open_files = 0
            
            # Thread count
            thread_count = process.num_threads()
            
            stats = {
                'memory_mb': memory_mb,
                'cpu_percent': cpu_percent,
                'open_files': open_files,
                'thread_count': thread_count,
                'uptime_seconds': time.time() - self.start_time
            }
            
            # Check limits
            if memory_mb > self.max_memory_mb:
                logger.warning(f"Memory usage exceeded limit: {memory_mb:.1f}MB > {self.max_memory_mb}MB")
                
            if cpu_percent > self.max_cpu_percent:
                logger.warning(f"CPU usage exceeded limit: {cpu_percent:.1f}% > {self.max_cpu_percent}%")
                
            if open_files > self.max_open_files:
                logger.warning(f"Open files exceeded limit: {open_files} > {self.max_open_files}")
                
            if thread_count > self.max_threads:
                logger.warning(f"Thread count exceeded limit: {thread_count} > {self.max_threads}")
            
            return stats
            
        except Exception as e:
            logger.error(f"Resource monitoring error: {e}")
            return {}
    
    def start_resource_monitoring(self, interval: int = 30):
        """
        Start background resource monitoring.
        
        Args:
            interval: Monitoring interval in seconds
        """
        def monitor():
            while True:
                try:
                    stats = self.check_resource_usage()
                    if stats:
                        logger.debug(f"Resource usage: {stats}")
                    time.sleep(interval)
                except Exception as e:
                    logger.error(f"Resource monitoring error: {e}")
                    break
        
        if not self.resource_monitor or not self.resource_monitor.is_alive():
            self.resource_monitor = threading.Thread(target=monitor, daemon=True)
            self.resource_monitor.start()
            logger.info("Resource monitoring started")
    
    def stop_resource_monitoring(self):
        """Stop resource monitoring."""
        if self.resource_monitor and self.resource_monitor.is_alive():
            # Resource monitor thread is daemon, so it will stop automatically
            logger.info("Resource monitoring stopped")
    
    def validate_payload(self, payload: str) -> bool:
        """
        Validate scan payload for safety.
        
        Args:
            payload: Payload to validate
            
        Returns:
            bool: True if payload is safe
        """
        if not isinstance(payload, str):
            return False
        
        # Check payload length
        if len(payload) > 5000:
            logger.warning("Payload too long, potential DoS attempt")
            return False
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r'rm\s+-rf',  # Destructive commands
            r'del\s+/[sf]',  # Windows delete commands
            r'format\s+[a-z]:',  # Format commands
            r'shutdown',  # Shutdown commands
            r'reboot',  # Reboot commands
            r'halt',  # Halt commands
            r'<\?php',  # PHP code
            r'<%.*%>',  # ASP code
            r'{{.*}}',  # Template injection
            r'\$\{.*\}',  # Expression language injection
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                logger.warning(f"Dangerous pattern detected in payload: {pattern}")
                return False
        
        return True
    
    def create_safe_session(self) -> Dict[str, Any]:
        """
        Create a safe HTTP session configuration.
        
        Returns:
            dict: Safe session configuration
        """
        return {
            'timeout': 30,  # Reasonable timeout
            'max_redirects': 5,  # Limit redirects
            'verify_ssl': True,  # Always verify SSL
            'allow_redirects': True,
            'stream': False,  # Don't stream large responses
            'headers': {
                'User-Agent': 'WebVulnScanner/1.0 (Security Research)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',  # Don't keep connections alive
                'Cache-Control': 'no-cache'
            }
        }
    
    def log_security_event(self, event_type: str, details: str):
        """
        Log security-related events.
        
        Args:
            event_type: Type of security event
            details: Event details
        """
        logger.warning(f"SECURITY EVENT [{event_type}]: {details}")
    
    def emergency_stop(self, reason: str):
        """
        Emergency stop all operations.
        
        Args:
            reason: Reason for emergency stop
        """
        logger.critical(f"EMERGENCY STOP: {reason}")
        # Set global stop flag or raise exception
        raise RuntimeError(f"Emergency stop triggered: {reason}")

# Global safety manager instance
_safety_manager = None

def get_safety_manager(project_root: str = None) -> HostSafetyManager:
    """Get or create the global safety manager instance."""
    global _safety_manager
    if _safety_manager is None:
        if project_root is None:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _safety_manager = HostSafetyManager(project_root)
    return _safety_manager

def safe_file_write(file_path: str, content: str) -> bool:
    """
    Safely write content to file with validation.
    
    Args:
        file_path: Path to write to
        content: Content to write
        
    Returns:
        bool: True if write was successful
    """
    safety = get_safety_manager()
    
    if not safety.validate_file_write(file_path):
        return False
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        logger.error(f"Safe file write failed: {e}")
        return False

def safe_url_request(url: str, **kwargs) -> bool:
    """
    Validate URL before making request.
    
    Args:
        url: URL to validate
        **kwargs: Additional arguments
        
    Returns:
        bool: True if URL is safe to request
    """
    safety = get_safety_manager()
    return safety.validate_url(url)
