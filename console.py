#!/usr/bin/env python3
"""
Web Vulnerability Scanner - Command Line Interface

This module provides a command-line interface for the Web Vulnerability Scanner.
It allows users to configure and run scans against target URLs or domains,
selecting which plugins to use and customizing various scanning parameters.
"""

import argparse
import logging
import sys
import os
import time
import yaml
import json
import signal
import threading
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from scanner.crawler import Crawler
from scanner.http_client import HttpClient
from scanner.reporter import Reporter, Finding, Severity
from scanner.safety import get_safety_manager
from plugins.base import Plugin
import plugins  # This triggers plugin registration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('scanner.log', mode='w')
    ]
)

logger = logging.getLogger('console')

# Global interrupt flag for graceful shutdown
interrupt_flag = threading.Event()

def signal_handler(signum, frame):
    """Handle interrupt signals (Ctrl+C) gracefully."""
    print("\n\n[INTERRUPT] Stopping scan gracefully...")
    logger.info("Interrupt signal received, setting stop flag")
    interrupt_flag.set()

# Default configuration
DEFAULT_CONFIG = {
    'crawler': {
        'max_depth': 3,
        'max_urls': 100,
        'respect_robots_txt': True,
        'threads': 5,
        'timeout': 10,
        'delay': 0.5,
    },
    'http': {
        'timeout': 30,
        'max_retries': 3,
        'verify_ssl': True,
        'user_agent': 'WebVulnScanner/1.0',
        'headers': {},
        'proxies': None,
        'cookies': None,
        'rotate_user_agents': True,  # Enable user-agent rotation for stealth
        'random_delay': True,  # Add random delays between requests
        'min_delay': 1.0,  # Minimum delay between requests
        'max_delay': 3.0   # Maximum delay between requests
    },
    'plugins': {
        'enabled': ['all'],
        'disabled': [],
        'sql_injection': {
            'max_payloads': 10
        },
        'xss': {
            'max_payloads': 10
        },
        'directory_traversal': {
            'max_payloads': 10
        },
        'open_redirect': {
            'max_payloads': 10
        },
        'security_headers': {
            'check_cookies': True
        }
    },
    'reporting': {
        'output_format': 'all',  # Options: json, html, console, all
        'output_directory': 'reports',
        'min_severity': 'low',  # Options: info, low, medium, high, critical
        'report_name_prefix': 'scan_report_',
        'include_evidence': True
    }
}

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from a YAML file or use defaults.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    config = DEFAULT_CONFIG.copy()
    
    if config_path:
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                
            # Deep merge user config with defaults
            if user_config:
                deep_merge(config, user_config)
                
            logger.info(f"Configuration loaded from {config_path}")
        except Exception as e:
            logger.error(f"Error loading configuration from {config_path}: {e}")
            logger.info("Using default configuration")
    else:
        logger.info("No configuration file specified, using default configuration")
        
    return config

def deep_merge(base: Dict, override: Dict) -> Dict:
    """
    Deep merge two dictionaries, with override values taking precedence.
    
    Args:
        base: Base dictionary
        override: Dictionary with override values
        
    Returns:
        Dict: Merged dictionary
    """
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base

def setup_reporter(config: Dict[str, Any], target_url: str = None) -> Reporter:
    """
    Set up the reporter based on configuration.
    
    Args:
        config: Configuration dictionary
        target_url: Target URL being scanned (for naming reports)
        
    Returns:
        Reporter: Configured reporter
    """
    reporting_config = config.get('reporting', {})
    
    # Create output directory if it doesn't exist
    output_dir = reporting_config.get('output_directory', 'reports')
    os.makedirs(output_dir, exist_ok=True)

    # Define database path with domain and date
    if target_url:
        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc
        # Clean domain name for filename (remove www, special chars)
        clean_domain = domain.replace('www.', '').replace(':', '_').replace('/', '_')
        date_str = time.strftime('%Y-%m-%d')
        time_str = time.strftime('%H%M%S')
        report_name = f"{clean_domain}_{date_str}_{time_str}"
    else:
        # Fallback to generic naming
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        report_prefix = reporting_config.get('report_name_prefix', 'scan_report_')
        report_name = f"{report_prefix}{timestamp}"
    
    db_path = os.path.join(output_dir, f"{report_name}.db")

    # Set up reporter with correct arguments
    reporter = Reporter(
        db_path=db_path,
        report_dir=output_dir
    )
    
    return reporter

def setup_http_client(config: Dict[str, Any]) -> HttpClient:
    """
    Set up the HTTP client based on configuration.

    Args:
        config: Configuration dictionary

    Returns:
        HttpClient: Configured HTTP client
    """
    http_config = config.get('http', {})

    # Note: The config key is 'proxies', but the HttpClient constructor expects 'proxy'.
    client = HttpClient(
        user_agent=http_config.get('user_agent', 'WebVulnScanner/1.0'),
        timeout=http_config.get('timeout', 30),
        max_retries=http_config.get('max_retries', 3),
        verify_ssl=http_config.get('verify_ssl', True),
        proxy=http_config.get('proxies'),
        cookies=http_config.get('cookies'),
        headers=http_config.get('headers'),
        rotate_user_agents=http_config.get('rotate_user_agents', True)  # Enable by default for stealth
    )

    logger.info("HTTP client set up successfully")
    return client

def setup_crawler(config: Dict[str, Any], http_client: HttpClient, target_url: str) -> Crawler:
    """
    Set up the crawler based on configuration.
    
    Args:
        config: Configuration dictionary
        http_client: HTTP client (not used by current Crawler implementation)
        target_url: Target URL to crawl
        
    Returns:
        Crawler: Configured crawler
    """
    crawler_config = config.get('crawler', {})
    
    # Note: Current Crawler implementation doesn't use http_client parameter
    # It uses its own requests for HTTP calls
    crawler = Crawler(
        start_urls=[target_url],
        max_depth=crawler_config.get('max_depth', 3),
        max_urls_per_domain=crawler_config.get('max_urls', 100),
        request_delay=crawler_config.get('delay', 0.5),
        respect_robots_txt=crawler_config.get('respect_robots_txt', True),
        custom_user_agent=crawler_config.get('user_agent', 'WebVulnScanner/1.0'),
        thread_count=crawler_config.get('threads', 5)
    )
    
    logger.info("Crawler set up successfully")
    return crawler

def load_plugins(config: Dict[str, Any], reporter: Reporter) -> List[Plugin]:
    """
    Load and configure plugins based on configuration.
    
    Args:
        config: Configuration dictionary
        reporter: Reporter instance
        
    Returns:
        List[Plugin]: List of plugin instances
    """
    plugin_config = config.get('plugins', {})
    enabled_plugins = plugin_config.get('enabled', ['all'])
    disabled_plugins = plugin_config.get('disabled', [])
    
    all_plugins = Plugin.get_all_plugins()
    loaded_plugins = []
    
    for name, plugin_cls in all_plugins.items():
        if name in disabled_plugins:
            continue
        if 'all' in enabled_plugins or name in enabled_plugins:
            plugin_instance = plugin_cls(reporter)
            loaded_plugins.append(plugin_instance)
            logger.info(f"Loaded plugin: {name}")
            
    return loaded_plugins

def validate_url(url: str) -> str:
    """
    Validate and normalize a URL.
    
    Args:
        url: URL to validate
        
    Returns:
        str: Normalized URL
        
    Raises:
        ValueError: If URL is invalid
    """
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
        
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise ValueError(f"Invalid URL: {url}")
        
    return url

def generate_reports(reporter: Reporter, config: Dict[str, Any], target_url: str) -> List[str]:
    """
    Generate reports based on configuration.
    
    Args:
        reporter: Reporter instance with findings
        config: Configuration dictionary
        target_url: URL that was scanned
        
    Returns:
        List[str]: List of report file paths
    """
    reporting_config = config.get('reporting', {})
    output_format = reporting_config.get('output_format', 'all')
    min_severity_str = reporting_config.get('min_severity', 'low').upper()
    min_severity = getattr(Severity, min_severity_str, Severity.LOW)
    
    # Get all findings and filter by minimum severity
    all_findings = reporter.get_findings()
    findings = [f for f in all_findings if f.severity.value >= min_severity.value]
    
    if not findings:
        print("\nNo findings to report.")
        return []
        
    print(f"\nFound {len(findings)} issues:")
    for finding in findings:
        print(f"  - [{finding.severity.name}] {finding.title} at {finding.url}")
        
    report_paths = []
    
    if output_format in ['json', 'all']:
        json_path = reporter.export_to_json()
        print(f"\nJSON report generated: {json_path}")
        report_paths.append(json_path)
        
    if output_format in ['html', 'all']:
        html_path = reporter.export_to_html()
        print(f"HTML report generated: {html_path}")
        report_paths.append(html_path)
        
    if output_format in ['console', 'all']:
        # Print console summary
        stats = reporter.get_statistics()
        print(f"\n=== SCAN SUMMARY ===")
        print(f"Total findings: {stats['total']}")
        print(f"False positives: {stats['false_positives']}")
        print(f"By severity: {stats['by_severity']}")
        print(f"By plugin: {stats['by_plugin']}")
        
    return report_paths

def main():
    """Main function for the command line interface."""
    # Initialize safety manager for host protection
    safety_manager = get_safety_manager()
    safety_manager.start_resource_monitoring()
    
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-d', '--depth', type=int, help='Maximum crawl depth')
    parser.add_argument('--max-urls', type=int, help='Maximum number of URLs to scan')
    parser.add_argument('-t', '--threads', type=int, help='Number of crawler threads')
    parser.add_argument('-o', '--output', help='Output format (json, html, console, all)')
    parser.add_argument('-p', '--plugins', help='Comma-separated list of plugins to enable')
    parser.add_argument('-x', '--exclude', help='Comma-separated list of plugins to disable')
    parser.add_argument('--no-robots', action='store_true', help='Ignore robots.txt')
    parser.add_argument('--delay', type=float, help='Delay between requests in seconds')
    parser.add_argument('--timeout', type=int, help='Request timeout in seconds (default: 30)')
    parser.add_argument('--list-plugins', action='store_true', help='List available plugins and exit')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # List plugins and exit if requested
    if args.list_plugins:
        all_plugins = Plugin.get_all_plugins()
        print("Available plugins:")
        for name, plugin_cls in all_plugins.items():
            print(f"  - {name}: {plugin_cls.description}")
        return 0
    
    # Require URL if not listing plugins
    if not args.url:
        parser.error("the following arguments are required: -u/--url")
    
    # Load configuration
    config = load_config(args.config)
    
    # Override configuration with command line arguments
    if args.depth:
        config['crawler']['max_depth'] = args.depth
    
    if args.max_urls:
        config['crawler']['max_urls'] = args.max_urls
    
    if args.threads:
        config['crawler']['threads'] = args.threads
    
    if args.no_robots:
        config['crawler']['respect_robots_txt'] = False
    
    if args.delay:
        config['crawler']['delay'] = args.delay
    
    if args.timeout:
        config['http']['timeout'] = args.timeout
    
    if args.output:
        config['reporting']['output_format'] = args.output
    
    if args.plugins:
        config['plugins']['enabled'] = args.plugins.split(',')
    
    if args.exclude:
        config['plugins']['disabled'] = args.exclude.split(',')
    
    # Validate URL
    try:
        target_url = validate_url(args.url)
    except ValueError as e:
        logger.error(str(e))
        return 1
    
    # Set up components
    reporter = setup_reporter(config, target_url)
    http_client = setup_http_client(config)
    crawler = setup_crawler(config, http_client, target_url)
    plugins = load_plugins(config, reporter)
    
    if not plugins:
        logger.error("No plugins enabled. Exiting.")
        return 1
    
    # Start scan
    logger.info(f"Starting scan of {target_url}")
    print(f"\nScanning {target_url}...")
    print(f"Max depth: {config['crawler']['max_depth']}")
    print(f"Max URLs: {config['crawler']['max_urls']}")
    print(f"Plugins: {', '.join(p.name for p in plugins)}")
    
    start_time = time.time()
    discovered_urls = []
    
    def process_page_callback(url, response, depth):
        # Check for interrupt at the start of processing
        if interrupt_flag.is_set():
            logger.info("Interrupt detected in callback, stopping page processing")
            return []
            
        discovered_urls.append(url)
        print(f"\rDiscovered {len(discovered_urls)} URLs", end='')
        
        # Track plugin failures to avoid repeated attempts on clearly blocked requests
        plugin_failures = {}
        
        # Apply each plugin to the URL
        for plugin in plugins:
            # Check for interrupt before each plugin
            if interrupt_flag.is_set():
                logger.info(f"Interrupt detected before plugin {plugin.name}, stopping")
                break
                
            try:
                # Skip plugin if it has failed too many times (likely blocked)
                if plugin.name in plugin_failures and plugin_failures[plugin.name] >= 3:
                    logger.debug(f"Skipping plugin {plugin.name} due to repeated failures (likely blocked)")
                    continue
                    
                plugin.scan(url, http_client)
                # Reset failure count on success
                if plugin.name in plugin_failures:
                    del plugin_failures[plugin.name]
                    
            except Exception as e:
                # Track failures
                plugin_failures[plugin.name] = plugin_failures.get(plugin.name, 0) + 1
                
                # Check if it's a blocking-related error
                error_str = str(e).lower()
                if any(keyword in error_str for keyword in ['503', '429', '403', 'service unavailable', 'rate limit', 'forbidden']):
                    logger.warning(f"Plugin {plugin.name} blocked on {url}: {e}")
                else:
                    logger.error(f"Error running plugin {plugin.name} on {url}: {e}")
        
        # Extract links from the response for further crawling
        try:
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin
            
            soup = BeautifulSoup(response.text, 'html.parser')
            links = []
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url, link['href'])
                links.append(absolute_url)
            return links
        except Exception as e:
            logger.debug(f"Error extracting links from {url}: {e}")
            return []
    
    try:
        # Start crawling with the callback and interrupt flag
        crawler.crawl(process_page_callback, interrupt_flag)
        
        if interrupt_flag.is_set():
            print(f"\n[INTERRUPTED] Scan interrupted by user")
            print(f"[RESULTS] Partial results: {len(discovered_urls)} URLs discovered before interruption")
        else:
            print(f"\n[SUCCESS] Scan completed successfully")
            print(f"[RESULTS] Total URLs discovered and scanned: {len(discovered_urls)}")
        
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Scan interrupted by user (KeyboardInterrupt)")
        logger.warning("Scan interrupted by user")
        interrupt_flag.set()  # Ensure flag is set
    except Exception as e:
        print(f"\n[ERROR] Error during scan: {e}")
        logger.error(f"Error during scan: {e}", exc_info=True)
    
    # Generate reports
    generate_reports(reporter, config, target_url)
    
    # Print elapsed time
    elapsed_time = time.time() - start_time
    print(f"\nScan completed in {elapsed_time:.2f} seconds")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
