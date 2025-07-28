"""
Web Vulnerability Scanner - Crawler Module

This module implements the URL crawling functionality, including:
- URL frontier management
- robots.txt parsing and adherence
- Rate limiting and crawl depth management
- URL queue handling
"""

import time
import logging
import random
from urllib.parse import urlparse, urljoin
from collections import deque
import threading
import requests
from robotexclusionrulesparser import RobotExclusionRulesParser
from typing import Set, Dict, List, Optional, Callable
from .safety import get_safety_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('scanner.crawler')

class Crawler:
    """Web crawler that respects robots.txt, rate limits, and crawl depth."""

    def __init__(
        self, 
        start_urls: List[str],
        max_depth: int = 3,
        max_urls_per_domain: int = 100,
        request_delay: float = 0.5,
        respect_robots_txt: bool = True,
        allowed_domains: Optional[List[str]] = None,
        custom_user_agent: str = "WebVulnScanner/0.1.0",
        follow_subdomains: bool = False,
        thread_count: int = 1
    ):
        """
        Initialize the crawler with configuration parameters.
        
        Args:
            start_urls: List of seed URLs to begin crawling from
            max_depth: Maximum link depth to crawl
            max_urls_per_domain: Maximum number of URLs to crawl per domain
            request_delay: Delay between requests to the same domain (in seconds)
            respect_robots_txt: Whether to adhere to robots.txt directives
            allowed_domains: List of domains to restrict crawling to (None = no restriction)
            custom_user_agent: User-Agent string to use for requests
            follow_subdomains: Whether to follow links to subdomains of allowed domains
            thread_count: Number of crawler threads to use
        """
        # Initialize safety manager for host protection
        self.safety_manager = get_safety_manager()
        
        # Validate all start URLs for safety
        validated_urls = []
        for url in start_urls:
            if self.safety_manager.validate_url(url):
                validated_urls.append(url)
            else:
                logger.warning(f"Unsafe URL blocked: {url}")
        
        if not validated_urls:
            raise ValueError("No safe URLs provided for crawling")
        
        self.start_urls = validated_urls
        self.max_depth = max_depth
        self.max_urls_per_domain = max_urls_per_domain
        self.request_delay = request_delay
        self.respect_robots_txt = respect_robots_txt
        self.custom_user_agent = custom_user_agent
        self.follow_subdomains = follow_subdomains
        self.thread_count = thread_count

        # Initialize URL collections
        self.url_queue = deque()  # URLs to be crawled
        self.crawled_urls: Set[str] = set()  # URLs already crawled
        self.url_depth: Dict[str, int] = {}  # Track URL depths
        
        # Domain-specific tracking
        self.domain_url_count: Dict[str, int] = {}  # Count of URLs crawled per domain
        self.domain_last_request: Dict[str, float] = {}  # Timestamp of last request per domain
        self.robots_cache: Dict[str, RobotExclusionRulesParser] = {}  # Cache of robots.txt parsers
        
        # Set allowed domains
        if allowed_domains:
            self.allowed_domains = set(allowed_domains)
        else:
            # Extract domains from start URLs if not specified
            self.allowed_domains = {urlparse(url).netloc for url in start_urls}
        
        # Thread synchronization
        self.queue_lock = threading.Lock()
        self.data_lock = threading.Lock()
        
        # Initialize queue with start URLs
        for url in start_urls:
            self.add_url_to_queue(url, 0)
    
    def add_url_to_queue(self, url: str, depth: int = 0) -> bool:
        """
        Add a URL to the crawling queue if it passes all filters.
        
        Args:
            url: URL to add to the queue
            depth: Depth level of this URL
            
        Returns:
            bool: True if URL was added, False if filtered out
        """
        # Normalize URL
        url = url.strip()
        if not url:
            return False
        
        # Safety validation - block unsafe URLs
        if not self.safety_manager.validate_url(url):
            logger.debug(f"URL blocked by safety manager: {url}")
            return False
        
        # Skip if URL already crawled or queued
        if url in self.crawled_urls or url in self.url_queue:
            return False
            
        # Parse URL to get domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Skip if max depth exceeded
        if depth > self.max_depth:
            logger.debug(f"Skipping {url}: max depth exceeded")
            return False
            
        # Skip if domain not allowed
        if self.allowed_domains and domain not in self.allowed_domains:
            # Check if it's a subdomain we should follow
            if self.follow_subdomains and any(domain.endswith('.' + allowed) for allowed in self.allowed_domains):
                pass  # Allow this subdomain
            else:
                logger.debug(f"Skipping {url}: domain not allowed")
                return False
                
        # Check robots.txt
        if self.respect_robots_txt and not self._is_allowed_by_robots(url):
            logger.debug(f"Skipping {url}: disallowed by robots.txt")
            return False
            
        # Check domain URL limit
        with self.data_lock:
            if domain in self.domain_url_count and self.domain_url_count[domain] >= self.max_urls_per_domain:
                logger.debug(f"Skipping {url}: max URLs for domain reached")
                return False
                
        # Add URL to queue
        with self.queue_lock:
            self.url_queue.append(url)
            self.url_depth[url] = depth
            
        return True
        
    def _is_allowed_by_robots(self, url: str) -> bool:
        """
        Check if a URL is allowed according to the site's robots.txt file.
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if URL is allowed (or robots.txt couldn't be fetched), False otherwise
        """
        # Skip robots check if disabled
        if not self.respect_robots_txt:
            return True
            
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Use cached robots.txt parser if available
        if domain in self.robots_cache:
            robots = self.robots_cache[domain]
        else:
            # Fetch and parse robots.txt
            try:
                robots_url = f"{parsed_url.scheme}://{domain}/robots.txt"
                headers = {'User-Agent': self.custom_user_agent}
                response = requests.get(robots_url, headers=headers, timeout=10)
                
                # Initialize parser
                robots = RobotExclusionRulesParser()
                robots.parse(response.text)
                
                # Cache the robots.txt parser
                self.robots_cache[domain] = robots
                
            except Exception as e:
                logger.warning(f"Error fetching robots.txt for {domain}: {e}")
                return True
                
        # Check if URL is allowed
        return robots.is_allowed(self.custom_user_agent, url)
        
    def _respect_rate_limit(self, domain: str) -> None:
        """
        Ensure rate limiting by waiting if necessary.
        
        Args:
            domain: Domain to check rate limit for
        """
        with self.data_lock:
            if domain in self.domain_last_request:
                last_request = self.domain_last_request[domain]
                time_since_last = time.time() - last_request
                
                if time_since_last < self.request_delay:
                    # Need to wait to respect rate limit
                    wait_time = self.request_delay - time_since_last
                    # Add some randomization to make requests less predictable
                    random_factor = random.uniform(0.5, 1.5)
                    wait_time *= random_factor
                    logger.debug(f"Rate limiting: waiting {wait_time:.2f}s for {domain}")
                    time.sleep(wait_time)
                    
            # Update the last request timestamp
            self.domain_last_request[domain] = time.time()
            
            # Initialize or increment domain URL counter
            if domain not in self.domain_url_count:
                self.domain_url_count[domain] = 1
            else:
                self.domain_url_count[domain] += 1
    
    def get_next_url(self) -> Optional[str]:
        """
        Get the next URL from the queue.
        
        Returns:
            str or None: Next URL to crawl, or None if queue is empty
        """
        with self.queue_lock:
            if not self.url_queue:
                return None
            return self.url_queue.popleft()
    
    def mark_url_crawled(self, url: str) -> None:
        """
        Mark a URL as crawled.
        
        Args:
            url: URL that has been crawled
        """
        with self.data_lock:
            self.crawled_urls.add(url)
    
    def get_url_depth(self, url: str) -> int:
        """
        Get the depth of a URL.
        
        Args:
            url: URL to get depth for
            
        Returns:
            int: Depth of the URL
        """
        return self.url_depth.get(url, 0)
    
    def crawl(self, process_page_callback: Callable[[str, requests.Response, int], List[str]], interrupt_flag=None) -> None:
        """
        Start the crawling process.
        
        Args:
            process_page_callback: Function to call for each crawled page.
                                   Should accept (url, response, depth) and return a list of new URLs.
            interrupt_flag: Threading event to signal interruption
        """
        def worker():
            while True:
                # Check for interrupt signal
                if interrupt_flag and interrupt_flag.is_set():
                    logger.info("Worker thread received interrupt signal, stopping")
                    break
                    
                url = self.get_next_url()
                if url is None:
                    # No more URLs to process
                    break
                
                depth = self.get_url_depth(url)
                domain = urlparse(url).netloc
                
                # Respect rate limiting
                self._respect_rate_limit(domain)
                
                try:
                    # Check for interrupt before making request
                    if interrupt_flag and interrupt_flag.is_set():
                        logger.info("Interrupt detected before request, stopping")
                        break
                        
                    logger.info(f"Crawling {url} (depth {depth})")
                    headers = {'User-Agent': self.custom_user_agent}
                    # Use longer timeout for initial connection
                    timeout = 30 if depth == 0 else 15
                    response = requests.get(url, headers=headers, timeout=timeout)
                    
                    # Check for interrupt after request
                    if interrupt_flag and interrupt_flag.is_set():
                        logger.info("Interrupt detected after request, stopping")
                        break
                    
                    # Process the page and get new URLs
                    new_urls = process_page_callback(url, response, depth)
                    
                    # Add new URLs to queue
                    for new_url in new_urls:
                        if interrupt_flag and interrupt_flag.is_set():
                            logger.info("Interrupt detected while adding URLs, stopping")
                            break
                        self.add_url_to_queue(new_url, depth + 1)
                        
                except requests.exceptions.ConnectTimeout as e:
                    logger.warning(f"Connection timeout for {url} - target may be slow or unreachable")
                    logger.info(f"💡 Try: Increase timeout with --timeout option or check network connectivity")
                except requests.exceptions.ConnectionError as e:
                    logger.warning(f"Connection failed for {url} - target may be down or blocking requests")
                    logger.info(f"💡 Try: Check if target is accessible in browser or use different user-agent")
                except requests.exceptions.Timeout as e:
                    logger.warning(f"Request timeout for {url} - target is responding slowly")
                    logger.info(f"💡 Try: Increase timeout or reduce concurrent threads")
                except Exception as e:
                    logger.error(f"Error crawling {url}: {e}")
                
                # Mark as crawled
                self.mark_url_crawled(url)
        
        # Start worker threads
        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=worker)
            t.daemon = True
            threads.append(t)
            t.start()
            
        # Wait for all threads to complete
        for t in threads:
            t.join()
            
        logger.info(f"Crawling completed. Crawled {len(self.crawled_urls)} URLs.")
