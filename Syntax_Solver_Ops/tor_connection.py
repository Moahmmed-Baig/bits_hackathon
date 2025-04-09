import logging
import requests
import time
import random
from stem import Signal
from stem.control import Controller
import trafilatura
from typing import List, Dict, Any, Optional, Tuple

# Set up logger
logger = logging.getLogger(__name__)

class TorConnection:
    """Handles connections to the Tor network for anonymous web scraping"""
    
    def __init__(self, 
                 socks_port: int = 9050, 
                 control_port: int = 9051, 
                 password: Optional[str] = None,
                 user_agents: Optional[List[str]] = None,
                 max_attempts: int = 3,
                 circuit_timeout: int = 30):
        """
        Initialize the Tor connection manager.
        
        Args:
            socks_port: Port number for Tor's SOCKS proxy
            control_port: Port number for Tor's control port
            password: Password for Tor's control port authentication
            user_agents: List of user agents to rotate through for requests
            max_attempts: Maximum number of connection attempts per request
            circuit_timeout: Timeout for Tor circuit establishment in seconds
        """
        self.socks_port = socks_port
        self.control_port = control_port
        self.password = password
        self.max_attempts = max_attempts
        self.circuit_timeout = circuit_timeout
        
        # Connection statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'identity_changes': 0,
            'last_identity_change': None,
            'status': 'initialized'
        }
        
        # Tor proxy configuration
        self.proxies = {
            'http': f'socks5h://127.0.0.1:{self.socks_port}',
            'https': f'socks5h://127.0.0.1:{self.socks_port}'
        }
        
        # Default expanded list of more realistic user agents if none provided
        self.user_agents = user_agents or [
            # Firefox agents
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:96.0) Gecko/20100101 Firefox/96.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
            
            # Chrome agents
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
            
            # Edge agents
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36 Edg/97.0.1072.62',
            
            # Safari agents
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15',
            
            # Tablet and mobile agents for variety
            'Mozilla/5.0 (iPad; CPU OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1'
        ]
        
        # Test the connection on initialization
        self.test_connection()
    
    def get_random_user_agent(self) -> str:
        """Return a random user agent from the list."""
        return random.choice(self.user_agents)
    
    def renew_tor_identity(self) -> bool:
        """
        Request a new identity from the Tor network to change the exit node.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with Controller.from_port(port=self.control_port) as controller:
                if self.password:
                    controller.authenticate(password=self.password)
                else:
                    controller.authenticate()
                controller.signal(Signal.NEWNYM)
                logger.info("Tor identity renewed successfully")
                time.sleep(5)  # Wait for the new identity to be established
                return True
        except Exception as e:
            logger.error(f"Failed to renew Tor identity: {e}")
            return False
    
    def make_request(self, url: str, max_retries: int = 3) -> Optional[str]:
        """
        Make a request through the Tor network.
        
        Args:
            url: The URL to request
            max_retries: Maximum number of retries if request fails
            
        Returns:
            Optional[str]: The response text if successful, None otherwise
        """
        headers = {'User-Agent': self.get_random_user_agent()}
        
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    url, 
                    headers=headers, 
                    proxies=self.proxies, 
                    timeout=30
                )
                
                if response.status_code == 200:
                    logger.info(f"Successfully retrieved content from {url}")
                    return response.text
                else:
                    logger.warning(f"Request to {url} failed with status code {response.status_code}")
            
            except Exception as e:
                logger.error(f"Error making request to {url}: {e}")
            
            # Retry with a new identity
            logger.info(f"Retrying with new Tor identity (attempt {attempt+1}/{max_retries})")
            self.renew_tor_identity()
            time.sleep(5 + random.uniform(1, 5))  # Add randomized delay
            
        logger.error(f"Failed to retrieve {url} after {max_retries} attempts")
        return None
    
    def extract_content(self, html: str) -> Optional[str]:
        """
        Extract the main content from HTML using trafilatura.
        
        Args:
            html: The HTML content to extract from
            
        Returns:
            Optional[str]: The extracted text if successful, None otherwise
        """
        try:
            extracted_text = trafilatura.extract(html)
            return extracted_text
        except Exception as e:
            logger.error(f"Error extracting content: {e}")
            return None
    
    def test_connection(self) -> bool:
        """
        Test the Tor connection by making a request to the Tor check service.
        Updates the connection status and returns success/failure.
        
        Returns:
            bool: True if connected successfully, False otherwise
        """
        try:
            # Several onion service test URLs we can try
            test_urls = [
                'https://check.torproject.org/',     # Not an onion, but confirms Tor exit
                'http://httpbin.org/ip'              # Simple IP check service
            ]
            
            for url in test_urls:
                try:
                    logger.info(f"Testing Tor connection with {url}")
                    headers = {'User-Agent': self.get_random_user_agent()}
                    
                    response = requests.get(
                        url,
                        headers=headers,
                        proxies=self.proxies,
                        timeout=self.circuit_timeout
                    )
                    
                    if response.status_code == 200:
                        logger.info("Tor connection successful")
                        self.stats['status'] = 'connected'
                        return True
                except Exception as e:
                    logger.warning(f"Test connection to {url} failed: {e}")
            
            # If we reach here, all test URLs failed
            logger.error("All Tor connection tests failed")
            self.stats['status'] = 'disconnected'
            return False
            
        except Exception as e:
            logger.error(f"Error testing Tor connection: {e}")
            self.stats['status'] = 'error'
            return False
    
    def make_request(self, url: str, max_retries: Optional[int] = None) -> Optional[str]:
        """
        Make a request through the Tor network with improved handling and retries.
        
        Args:
            url: The URL to request
            max_retries: Maximum number of retries if request fails, 
                         defaults to self.max_attempts if None
            
        Returns:
            Optional[str]: The response text if successful, None otherwise
        """
        max_retries = max_retries if max_retries is not None else self.max_attempts
        headers = {
            'User-Agent': self.get_random_user_agent(),
            # Add common headers to appear more like a normal browser
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',  # Do Not Track
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Track request in stats
        self.stats['total_requests'] += 1
        
        # Add variability to request timing
        time.sleep(random.uniform(0.5, 2.0))
        
        for attempt in range(max_retries):
            try:
                # Add slight variation to timeout to appear more human-like
                timeout = self.circuit_timeout + random.uniform(-2, 2)
                timeout = max(5, timeout)  # But never less than 5 seconds
                
                response = requests.get(
                    url, 
                    headers=headers, 
                    proxies=self.proxies, 
                    timeout=timeout,
                    # Disable redirects if dealing with potentially malicious sites
                    allow_redirects=True
                )
                
                # Simulate human-like behavior with a random pause after receiving a response
                time.sleep(random.uniform(0.1, 1.0))
                
                if response.status_code == 200:
                    logger.info(f"Successfully retrieved content from {url}")
                    self.stats['successful_requests'] += 1
                    return response.text
                elif response.status_code == 429:  # Too Many Requests
                    logger.warning(f"Rate limited (429) at {url}, waiting longer before retry")
                    # Wait longer for rate limit cooldown
                    time.sleep(30 + random.uniform(0, 30))
                elif response.status_code in [403, 404, 500, 502, 503, 504]:
                    logger.warning(f"Request to {url} failed with status code {response.status_code}")
                    # Less aggressive retry for these common errors
                    time.sleep(5 + random.uniform(0, 5))
                else:
                    logger.warning(f"Request to {url} failed with status code {response.status_code}")
            
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout when requesting {url}")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error when requesting {url}")
            except Exception as e:
                logger.error(f"Error making request to {url}: {e}")
            
            # Retry with a new identity if not the last attempt
            if attempt < max_retries - 1:
                logger.info(f"Retrying with new Tor identity (attempt {attempt+1}/{max_retries})")
                success = self.renew_tor_identity()
                if success:
                    self.stats['identity_changes'] += 1
                    self.stats['last_identity_change'] = time.time()
                
                # Add randomized delay that increases with each failed attempt
                delay = 5 + (attempt * 2) + random.uniform(1, 5)
                time.sleep(delay)
                
                # Get a new user agent for the retry
                headers['User-Agent'] = self.get_random_user_agent()
        
        # If all retries failed
        logger.error(f"Failed to retrieve {url} after {max_retries} attempts")
        self.stats['failed_requests'] += 1
        return None
    
    def scrape_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Scrape content from a URL through Tor.
        
        Args:
            url: The URL to scrape
            
        Returns:
            Tuple[Optional[str], Optional[str]]: A tuple containing 
            (raw_html, extracted_text) if successful, (None, None) otherwise
        """
        # Check connection status first
        if self.stats['status'] != 'connected':
            success = self.test_connection()
            if not success:
                logger.error("Cannot scrape URL without Tor connection")
                return None, None
        
        # Make the request with our enhanced retry logic
        html = self.make_request(url)
        
        if html:
            text = self.extract_content(html)
            return html, text
        
        return None, None
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the Tor connection.
        
        Returns:
            Dict[str, Any]: Dictionary with connection statistics
        """
        # Update some live stats before returning
        uptime = time.time() - self.stats.get('start_time', time.time())
        
        stats = {
            **self.stats,
            'uptime_seconds': uptime,
            'success_rate': (self.stats['successful_requests'] / 
                            max(1, self.stats['total_requests'])) * 100,
            'current_time': time.time()
        }
        
        return stats
