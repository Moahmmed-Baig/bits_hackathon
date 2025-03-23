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
                 user_agents: Optional[List[str]] = None):
        """
        Initialize the Tor connection manager.
        
        Args:
            socks_port: Port number for Tor's SOCKS proxy
            control_port: Port number for Tor's control port
            password: Password for Tor's control port authentication
            user_agents: List of user agents to rotate through for requests
        """
        self.socks_port = socks_port
        self.control_port = control_port
        self.password = password
        
        # Tor proxy configuration
        self.proxies = {
            'http': f'socks5h://127.0.0.1:{self.socks_port}',
            'https': f'socks5h://127.0.0.1:{self.socks_port}'
        }
        
        # Default user agents if none provided
        self.user_agents = user_agents or [
            'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'
        ]
    
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
    
    def scrape_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Scrape content from a URL through Tor.
        
        Args:
            url: The URL to scrape
            
        Returns:
            Tuple[Optional[str], Optional[str]]: A tuple containing 
            (raw_html, extracted_text) if successful, (None, None) otherwise
        """
        html = self.make_request(url)
        if html:
            text = self.extract_content(html)
            return html, text
        return None, None
