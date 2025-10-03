"""Core API Discovery functionality."""

import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import json
import time
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from .auth import Authenticator

@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint."""
    url: str
    method: str = 'GET'
    parameters: List[str] = None
    headers: Dict[str, str] = None
    source: str = 'unknown'
    confidence: float = 0.0
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = []
        if self.headers is None:
            self.headers = {}

class APIDiscovery:
    """Main class for discovering API endpoints from web pages."""
    
    def __init__(self, base_url: str, timeout: int = 30, authenticator: Authenticator = None, verbose: bool = False):
        self.base_url = base_url
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'APIHunter/1.0 (API Discovery Tool)'
        })
        self.authenticator = authenticator or Authenticator(self.session)
        
        # Common API patterns
        self.api_patterns = [
            r'/api/v?\d*/?.*',
            r'/rest/.*',
            r'/graphql/?.*',
            r'/endpoints?/.*',
            r'/services?/.*',
            r'\.json$',
            r'\.xml$',
            r'/json/.*',
            r'/xml/.*'
        ]
        
    def discover_endpoints(self) -> List[APIEndpoint]:
        """Main method to discover API endpoints from the target URL."""
        endpoints = []
        
        try:
            # Get the main page (use the full URL, not just domain)
            print(f"🌐 Fetching: {self.base_url}")
            response = self.session.get(self.base_url, timeout=self.timeout)
            response.raise_for_status()
            
            print(f"📄 Response: {response.status_code} ({len(response.text)} chars)")
            
            # If we have an authenticator, check if we need to look for more dynamic content
            if self.authenticator.is_authenticated():
                print("🔐 Authenticated session - looking for authenticated content")
                # Look for dynamic content that might be loaded after authentication
                endpoints.extend(self._discover_authenticated_content(response.text))
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Discovery methods
            endpoints.extend(self._discover_from_links(soup))
            endpoints.extend(self._discover_from_scripts(soup))
            endpoints.extend(self._discover_from_forms(soup))
            endpoints.extend(self._discover_from_ajax_calls(response.text))
            endpoints.extend(self._discover_from_meta_tags(soup))
            endpoints.extend(self._discover_from_comments(response.text))
            
            # Test common authenticated endpoints if we have authentication
            if self.authenticator and self.authenticator.authenticated:
                endpoints.extend(self._test_authenticated_endpoints(self.base_url))
            
            # Remove duplicates
            unique_endpoints = self._deduplicate_endpoints(endpoints)
            
            # Validate endpoints
            validated_endpoints = self._validate_endpoints(unique_endpoints)
            
            return validated_endpoints
            
        except requests.RequestException as e:
            print(f"Error fetching {self.base_url}: {e}")
            return []
    
    def _discover_from_links(self, soup: BeautifulSoup) -> List[APIEndpoint]:
        """Discover endpoints from HTML links."""
        endpoints = []
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(self.base_url, href)
            
            if self._is_api_endpoint(full_url):
                endpoint = APIEndpoint(
                    url=full_url,
                    source='html_link',
                    confidence=0.7
                )
                endpoints.append(endpoint)
                
        return endpoints
    
    def _discover_from_scripts(self, soup: BeautifulSoup) -> List[APIEndpoint]:
        """Discover endpoints from JavaScript code."""
        endpoints = []
        
        for script in soup.find_all('script'):
            if script.string:
                # Look for fetch/XMLHttpRequest patterns
                fetch_patterns = [
                    r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                    r'XMLHttpRequest.*open\s*\(\s*[\'"`](\w+)[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]',
                    r'ajax\s*\(\s*{.*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
                    r'\.get\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                    r'\.post\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'
                ]
                
                for pattern in fetch_patterns:
                    matches = re.findall(pattern, script.string, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            method, url = match[0], match[1] if len(match) > 1 else match[0]
                        else:
                            method, url = 'GET', match
                            
                        full_url = urljoin(self.base_url, url)
                        if self._is_potential_endpoint(full_url):
                            endpoint = APIEndpoint(
                                url=full_url,
                                method=method.upper() if method else 'GET',
                                source='javascript',
                                confidence=0.8
                            )
                            endpoints.append(endpoint)
                            
        return endpoints
    
    def _discover_from_forms(self, soup: BeautifulSoup) -> List[APIEndpoint]:
        """Discover endpoints from HTML forms."""
        endpoints = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            if action:
                full_url = urljoin(self.base_url, action)
                
                # Get form parameters
                parameters = []
                for input_tag in form.find_all(['input', 'select', 'textarea']):
                    name = input_tag.get('name')
                    if name:
                        parameters.append(name)
                
                endpoint = APIEndpoint(
                    url=full_url,
                    method=method,
                    parameters=parameters,
                    source='html_form',
                    confidence=0.6
                )
                endpoints.append(endpoint)
                
        return endpoints
    
    def _discover_from_ajax_calls(self, html_content: str) -> List[APIEndpoint]:
        """Discover endpoints from AJAX calls in JavaScript."""
        endpoints = []
        
        # Advanced JavaScript patterns for API calls
        advanced_patterns = [
            r'axios\.[get|post|put|delete|patch]+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\$\.ajax\s*\(\s*{[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
            r'api\s*\.\s*\w+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'endpoint\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            r'baseURL\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            # Modern fetch and API patterns
            r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
            r'[\'"`](/(?:client/)?api/[^\'"`]*)[\'"`]',
            # Spond-specific patterns
            r'[\'"`](https?://[^\'"`]*spond[^\'"`]*)[\'"`]',
            r'/client/api/[a-zA-Z0-9/_.-]*'
        ]
        
        for pattern in advanced_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                full_url = urljoin(self.base_url, match)
                if self._is_potential_endpoint(full_url):
                    endpoint = APIEndpoint(
                        url=full_url,
                        source='ajax_call',
                        confidence=0.9
                    )
                    endpoints.append(endpoint)
                    
        return endpoints
    
    def _discover_from_meta_tags(self, soup: BeautifulSoup) -> List[APIEndpoint]:
        """Discover endpoints from meta tags and data attributes."""
        endpoints = []
        
        # Check meta tags
        for meta in soup.find_all('meta'):
            content = meta.get('content', '')
            if self._is_potential_endpoint(content):
                full_url = urljoin(self.base_url, content)
                endpoint = APIEndpoint(
                    url=full_url,
                    source='meta_tag',
                    confidence=0.5
                )
                endpoints.append(endpoint)
        
        # Check data attributes
        for element in soup.find_all(attrs={'data-api-url': True}):
            url = element['data-api-url']
            full_url = urljoin(self.base_url, url)
            endpoint = APIEndpoint(
                url=full_url,
                source='data_attribute',
                confidence=0.8
            )
            endpoints.append(endpoint)
            
        return endpoints
    
    def _discover_from_comments(self, html_content: str) -> List[APIEndpoint]:
        """Discover endpoints from HTML/JavaScript comments."""
        endpoints = []
        
        # HTML comments
        comment_pattern = r'<!--.*?-->'
        comments = re.findall(comment_pattern, html_content, re.DOTALL)
        
        # JavaScript comments
        js_comment_patterns = [
            r'//.*',
            r'/\*.*?\*/'
        ]
        
        all_comments = comments[:]
        for pattern in js_comment_patterns:
            all_comments.extend(re.findall(pattern, html_content, re.DOTALL))
        
        for comment in all_comments:
            # Look for URLs in comments
            url_pattern = r'https?://[^\s<>\"\']+|/[a-zA-Z0-9/_.-]+(?:\?[^\s<>\"\']*)?'
            urls = re.findall(url_pattern, comment)
            
            for url in urls:
                full_url = urljoin(self.base_url, url)
                if self._is_potential_endpoint(full_url):
                    endpoint = APIEndpoint(
                        url=full_url,
                        source='comment',
                        confidence=0.4
                    )
                    endpoints.append(endpoint)
                    
        return endpoints
    
    def _is_api_endpoint(self, url: str) -> bool:
        """Check if a URL matches common API endpoint patterns."""
        for pattern in self.api_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False
    
    def _is_potential_endpoint(self, url: str) -> bool:
        """Check if a URL could potentially be an API endpoint."""
        # Basic checks
        if not url or url.startswith('javascript:') or url.startswith('mailto:'):
            return False
            
        # Check for API-like patterns
        api_indicators = [
            'api', 'rest', 'graphql', 'endpoint', 'service',
            'json', 'xml', 'data', 'ajax', 'fetch'
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in api_indicators)
    
    def _deduplicate_endpoints(self, endpoints: List[APIEndpoint]) -> List[APIEndpoint]:
        """Remove duplicate endpoints."""
        seen = set()
        unique_endpoints = []
        
        for endpoint in endpoints:
            key = (endpoint.url, endpoint.method)
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(endpoint)
                
        return unique_endpoints
    
    def _validate_endpoints(self, endpoints: List[APIEndpoint]) -> List[APIEndpoint]:
        """Validate endpoints by making HTTP requests."""
        validated = []
        
        for endpoint in endpoints:
            try:
                # Make a HEAD request to check if endpoint exists
                response = self.session.head(endpoint.url, timeout=5, allow_redirects=True)
                
                # Update confidence based on response
                if response.status_code < 400:
                    endpoint.confidence = min(endpoint.confidence + 0.2, 1.0)
                    
                    # Check content type for API indicators
                    content_type = response.headers.get('content-type', '').lower()
                    if any(ct in content_type for ct in ['json', 'xml', 'api']):
                        endpoint.confidence = min(endpoint.confidence + 0.1, 1.0)
                        
                validated.append(endpoint)
                
            except requests.RequestException:
                # Keep endpoint but with lower confidence
                endpoint.confidence = max(endpoint.confidence - 0.3, 0.1)
                validated.append(endpoint)
                
            # Rate limiting
            time.sleep(0.1)
            
        return validated
    
    def _discover_authenticated_content(self, html_content: str) -> List[APIEndpoint]:
        """Discover endpoints that are typically only visible when authenticated."""
        endpoints = []
        
        # Only run if we have authentication
        if not self.authenticator or not self.authenticator.authenticated:
            return endpoints
        
        # Look for authenticated-specific patterns
        auth_patterns = [
            r'api[/.].*user.*',
            r'api[/.].*profile.*',
            r'api[/.].*dashboard.*',
            r'api[/.].*admin.*',
            r'api[/.].*settings.*',
            r'api[/.].*account.*',
            r'/user/.*',
            r'/profile/.*',
            r'/dashboard/.*',
            r'/admin/.*',
            # Spond-specific patterns (more comprehensive)
            r'/client/api/[^\'\"\\s]*',
            r'/api/[^\'\"\\s]*spond[^\'\"\\s]*',
            r'/api/[^\'\"\\s]*event[^\'\"\\s]*',
            r'/api/[^\'\"\\s]*group[^\'\"\\s]*',
            r'/api/[^\'\"\\s]*member[^\'\"\\s]*',
            r'/api/[^\'\"\\s]*notification[^\'\"\\s]*',
            r'/api/[^\'\"\\s]*chat[^\'\"\\s]*',
            r'/api/[^\'\"\\s]*message[^\'\"\\s]*',
            r'client/api/[^\'\"\\s]*',
            r'api/sponds[^\'\"\\s]*',
            r'api/events[^\'\"\\s]*',
            r'api/groups[^\'\"\\s]*',
            r'api/users[^\'\"\\s]*'
        ]
        
        for pattern in auth_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(self.base_url, match)
                endpoint = APIEndpoint(
                    url=full_url,
                    source='authenticated_content',
                    confidence=0.8
                )
                endpoints.append(endpoint)
        
        # Look for data-* attributes that might contain authenticated endpoints
        data_attr_pattern = r'data-[a-zA-Z-]*url[a-zA-Z-]*=[\'"]([^\'"]+)[\'"]'
        matches = re.findall(data_attr_pattern, html_content, re.IGNORECASE)
        for match in matches:
            if self._is_potential_endpoint(match):
                full_url = urljoin(self.base_url, match)
                endpoint = APIEndpoint(
                    url=full_url,
                    source='authenticated_data_attr',
                    confidence=0.7
                )
                endpoints.append(endpoint)
        
        return endpoints
    
    def _test_authenticated_endpoints(self, url: str) -> List[APIEndpoint]:
        """Test common authenticated endpoints to discover more APIs."""
        endpoints = []
        session = self.authenticator.session
        
        # Get the base URL
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common authenticated API paths to test
        common_auth_paths = [
            '/client/api/user',
            '/client/api/sponds',
            '/client/api/events',
            '/client/api/groups',
            '/client/api/calendar',
            '/client/api/invitations',
            '/client/api/messages',
            '/api/user',
            '/api/sponds', 
            '/api/events',
            '/api/groups',
            '/api/calendar',
            '/api/invitations',
            '/api/messages',
            '/api/profile',
            '/api/dashboard',
            '/api/settings'
        ]
        
        print("🔍 Testing common authenticated endpoints...")
        
        for path in common_auth_paths:
            try:
                auth_url = urljoin(base_url, path)
                if self.verbose:
                    print(f"  Testing: {auth_url}")
                    
                response = session.get(auth_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    print(f"  ✅ Found: {auth_url} (200 OK)")
                    endpoint = APIEndpoint(
                        url=auth_url,
                        method='GET',
                        source='authenticated_endpoint_test',
                        confidence=0.95
                    )
                    endpoints.append(endpoint)
                    
                    # Also scan the response content for more API references
                    try:
                        content_endpoints = self._discover_from_ajax_calls(response.text)
                        endpoints.extend(content_endpoints)
                    except:
                        pass
                        
                elif response.status_code in [401, 403]:
                    if self.verbose:
                        print(f"  ⚠️  {auth_url} needs different auth ({response.status_code})")
                elif self.verbose:
                    print(f"  ❌ {auth_url} returned {response.status_code}")
                    
            except Exception as e:
                if self.verbose:
                    print(f"  ⚠️  Error testing {auth_url}: {e}")
        
        return endpoints