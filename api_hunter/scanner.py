"""Endpoint scanning utilities."""

import re
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set
from .core import APIEndpoint

class EndpointScanner:
    """Advanced scanner for discovering API endpoints."""
    
    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        
        # Common API file extensions and patterns
        self.api_extensions = ['.json', '.xml', '.api', '.rest', '.graphql']
        self.common_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/endpoints', '/services', '/data', '/ajax',
            # Spond-specific paths
            '/client/api', '/client/api/sponds', '/client/api/events',
            '/client/api/groups', '/client/api/user', '/client/api/notifications'
        ]
        
    def scan_common_paths(self, base_url: str, session) -> List[APIEndpoint]:
        """Scan common API paths."""
        endpoints = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for path in self.common_paths:
                url = base_url.rstrip('/') + path
                future = executor.submit(self._test_endpoint, url, session)
                futures.append(future)
                
            for future in as_completed(futures):
                result = future.result()
                if result:
                    endpoints.append(result)
                    
        return endpoints
    
    def scan_robots_txt(self, base_url: str, session) -> List[APIEndpoint]:
        """Scan robots.txt for potential API paths."""
        endpoints = []
        robots_url = base_url.rstrip('/') + '/robots.txt'
        
        try:
            response = session.get(robots_url, timeout=5)
            if response.status_code == 200:
                lines = response.text.split('\\n')
                for line in lines:
                    if line.strip().startswith('Disallow:') or line.strip().startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if self._looks_like_api_path(path):
                            full_url = base_url.rstrip('/') + path
                            endpoint = APIEndpoint(
                                url=full_url,
                                source='robots_txt',
                                confidence=0.6
                            )
                            endpoints.append(endpoint)
        except:
            pass
            
        return endpoints
    
    def scan_sitemap(self, base_url: str, session) -> List[APIEndpoint]:
        """Scan sitemap.xml for API endpoints."""
        endpoints = []
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemaps/sitemap.xml'
        ]
        
        for sitemap_path in sitemap_urls:
            sitemap_url = base_url.rstrip('/') + sitemap_path
            try:
                response = session.get(sitemap_url, timeout=5)
                if response.status_code == 200:
                    # Parse XML and look for API-like URLs
                    import xml.etree.ElementTree as ET
                    try:
                        root = ET.fromstring(response.text)
                        for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                            loc_elem = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                            if loc_elem is not None and loc_elem.text:
                                if self._looks_like_api_path(loc_elem.text):
                                    endpoint = APIEndpoint(
                                        url=loc_elem.text,
                                        source='sitemap',
                                        confidence=0.7
                                    )
                                    endpoints.append(endpoint)
                    except ET.ParseError:
                        pass
            except:
                continue
                
        return endpoints
    
    def discover_swagger_docs(self, base_url: str, session) -> List[APIEndpoint]:
        """Discover Swagger/OpenAPI documentation endpoints."""
        endpoints = []
        swagger_paths = [
            '/swagger.json',
            '/swagger.yaml',
            '/api-docs',
            '/api-docs.json',
            '/openapi.json',
            '/openapi.yaml',
            '/v1/api-docs',
            '/v2/api-docs',
            '/swagger/v1/swagger.json',
            '/swagger-ui.html',
            '/docs'
        ]
        
        for path in swagger_paths:
            url = base_url.rstrip('/') + path
            try:
                response = session.get(url, timeout=5)
                if response.status_code == 200:
                    endpoint = APIEndpoint(
                        url=url,
                        source='swagger_docs',
                        confidence=0.9
                    )
                    endpoints.append(endpoint)
                    
                    # If it's a JSON swagger doc, parse it for more endpoints
                    if 'json' in path and response.headers.get('content-type', '').startswith('application/json'):
                        try:
                            swagger_data = response.json()
                            if 'paths' in swagger_data:
                                base_path = swagger_data.get('basePath', '')
                                for path_key in swagger_data['paths']:
                                    api_url = base_url.rstrip('/') + base_path + path_key
                                    for method in swagger_data['paths'][path_key]:
                                        endpoint = APIEndpoint(
                                            url=api_url,
                                            method=method.upper(),
                                            source='swagger_spec',
                                            confidence=1.0
                                        )
                                        endpoints.append(endpoint)
                        except (json.JSONDecodeError, KeyError):
                            pass
            except:
                continue
                
        return endpoints
    
    def _test_endpoint(self, url: str, session) -> APIEndpoint:
        """Test if an endpoint exists and returns API-like content."""
        try:
            response = session.head(url, timeout=3, allow_redirects=True)
            if response.status_code < 400:
                content_type = response.headers.get('content-type', '').lower()
                
                confidence = 0.5
                if any(ct in content_type for ct in ['json', 'xml', 'api']):
                    confidence = 0.8
                    
                return APIEndpoint(
                    url=url,
                    source='path_scan',
                    confidence=confidence
                )
        except:
            pass
        return None
    
    def _looks_like_api_path(self, path: str) -> bool:
        """Check if a path looks like it could be an API endpoint."""
        api_indicators = [
            'api', 'rest', 'graphql', 'endpoint', 'service',
            'json', 'xml', 'data', 'ajax', 'fetch', 'webhook'
        ]
        
        path_lower = path.lower()
        return any(indicator in path_lower for indicator in api_indicators)