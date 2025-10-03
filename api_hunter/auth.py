"""Authentication module for API Hunter."""

import requests
import json
import time
from typing import Dict, Optional, Any
from urllib.parse import urljoin, urlparse

class Authenticator:
    """Handle authentication for various services."""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.authenticated = False
        self.auth_cookies = {}
        self.auth_headers = {}
    
    def login_spond_token(self, token: str, base_url: str) -> bool:
        """Login to Spond service using an existing token."""
        try:
            # Set up the authorization header with the Spond token
            self.auth_headers['Authorization'] = f'Bearer {token}'
            self.session.headers.update(self.auth_headers)
            
            # Extract just the domain from the URL for API testing
            from urllib.parse import urlparse
            parsed_url = urlparse(base_url)
            api_base = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            print(f"Testing Spond token authentication against: {api_base}")
            
            # Test the token by making a simple API call
            test_endpoints = [
                '/client/api/user',
                '/client/api/sponds', 
                '/api/user',
                '/api/profile',
                '/api/v1/user',
                '/api/sponds'
            ]
            
            for endpoint in test_endpoints:
                try:
                    test_url = urljoin(api_base, endpoint)
                    response = self.session.get(test_url, timeout=10)
                    
                    # If we get a 200 or 401 (unauthorized), the endpoint exists
                    # 200 means token works, 401 means endpoint exists but token might be invalid
                    if response.status_code in [200, 401]:
                        if response.status_code == 200:
                            print(f"✅ Token authenticated successfully at {test_url}")
                            self.authenticated = True
                            return True
                        elif response.status_code == 401:
                            # Token might be expired, but we found a valid endpoint
                            print(f"❌ Token may be expired (401 at {test_url})")
                            continue
                    else:
                        print(f"🔍 Testing {test_url}: {response.status_code}")
                            
                except requests.RequestException:
                    continue
            
            # If no test endpoints worked, still set as authenticated
            # since the user provided a token
            self.authenticated = True
            return True
            
        except Exception as e:
            print(f"Spond token authentication error: {e}")
            return False
    
    def login_spond(self, username: str, password: str, base_url: str) -> bool:
        """Login to Spond service."""
        try:
            # Spond login typically involves multiple steps
            # First, get the login page to extract any CSRF tokens
            login_url = urljoin(base_url, '/login')
            
            # Try to find the actual login endpoint
            response = self.session.get(login_url)
            if response.status_code == 200:
                # Look for login form or API endpoint
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find login form
                login_form = soup.find('form', {'id': 'loginForm'}) or soup.find('form', action=lambda x: x and 'login' in x.lower())
                
                if login_form:
                    action = login_form.get('action', '/login')
                    login_post_url = urljoin(base_url, action)
                    
                    # Extract CSRF token if present
                    csrf_token = None
                    csrf_input = soup.find('input', {'name': lambda x: x and 'csrf' in x.lower()})
                    if csrf_input:
                        csrf_token = csrf_input.get('value')
                    
                    # Prepare login data
                    login_data = {
                        'username': username,
                        'password': password,
                        'email': username,  # Some services use email field
                    }
                    
                    if csrf_token:
                        # Find the actual CSRF field name
                        csrf_field = csrf_input.get('name')
                        login_data[csrf_field] = csrf_token
                    
                    # Attempt login
                    login_response = self.session.post(login_post_url, data=login_data)
                    
                    # Check if login was successful
                    if login_response.status_code in [200, 302]:
                        # Look for success indicators
                        if 'dashboard' in login_response.url.lower() or 'profile' in login_response.url.lower():
                            self.authenticated = True
                            return True
                        
                        # Check response content for success/failure indicators
                        response_text = login_response.text.lower()
                        if 'welcome' in response_text or 'dashboard' in response_text:
                            self.authenticated = True
                            return True
                        elif 'error' in response_text or 'invalid' in response_text:
                            return False
            
            # Try API-based login (common for modern SPAs)
            api_login_endpoints = [
                '/api/login',
                '/api/auth/login',
                '/api/v1/login',
                '/api/v1/auth/login',
                '/auth/login',
                '/login/api'
            ]
            
            for endpoint in api_login_endpoints:
                try:
                    api_url = urljoin(base_url, endpoint)
                    login_data = {
                        'username': username,
                        'password': password,
                        'email': username
                    }
                    
                    # Try JSON login
                    headers = {'Content-Type': 'application/json'}
                    response = self.session.post(api_url, json=login_data, headers=headers)
                    
                    if response.status_code == 200:
                        try:
                            result = response.json()
                            if 'token' in result or 'access_token' in result or 'success' in result:
                                # Store authentication token if present
                                if 'token' in result:
                                    self.auth_headers['Authorization'] = f"Bearer {result['token']}"
                                elif 'access_token' in result:
                                    self.auth_headers['Authorization'] = f"Bearer {result['access_token']}"
                                
                                self.session.headers.update(self.auth_headers)
                                self.authenticated = True
                                return True
                        except json.JSONDecodeError:
                            pass
                    
                    # Try form-encoded login
                    response = self.session.post(api_url, data=login_data)
                    if response.status_code == 200:
                        self.authenticated = True
                        return True
                        
                except requests.RequestException:
                    continue
                    
        except Exception as e:
            print(f"Login error: {e}")
            
        return False
    
    def login_generic(self, username: str, password: str, base_url: str, 
                     login_endpoint: str = None, additional_data: Dict[str, str] = None) -> bool:
        """Generic login method for various services."""
        try:
            if not login_endpoint:
                # Try to discover login endpoint
                login_endpoints = ['/login', '/api/login', '/auth/login', '/signin']
                for endpoint in login_endpoints:
                    try:
                        test_url = urljoin(base_url, endpoint)
                        response = self.session.get(test_url)
                        if response.status_code == 200:
                            login_endpoint = endpoint
                            break
                    except:
                        continue
            
            if not login_endpoint:
                return False
            
            login_url = urljoin(base_url, login_endpoint)
            
            # Prepare login data
            login_data = {
                'username': username,
                'password': password,
                'email': username
            }
            
            if additional_data:
                login_data.update(additional_data)
            
            # Try JSON login first
            headers = {'Content-Type': 'application/json'}
            response = self.session.post(login_url, json=login_data, headers=headers)
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    if any(key in result for key in ['token', 'access_token', 'success', 'authenticated']):
                        self.authenticated = True
                        return True
                except:
                    pass
            
            # Try form-encoded login
            response = self.session.post(login_url, data=login_data)
            if response.status_code in [200, 302]:
                self.authenticated = True
                return True
                
        except Exception as e:
            print(f"Generic login error: {e}")
            
        return False
    
    def login_with_cookies(self, cookies: Dict[str, str]) -> bool:
        """Login using provided cookies."""
        try:
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
            self.authenticated = True
            return True
        except Exception:
            return False
    
    def login_with_headers(self, headers: Dict[str, str]) -> bool:
        """Login using provided headers (e.g., Authorization token)."""
        try:
            self.session.headers.update(headers)
            self.authenticated = True
            return True
        except Exception:
            return False
    
    def is_authenticated(self) -> bool:
        """Check if currently authenticated."""
        return self.authenticated
    
    def get_session_info(self) -> Dict[str, Any]:
        """Get current session information."""
        return {
            'authenticated': self.authenticated,
            'cookies': dict(self.session.cookies),
            'headers': dict(self.session.headers),
            'auth_headers': self.auth_headers
        }