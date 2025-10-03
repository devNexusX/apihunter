#!/usr/bin/env python3
"""
API Hunter - Command Line Interface
A tool for discovering API endpoints from web pages
"""

import argparse
import sys
import requests
from pathlib import Path

from api_hunter import APIDiscovery, EndpointScanner, Reporter, Authenticator

def main():
    parser = argparse.ArgumentParser(
        description='API Hunter - Discover API endpoints from web pages',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s https://example.com
  %(prog)s https://api.example.com --output report.json
  %(prog)s https://example.com --format html --output report.html
  %(prog)s https://example.com --scan-common-paths --timeout 60 --auto-save
  %(prog)s https://example.com --format detailed --auto-save
  %(prog)s https://spond.com --username user@email.com --password mypass --login-type spond
  %(prog)s https://spond.com --spond-token your_spond_token_here
  %(prog)s https://example.com --cookies '{"session_id": "abc123"}'
  %(prog)s https://api.example.com --auth-headers '{"Authorization": "Bearer token123"}''
        '''
    )
    
    # Required arguments
    parser.add_argument('url', help='Target URL to scan for API endpoints')
    
    # Optional arguments
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: print to console)'
    )
    
    parser.add_argument(
        '--auto-save',
        action='store_true',
        help='Automatically save results to timestamped file'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['console', 'json', 'csv', 'html', 'list', 'detailed'],
        default='console',
        help='Output format (default: console). "list" saves simple URLs, "detailed" saves comprehensive info'
    )
    
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--scan-common-paths',
        action='store_true',
        help='Also scan common API paths like /api, /rest, etc.'
    )
    
    parser.add_argument(
        '--include-swagger',
        action='store_true',
        help='Look for Swagger/OpenAPI documentation'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--confidence-threshold',
        type=float,
        default=0.0,
        help='Minimum confidence threshold (0.0-1.0, default: 0.0)'
    )
    
    # Authentication arguments
    auth_group = parser.add_argument_group('Authentication options')
    auth_group.add_argument(
        '--username', '-u',
        help='Username for authentication'
    )
    
    auth_group.add_argument(
        '--password', '-p',
        help='Password for authentication'
    )
    
    auth_group.add_argument(
        '--login-type',
        choices=['spond', 'generic'],
        default='generic',
        help='Type of login to use (default: generic)'
    )
    
    auth_group.add_argument(
        '--login-endpoint',
        help='Custom login endpoint (for generic login)'
    )
    
    auth_group.add_argument(
        '--cookies',
        help='Cookies for authentication (JSON format: {"name": "value"})'
    )
    
    auth_group.add_argument(
        '--auth-headers',
        help='Authentication headers (JSON format: {"Authorization": "Bearer token"})'
    )
    
    auth_group.add_argument(
        '--spond-token',
        help='Spond authentication token for direct token-based login'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://", file=sys.stderr)
        return 1
    
    if args.confidence_threshold < 0.0 or args.confidence_threshold > 1.0:
        print("Error: Confidence threshold must be between 0.0 and 1.0", file=sys.stderr)
        return 1
    
    try:
        # Initialize discovery
        if args.verbose:
            print(f"🔍 Starting API discovery for: {args.url}")
            print(f"⚙️  Timeout: {args.timeout}s")
            print(f"📊 Confidence threshold: {args.confidence_threshold}")
        
        # Initialize authenticator
        authenticator = None
        
        # Handle Spond token authentication
        if args.spond_token:
            if args.verbose:
                print("🔐 Attempting Spond token authentication...")
            
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'APIHunter/1.0 (API Discovery Tool)'
            })
            
            authenticator = Authenticator(session)
            login_success = authenticator.login_spond_token(args.spond_token, args.url)
            
            if login_success:
                if args.verbose:
                    print("✅ Spond token authentication successful!")
            else:
                if args.verbose:
                    print("❌ Spond token authentication failed, continuing without authentication...")
                authenticator = None
        
        # Handle authentication if credentials provided
        elif args.username and args.password:
            if args.verbose:
                print(f"🔐 Attempting {args.login_type} login...")
            
            # Create a session for authentication
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'APIHunter/1.0 (API Discovery Tool)'
            })
            
            authenticator = Authenticator(session)
            
            if args.login_type == 'spond':
                login_success = authenticator.login_spond(args.username, args.password, args.url)
            else:
                additional_data = {}
                login_success = authenticator.login_generic(
                    args.username, args.password, args.url, 
                    args.login_endpoint, additional_data
                )
            
            if login_success:
                if args.verbose:
                    print("✅ Login successful!")
            else:
                if args.verbose:
                    print("❌ Login failed, continuing without authentication...")
                authenticator = None
        
        # Handle cookie-based authentication
        elif args.cookies:
            try:
                import json
                cookies = json.loads(args.cookies)
                session = requests.Session()
                authenticator = Authenticator(session)
                if authenticator.login_with_cookies(cookies):
                    if args.verbose:
                        print("✅ Cookie authentication successful!")
                else:
                    authenticator = None
            except json.JSONDecodeError:
                print("❌ Invalid cookies JSON format")
                return 1
        
        # Handle header-based authentication
        elif args.auth_headers:
            try:
                import json
                headers = json.loads(args.auth_headers)
                session = requests.Session()
                authenticator = Authenticator(session)
                if authenticator.login_with_headers(headers):
                    if args.verbose:
                        print("✅ Header authentication successful!")
                else:
                    authenticator = None
            except json.JSONDecodeError:
                print("❌ Invalid headers JSON format")
                return 1
        
        discovery = APIDiscovery(args.url, timeout=args.timeout, authenticator=authenticator, verbose=args.verbose)
        
        # Main discovery
        if args.verbose:
            print("🕷️  Scanning web page...")
        endpoints = discovery.discover_endpoints()
        
        # Additional scanning methods
        scanner = EndpointScanner()
        
        if args.scan_common_paths:
            if args.verbose:
                print("🔎 Scanning common API paths...")
            common_endpoints = scanner.scan_common_paths(args.url, discovery.session)
            endpoints.extend(common_endpoints)
        
        if args.include_swagger:
            if args.verbose:
                print("📚 Looking for Swagger documentation...")
            swagger_endpoints = scanner.discover_swagger_docs(args.url, discovery.session)
            endpoints.extend(swagger_endpoints)
        
        # Additional scans
        if args.verbose:
            print("🤖 Checking robots.txt...")
        robots_endpoints = scanner.scan_robots_txt(args.url, discovery.session)
        endpoints.extend(robots_endpoints)
        
        if args.verbose:
            print("🗺️  Checking sitemap...")
        sitemap_endpoints = scanner.scan_sitemap(args.url, discovery.session)
        endpoints.extend(sitemap_endpoints)
        
        # Remove duplicates and filter by confidence
        unique_endpoints = discovery._deduplicate_endpoints(endpoints)
        filtered_endpoints = [
            ep for ep in unique_endpoints 
            if ep.confidence >= args.confidence_threshold
        ]
        
        if args.verbose:
            print(f"✅ Discovery complete! Found {len(filtered_endpoints)} endpoints")
        
        # Auto-save functionality and filename enhancement
        output_file = args.output
        
        # Extract domain for filename generation
        from datetime import datetime
        from urllib.parse import urlparse
        parsed_url = urlparse(args.url)
        domain = parsed_url.netloc.replace(':', '_').replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create extracts folder if it doesn't exist
        import os
        extracts_dir = "extracts"
        if not os.path.exists(extracts_dir):
            os.makedirs(extracts_dir)
        
        # If user provided output file, enhance it with domain if not already included
        if output_file and domain not in output_file:
            # Split filename and extension
            from pathlib import Path
            path = Path(output_file)
            stem = path.stem
            suffix = path.suffix
            
            # Add domain to filename and move to extracts folder
            output_file = os.path.join(extracts_dir, f"{stem}_{domain}{suffix}")
        
        # Auto-save functionality
        if args.auto_save and not args.output:
            
            if args.format == 'json':
                output_file = os.path.join(extracts_dir, f"api_endpoints_{domain}_{timestamp}.json")
            elif args.format == 'csv':
                output_file = os.path.join(extracts_dir, f"api_endpoints_{domain}_{timestamp}.csv")
            elif args.format == 'html':
                output_file = os.path.join(extracts_dir, f"api_endpoints_{domain}_{timestamp}.html")
            elif args.format == 'list':
                output_file = os.path.join(extracts_dir, f"api_endpoints_{domain}_{timestamp}.txt")
            elif args.format == 'detailed':
                output_file = os.path.join(extracts_dir, f"api_detailed_{domain}_{timestamp}.txt")
            else:
                output_file = os.path.join(extracts_dir, f"api_endpoints_{domain}_{timestamp}.txt")
        
        # Generate report
        reporter = Reporter()
        
        if args.format == 'console':
            output = reporter.generate_console_report(filtered_endpoints)
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"Report saved to: {output_file}")
                print(output)  # Also display on console
            else:
                print(output)
                
        elif args.format == 'json':
            output = reporter.generate_json_report(filtered_endpoints, output_file)
            if output_file:
                print(f"JSON report saved to: {output_file}")
            else:
                print(output)
                
        elif args.format == 'csv':
            output = reporter.generate_csv_report(filtered_endpoints, output_file)
            if output_file:
                print(f"CSV report saved to: {output_file}")
            else:
                print(output)
                
        elif args.format == 'html':
            output = reporter.generate_html_report(filtered_endpoints, args.url, output_file)
            if output_file:
                print(f"HTML report saved to: {output_file}")
            else:
                # For HTML without output file, create a temporary file
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                    f.write(output)
                    temp_path = f.name
                print(f"HTML report created: {temp_path}")
                
        elif args.format == 'list':
            output = reporter.generate_simple_list(filtered_endpoints, output_file)
            if output_file:
                print(f"Endpoint list saved to: {output_file}")
            else:
                print(output)
                
        elif args.format == 'detailed':
            output = reporter.generate_detailed_list(filtered_endpoints, args.url, output_file)
            if output_file:
                print(f"Detailed endpoint report saved to: {output_file}")
            else:
                print(output)
        
        return 0
        
    except KeyboardInterrupt:
        print("\\n❌ Scan interrupted by user", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"❌ Error during scan: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())