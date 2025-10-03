"""Reporting and output functionality."""

import json
import csv
from typing import List, Dict
from datetime import datetime
from .core import APIEndpoint

class Reporter:
    """Generate reports from discovered API endpoints."""
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def generate_json_report(self, endpoints: List[APIEndpoint], output_file: str = None) -> str:
        """Generate a JSON report of discovered endpoints."""
        report_data = {
            'timestamp': self.timestamp,
            'total_endpoints': len(endpoints),
            'endpoints': []
        }
        
        for endpoint in endpoints:
            endpoint_data = {
                'url': endpoint.url,
                'method': endpoint.method,
                'parameters': endpoint.parameters,
                'headers': endpoint.headers,
                'source': endpoint.source,
                'confidence': endpoint.confidence
            }
            report_data['endpoints'].append(endpoint_data)
        
        # Sort by confidence (highest first)
        report_data['endpoints'].sort(key=lambda x: x['confidence'], reverse=True)
        
        json_output = json.dumps(report_data, indent=2, ensure_ascii=False)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_output)
                
        return json_output
    
    def generate_csv_report(self, endpoints: List[APIEndpoint], output_file: str = None) -> str:
        """Generate a CSV report of discovered endpoints."""
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['URL', 'Method', 'Parameters', 'Source', 'Confidence', 'Headers'])
        
        # Sort by confidence
        sorted_endpoints = sorted(endpoints, key=lambda x: x.confidence, reverse=True)
        
        for endpoint in sorted_endpoints:
            writer.writerow([
                endpoint.url,
                endpoint.method,
                ', '.join(endpoint.parameters) if endpoint.parameters else '',
                endpoint.source,
                f'{endpoint.confidence:.2f}',
                json.dumps(endpoint.headers) if endpoint.headers else ''
            ])
        
        csv_content = output.getvalue()
        output.close()
        
        if output_file:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                f.write(csv_content)
                
        return csv_content
    
    def generate_html_report(self, endpoints: List[APIEndpoint], target_url: str, output_file: str = None) -> str:
        """Generate an HTML report of discovered endpoints."""
        # Sort by confidence
        sorted_endpoints = sorted(endpoints, key=lambda x: x.confidence, reverse=True)
        
        html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Hunter Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        .summary {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .endpoint {
            border: 1px solid #ddd;
            margin: 15px 0;
            border-radius: 5px;
            padding: 15px;
            background: #fafafa;
        }
        .endpoint-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .method {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 12px;
        }
        .GET { background: #27ae60; color: white; }
        .POST { background: #f39c12; color: white; }
        .PUT { background: #3498db; color: white; }
        .DELETE { background: #e74c3c; color: white; }
        .PATCH { background: #9b59b6; color: white; }
        .confidence {
            font-weight: bold;
        }
        .high-confidence { color: #27ae60; }
        .medium-confidence { color: #f39c12; }
        .low-confidence { color: #e74c3c; }
        .url {
            font-family: 'Courier New', monospace;
            background: #2c3e50;
            color: #ecf0f1;
            padding: 8px;
            border-radius: 3px;
            word-break: break-all;
        }
        .source {
            font-style: italic;
            color: #7f8c8d;
            font-size: 14px;
        }
        .parameters {
            margin-top: 10px;
        }
        .param-tag {
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 2px 6px;
            margin: 2px;
            border-radius: 3px;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 API Hunter Report</h1>
        
        <div class="summary">
            <strong>Target URL:</strong> {target_url}<br>
            <strong>Scan Time:</strong> {timestamp}<br>
            <strong>Total Endpoints Found:</strong> {total_endpoints}
        </div>
        
        <h2>Discovered API Endpoints</h2>
        {endpoints_html}
    </div>
</body>
</html>
        '''
        
        endpoints_html = ''
        for endpoint in sorted_endpoints:
            # Determine confidence class
            if endpoint.confidence >= 0.8:
                confidence_class = 'high-confidence'
            elif endpoint.confidence >= 0.5:
                confidence_class = 'medium-confidence'
            else:
                confidence_class = 'low-confidence'
            
            # Parameters HTML
            params_html = ''
            if endpoint.parameters:
                params_html = '<div class="parameters"><strong>Parameters:</strong> '
                for param in endpoint.parameters:
                    params_html += f'<span class="param-tag">{param}</span>'
                params_html += '</div>'
            
            endpoint_html = f'''
            <div class="endpoint">
                <div class="endpoint-header">
                    <span class="method {endpoint.method}">{endpoint.method}</span>
                    <span class="confidence {confidence_class}">Confidence: {endpoint.confidence:.2f}</span>
                </div>
                <div class="url">{endpoint.url}</div>
                <div class="source">Source: {endpoint.source}</div>
                {params_html}
            </div>
            '''
            endpoints_html += endpoint_html
        
        html_output = html_template.format(
            target_url=target_url,
            timestamp=self.timestamp,
            total_endpoints=len(endpoints),
            endpoints_html=endpoints_html
        )
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_output)
                
        return html_output
    
    def generate_simple_list(self, endpoints: List[APIEndpoint], output_file: str = None) -> str:
        """Generate a simple list of endpoints, one per line."""
        if not endpoints:
            return "No API endpoints discovered."
        
        # Sort by confidence
        sorted_endpoints = sorted(endpoints, key=lambda x: x.confidence, reverse=True)
        
        lines = []
        lines.append(f"# API Endpoints discovered on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"# Total endpoints: {len(endpoints)}")
        lines.append("")
        
        for endpoint in sorted_endpoints:
            lines.append(f"{endpoint.url}")
        
        output = "\n".join(lines)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
        
        return output
    
    def generate_detailed_list(self, endpoints: List[APIEndpoint], target_url: str, output_file: str = None) -> str:
        """Generate a detailed text list with comprehensive endpoint information."""
        if not endpoints:
            return "No API endpoints discovered."
        
        # Sort by confidence
        sorted_endpoints = sorted(endpoints, key=lambda x: x.confidence, reverse=True)
        
        lines = []
        lines.append("=" * 80)
        lines.append(f"API ENDPOINTS DISCOVERY REPORT")
        lines.append("=" * 80)
        lines.append(f"Target URL: {target_url}")
        lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Endpoints Found: {len(endpoints)}")
        lines.append("=" * 80)
        lines.append("")
        
        # Group by confidence level
        high_conf = [e for e in sorted_endpoints if e.confidence >= 0.8]
        medium_conf = [e for e in sorted_endpoints if 0.5 <= e.confidence < 0.8]
        low_conf = [e for e in sorted_endpoints if e.confidence < 0.5]
        
        def add_endpoint_section(title, endpoints_list, emoji):
            if endpoints_list:
                lines.append(f"{emoji} {title} ({len(endpoints_list)} endpoints)")
                lines.append("-" * 60)
                
                for i, endpoint in enumerate(endpoints_list, 1):
                    lines.append(f"{i:2d}. URL: {endpoint.url}")
                    lines.append(f"    Method: {endpoint.method}")
                    lines.append(f"    Source: {endpoint.source}")
                    lines.append(f"    Confidence: {endpoint.confidence:.2f}")
                    
                    if endpoint.parameters:
                        lines.append(f"    Parameters: {', '.join(endpoint.parameters)}")
                    
                    if endpoint.headers:
                        lines.append(f"    Headers: {endpoint.headers}")
                    
                    lines.append("")
                
                lines.append("")
        
        add_endpoint_section("HIGH CONFIDENCE ENDPOINTS", high_conf, "🟢")
        add_endpoint_section("MEDIUM CONFIDENCE ENDPOINTS", medium_conf, "🟡")
        add_endpoint_section("LOW CONFIDENCE ENDPOINTS", low_conf, "🟠")
        
        # Summary
        lines.append("=" * 80)
        lines.append("SUMMARY")
        lines.append("=" * 80)
        lines.append(f"High Confidence: {len(high_conf)} endpoints")
        lines.append(f"Medium Confidence: {len(medium_conf)} endpoints")
        lines.append(f"Low Confidence: {len(low_conf)} endpoints")
        lines.append(f"Total: {len(endpoints)} endpoints")
        lines.append("=" * 80)
        
        output = "\n".join(lines)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
        
        return output
    
    def generate_console_report(self, endpoints: List[APIEndpoint]) -> str:
        """Generate a console-friendly report."""
        if not endpoints:
            return "No API endpoints discovered."
        
        # Sort by confidence
        sorted_endpoints = sorted(endpoints, key=lambda x: x.confidence, reverse=True)
        
        output = []
        output.append(f"\\n🔍 API Hunter Results ({len(endpoints)} endpoints found)")
        output.append("=" * 60)
        
        # Group by confidence level
        high_conf = [e for e in sorted_endpoints if e.confidence >= 0.8]
        medium_conf = [e for e in sorted_endpoints if 0.5 <= e.confidence < 0.8]
        low_conf = [e for e in sorted_endpoints if e.confidence < 0.5]
        
        if high_conf:
            output.append("\\n🟢 HIGH CONFIDENCE ENDPOINTS:")
            for endpoint in high_conf:
                output.append(f"  [{endpoint.method}] {endpoint.url}")
                output.append(f"      Source: {endpoint.source} | Confidence: {endpoint.confidence:.2f}")
                if endpoint.parameters:
                    output.append(f"      Parameters: {', '.join(endpoint.parameters)}")
        
        if medium_conf:
            output.append("\\n🟡 MEDIUM CONFIDENCE ENDPOINTS:")
            for endpoint in medium_conf:
                output.append(f"  [{endpoint.method}] {endpoint.url}")
                output.append(f"      Source: {endpoint.source} | Confidence: {endpoint.confidence:.2f}")
        
        if low_conf:
            output.append("\\n🟠 LOW CONFIDENCE ENDPOINTS:")
            for endpoint in low_conf:
                output.append(f"  [{endpoint.method}] {endpoint.url}")
                output.append(f"      Source: {endpoint.source} | Confidence: {endpoint.confidence:.2f}")
        
        output.append("\\n" + "=" * 60)
        output.append(f"Summary: {len(high_conf)} high, {len(medium_conf)} medium, {len(low_conf)} low confidence")
        
        return "\\n".join(output)