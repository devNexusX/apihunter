# API Hunter 🕷️

A powerful Python tool for discovering API endpoints from web pages. API Hunter analyzes web pages, JavaScript code, HTML forms, and various web resources to identify potential API endpoints that applications use.

## ⚠️ IMPORTANT LEGAL AND ETHICAL NOTICE ⚠️

**PLEASE READ CAREFULLY BEFORE USING THIS TOOL**

### Legal Compliance and Best Practices

This tool is intended for **legitimate security research, penetration testing, and authorized web application analysis ONLY**. Users are solely responsible for ensuring their use complies with all applicable laws, regulations, and terms of service.

**MANDATORY REQUIREMENTS:**

1. **Authorization Required**: Only use this tool on systems you own, have explicit written permission to test, or are part of authorized security assessments
2. **Respect robots.txt**: Always check and honor robots.txt directives - this tool checks robots.txt but does not enforce restrictions
3. **Follow Rate Limits**: Use appropriate delays and respect server resources to avoid overwhelming target systems
4. **Terms of Service**: Ensure compliance with target website's Terms of Service, Privacy Policy, and API usage guidelines
5. **Data Privacy**: Handle any discovered data responsibly and in accordance with privacy laws (GDPR, CCPA, etc.)

**PROHIBITED USES:**

- ❌ Unauthorized scanning of systems you don't own or have permission to test
- ❌ Violating website Terms of Service or robots.txt directives
- ❌ Excessive requests that could cause denial of service
- ❌ Harvesting private or sensitive information
- ❌ Any illegal or malicious activities

**BEST PRACTICES:**

- ✅ Always obtain proper authorization before scanning
- ✅ Review and respect robots.txt files
- ✅ Use reasonable timeouts and delays
- ✅ Limit scan scope to necessary endpoints
- ✅ Document your authorization and testing scope
- ✅ Report findings through proper security channels
- ✅ Follow responsible disclosure practices

**DISCLAIMER**: The developers of API Hunter are not responsible for any misuse of this tool. By using this software, you acknowledge that you understand and will comply with all applicable laws and ethical guidelines.

## Features

- **Web Page Analysis**: Scans HTML, JavaScript, and CSS for API endpoint references
- **Multiple Discovery Methods**: 
  - HTML link analysis
  - JavaScript code parsing (fetch, XMLHttpRequest, axios, etc.)
  - Form action analysis
  - Meta tag and data attribute scanning
  - HTML/JS comment analysis
- **Advanced Scanning**:
  - Common API path discovery (`/api`, `/rest`, `/graphql`, etc.)
  - robots.txt analysis
  - Sitemap.xml parsing
  - Swagger/OpenAPI documentation discovery
- **Multiple Output Formats**: Console, JSON, CSV, HTML, simple lists, and detailed reports
- **Confidence Scoring**: Each discovered endpoint gets a confidence score
- **Concurrent Scanning**: Multi-threaded scanning for better performance

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/apiHunter.git
cd apiHunter
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## 🛡️ Pre-Scan Safety Checklist

**Before running any scans, ensure you have:**

- [ ] **Authorization**: Written permission to scan the target system
- [ ] **Legal Review**: Confirmed compliance with local cybersecurity laws
- [ ] **robots.txt Check**: Reviewed and will respect robots.txt directives
- [ ] **ToS Compliance**: Read and understood target website's Terms of Service
- [ ] **Scope Definition**: Clear boundaries on what you're authorized to scan
- [ ] **Rate Limiting**: Plan to use appropriate delays and timeouts
- [ ] **Documentation**: Ready to document findings responsibly

**If you cannot check all boxes above, DO NOT proceed with scanning.**

## Usage

> **⚠️ WARNING**: Only scan systems you own or have explicit written authorization to test. Unauthorized scanning may violate laws and terms of service. Always check robots.txt and respect rate limits.

### Basic Usage

```bash
# Scan a website for API endpoints
python main.py https://example.com

# Save results to JSON file
python main.py https://example.com --output report.json --format json

# Generate HTML report
python main.py https://example.com --format html --output report.html
```

### File Output Options

```bash
# Auto-save with timestamp (creates files in 'extracts/' folder)
python main.py https://example.com --auto-save --format json

# Save simple endpoint list (one URL per line) - domain automatically added to filename
python main.py https://example.com --format list --output endpoints.txt
# Creates: extracts/endpoints_example_com.txt

# Save detailed report with comprehensive endpoint information
python main.py https://example.com --format detailed --auto-save
# Creates: extracts/api_detailed_example_com_YYYYMMDD_HHMMSS.txt

# Comprehensive Spond scan with detailed auto-save
python main.py https://spond.com --spond-token your_token --auto-save --format detailed --scan-common-paths
```

### Authentication Support

```bash
# Login with username/password (Spond-specific)
python main.py https://spond.com --username user@email.com --password mypass --login-type spond

# Generic login
python main.py https://example.com --username user --password pass --login-type generic

# Use existing cookies
python main.py https://example.com --cookies '{"session_id": "abc123", "auth_token": "xyz789"}'

# Use authentication headers
python main.py https://api.example.com --auth-headers '{"Authorization": "Bearer your_token_here"}'
```

### Advanced Options

```bash
# Comprehensive scan with all features
python main.py https://example.com \\
    --scan-common-paths \\
    --include-swagger \\
    --verbose \\
    --confidence-threshold 0.7 \\
    --timeout 60

# Filter results by confidence level
python main.py https://example.com --confidence-threshold 0.8
```

### Command Line Options

- `url`: Target URL to scan (required)
- `--output, -o`: Output file path
- `--format, -f`: Output format (`console`, `json`, `csv`, `html`)
- `--timeout, -t`: Request timeout in seconds (default: 30)
- `--scan-common-paths`: Scan common API paths
- `--include-swagger`: Look for Swagger/OpenAPI docs
- `--verbose, -v`: Enable verbose output
- `--confidence-threshold`: Minimum confidence threshold (0.0-1.0)
- `--username, -u`: Username for authentication
- `--password, -p`: Password for authentication
- `--login-type`: Type of login (spond, generic)
- `--login-endpoint`: Custom login endpoint
- `--cookies`: Authentication cookies (JSON format)
- `--auth-headers`: Authentication headers (JSON format)\n- `--spond-token`: Spond authentication token for direct token-based login

## Example Output

```
🔍 API Hunter Results (12 endpoints found)
============================================================

🟢 HIGH CONFIDENCE ENDPOINTS:
  [GET] https://example.com/api/v1/users
      Source: swagger_spec | Confidence: 1.00
  [POST] https://example.com/api/v1/auth/login
      Source: javascript | Confidence: 0.90

🟡 MEDIUM CONFIDENCE ENDPOINTS:
  [GET] https://example.com/api/data.json
      Source: html_link | Confidence: 0.70

🟠 LOW CONFIDENCE ENDPOINTS:
  [GET] https://example.com/api/legacy
      Source: comment | Confidence: 0.40

============================================================
Summary: 2 high, 1 medium, 1 low confidence
```

## API Usage

You can also use API Hunter programmatically:

```python
from api_hunter import APIDiscovery, EndpointScanner, Reporter

# Initialize discovery
discovery = APIDiscovery("https://example.com")

# Discover endpoints
endpoints = discovery.discover_endpoints()

# Use advanced scanner
scanner = EndpointScanner()
additional_endpoints = scanner.scan_common_paths("https://example.com", discovery.session)

# Generate reports
reporter = Reporter()
json_report = reporter.generate_json_report(endpoints)
html_report = reporter.generate_html_report(endpoints, "https://example.com")
```

## Discovery Methods

### 1. HTML Analysis
- Scans `<a>` tags for API-like URLs
- Analyzes `<form>` actions and methods
- Checks meta tags and data attributes

### 2. JavaScript Analysis
- Parses JavaScript for `fetch()` calls
- Detects `XMLHttpRequest` usage
- Finds axios/jQuery AJAX calls
- Extracts API URLs from variable assignments

### 3. Advanced Scanning
- Tests common API paths (`/api`, `/rest`, `/graphql`)
- Analyzes `robots.txt` for restricted API paths
- Parses `sitemap.xml` for structured URLs
- Discovers Swagger/OpenAPI documentation

### 4. Comment Analysis
- Searches HTML and JavaScript comments
- Extracts URLs and API references from developer comments

## Confidence Scoring

Each discovered endpoint receives a confidence score (0.0-1.0):

- **1.0**: Confirmed API endpoint (e.g., from Swagger spec)
- **0.8-0.9**: High confidence (e.g., JavaScript fetch calls)
- **0.6-0.7**: Medium confidence (e.g., HTML links to JSON)
- **0.4-0.5**: Lower confidence (e.g., found in comments)
- **< 0.4**: Low confidence (speculative matches)

## Output Formats

### Console
Human-readable output with color coding and confidence levels.

### JSON
Structured data format perfect for integration with other tools:
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "total_endpoints": 5,
  "endpoints": [
    {
      "url": "https://example.com/api/users",
      "method": "GET",
      "parameters": ["id", "name"],
      "source": "javascript",
      "confidence": 0.9
    }
  ]
}
```

### CSV
Spreadsheet-compatible format for analysis and reporting.

### HTML
Rich visual report with styling, confidence indicators, and detailed endpoint information.

## Responsible Scanning Practices

### Before You Scan

1. **Check Authorization**
   - Ensure you have explicit permission to scan the target
   - Verify you're authorized by the website owner or as part of a legitimate security assessment
   - Document your authorization scope and limitations

2. **Review robots.txt**
   ```bash
   curl https://example.com/robots.txt
   ```
   - API Hunter checks robots.txt but does not enforce restrictions
   - Respect User-agent directives and Disallow rules
   - Honor Crawl-delay specifications

3. **Check Terms of Service**
   - Review the target website's Terms of Service
   - Look for API usage policies and rate limits
   - Ensure your scanning activity is permitted

### During Scanning

4. **Use Appropriate Timeouts**
   ```bash
   # Use longer timeouts for slower servers
   python main.py https://example.com --timeout 60
   ```

5. **Respect Rate Limits**
   - The tool includes built-in delays between requests
   - Monitor server response times and adjust if needed
   - Stop if you receive 429 (Too Many Requests) responses

6. **Minimize Impact**
   - Scan only what's necessary for your assessment
   - Use `--confidence-threshold` to filter results
   - Avoid repeated scans of the same target

### Legal Compliance Framework

- **Authorization**: Always have explicit permission
- **Scope**: Stay within defined boundaries
- **Documentation**: Keep records of permissions and findings
- **Reporting**: Use proper disclosure channels for vulnerabilities
- **Data Handling**: Protect any sensitive information discovered

### International Legal Considerations

- **United States**: Comply with Computer Fraud and Abuse Act (CFAA)
- **European Union**: Follow GDPR and national cybersecurity laws
- **United Kingdom**: Adhere to Computer Misuse Act 1990
- **Australia**: Comply with Cybercrime Act 2001
- **Other Jurisdictions**: Research local cybersecurity and computer crime laws

**Remember**: Laws vary by jurisdiction. When in doubt, consult legal counsel.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Legal Disclaimer

**READ CAREFULLY - BY USING THIS SOFTWARE, YOU AGREE TO THESE TERMS**

This software (API Hunter) is provided "as is" for educational, research, and authorized security testing purposes only. 

### User Responsibilities

- **You are solely responsible** for ensuring your use of this tool complies with all applicable laws, regulations, and terms of service
- **You must obtain proper authorization** before scanning any systems you do not own
- **You must respect** robots.txt files, rate limits, and website terms of service
- **You assume all legal liability** for your use of this tool

### Prohibited Uses

This tool must NOT be used for:
- Unauthorized access or scanning of systems
- Violating website terms of service or robots.txt
- Denial of service attacks or excessive requests
- Harvesting private or confidential information
- Any illegal activities under applicable law

### No Warranty

The developers provide no warranties regarding:
- Legal compliance of your use
- Accuracy or completeness of results
- Fitness for any particular purpose
- Freedom from errors or security vulnerabilities

### Limitation of Liability

The developers shall not be liable for any damages, legal issues, or consequences resulting from use or misuse of this software, including but not limited to legal action, fines, or criminal charges.

### Indemnification

You agree to indemnify and hold harmless the developers from any claims, damages, or legal actions resulting from your use of this software.

**By using this software, you acknowledge that you have read, understood, and agree to comply with these terms and all applicable laws.**