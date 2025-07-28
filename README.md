# Web Vulnerability Scanner

A modular and extensible web vulnerability scanner designed to identify common security issues in web applications.

## Features

- **Modular Architecture**: Easily add new vulnerability detection plugins
- **Multi-threaded Crawler**: Efficiently discover and scan pages within websites
- **Graceful Interrupt Handling**: Stop scans cleanly with Ctrl+C without hanging processes
- **Enhanced Timeout Management**: Configurable timeouts for slow or unreachable targets
- **Connectivity Diagnostics**: Built-in tools to test target accessibility before scanning
- **Anti-Blocking Measures**: User-agent rotation and randomized delays to avoid detection
- **Cross-Platform Compatibility**: Works seamlessly on Windows, Linux, and macOS
- **Professional Reporting**: Domain-based report naming with multiple output formats
- **Host Safety Protection**: Comprehensive security measures to protect your machine during scans
- **Network Safety Validation**: Blocks localhost and private network scanning to prevent accidents
- **Resource Monitoring**: Built-in limits for memory, CPU, and thread usage
- **Comprehensive Detection**: Find common web vulnerabilities including:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Directory Traversal
  - Open Redirect Vulnerabilities
  - Security Header Misconfiguration
- **Configurable**: Customize scanning behavior through YAML configuration files
- **Multiple Report Formats**: Export findings as JSON, HTML, or to SQLite database
- **Command-Line Interface**: Easy to use from the terminal or integrate into CI/CD pipelines

## Installation

### Prerequisites

- Python 3.8+
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone https://github.com/alwalid54321/webvuln-scanner.git
cd webvuln-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Scanning

Scan a website for vulnerabilities:

```bash
python console.py https://example.com
```

### Advanced Options

```bash
# Specify configuration file
python console.py https://example.com -c configs/custom.yaml

# Set crawl depth
python console.py https://example.com -d 5

# Limit number of URLs to scan
python console.py https://example.com -u 200

# Change number of crawler threads
python console.py https://example.com -t 10

# Select specific plugins
python console.py https://example.com -p sql_injection,xss,open_redirect

# Exclude specific plugins
python console.py https://example.com -x security_headers

# Ignore robots.txt
python console.py https://example.com --no-robots

# Configure timeout for slow targets
python console.py https://example.com --timeout 60

# Test connectivity before scanning
python test_connectivity.py https://example.com

# Control request rate (delay in seconds)
python console.py https://example.com --delay 1.0

# Enable verbose output
python console.py https://example.com -v
```

### List Available Plugins

```bash
python console.py --list-plugins
```

### Troubleshooting

### Connection Issues

If you encounter connection timeouts or unreachable targets:

```bash
# Test target connectivity first
python test_connectivity.py https://target.com

# Use enhanced settings for problematic targets
python console.py -u https://target.com --timeout 60 --delay 2.0 --threads 1
```

### Stopping Scans

The scanner supports graceful interruption:

- **Press Ctrl+C** to stop a running scan cleanly
- All threads will terminate gracefully
- Partial results will be saved to reports
- No hanging processes or incomplete states

### Windows Compatibility

The scanner is fully compatible with Windows systems:

- No Unicode/emoji display issues
- Proper console output formatting
- Cross-platform file path handling
- PowerShell and Command Prompt support

### Host Safety

The scanner includes comprehensive safety measures to protect your machine:

```bash
# Safe scanning - only external targets allowed
python console.py -u https://example.com --verbose

# These will be blocked for your safety:
# python console.py -u http://localhost:8080      # Localhost blocked
# python console.py -u http://192.168.1.1        # Private network blocked
# python console.py -u file:///etc/passwd        # File scheme blocked
```

**Safety Features:**
- ✅ Blocks localhost and private network scanning
- ✅ Validates all URLs before requests
- ✅ Restricts file writes to reports directory only
- ✅ Monitors resource usage (memory, CPU, threads)
- ✅ Input sanitization to prevent injection attacks
- ✅ No shell command execution or code evaluation

**What the scanner CANNOT do:**
- ❌ Access your local files or system
- ❌ Modify system settings or configurations
- ❌ Execute shell commands or install software
- ❌ Scan localhost or internal networks
- ❌ Write files outside the reports directory

See [HOST_SAFETY.md](docs/HOST_SAFETY.md) for complete security details.

## Configuration

The scanner can be configured using YAML configuration files. Create a `config.yaml` file:

- `configs/default.yaml`: Default configuration
- `configs/payloads.yaml`: Attack payloads used by plugins

You can create custom configuration files based on these templates.

## Project Structure

```
webvuln-scanner/
│
├── scanner/             # Core scanner components
│   ├── __init__.py
│   ├── crawler.py       # URL discovery and crawling
│   ├── http_client.py   # HTTP request handling
│   ├── parser.py        # HTML parsing and extraction
│   └── reporter.py      # Findings and reporting
│
├── plugins/             # Vulnerability detection plugins
│   ├── __init__.py
│   ├── base.py          # Abstract plugin class
│   ├── sql_injection.py
│   ├── xss.py
│   ├── directory_traversal.py
│   ├── open_redirect.py
│   └── security_headers.py
│
├── configs/             # Configuration files
│   ├── default.yaml
│   └── payloads.yaml
│
├── reports/             # Generated scan reports (created at runtime)
│
├── tests/               # Unit and integration tests
│
├── console.py           # Command-line interface
└── requirements.txt     # Project dependencies
```

## Creating Custom Plugins

To create a new vulnerability detection plugin:

1. Create a new file in the `plugins` directory
2. Inherit from the `Plugin` base class
3. Implement the required `scan` method
4. Register your plugin with the plugin system

Example:

```python
from plugins.base import Plugin
from scanner.reporter import Finding, Severity

class MyCustomPlugin(Plugin):
    name = "my_custom_plugin"
    description = "Detects custom vulnerability type"
    
    def scan(self, target_url, http_client):
        # Implement detection logic
        
        # Example finding creation
        finding = Finding(
            plugin_name=self.name,
            title="Custom Vulnerability Found",
            description="Description of the vulnerability",
            severity=Severity.MEDIUM,
            url=target_url,
            request="GET " + target_url,
            response="Response content...",
            evidence="Evidence of vulnerability",
            cwe_id="CWE-123",
            remediation="How to fix the vulnerability"
        )
        
        self.report_finding(finding)
        
        return self.findings
```

## Running Tests

Run the unit tests to verify the scanner components:

```bash
python -m unittest discover tests
```

## Security Considerations

- This tool is intended for security testing with proper authorization
- Always obtain permission before scanning websites you don't own
- Some scanning techniques may be disruptive to web services
- Use this tool responsibly and ethically

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
