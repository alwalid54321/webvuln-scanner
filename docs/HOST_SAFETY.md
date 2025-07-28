# Host Safety and Security Guide

## Overview

The Web Vulnerability Scanner implements comprehensive host safety measures to protect your machine during scanning operations. This document outlines the security features and safety protocols built into the scanner.

## 🛡️ Security Principles

### 1. **No Destructive Actions**
- Scanner never executes shell commands
- No file modifications outside designated directories
- No code evaluation or dynamic imports
- No system configuration changes

### 2. **Restricted File Operations**
- File writes only allowed in:
  - `reports/` directory
  - `logs/` directory
- All file paths validated before operations
- No writes to system directories or user files

### 3. **Network Safety**
- Blocks localhost and private network scanning
- Prevents scanning of internal infrastructure
- Validates all URLs before requests
- Safe HTTP session configuration

### 4. **Resource Limits**
- Memory usage monitoring (max 512MB)
- CPU usage limits (max 50%)
- Thread count restrictions (max 20)
- Open file descriptor limits (max 100)

## 🚫 Blocked Targets

The scanner automatically blocks these potentially dangerous targets:

### Localhost Variants
- `localhost`
- `127.0.0.1`
- `::1`
- `0.0.0.0`

### Private Networks
- `10.x.x.x` (Class A private)
- `172.16.x.x - 172.31.x.x` (Class B private)
- `192.168.x.x` (Class C private)

### Dangerous Schemes
- `file://` (local file access)
- `ftp://` (file transfer)
- `ssh://` (secure shell)
- `telnet://` (insecure remote access)

## 🔒 Input Sanitization

All input data is sanitized to prevent:

### Shell Injection
- Removes shell metacharacters: `;`, `&`, `|`, `` ` ``, `$`, `(`, `)`
- Blocks command execution patterns

### Code Injection
- Removes `<script>` tags
- Blocks `javascript:` URLs
- Prevents `eval()` and `exec()` calls
- Filters `import` statements

### Data Validation
- Input length limits (max 10,000 characters)
- Payload validation for scan parameters
- URL format validation

## 📊 Resource Monitoring

The scanner continuously monitors system resources:

```
Memory Usage: Current / 512MB limit
CPU Usage: Current / 50% limit
Open Files: Current / 100 limit
Thread Count: Current / 20 limit
```

Warnings are logged when limits are approached.

## 🚨 Emergency Stop

The scanner includes emergency stop functionality:

- Triggered by resource limit violations
- Activated by security policy violations
- Stops all operations immediately
- Logs security events for review

## 🔧 Configuration

### Safe Session Settings
```python
{
    'timeout': 30,           # Reasonable timeout
    'max_redirects': 5,      # Limit redirects
    'verify_ssl': True,      # Always verify SSL
    'stream': False,         # Don't stream large responses
    'connection': 'close'    # Don't keep connections alive
}
```

### File Operation Safety
- All file writes validated against allowed directories
- Path traversal prevention (`../` blocked)
- Absolute path resolution and validation
- Safe encoding (UTF-8) for all text files

## ⚠️ Security Warnings

### What the Scanner CANNOT Do
- ❌ Access your local files
- ❌ Modify system settings
- ❌ Execute shell commands
- ❌ Install software
- ❌ Access private networks
- ❌ Scan localhost/internal systems
- ❌ Write files outside reports directory

### What the Scanner DOES
- ✅ Only scans external targets you specify
- ✅ Validates all URLs before requests
- ✅ Monitors resource usage
- ✅ Logs all security events
- ✅ Respects robots.txt by default
- ✅ Uses safe HTTP configurations

## 🛠️ Usage Guidelines

### Safe Scanning Practices

1. **Only scan targets you own or have permission to test**
2. **Verify target URLs before scanning**
3. **Monitor resource usage during scans**
4. **Review security logs after scans**
5. **Use appropriate delays to avoid overloading targets**

### Example Safe Commands
```bash
# Scan external target with safety validation
python console.py -u https://example.com --verbose

# Test connectivity first
python test_connectivity.py https://example.com

# Scan with conservative settings
python console.py -u https://target.com --timeout 60 --delay 2.0 --threads 1
```

### Blocked Commands (Will Fail)
```bash
# These will be blocked by safety validation
python console.py -u http://localhost:8080      # Localhost blocked
python console.py -u http://192.168.1.1        # Private network blocked
python console.py -u file:///etc/passwd        # File scheme blocked
```

## 📋 Security Checklist

Before each scan, the safety manager validates:

- [ ] Target URL is not localhost/private network
- [ ] URL scheme is HTTP/HTTPS only
- [ ] Input data is sanitized
- [ ] File operations are within allowed directories
- [ ] Resource limits are not exceeded
- [ ] No dangerous patterns in payloads

## 🔍 Monitoring and Logging

### Security Events Logged
- Blocked URLs and reasons
- Resource limit warnings
- File operation violations
- Emergency stops
- Input sanitization actions

### Log Locations
- Console output (real-time)
- Log files in `logs/` directory
- Security events marked with `[SECURITY]` prefix

## 🆘 Troubleshooting

### "URL blocked by security policy"
- **Cause**: Attempting to scan localhost or private network
- **Solution**: Only scan external targets you have permission to test

### "File path blocked by security policy"
- **Cause**: Attempting to write outside allowed directories
- **Solution**: Reports are automatically saved to `reports/` directory

### "Resource limit exceeded"
- **Cause**: Scanner using too much memory/CPU
- **Solution**: Reduce thread count or add delays between requests

## 📞 Support

If you encounter security-related issues:

1. Check the security logs for details
2. Verify your target URLs are external and permitted
3. Ensure you have write permissions to the `reports/` directory
4. Review resource usage if performance is slow

## 🔐 Conclusion

The Web Vulnerability Scanner is designed with security-first principles to protect your host machine while providing effective vulnerability scanning capabilities. All operations are contained, validated, and monitored to ensure safe operation.

**Remember**: Only scan targets you own or have explicit permission to test. The scanner's safety features protect your machine, but ethical scanning practices are your responsibility.
