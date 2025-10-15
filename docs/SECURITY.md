# Security Policy

## Security Measures Implemented

This document outlines the security measures implemented in the Archer threat detection tool.

### 1. Server-Side Request Forgery (SSRF) Protection

**Location**: `archer/parsers/blog_analyzer.py`

**Measures**:
- URL scheme validation (only HTTP/HTTPS allowed)
- Hostname validation
- Private IP range blocking:
  - 10.0.0.0/8 (private network)
  - 172.16.0.0/12 (private network)
  - 192.168.0.0/16 (private network)
  - 127.0.0.0/8 (localhost)
  - 169.254.0.0/16 (link-local)
  - 224.0.0.0/4+ (multicast/reserved)
- DNS resolution before request to prevent DNS rebinding
- Response size limit (10MB maximum)
- Redirect limit (maximum 3 redirects)
- Request timeout (30 seconds)

### 2. File Upload Security

**Location**: `archer/app.py` - `/upload` endpoint

**Measures**:
- Filename sanitization (path traversal prevention)
- File extension whitelist validation
- File size limit (50MB maximum)
- Dangerous character removal from filenames
- Path component extraction (basename only)
- Safe filename generation with regex filtering

**Allowed File Types**:
- `.pdf`, `.txt`, `.md`, `.json`, `.csv`
- `.xlsx`, `.xls`, `.docx`, `.doc`
- `.yar`, `.yara`

### 3. Path Traversal Protection

**Location**: `archer/security/validation.py`

**Functions**:
- `sanitize_filename()` - Removes path components and dangerous characters
- `sanitize_path_component()` - Sanitizes directory/file names
- `sanitize_group_name()` - Sanitizes group names used in file paths
- `validate_safe_path()` - Ensures paths remain within allowed directories

**Applied To**:
- File uploads
- Group name parameters
- Blog analysis results
- Draft saving/loading
- Correlation file access

### 4. Cross-Site Scripting (XSS) Prevention

**Location**: `static/js/index.js`

**Measures**:
- HTML escaping function (`escapeHtml()`) for user-provided data
- Escaping applied to:
  - Filenames in extraction results
  - TTP identifiers
  - IOC values
  - IOC type names
- Characters escaped: `& < > " '`

### 5. Input Validation

**Security Module**: `archer/security/validation.py`

**Validations**:
- URL format validation
- URL length limits (2048 characters maximum)
- JSON size validation
- Filename sanitization
- Path component sanitization
- Group name sanitization

### 6. Command Injection Prevention

**Note**: The application uses `subprocess` with `shell=True` in emulation modules (`archer/emulation/atomic.py`, `archer/emulation/remote.py`) for executing adversary emulation tests.

**Risk Mitigation**:
- These modules are intentionally designed for controlled execution environments
- Should only be used in isolated testing environments
- NOT recommended for production use without additional input sanitization
- Users must understand they are executing potentially dangerous commands

**Recommendation**: If deploying to production, consider:
- Disabling the emulation functionality
- Adding strict command whitelisting
- Using `shell=False` with command arrays
- Implementing role-based access controls

## Security Best Practices for Deployment

### 1. Environment Configuration

```bash
# Use environment variables for sensitive data
export OPENAI_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"

# Never commit .env files to version control
echo ".env" >> .gitignore
```

### 2. Network Security

- Deploy behind a reverse proxy (nginx, Apache)
- Enable HTTPS/TLS for all connections
- Use a Web Application Firewall (WAF)
- Implement rate limiting
- Restrict access to internal/admin endpoints

### 3. File System Security

```bash
# Ensure proper permissions on data directories
chmod 750 data/
chmod 750 data/uploads/
chmod 750 data/blog_analysis/

# Run application with limited user privileges
# Never run as root
```

### 4. Monitoring and Logging

- Monitor for suspicious URL patterns
- Log all file uploads with checksums
- Alert on repeated failed validations
- Track API usage and rate limits

### 5. Regular Updates

- Keep dependencies updated
- Monitor security advisories for:
  - FastAPI
  - BeautifulSoup4
  - Requests
  - OpenAI SDK
  - Other dependencies

## Reporting Security Issues

If you discover a security vulnerability, please email [security contact] with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact assessment
4. Suggested fix (if any)

**Do NOT** open public GitHub issues for security vulnerabilities.

## Security Testing

### Recommended Tests

1. **SSRF Testing**:
```bash
# Test private IP blocking
curl -X POST http://localhost:8000/analyze_blog \
  -F "url=http://127.0.0.1:8000"

# Should return error: "Access to localhost is not allowed"
```

2. **Path Traversal Testing**:
```bash
# Test path traversal in file operations
# Should be sanitized and rejected
```

3. **XSS Testing**:
```javascript
// Test with malicious filename
filename: "<script>alert('XSS')</script>"
// Should be escaped in UI
```

4. **File Upload Testing**:
```bash
# Test oversized file (should reject >50MB)
# Test invalid file types (should reject)
# Test malicious filenames (should sanitize)
```

## Compliance Considerations

This application handles threat intelligence data which may include:
- Personally Identifiable Information (PII)
- Security vulnerability information
- Network topology data

**Recommendations**:
- Implement data retention policies
- Ensure GDPR compliance if applicable
- Consider encryption at rest for sensitive data
- Implement audit logging for compliance requirements

## License and Disclaimer

This security documentation is provided as-is. While security measures have been implemented, no system is 100% secure. Users are responsible for:
- Proper deployment configuration
- Network security
- Access controls
- Regular security audits
- Compliance with applicable laws and regulations

Last Updated: 2025-01-XX
Version: 1.0
