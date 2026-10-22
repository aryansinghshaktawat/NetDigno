# Security Policy

## Supported Versions

We take security seriously and actively maintain the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We appreciate your efforts to responsibly disclose security vulnerabilities. If you discover a security issue, please follow these guidelines:

### How to Report

**Please DO NOT create a public GitHub issue for security vulnerabilities.**

Instead, please report security vulnerabilities by:

1. **Email**: Send details to [security@example.com] (replace with actual email)
2. **Subject Line**: "Security Vulnerability in NetDigno"
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
   - Your contact information

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 5 business days
- **Updates**: We will keep you informed about our progress
- **Fix Timeline**: We aim to release a fix within 30 days for critical issues
- **Credit**: We will publicly acknowledge your contribution (unless you prefer to remain anonymous)

### Disclosure Policy

- We follow a **coordinated disclosure** approach
- We request that you do not publicly disclose the vulnerability until we have released a fix
- Once a fix is released, we will publish a security advisory
- We will credit you for the discovery (unless you prefer anonymity)

## Security Considerations

### Known Limitations

1. **Nmap Dependency**: This application relies on Nmap, which must be properly secured
2. **Command Execution**: The application executes system commands (Nmap)
3. **Network Scanning**: Users must have authorization to scan target systems

### Security Best Practices

When deploying this application:

#### 1. Input Validation
- All user inputs are validated before processing
- IP addresses and domain names are verified
- Command injection protection is implemented

#### 2. Network Security
```bash
# Use firewall rules
sudo ufw allow 22/tcp    # SSH only
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw deny 8000/tcp   # Block direct backend access
```

#### 3. Environment Variables
```bash
# Never commit .env files
# Use strong, random values in production
# Restrict CORS origins
CORS_ORIGINS=https://your-domain.com
```

#### 4. Authentication (Recommended)
This application currently does not include authentication. For production use:
- Implement OAuth 2.0 or JWT authentication
- Use API keys for backend access
- Implement rate limiting
- Add user session management

#### 5. Secure Deployment
```bash
# Use HTTPS only
# Implement reverse proxy (Nginx)
# Enable SSL/TLS certificates
# Use security headers
```

#### 6. Docker Security
```dockerfile
# Run as non-root user
USER nextjs

# Use specific versions
FROM python:3.11-slim

# Scan images for vulnerabilities
docker scan vuln-scanner-backend
```

#### 7. Monitoring and Logging
- Enable comprehensive logging
- Monitor for suspicious activity
- Set up alerts for security events
- Regular security audits

### Secure Configuration Examples

#### Backend (.env)
```bash
# Production settings
HOST=127.0.0.1  # Bind to localhost only
PORT=8000
CORS_ORIGINS=https://yourdomain.com  # Specific domain only
LOG_LEVEL=INFO
```

#### Nginx Security Headers
```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
```

## Common Vulnerabilities and Mitigations

### 1. Command Injection
**Risk**: User input could be used to execute arbitrary commands

**Mitigation**:
- Input validation with whitelist approach
- Use of subprocess with list arguments (not shell=True)
- Timeout limits on command execution

**Code Example**:
```python
# SAFE - Using list arguments
subprocess.run(["nmap", "-sV", target], timeout=180)

# UNSAFE - Avoid this
# subprocess.run(f"nmap -sV {target}", shell=True)
```

### 2. Denial of Service (DoS)
**Risk**: Long-running scans could exhaust resources

**Mitigation**:
- Timeout limits (180s for basic, 300s for vuln scans)
- Rate limiting (to be implemented)
- Resource monitoring

### 3. Information Disclosure
**Risk**: Error messages could reveal sensitive information

**Mitigation**:
- Generic error messages to users
- Detailed errors logged server-side only
- Sanitized API responses

### 4. Cross-Site Scripting (XSS)
**Risk**: User input could be rendered as HTML

**Mitigation**:
- React's built-in XSS protection
- Input sanitization
- Content Security Policy headers

### 5. Cross-Origin Resource Sharing (CORS)
**Risk**: Unauthorized domains accessing API

**Mitigation**:
- Restricted CORS origins
- Proper CORS configuration
- Origin validation

## Security Checklist for Deployment

- [ ] Change default ports
- [ ] Set strong CORS policies
- [ ] Enable HTTPS/TLS
- [ ] Implement authentication
- [ ] Add rate limiting
- [ ] Configure firewall rules
- [ ] Use environment variables
- [ ] Enable security headers
- [ ] Regular dependency updates
- [ ] Log monitoring setup
- [ ] Backup strategy implemented
- [ ] Incident response plan
- [ ] Regular security audits

## Dependency Security

### Automated Scanning
We use automated tools to scan dependencies:

```bash
# Python dependencies
pip install safety
safety check -r requirements.txt

# Node.js dependencies
npm audit
npm audit fix
```

### Update Policy
- Dependencies are reviewed monthly
- Security patches are applied immediately
- Major version updates are tested thoroughly

## Compliance

### Legal Requirements
- Users must comply with all applicable laws
- Scanning is only permitted on authorized systems
- Users are responsible for obtaining proper authorization

### Ethical Use
This tool is intended for:
- Authorized security testing
- Educational purposes
- Network administration on owned systems

This tool should NOT be used for:
- Unauthorized network scanning
- Malicious activities
- Violating privacy or security policies

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Nmap Security](https://nmap.org/book/legal-issues.html)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [Next.js Security](https://nextjs.org/docs/advanced-features/security-headers)

## Contact

For security concerns or questions:
- Email: security@example.com (replace with actual email)
- GitHub: [@aryansinghshaktawat](https://github.com/aryansinghshaktawat)

---

**Last Updated**: November 2025

Thank you for helping keep this project secure! 🔒
