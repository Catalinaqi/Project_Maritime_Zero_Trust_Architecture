# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@maritime-ops.local**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Measures Implemented

### 1. **Mutual TLS (mTLS)**
All communication between clients and services requires valid X.509 certificates signed by our internal CA.

- Certificate rotation: 365 days
- Minimum TLS version: TLS 1.2
- Cipher suites: ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384

### 2. **Zero Trust Architecture**
- **Default Deny**: All access is denied by default
- **Least Privilege**: Services run with minimum required permissions
- **Attribute-Based Access Control (ABAC)**: Dynamic authorization based on user, device, location, and risk score
- **Continuous Verification**: Every request is authenticated and authorized

### 3. **Network Segmentation**
- **Perimeter Network**: NFTables firewall blocks all direct access to backend services
- **Zero Trust Network**: Envoy proxy enforces mTLS and policy checks
- **Backend Network**: Internal-only network for data services
- **Monitoring Network**: Isolated network for SIEM and logging

### 4. **Intrusion Detection**
- **Snort IDS**: Network-based intrusion detection with custom rulesets
- **Real-time Alerting**: Integration with Splunk SIEM for immediate threat response
- **15+ Custom Rules**: Specific detection for Zero Trust violations

### 5. **Secrets Management**
- **NO hardcoded secrets**: All secrets are externalized
- **Docker Secrets**: Production secrets stored in Docker secrets
- **Environment Variables**: Development secrets in `.env` (never committed)
- **Certificate Protection**: Private keys are never committed to version control

### 6. **Audit Logging**
- **Comprehensive Logging**: All access attempts logged
- **Tamper-Proof**: Logs sent to centralized SIEM
- **Retention**: 90 days minimum
- **Sanitization**: No sensitive data in logs

### 7. **Container Security**
- **Non-Root Execution**: Containers run as non-root users
- **Read-Only Filesystems**: Where possible
- **Minimal Base Images**: Alpine/Ubuntu slim images
- **Vulnerability Scanning**: Automated scanning with Trivy
- **Image Signing**: SHA256 pinning

### 8. **Rate Limiting & DDoS Protection**
- **Envoy Rate Limiting**: Per-user and global limits
- **Connection Limits**: Maximum concurrent connections enforced
- **Timeout Configuration**: Prevents resource exhaustion

### 9. **Security Headers**
All HTTP responses include:
- `Strict-Transport-Security`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`

### 10. **Dependency Management**
- **Automated Updates**: Dependabot monitors dependencies
- **Security Scanning**: `safety` checks Python dependencies
- **Pinned Versions**: All Docker images use specific versions with SHA256

## Security Testing

### Automated Tests
```bash
make security-check  # Python security scanning
make scan-images     # Docker image vulnerability scanning
make test-security   # Security-specific test suite
```

### Manual Testing
1. **Penetration Testing**: Recommended quarterly
2. **Code Review**: All changes reviewed before merge
3. **Compliance Checks**: NIST SP 800-207 alignment

## Security Best Practices for Contributors

### Before Committing

1. **Never commit secrets**
   ```bash
   # Check for accidentally staged secrets
   git diff --cached
   ```

2. **Run pre-commit hooks**
   ```bash
   make pre-commit
   ```

3. **Scan for vulnerabilities**
   ```bash
   make security-check
   ```

### Certificate Management

1. **Never commit private keys** (`.key`, `.pem` files)
2. **Rotate certificates** before expiration
3. **Use strong passwords** for certificate generation
4. **Store CA keys securely** (ideally in HSM for production)

### Docker Images

1. **Always pin versions** with SHA256
   ```yaml
   image: envoyproxy/envoy:v1.29-latest@sha256:abc123...
   ```

2. **Scan before deployment**
   ```bash
   trivy image your-image:tag
   ```

3. **Minimize attack surface**
   - Use minimal base images
   - Remove unnecessary packages
   - Run as non-root

### Configuration

1. **Validate before deployment**
   ```bash
   make validate-config
   ```

2. **Use environment-specific configs**
   - Development: `docker-compose.yml`
   - Production: `docker-compose.prod.yml`

3. **Never expose internal architecture**
   - Generic error messages
   - Sanitized logs
   - No stack traces in production

## Incident Response

In case of a security incident:

1. **Immediate Actions**
   - Isolate affected systems: `docker compose down`
   - Preserve evidence: `docker compose logs > incident.log`
   - Notify security team: security@maritime-ops.local

2. **Investigation**
   - Review Splunk SIEM for anomalies
   - Check OPA decision logs
   - Analyze network traffic captures

3. **Remediation**
   - Patch vulnerabilities
   - Rotate certificates if compromised
   - Update firewall rules
   - Deploy fixes

4. **Post-Incident**
   - Document incident
   - Update security measures
   - Conduct lessons learned review

## Compliance & Standards

This project aims to comply with:

- **NIST SP 800-207**: Zero Trust Architecture
- **NIST Cybersecurity Framework**: Identify, Protect, Detect, Respond, Recover
- **OWASP Top 10**: Web application security risks
- **CIS Docker Benchmark**: Container security best practices
- **ISO 27001**: Information security management

## Security Contacts

- **Security Team**: security@maritime-ops.local
- **Incident Response**: incident-response@maritime-ops.local
- **Compliance**: compliance@maritime-ops.local

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report vulnerabilities to us.

---

**Last Updated**: 2026-05-08
**Next Review**: 2026-08-08
