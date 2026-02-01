# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in nothx, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Email the maintainers directly with details
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- Acknowledgment within 48 hours
- Regular updates on progress
- Credit in the security advisory (if desired)

### Scope

Security issues we're interested in:

- Credential exposure or leakage
- Unauthorized access to email data
- Remote code execution
- SQL injection in the local database
- Cross-site scripting (if web UI is added)
- Insecure storage of sensitive data

### Out of Scope

- Issues requiring physical access to the machine
- Social engineering attacks
- Denial of service against local CLI
- Issues in dependencies (report to upstream)

## Security Design

nothx is designed with privacy and security in mind:

- **No email bodies** - Only headers are processed
- **Local storage** - All data stays on your machine
- **Encrypted credentials** - Config files use 0600 permissions
- **No telemetry** - No data sent to external servers
- **App passwords** - We recommend app-specific passwords, not main account passwords

## Best Practices for Users

1. Use app-specific passwords, not your main email password
2. Keep your API keys secure and never commit them
3. Review the senders list before enabling auto-unsubscribe
4. Keep nothx updated to get security fixes
