# Security Policy

## Supported Versions

CodexSentinel follows semantic versioning and provides security updates for the following versions:

| Version | Supported | OWASP Top 10 Coverage | Security Features |
| ------- | --------- | --------------------- | ----------------- |
| 1.5.x   | ✅        | 2025 (A01-A10)        | Full Coverage     |
| 1.4.x   | ✅        | 2021 (A01-A10)        | Partial Coverage  |
| 1.3.x   | ❌        | 2021 (Partial)        | Basic Coverage    |
| < 1.3   | ❌        | None                  | No Coverage       |

### Version Support Details

- **v1.5.x**: Latest release with full OWASP Top 10 2025 support

  - Complete A01-A10:2025 coverage
  - Enhanced security rules (20+ rules)
  - Advanced pattern matching
  - Future-ready architecture

- **v1.4.x**: Previous stable release

  - OWASP Top 10 2021 coverage
  - Core security rules
  - Basic dependency analysis

- **v1.3.x and below**: No longer supported

  - Security vulnerabilities may exist
  - No updates provided
  - Upgrade recommended

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in CodexSentinel, please follow these steps:

### 🚨 **How to Report**

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. **DO** use our [Security Advisory](https://github.com/Voskan/codexsentinel/security/advisories) form

### 📧 **Email Template**

Subject: `[SECURITY] Vulnerability Report - CodexSentinel`

```
Vulnerability Type: [e.g., CVE, OWASP Category, etc.]
Severity: [Critical/High/Medium/Low]
Version Affected: [e.g., v1.5.0]

Description:
[Detailed description of the vulnerability]

Steps to Reproduce:
1. [Step 1]
2. [Step 2]
3. [Step 3]

Expected Behavior:
[What should happen]

Actual Behavior:
[What actually happens]

Environment:
- OS: [e.g., Linux, macOS, Windows]
- Go Version: [e.g., 1.24.2]
- CodexSentinel Version: [e.g., v1.5.0]

Additional Information:
[Any other relevant details]
```

### ⏰ **Response Timeline**

- **Initial Response**: Within 24 hours
- **Status Update**: Within 3-5 business days
- **Resolution**: Depends on severity and complexity
  - Critical: 1-3 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: 1-2 months

### 🔍 **What to Expect**

#### If Accepted:

- ✅ Vulnerability confirmed
- 🔧 Fix development begins
- 📝 CVE assignment (if applicable)
- 🚀 Patch release scheduled
- 📢 Public disclosure coordinated

#### If Declined:

- ❌ Vulnerability not confirmed
- 📋 Detailed explanation provided
- 🔄 Alternative solutions suggested
- 📚 Documentation updates (if needed)

### 🛡️ **Security Best Practices**

#### For Users:

- Always use the latest supported version
- Regularly update dependencies
- Run security scans in CI/CD
- Monitor security advisories
- Report suspicious findings

#### For Contributors:

- Follow secure coding practices
- Review security implications of changes
- Test with security rules enabled
- Document security-related changes
- Participate in security reviews

### 🔗 **Security Resources**

- **OWASP Top 10 2025**: [https://owasp.org/Top10/](https://owasp.org/Top10/)
- **Go Security**: [https://golang.org/security/](https://golang.org/security/)
- **SLSA Framework**: [https://slsa.dev/](https://slsa.dev/)
- **CVE Database**: [https://cve.mitre.org/](https://cve.mitre.org/)

### 📊 **Security Metrics**

CodexSentinel maintains high security standards:

- **OWASP Top 10 2025 Coverage**: 100% (A01-A10)
- **Security Rules**: 20+ built-in rules
- **Dependency Analysis**: OSV + GHSA integration
- **Test Coverage**: 90%+
- **SLSA Level**: 3 (Supply chain security)

### 🏆 **Security Recognition**

- ✅ **OWASP Top 10 2025 Compliant**
- ✅ **Go Security Best Practices**
- ✅ **SLSA Level 3 Certified**
- ✅ **Enterprise Security Ready**

### 📞 **Contact Information**

- **Security Email**: `voskan1989@gmail.com`
- **GitHub Security**: [https://github.com/Voskan/codexsentinel/security](https://github.com/Voskan/codexsentinel/security)
- **Discussions**: [https://github.com/Voskan/codexsentinel/discussions](https://github.com/Voskan/codexsentinel/discussions)
- **Issues**: [https://github.com/Voskan/codexsentinel/issues](https://github.com/Voskan/codexsentinel/issues)

---

**Thank you for helping keep CodexSentinel secure!** 🛡️

_This security policy is reviewed and updated regularly to ensure the highest standards of security for our users._
