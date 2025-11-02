# Security Guidelines - File-Based System

This directory contains security guidelines stored as individual text/markdown files. This approach makes it easy to add, modify, and review security best practices without code changes.

## 🎯 OWASP Integration

We have integrated **101 OWASP Cheat Sheets** from the official [OWASP Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries). These provide comprehensive, expert-reviewed security guidance across all major security categories.

See [OWASP_INTEGRATION.md](docs/OWASP_INTEGRATION.md) for complete details on:
- Category taxonomy and distribution
- OWASP Top 10 2021 coverage
- Technology-specific cheat sheets
- Priority assignments
- Update procedures

## 📁 File Structure

```
guidelines/
├── README.md                        # This file
├── OWASP_INTEGRATION.md            # OWASP integration documentation
├── docs/                           # Guidelines directory
│   ├── authentication/             # 17 OWASP guidelines
│   ├── authorization/              # 7 OWASP guidelines
│   ├── database/                   # 17 OWASP guidelines
│   ├── cryptography/               # 11 OWASP guidelines
│   ├── web_security/               # 11 OWASP guidelines
│   ├── data_validation/            # 7 OWASP guidelines
│   ├── api_security/               # 6 OWASP guidelines
│   ├── cloud_security/             # 5 OWASP guidelines
│   ├── infrastructure_security/    # 5 OWASP guidelines
│   ├── supply_chain_security/      # 5 OWASP guidelines
│   ├── mobile_security/            # 2 OWASP guidelines
│   ├── secrets_management/         # 2 OWASP guidelines
│   ├── logging/                    # 4 OWASP guidelines
│   ├── error_handling/             # 1 OWASP guideline
│   └── secure_development/         # 1 OWASP guideline
└── ...
```

**Total Guidelines**: 101 OWASP Cheat Sheets

## 📝 Adding New Guidelines

### 1. Create a New File

Create a new `.md` or `.txt` file in this directory with a descriptive name:

```bash
# Example: Create a new guideline for API security
touch api_rate_limiting.md
```

### 2. File Format

Each guideline file should follow this structure:

```markdown
# Guideline Title

category: authentication          # Required: category name
priority: high                   # Required: critical, high, medium, low
tags: jwt, token, security       # Optional: comma-separated tags

## Description

Brief description of the security guideline and why it's important.

## Implementation

Detailed implementation instructions and best practices.

## Examples

- Example 1: Specific implementation example
- Example 2: Another example
- Example 3: Code snippet or configuration

## References

- [OWASP Cheat Sheet](https://example.com)
- [NIST Guidelines](https://example.com)
- [RFC Document](https://example.com)

## Code Example

```python
# Example code implementation
def secure_function():
    # Implementation details
    pass
```
```

### 3. Metadata Fields

| Field | Required | Description | Values |
|-------|----------|-------------|---------|
| `category` | Yes | Security category | `authentication`, `authorization`, `database`, `cryptography`, `web_security`, `data_validation`, `api_security`, `cloud_security`, `infrastructure_security`, `supply_chain_security`, `mobile_security`, `secrets_management`, `logging`, `error_handling`, `secure_development` |
| `priority` | Yes | Priority level | `critical`, `high`, `medium`, `low` |
| `tags` | No | Comma-separated tags | Any relevant keywords |

### 4. Auto-Detection

The system can automatically detect some metadata from content:

- **Category**: Inferred from keywords in the content
- **Priority**: Inferred from words like "critical", "urgent", "important"
- **Tags**: Extracted from security-related keywords

## 🔍 Using Guidelines

### In Code

```python
from mcp_security_review.security.guidelines import SecurityGuidelinesLoader

# Load guidelines
loader = SecurityGuidelinesLoader()

# Get guidelines for specific context
auth_guidelines = loader.get_guidelines_for_context("authentication", ["python", "django"])

# Search for specific guidelines
jwt_guidelines = loader.search_guidelines("jwt")

# Get guidelines by priority
critical_guidelines = loader.get_guidelines_by_priority("critical")

# Reload guidelines (useful after adding new files)
loader.reload_guidelines()
```

### In Security Assessment

The guidelines are automatically used by the security assessment tool:

```python
from mcp_security_review.security import SecurityAssessment

assessment = SecurityAssessment()
requirements = assessment.assess_ticket(ticket_data)

# Guidelines are automatically included based on ticket content
print(requirements.guidelines)
```

## 📋 Available Categories

### Core Security Categories

| Category | Description | Common Keywords | Guidelines |
|----------|-------------|-----------------|------------|
| `authentication` | User authentication, login, passwords, sessions | `auth`, `login`, `password`, `token`, `session`, `oauth`, `jwt`, `mfa` | 17+ |
| `authorization` | Access control, permissions, roles, RBAC | `permission`, `role`, `access`, `admin`, `privilege`, `rbac` | 7+ |
| `database` | Database security, SQL injection, NoSQL | `database`, `sql`, `query`, `db`, `mongo`, `redis`, `injection` | 17+ |
| `cryptography` | Encryption, hashing, SSL/TLS, key management | `encrypt`, `hash`, `crypto`, `ssl`, `tls`, `certificate`, `key` | 11+ |
| `web_security` | Web app security, XSS, CSRF, CSP | `web`, `http`, `https`, `cors`, `csrf`, `xss`, `csp` | 11+ |
| `data_validation` | Input validation, sanitization, encoding | `input`, `form`, `data`, `validation`, `sanitize`, `encode` | 7+ |
| `api_security` | API security, REST, GraphQL, rate limiting | `api`, `endpoint`, `rest`, `graphql`, `webhook`, `rate limit` | 6+ |

### Infrastructure & Cloud

| Category | Description | Common Keywords | Guidelines |
|----------|-------------|-----------------|------------|
| `cloud_security` | Cloud platforms, containers, serverless | `aws`, `azure`, `gcp`, `kubernetes`, `docker`, `serverless` | 5 |
| `infrastructure_security` | Network security, zero trust, SSRF | `network`, `firewall`, `zero trust`, `ssrf`, `segmentation` | 5 |
| `supply_chain_security` | Dependencies, packages, SBOM | `dependency`, `npm`, `package`, `vulnerability`, `sbom` | 5 |

### Development & Operations

| Category | Description | Common Keywords | Guidelines |
|----------|-------------|-----------------|------------|
| `secrets_management` | Secrets storage, key management, CI/CD | `secret`, `key`, `credential`, `vault`, `ci/cd` | 2+ |
| `logging` | Security logging, monitoring, audit trails | `log`, `audit`, `monitor`, `trace`, `siem` | 4+ |
| `error_handling` | Secure error handling, exception management | `error`, `exception`, `fail`, `handling` | 1+ |
| `secure_development` | Secure design, code review, best practices | `secure design`, `code review`, `threat model` | 1+ |
| `mobile_security` | Mobile app security, Android, iOS | `mobile`, `android`, `ios`, `app security` | 2 |

## 🎯 Priority Levels

| Priority | Description | When to Use |
|----------|-------------|-------------|
| `critical` | Immediate security risk | SQL injection, authentication bypass, data breaches |
| `high` | Significant security concern | Weak authentication, missing validation, insecure APIs |
| `medium` | Moderate security risk | Missing security headers, weak error handling |
| `low` | Minor security consideration | Documentation, best practices, nice-to-have features |

## 🔄 Workflow

1. **Identify Security Need**: Determine what security guideline is needed
2. **Create Guideline File**: Add a new `.md` file with proper metadata
3. **Test Integration**: Use the test script to verify the guideline loads correctly
4. **Deploy**: The guideline is automatically available in security assessments
5. **Review & Update**: Regularly review and update guidelines as needed

## 🧪 Testing

Use the test script to verify guidelines are loaded correctly:

```bash
python3 scripts/test_guidelines_standalone.py
```

This will show:
- Total guidelines loaded
- Available categories
- Context-based filtering
- Priority filtering
- Search functionality
- Detailed examples

## 💡 Best Practices

1. **Use Descriptive Filenames**: Make it easy to find specific guidelines
2. **Include Metadata**: Always specify category and priority
3. **Provide Examples**: Include practical implementation examples
4. **Add References**: Link to authoritative sources like OWASP, NIST
5. **Keep Updated**: Regularly review and update guidelines
6. **Test Changes**: Use the test script after adding new guidelines

## 🔗 Integration

The file-based guidelines system integrates with:

- **Security Assessment Tool**: Automatically selects relevant guidelines
- **MCP Tools**: Used by the `assess_ticket_security` tool
- **AI Code Generation**: Guidelines are injected into prompts
- **Development Workflow**: Seamlessly integrated into the development process

## 📚 Example Guidelines

See the existing files in this directory for examples:

- `jwt_security.md` - JWT token security
- `sql_injection_prevention.md` - SQL injection prevention
- `mfa_implementation.md` - Multi-factor authentication
- `password_security.md` - Password requirements
- `input_validation.md` - Input validation

Each file demonstrates the proper format and structure for security guidelines.
