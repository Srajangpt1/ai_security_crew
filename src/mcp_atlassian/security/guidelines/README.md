# Security Guidelines - File-Based System

This directory contains security guidelines stored as individual text/markdown files. This approach makes it easy to add, modify, and review security best practices without code changes.

## 📁 File Structure

```
guidelines/
├── README.md                    # This file
├── jwt_security.md             # JWT token security guidelines
├── sql_injection_prevention.md # SQL injection prevention
├── mfa_implementation.md       # Multi-factor authentication
├── password_security.md        # Password security requirements
├── input_validation.md         # Input validation and sanitization
└── ...                         # Add more guideline files here
```

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
| `category` | Yes | Security category | `authentication`, `database`, `api_security`, `cryptography`, `web_security`, `data_validation`, `secrets_management`, `logging`, `error_handling`, `authorization` |
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
from mcp_atlassian.security.guidelines import SecurityGuidelinesLoader

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
from mcp_atlassian.security import SecurityAssessment

assessment = SecurityAssessment()
requirements = assessment.assess_ticket(ticket_data)

# Guidelines are automatically included based on ticket content
print(requirements.guidelines)
```

## 📋 Available Categories

| Category | Description | Common Keywords |
|----------|-------------|-----------------|
| `authentication` | User authentication, login, passwords | `auth`, `login`, `password`, `token`, `session` |
| `authorization` | Access control, permissions, roles | `permission`, `role`, `access`, `admin`, `privilege` |
| `data_validation` | Input validation, sanitization | `input`, `form`, `data`, `validation`, `sanitize` |
| `cryptography` | Encryption, hashing, SSL/TLS | `encrypt`, `hash`, `crypto`, `ssl`, `tls`, `certificate` |
| `api_security` | API endpoints, REST, GraphQL | `api`, `endpoint`, `rest`, `graphql`, `webhook` |
| `database` | Database security, SQL injection | `database`, `sql`, `query`, `db`, `mongo`, `redis` |
| `web_security` | Web application security | `web`, `http`, `https`, `cors`, `csrf`, `xss` |
| `secrets_management` | Secrets, keys, credentials | `secret`, `key`, `credential`, `password`, `token` |
| `logging` | Security logging, monitoring | `log`, `audit`, `monitor`, `trace` |
| `error_handling` | Error handling, exception management | `error`, `exception`, `fail`, `handling` |

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
