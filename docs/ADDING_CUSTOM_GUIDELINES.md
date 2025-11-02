# Adding Custom Security Guidelines

This guide shows you how to easily add your own organization-specific security guidelines without manually specifying metadata.

## 🚀 Quick Start

### Method 1: Interactive Mode (Easiest)

Just run the script and follow the prompts:

```bash
python3 scripts/add_custom_guideline.py
```

**Example:**
```
🔒 Add Custom Security Guideline
============================================================

📝 Guideline Title: API Key Rotation Policy

📄 Guideline Content (press Ctrl+D or Ctrl+Z when done):
   You can write in markdown format.

## Description
All API keys must be rotated every 90 days to minimize security risk.

## Implementation
- Set up automated key rotation in your key management system
- Implement key versioning to support gradual rollout
- Monitor key usage and alert on anomalies

## Examples
- AWS Secrets Manager automatic rotation
- Azure Key Vault rotation policies
- Custom rotation scripts
^D

🤖 Auto-detecting metadata...
   Category: api_security
   Priority: high
   Tags: api, key, rotation, security, credential

✅ Save guideline? (y/n): y

✅ Guideline saved to: src/mcp_security_review/security/guidelines/docs/api_security/api_key_rotation_policy.md

💡 The guideline will be automatically loaded on next use!
```

### Method 2: From a File

If you already have a markdown file:

```bash
python3 scripts/add_custom_guideline.py --file my_guideline.md
```

The script will:
- ✅ Auto-detect the title from the first `#` heading
- ✅ Auto-detect the category from content
- ✅ Auto-detect the priority level
- ✅ Auto-generate relevant tags
- ✅ Save to the appropriate category folder

### Method 3: Quick Command Line

For quick additions:

```bash
python3 scripts/add_custom_guideline.py \
  --title "Database Backup Encryption" \
  --content "All database backups must be encrypted at rest using AES-256..."
```

### Method 4: Override Auto-Detection

If you want to specify metadata manually:

```bash
python3 scripts/add_custom_guideline.py \
  --file my_guideline.md \
  --category compliance_security \
  --priority critical \
  --tags "compliance,gdpr,backup,encryption"
```

## 🤖 Auto-Detection Features

The script automatically detects:

### Categories

Based on content keywords, it will categorize your guideline into:

| Category | Detected From Keywords |
|----------|----------------------|
| `authentication` | login, password, oauth, jwt, mfa, session |
| `authorization` | permission, role, rbac, access control |
| `api_security` | api, rest, graphql, endpoint, rate limit |
| `database` | sql, nosql, query, injection, mongodb |
| `cryptography` | encryption, hash, ssl, tls, certificate |
| `web_security` | xss, csrf, cors, csp, clickjacking |
| `data_validation` | validation, sanitization, input, output |
| `cloud_security` | aws, azure, gcp, kubernetes, docker |
| `infrastructure_security` | network, firewall, vpn, dns |
| `supply_chain_security` | dependency, npm, vulnerability, cve |
| `secrets_management` | secret, key, vault, credential storage |
| `mobile_security` | mobile, android, ios, app |
| `logging` | logging, monitoring, siem, audit trail |
| `error_handling` | error, exception, handling |
| `compliance_security` | compliance, gdpr, hipaa, pci, audit |
| `general` | (default if no match) |

### Priority Levels

| Priority | Detected From |
|----------|--------------|
| `critical` | critical, urgent, sql injection, authentication bypass, data breach, password, secret |
| `high` | important, essential, xss, csrf, injection, vulnerability, security risk |
| `medium` | (default) |
| `low` | optional, nice to have, recommendation, best practice |

### Tags

Automatically extracts relevant security keywords from your content:
- `authentication`, `authorization`, `encryption`, `api`, `database`, `cloud`
- Technology names: `aws`, `kubernetes`, `docker`, `oauth`, `jwt`
- Security concepts: `xss`, `csrf`, `injection`, `vulnerability`
- Compliance: `gdpr`, `hipaa`, `pci`

## 📝 Guideline Format

Your guideline content can be simple markdown:

```markdown
# My Security Guideline Title

## Description
Brief description of what this guideline covers.

## Implementation
Step-by-step implementation instructions:
- Step 1
- Step 2
- Step 3

## Examples
- Example 1: Real-world scenario
- Example 2: Code snippet
- Example 3: Configuration

## References
- [OWASP Guide](https://example.com)
- [Internal Wiki](https://wiki.company.com)
```

The script will automatically add metadata at the top:

```markdown
category: api_security
priority: high
tags: api, security, authentication

# My Security Guideline Title
...
```

## 🎯 Best Practices

### 1. Write Clear Titles
Good: "API Key Rotation Policy"
Bad: "Keys"

### 2. Include Implementation Details
The more specific you are, the more useful the guideline:
```markdown
## Implementation
- Use AWS Secrets Manager for automatic rotation
- Set rotation period to 90 days
- Implement key versioning with 7-day overlap
- Monitor CloudWatch for rotation failures
```

### 3. Add Real Examples
Include actual code, commands, or configurations:
```markdown
## Examples

AWS CLI command for key rotation:
```bash
aws secretsmanager rotate-secret \
  --secret-id prod/api/key \
  --rotation-lambda-arn arn:aws:lambda:...
```
```

### 4. Link to Internal Resources
```markdown
## References
- [Company Security Policy](https://wiki.company.com/security)
- [Incident Response Runbook](https://runbooks.company.com)
```

## 🔄 Updating Existing Guidelines

To update an existing guideline:

1. Edit the file directly in `src/mcp_security_review/security/guidelines/docs/`
2. The system automatically reloads guidelines
3. No need to restart anything!

## 🗂️ Organization

Guidelines are automatically organized by category:

```
src/mcp_security_review/security/guidelines/docs/
├── api_security/
│   ├── api_key_rotation_policy.md
│   └── rate_limiting_best_practices.md
├── compliance_security/
│   ├── gdpr_data_handling.md
│   └── audit_logging_requirements.md
├── cloud_security/
│   ├── aws_iam_policies.md
│   └── kubernetes_rbac.md
└── ...
```

## 🧪 Testing Your Guidelines

After adding guidelines, test that they load correctly:

```bash
# Test loading
python3 scripts/test_guidelines_standalone.py

# Run unit tests
uv run pytest tests/unit/security/

# Use in security assessment
python3 scripts/test_security_assessment.py
```

## 💡 Tips

1. **Start Simple**: Just write content, let the script handle metadata
2. **Review Auto-Detection**: Check the suggested category/priority before saving
3. **Use Descriptive Keywords**: More keywords = better auto-detection
4. **Iterate**: You can always edit the file later
5. **Share**: Guidelines are just markdown files - easy to version control and share

## 🆘 Troubleshooting

### Wrong Category Detected?
Override it:
```bash
python3 scripts/add_custom_guideline.py \
  --file my_guideline.md \
  --category my_custom_category
```

### Want a New Category?
Just specify it! The system accepts any category name:
```bash
--category my_new_category
```

### Tags Not Relevant?
Override them:
```bash
--tags "tag1,tag2,tag3"
```

### Need to Edit Metadata Later?
Just edit the file directly - metadata is at the top in plain text.

## 📚 Examples

See existing guidelines for reference:
- OWASP cheat sheets in `docs/*/`
- Custom guidelines you've added

## 🎓 Advanced Usage

### Batch Import

Import multiple guidelines from a directory:

```bash
for file in my_guidelines/*.md; do
  python3 scripts/add_custom_guideline.py --file "$file"
done
```

### Custom Category Structure

Create your own category hierarchy:

```bash
# Create a new category
mkdir -p src/mcp_security_review/security/guidelines/docs/incident_response

# Add guidelines to it
python3 scripts/add_custom_guideline.py \
  --title "Data Breach Response" \
  --category incident_response \
  --content "..."
```

### Integration with CI/CD

Add guidelines as part of your security review process:

```yaml
# .github/workflows/add-guideline.yml
name: Add Security Guideline
on:
  workflow_dispatch:
    inputs:
      title:
        description: 'Guideline Title'
        required: true
      content:
        description: 'Guideline Content'
        required: true

jobs:
  add-guideline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Add Guideline
        run: |
          python3 scripts/add_custom_guideline.py \
            --title "${{ github.event.inputs.title }}" \
            --content "${{ github.event.inputs.content }}"
```

---

**Questions?** Check the main [README](../README.md) or [CONTRIBUTING](../CONTRIBUTING.md) guide.
