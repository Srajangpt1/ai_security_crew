# Security Assessment Tool

The MCP Security Review Assessment Tool provides automated security analysis of Jira tickets and generates security requirements that can be injected into code generation prompts. This ensures that security considerations are built into the development process from the start.

## Overview

The security assessment tool analyzes Jira ticket content to:

- **Identify security-relevant technologies** (Python, JavaScript, databases, etc.)
- **Detect security keywords** (authentication, authorization, encryption, etc.)
- **Recognize sensitive data types** (personal data, credentials, financial data)
- **Identify potential attack vectors** (SQL injection, XSS, CSRF, etc.)
- **Generate risk assessments** (low, medium, high, critical)
- **Provide specific security guidelines** following OWASP and industry best practices
- **Create formatted prompt injections** for AI code generation

## Usage

### Basic Usage

```python
# Using the MCP tool
result = await assess_ticket_security(ctx, "PROJ-123")
```

### Advanced Usage

```python
# Customize the assessment output
result = await assess_ticket_security(
    ctx, 
    "PROJ-123",
    include_guidelines=True,      # Include detailed security guidelines
    include_prompt_injection=True # Include formatted prompt injection
)
```

## Tool Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `issue_key` | string | required | Jira issue key (e.g., 'PROJ-123') |
| `include_guidelines` | boolean | true | Whether to include detailed security guidelines |
| `include_prompt_injection` | boolean | true | Whether to include formatted prompt injection |

## Response Format

The tool returns a JSON response with the following structure:

```json
{
  "success": true,
  "issue_key": "PROJ-123",
  "assessment": {
    "risk_level": "high",
    "security_categories": ["authentication", "api_security"],
    "technologies": ["python", "javascript"],
    "summary": "High risk authentication implementation with JWT tokens",
    "guidelines": [
      {
        "category": "authentication",
        "title": "JWT Token Security",
        "description": "Implement secure JWT token handling",
        "priority": "high",
        "implementation": "Use proper token validation and expiration",
        "examples": [
          "Validate token signature",
          "Check token expiration",
          "Use secure token storage"
        ],
        "references": ["OWASP JWT Guidelines"]
      }
    ],
    "prompt_injection": "🔒 SECURITY REQUIREMENTS:\n\n⚠️ HIGH SECURITY RISK DETECTED..."
  },
  "metadata": {
    "total_guidelines": 5,
    "assessment_timestamp": "2024-01-01T00:00:00.000Z",
    "issue_type": "Story",
    "issue_status": "In Progress"
  }
}
```

## Security Categories

The tool identifies and provides guidelines for the following security categories:

### Authentication
- Strong password requirements
- Multi-factor authentication (MFA)
- Secure session management
- JWT token security
- OAuth implementation

### Authorization
- Principle of least privilege
- Role-based access control (RBAC)
- Access control validation
- Permission management

### Data Validation
- Input validation and sanitization
- Output encoding
- SQL injection prevention
- XSS prevention

### Cryptography
- Strong cryptographic algorithms
- Secure key management
- Password hashing
- Certificate management

### API Security
- API authentication and authorization
- Rate limiting and throttling
- CORS configuration
- API versioning

### Database Security
- SQL injection prevention
- Database access control
- Connection security
- Query optimization

### Web Security
- Cross-Site Scripting (XSS) prevention
- Cross-Site Request Forgery (CSRF) prevention
- Content Security Policy (CSP)
- Secure headers

### Secrets Management
- Secure secrets storage
- Secret rotation
- Environment variable security
- Key management services

### Logging and Monitoring
- Security event logging
- Log protection and integrity
- Audit trails
- SIEM integration

### Error Handling
- Secure error handling
- Information disclosure prevention
- Exception management
- Debug information security

## Risk Levels

The tool assigns risk levels based on the security implications found:

- **Low**: Minimal security implications, general best practices apply
- **Medium**: Some security considerations, specific guidelines recommended
- **High**: Significant security risks, comprehensive security measures required
- **Critical**: Immediate security concerns, urgent action required

## Prompt Injection Format

The tool generates formatted security requirements that can be directly injected into AI code generation prompts:

```
🔒 SECURITY REQUIREMENTS:

⚠️  HIGH SECURITY RISK DETECTED (HIGH)

🛠️  TECHNOLOGY-SPECIFIC SECURITY:
   • Python: Follow secure coding practices
   • JavaScript: Follow secure coding practices

🔐 SECURITY CATEGORIES TO ADDRESS:
   • Authentication
   • Api Security

📋 MANDATORY SECURITY GUIDELINES:

🚨 JWT Token Security
   Implement secure JWT token handling
   Implementation: Use proper token validation and expiration
   Examples:
     • Validate token signature
     • Check token expiration

🔍 GENERAL SECURITY REMINDERS:
   • Validate all inputs
   • Use parameterized queries
   • Implement proper error handling
   • Follow principle of least privilege
   • Use secure defaults
   • Implement proper logging and monitoring

⚠️  IMPORTANT: Review all generated code for security vulnerabilities before deployment!
```

## Integration with Code Generation

The security assessment tool is designed to work seamlessly with AI code generation workflows:

1. **Before Code Generation**: Run the security assessment on the Jira ticket
2. **Extract Prompt Injection**: Get the formatted security requirements
3. **Inject into Prompt**: Include the security requirements in your code generation prompt
4. **Generate Secure Code**: The AI will generate code that follows security best practices
5. **Review and Validate**: Always review generated code for security compliance

### Example Integration

```python
# 1. Assess the ticket for security requirements
security_result = await assess_ticket_security(ctx, "PROJ-123")
security_data = json.loads(security_result)

# 2. Extract the prompt injection
prompt_injection = security_data["assessment"]["prompt_injection"]

# 3. Create your code generation prompt
code_prompt = f"""
Generate code for the following Jira ticket:

{prompt_injection}

Ticket Details:
- Summary: {ticket_summary}
- Description: {ticket_description}

Requirements:
- Implement user authentication
- Add input validation
- Follow security best practices
"""

# 4. Generate code with security requirements included
generated_code = await generate_code(code_prompt)
```

## Best Practices

1. **Always Run Assessment**: Run security assessment on all tickets before code generation
2. **Review Guidelines**: Carefully review the provided security guidelines
3. **Customize as Needed**: Adjust the assessment parameters based on your needs
4. **Validate Generated Code**: Always review AI-generated code for security compliance
5. **Update Regularly**: Keep security guidelines and patterns up to date
6. **Team Training**: Ensure your team understands the security requirements

## Error Handling

The tool includes comprehensive error handling:

- **Issue Not Found**: Returns error response with fallback assessment
- **Authentication Errors**: Handles Jira authentication issues gracefully
- **Analysis Errors**: Provides fallback security guidelines
- **Network Issues**: Handles connectivity problems

## Limitations

- **Language Support**: Currently optimized for English ticket content
- **Technology Detection**: Limited to common technologies and frameworks
- **Custom Fields**: May not analyze all custom Jira fields
- **Historical Data**: Focuses on current ticket state, not historical changes

## Future Enhancements

Planned improvements include:

- **Multi-language Support**: Support for non-English ticket content
- **Custom Security Rules**: Ability to define organization-specific security rules
- **Integration with Security Tools**: Direct integration with SAST/DAST tools
- **Machine Learning**: Improved risk assessment using ML models
- **Real-time Updates**: Live security assessment as tickets are updated

## Support

For questions, issues, or feature requests related to the security assessment tool, please:

1. Check the [documentation](README.md)
2. Review the [test cases](tests/unit/security/)
3. Open an [issue](https://github.com/ai-security-crew/mcp-security-review/issues)
4. Contact the development team

## Contributing

Contributions to the security assessment tool are welcome! Please see the [contributing guidelines](CONTRIBUTING.md) for details on how to contribute.
