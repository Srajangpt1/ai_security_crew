# AI Security Crew

[![Run Tests](https://github.com/Srajangpt1/ai_security_crew/actions/workflows/tests.yml/badge.svg)](https://github.com/Srajangpt1/ai_security_crew/actions/workflows/tests.yml)
![License](https://img.shields.io/github/license/Srajangpt1/ai_security_crew)

A lightweight MCP server for security reviews across designs, tickets, and docs - built for vibe coding, which injects security requirements prior to code generation, automatically. Perfect for when you're in the flow and need to quickly assess security risks, check compliance, or document findings without breaking your coding rhythm. Currently supports Jira and Confluence.

## Security Review Workflows

Keep the vibe going while staying secure:

- **Ticket Review** – “I’m working on AUTH-234, give me the security requirements.”
- **Design Analysis** – “Analyze this architecture doc for third-party trust boundaries and data flow risks.”
- **Control Check** – “Does this feature meet our logging and monitoring requirements?”

**Integration with Code Generation:**
1. Run security assessment on your ticket or a document
2. Extract the formatted security requirements
3. Inject into your AI code generation prompt
4. Generate secure code that follows best practices

See [Security Assessment Documentation](docs/security-assessment.md) for detailed usage and examples.

## Security Guidelines

- The system includes **101 OWASP Cheat Sheets** providing comprehensive security guidance
- You can easily add your own organization-specific guidelines
- Guidelines are automatically loaded and integrated into security assessments

### Adding Custom Guidelines

**Easy way** - Use the helper script (auto-generates metadata):
```bash
python3 scripts/add_custom_guideline.py
```

Just write your guideline content, and the system automatically:
- ✅ Detects the appropriate category
- ✅ Assigns priority level
- ✅ Generates relevant tags
- ✅ Saves to the correct location

See [docs/ADDING_CUSTOM_GUIDELINES.md](docs/ADDING_CUSTOM_GUIDELINES.md) for detailed instructions.

**Manual way** - Create markdown files in `src/mcp_security_review/security/guidelines/docs/` with metadata:
```markdown
category: your_category
priority: high
tags: tag1, tag2, tag3

# Your Guideline Title
...
```

## Quick Start Guide

### 1. Authentication Setup

Keep it simple. Use whichever auth your stack already supports:

- API Token (Cloud) or Personal Access Token (Server/DC)
- OAuth 2.0 (Cloud) when you need delegated, per-user access

For OAuth setup, the image ships with a guided `--oauth-setup` wizard. If you already manage tokens elsewhere, you can pass them via env vars.

### 2. Installation

MCP Security Review can be build locally as container image. This is the recommended way to run the server, especially for IDE integration. Ensure you have Docker installed.

```bash
# Run from the root of the Project
docker build -t mcp-security-review .
```

## IDE / Configuration (Minimal)

Use Docker with either direct env vars or an env file. Typical vars:

- `JIRA_URL`, `JIRA_USERNAME`, `JIRA_API_TOKEN` (or `JIRA_PERSONAL_TOKEN`)
- `CONFLUENCE_URL`, `CONFLUENCE_USERNAME`, `CONFLUENCE_API_TOKEN` (or `CONFLUENCE_PERSONAL_TOKEN`)
- `READ_ONLY_MODE` to disable writes

Example (Cloud tokens):

```json
{
  "mcpServers": {
    "mcp-security-review": {
      "command": "docker",
      "args": ["run","--rm","-i",
        "-e","JIRA_URL","-e","JIRA_USERNAME","-e","JIRA_API_TOKEN",
        "-e","CONFLUENCE_URL","-e","CONFLUENCE_USERNAME","-e","CONFLUENCE_API_TOKEN",
        "mcp-security-review:latest"
      ]
    }
  }
}
```

### 👥 HTTP Transport Configuration

Instead of using `stdio`, you can run the server as a persistent HTTP service using either:
- `sse` (Server-Sent Events) transport at `/sse` endpoint
- `streamable-http` transport at `/mcp` endpoint

## Security

- Never share API tokens
- Keep .env files secure and private
- See [SECURITY.md](SECURITY.md) for best practices

## Contributing

We welcome contributions to MCP Security Review! If you'd like to contribute:

1. Check out our [CONTRIBUTING.md](CONTRIBUTING.md) guide for detailed development setup instructions.
2. Make changes and submit a pull request.

We use pre-commit hooks for code quality and follow semantic versioning for releases.

## License

Licensed under MIT - see [LICENSE](LICENSE) file.
