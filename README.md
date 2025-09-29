# MCP For Security Review

[![Run Tests](https://github.com/Srajangpt1/ai_security_crew/actions/workflows/tests.yml/badge.svg)](https://github.com/Srajangpt1/ai_security_crew/actions/workflows/tests.yml)
![License](https://img.shields.io/github/license/ai-security-crew/mcp-security-review)

A simple MCP server for security reviews while vibe coding. Perfect for when you're in the flow and need to quickly assess security risks, check compliance, or document findings in Jira and Confluence without breaking your coding rhythm. Supports both Cloud and Server/Data Center deployments.

## Security Review Workflows

Keep the vibe going while staying secure:

- **Security Assessment** - "Assess PROJ-123 for security requirements and generate secure coding guidelines"
- **Vulnerability Tracking** - "Find all high-priority security issues in the SEC project from last month"
- **Security Documentation** - "Create a security assessment report for the authentication feature"
- **Compliance Reviews** - "Search for OWASP compliance documentation in our security space"
- **Risk Analysis** - "Analyze security risks in tickets labeled 'security-critical'"

**Integration with Code Generation:**
1. Run security assessment on your ticket or a document
2. Extract the formatted security requirements
3. Inject into your AI code generation prompt
4. Generate secure code that follows best practices

See [Security Assessment Documentation](docs/security-assessment.md) for detailed usage and examples.

### Compatibility

| Product        | Deployment Type    | Support Status              |
|----------------|--------------------|-----------------------------|
| **Confluence** | Cloud              | ✅ Fully supported           |
| **Confluence** | Server/Data Center | ✅ Supported (version 6.0+)  |
| **Jira**       | Cloud              | ✅ Fully supported           |
| **Jira**       | Server/Data Center | ✅ Supported (version 8.14+) |

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
- `ENABLED_TOOLS` to explicitly allow a subset of tools

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

Both transport types support single-user and multi-user authentication:

**Authentication Options:**
- **Single-User**: Use server-level authentication configured via environment variables
- **Multi-User**: Each user provides their own authentication:
  - Cloud: OAuth 2.0 Bearer tokens
  - Server/Data Center: Personal Access Tokens (PATs)

<details> <summary>Basic HTTP Transport Setup</summary>

1. Start the server with your chosen transport:

    ```bash
    # For SSE transport
    docker run --rm -p 9000:9000 \
      --env-file /path/to/your/.env \
      mcp-security-review:latest \
      --transport sse --port 9000 -vv

    # OR for streamable-http transport
    docker run --rm -p 9000:9000 \
      --env-file /path/to/your/.env \
      mcp-security-review:latest \
      --transport streamable-http --port 9000 -vv
    ```

2. Configure your IDE (single-user example):

    ```json
    {
      "mcpServers": {
        "mcp-security-review-http": {
          "url": "http://localhost:9000/sse"
        }
      }
    }
    ```
</details>

<details> <summary>Multi-User Authentication Setup</summary>

Here's a complete example of setting up multi-user authentication with streamable-HTTP transport:

1. First, run the OAuth setup wizard to configure the server's OAuth credentials:
   ```bash
   docker run --rm -i \
     -p 8080:8080 \
     -v "${HOME}/.mcp-security-review:/home/app/.mcp-security-review" \
     mcp-security-review:latest --oauth-setup -v
   ```

2. Start the server with streamable-HTTP transport:
   ```bash
   docker run --rm -p 9000:9000 \
     --env-file /path/to/your/.env \
     mcp-security-review:latest \
     --transport streamable-http --port 9000 -vv
   ```

3. Configure your IDE's MCP settings:

**Cloud (OAuth 2.0) Example:**
```json
{
  "mcpServers": {
    "mcp-security-review-service": {
      "url": "http://localhost:9000/mcp",
      "headers": {
        "Authorization": "Bearer <USER_OAUTH_ACCESS_TOKEN>"
      }
    }
  }
}
```
- Include the required env vars in your .env file

</details>

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

Licensed under MIT - see [LICENSE](LICENSE) file. This is not an official Atlassian product.
