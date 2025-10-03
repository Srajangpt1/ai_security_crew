# AGENTS

> **Audience**: LLM-driven engineering agents

This file provides guidance for autonomous coding agents working inside the **AI Security Crew** repository.

---

## Repository map

| Path | Purpose |
| --- | --- |
| `src/mcp_security_review/` | Library source code (Python ≥ 3.10) |
| `  ├─ providers/atlassian/` | Atlassian service providers (Jira, Confluence) |
| `  ├─ models/atlassian/` | Pydantic data models for Atlassian APIs |
| `  ├─ servers/` | FastMCP server implementations |
| `  ├─ security/` | Security assessment and guidelines |
| `  └─ utils/` | Shared utilities (auth, logging, SSL) |
| `tests/` | Pytest test suite with fixtures |
| `scripts/` | OAuth setup and testing scripts |

---

## Mandatory dev workflow

```bash
uv sync --frozen --all-extras --dev  # install dependencies
pre-commit install                    # setup hooks
pre-commit run --all-files           # Ruff + Prettier + Pyright
uv run pytest                        # run full test suite
```

*Tests must pass* and *lint/typing must be clean* before committing.

---

## Core MCP patterns

**Tool naming**: `{provider}_{service}_{action}` (e.g., `atlassian_jira_create_issue`)

**Architecture**:
- **Mixins**: Functionality split into focused mixins extending base clients
- **Models**: All data structures extend `ApiModel` base class
- **Auth**: Supports API tokens, PAT tokens, and OAuth 2.0

---

## Development rules

1. **Package management**: ONLY use `uv`, NEVER `pip`
2. **Branching**: NEVER work on `main`, always create feature branches
3. **Type safety**: All functions require type hints
4. **Testing**: New features need tests, bug fixes need regression tests
5. **Commits**: Use trailers for attribution, never mention tools/AI

---

## Code conventions

* **Language**: Python ≥ 3.10
* **Line length**: 88 characters maximum
* **Imports**: Absolute imports, sorted by ruff
* **Naming**: `snake_case` functions, `PascalCase` classes
* **Docstrings**: Google-style for all public APIs
* **Error handling**: Specific exceptions only

---

## Development guidelines

1. Do what has been asked; nothing more, nothing less
2. NEVER create files unless absolutely necessary
3. Always prefer editing existing files
4. Follow established patterns and maintain consistency
5. Run `pre-commit run --all-files` before committing
6. Fix bugs immediately when reported

---

## Quick reference

```bash
# Running the server
uv run mcp-security-review                 # Start server
uv run mcp-security-review --oauth-setup   # OAuth wizard
uv run mcp-security-review -v              # Verbose mode

# Git workflow
git checkout -b feature/description   # New feature
git checkout -b fix/issue-description # Bug fix
git commit --trailer "Reported-by:<name>"      # Attribution
git commit --trailer "Github-Issue:#<number>"  # Issue reference
```
