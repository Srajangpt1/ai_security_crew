"""Jira FastMCP server instance and tool definitions.

Provides only security-relevant Jira tools: issue retrieval for context
and ticket security assessment.
"""

import json
import logging
from typing import Annotated

from fastmcp import Context, FastMCP
from pydantic import Field

from mcp_security_review.providers.atlassian.jira.constants import (
    DEFAULT_READ_JIRA_FIELDS,
)
from mcp_security_review.security import SecurityAssessment
from mcp_security_review.servers.dependencies import get_jira_fetcher

logger = logging.getLogger(__name__)

jira_mcp = FastMCP(
    name="Jira MCP Service",
    description="Provides security-focused tools for Jira integration.",
)


@jira_mcp.tool(tags={"jira", "read"})
async def get_issue(
    ctx: Context,
    issue_key: Annotated[str, Field(description="Jira issue key (e.g., 'PROJ-123')")],
    fields: Annotated[
        str,
        Field(
            description=(
                "(Optional) Comma-separated list of fields to return "
                "(e.g., 'summary,status,customfield_10010'). "
                "Use '*all' for all fields, or omit for essential fields only."
            ),
            default=",".join(DEFAULT_READ_JIRA_FIELDS),
        ),
    ] = ",".join(DEFAULT_READ_JIRA_FIELDS),
    expand: Annotated[
        str | None,
        Field(
            description=(
                "(Optional) Fields to expand. Examples: 'renderedFields' "
                "(for rendered content), 'transitions' (for available "
                "status transitions), 'changelog' (for history)"
            ),
            default=None,
        ),
    ] = None,
    comment_limit: Annotated[
        int,
        Field(
            description=(
                "Maximum number of comments to include (0 or null for no comments)"
            ),
            default=10,
            ge=0,
            le=100,
        ),
    ] = 10,
    properties: Annotated[
        str | None,
        Field(
            description=(
                "(Optional) A comma-separated list of issue properties to return"
            ),
            default=None,
        ),
    ] = None,
    update_history: Annotated[  # noqa: FBT002
        bool,
        Field(
            description=(
                "Whether to update the issue view history for the requesting user"
            ),
            default=True,
        ),
    ] = True,
) -> str:
    """Get details of a specific Jira issue.

    Includes Epic links and relationship information.

    Args:
        ctx: The FastMCP context.
        issue_key: Jira issue key.
        fields: Comma-separated list of fields to return.
        expand: Optional fields to expand.
        comment_limit: Maximum number of comments.
        properties: Issue properties to return.
        update_history: Whether to update issue view history.

    Returns:
        JSON string representing the Jira issue object.

    Raises:
        ValueError: If the Jira client is not configured or available.
    """
    jira = await get_jira_fetcher(ctx)
    fields_list: str | list[str] | None = fields
    if fields and fields != "*all":
        fields_list = [f.strip() for f in fields.split(",")]

    issue = jira.get_issue(
        issue_key=issue_key,
        fields=fields_list,
        expand=expand,
        comment_limit=comment_limit,
        properties=properties.split(",") if properties else None,
        update_history=update_history,
    )
    result = issue.to_simplified_dict()
    return json.dumps(result, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "read", "security"})
async def assess_ticket_security(
    ctx: Context,
    issue_key: Annotated[str, Field(description="Jira issue key (e.g., 'PROJ-123')")],
    include_guidelines: Annotated[  # noqa: FBT002
        bool,
        Field(
            description=(
                "Whether to include detailed security guidelines in the response"
            ),
            default=True,
        ),
    ] = True,
    include_prompt_injection: Annotated[  # noqa: FBT002
        bool,
        Field(
            description=(
                "Whether to include formatted prompt injection for code generation"
            ),
            default=True,
        ),
    ] = True,
) -> str:
    """Perform a comprehensive security assessment of a Jira ticket.

    This tool analyzes a Jira ticket for security implications and generates
    security requirements that can be injected into code generation prompts.
    It identifies technologies, security risks, and provides specific guidelines
    following OWASP and industry best practices.

    For quick security guidance without a Jira ticket, use
    'lightweight_security_review' instead. This tool is best when you have
    a specific Jira issue that needs thorough security analysis.

    Args:
        ctx: The FastMCP context.
        issue_key: Jira issue key to assess.
        include_guidelines: Whether to include detailed security guidelines.
        include_prompt_injection: Whether to include formatted prompt injection.

    Returns:
        JSON string containing security assessment results including:
        - Risk level (low/medium/high/critical)
        - Identified technologies
        - Security categories
        - Specific security guidelines
        - Formatted prompt injection for code generation
        - Assessment summary

    Raises:
        ValueError: If the Jira client is not configured or issue not found.
    """
    jira = await get_jira_fetcher(ctx)

    try:
        # Get the full issue data
        issue = jira.get_issue(
            issue_key=issue_key,
            fields="*all",
            expand="renderedFields,changelog",
            comment_limit=20,
        )

        # Convert issue to dict for analysis
        issue_data = issue.to_simplified_dict()

        # Perform security assessment
        security_assessment = SecurityAssessment()
        requirements = security_assessment.assess_ticket(issue_data)

        # Build response
        response: dict = {
            "success": True,
            "issue_key": issue_key,
            "assessment": {
                "risk_level": requirements.risk_level,
                "security_categories": requirements.security_categories,
                "technologies": requirements.technologies,
                "summary": requirements.summary,
            },
        }

        if include_guidelines:
            response["assessment"]["guidelines"] = requirements.guidelines

        if include_prompt_injection:
            response["assessment"]["prompt_injection"] = requirements.prompt_injection

        response["metadata"] = {
            "total_guidelines": len(requirements.guidelines),
            "assessment_timestamp": issue_data.get("updated", ""),
            "issue_type": issue_data.get("fields", {})
            .get("issuetype", {})
            .get("name", ""),
            "issue_status": issue_data.get("fields", {})
            .get("status", {})
            .get("name", ""),
        }

        return json.dumps(response, indent=2, ensure_ascii=False)

    except (ValueError, KeyError, TypeError, OSError) as e:
        error_message = str(e)
        logger.error(f"Security assessment failed for {issue_key}: {error_message}")

        error_response: dict = {
            "success": False,
            "issue_key": issue_key,
            "error": error_message,
            "assessment": {
                "risk_level": "unknown",
                "security_categories": [],
                "technologies": [],
                "summary": "Assessment failed due to error",
            },
        }

        return json.dumps(error_response, indent=2, ensure_ascii=False)
