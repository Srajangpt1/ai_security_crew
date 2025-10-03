"""General security tools that don't require specific providers."""

import json
import logging
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from mcp_security_review.security import SecurityAssessment

from .context import Context

logger = logging.getLogger("mcp-security-review.servers.general")

general_mcp = FastMCP(
    name="General Security MCP",
    description="Provider-agnostic security tools for lightweight reviews and assessments."
)


@general_mcp.tool(tags={"security", "review", "lightweight"})
async def lightweight_security_review(
    ctx: Context,
    task_description: Annotated[str, Field(description="Description of the coding task or feature to implement")],
    technologies: Annotated[
        str,
        Field(
            description="Technologies/frameworks involved (e.g., 'Python, Django, PostgreSQL')",
            default="",
        ),
    ] = "",
    include_guidelines: Annotated[
        bool,
        Field(
            description="Whether to include detailed security guidelines in the response",
            default=True,
        ),
    ] = True,
    include_prompt_injection: Annotated[
        bool,
        Field(
            description="Whether to include formatted prompt injection for code generation",
            default=True,
        ),
    ] = True,
) -> str:
    """Perform a lightweight security review before coding without requiring a Jira ticket.

    This tool provides immediate security guidance for any coding task, helping developers
    build security considerations into their work from the start. It's designed for the
    "vibe coding" workflow where you want quick, actionable security advice before writing code.

    Use this BEFORE starting any coding task to:
    - Identify potential security risks early
    - Get relevant security guidelines for your tech stack
    - Generate security-aware prompts for AI code generation
    - Ensure security is built-in, not bolted-on

    Args:
        ctx: The FastMCP context.
        task_description: What you're planning to build or implement.
        technologies: Tech stack involved (optional but recommended).
        include_guidelines: Whether to include detailed security guidelines.
        include_prompt_injection: Whether to include formatted prompt injection.

    Returns:
        JSON string containing security review results including:
        - Risk level assessment
        - Relevant security categories
        - Technology-specific security considerations
        - Actionable security guidelines
        - Formatted prompt injection for secure code generation

    Example:
        lightweight_security_review("Build user login form with password reset", "React, Node.js, PostgreSQL")
    """
    try:
        synthetic_ticket = {
            "summary": task_description,
            "description": f"Task: {task_description}\nTechnologies: {technologies}",
            "fields": {
                "issuetype": {"name": "Development Task"},
                "priority": {"name": "Medium"},
                "labels": technologies.lower().split(", ") if technologies else [],
            },
            "comments": []
        }
        
        security_assessment = SecurityAssessment()
        requirements = security_assessment.assess_ticket(synthetic_ticket)
        
        response = {
            "success": True,
            "task_description": task_description,
            "review_type": "lightweight_pre_coding",
            "assessment": {
                "risk_level": requirements.risk_level,
                "security_categories": requirements.security_categories,
                "technologies": requirements.technologies,
                "summary": f"Pre-coding security review: {requirements.summary}",
                "recommendations": [
                    "Review security guidelines before implementing",
                    "Use the provided prompt injection for AI code generation",
                    "Consider security implications at each development step",
                    "Validate all inputs and sanitize outputs",
                    "Follow principle of least privilege",
                ]
            }
        }
        
        if include_guidelines:
            response["assessment"]["guidelines"] = requirements.guidelines
        
        if include_prompt_injection:
            prompt_prefix = " PRE-CODING SECURITY REVIEW:\n\n"
            prompt_prefix += "⚡ IMPORTANT: Apply these security considerations BEFORE and DURING coding:\n\n"
            response["assessment"]["prompt_injection"] = prompt_prefix + requirements.prompt_injection
        
        response["metadata"] = {
            "total_guidelines": len(requirements.guidelines),
            "review_timestamp": "pre-coding",
            "review_purpose": "lightweight_security_guidance",
            "integration_workflow": "vibe_coding",
        }
        
        return json.dumps(response, indent=2, ensure_ascii=False)
        
    except Exception as e:
        error_message = str(e)
        logger.error(f"Lightweight security review failed: {error_message}")
        
        fallback_response = {
            "success": False,
            "task_description": task_description,
            "error": error_message,
            "assessment": {
                "risk_level": "medium",
                "security_categories": ["general"],
                "technologies": technologies.split(", ") if technologies else [],
                "summary": "Basic security review (fallback due to error)",
                "recommendations": [
                    "Validate all inputs",
                    "Use parameterized queries for databases",
                    "Implement proper authentication and authorization",
                    "Log security events appropriately",
                    "Handle errors securely without information disclosure",
                ],
                "prompt_injection": "SECURITY REQUIREMENTS:\n\n Apply basic security practices:\n• Input validation\n• Output encoding\n• Secure authentication\n• Error handling\n• Logging and monitoring"
            }
        }
        
        return json.dumps(fallback_response, indent=2, ensure_ascii=False)
