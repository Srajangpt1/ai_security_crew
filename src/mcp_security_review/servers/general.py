"""General security tools that don't require specific providers."""

import json
import logging
from typing import Annotated

from fastmcp import Context, FastMCP
from pydantic import Field

from mcp_security_review.security import CodeReviewContextBuilder, SecurityAssessment

logger = logging.getLogger("mcp-security-review.servers.general")

general_mcp = FastMCP(
    name="General Security MCP",
    description="Provider-agnostic security tools for lightweight reviews and assessments.",
)


@general_mcp.tool(tags={"security", "review", "lightweight"})
async def lightweight_security_review(
    ctx: Context,
    task_description: Annotated[
        str, Field(description="Description of the coding task or feature to implement")
    ],
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
            "comments": [],
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
                ],
            },
        }

        if include_guidelines:
            response["assessment"]["guidelines"] = requirements.guidelines

        if include_prompt_injection:
            prompt_prefix = " PRE-CODING SECURITY REVIEW:\n\n"
            prompt_prefix += "⚡ IMPORTANT: Apply these security considerations BEFORE and DURING coding:\n\n"
            response["assessment"]["prompt_injection"] = (
                prompt_prefix + requirements.prompt_injection
            )

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
                "prompt_injection": "SECURITY REQUIREMENTS:\n\n Apply basic security practices:\n• Input validation\n• Output encoding\n• Secure authentication\n• Error handling\n• Logging and monitoring",
            },
        }

        return json.dumps(fallback_response, indent=2, ensure_ascii=False)


@general_mcp.tool(tags={"security", "verification", "code_review"})
async def verify_code_security(
    ctx: Context,
    code: Annotated[
        str,
        Field(
            description="The source code to review for security vulnerabilities."
        ),
    ],
    file_path: Annotated[
        str,
        Field(
            description="Optional file path to help identify the programming language (e.g., 'auth.py', 'api.js')",
            default="",
        ),
    ] = "",
    security_context: Annotated[
        str,
        Field(
            description="Optional JSON string with security requirements from a prior assessment (e.g., from lightweight_security_review or assess_ticket_security). Include 'security_categories', 'risk_level', and 'technologies'.",
            default="",
        ),
    ] = "",
) -> str:
    """Request an AI-powered security review of generated code.

    This tool prepares a comprehensive security review context and returns
    structured guidance for you (the AI agent) to analyze the code for
    security vulnerabilities.

    YOU (the AI) will perform the actual security analysis using:
    - The security checklist provided
    - The focus areas based on detected technologies
    - The security categories from prior assessments
    - Your knowledge of security best practices

    Recommended workflow:
    1. Run lightweight_security_review or assess_ticket_security BEFORE coding
    2. Generate code following the security guidelines
    3. Call this tool with the generated code
    4. Analyze the code following the review_prompt instructions
    5. Report findings and provide secure code fixes

    Args:
        ctx: The FastMCP context.
        code: The source code to review.
        file_path: Optional file path for language detection.
        security_context: Optional JSON with prior security requirements.

    Returns:
        JSON containing:
        - review_prompt: Detailed instructions for performing the security review
        - security_checklist: Items to verify in the code
        - focus_areas: Specific vulnerability types to look for
        - technologies_detected: Languages/frameworks identified
        - code: The code to review (for reference)

    After receiving this response, analyze the code and provide:
    1. Security assessment (Secure/Needs Attention/Insecure)
    2. List of vulnerabilities found with severity
    3. Specific code fixes for each issue
    4. Checklist results

    Example:
        verify_code_security(
            code="def login(username, password): ...",
            file_path="auth.py",
            security_context='{"security_categories": ["authentication"], "risk_level": "high"}'
        )
    """
    try:
        # Parse security context if provided
        parsed_context = None
        if security_context and security_context.strip():
            try:
                parsed_context = json.loads(security_context)
            except json.JSONDecodeError:
                logger.warning(
                    "Invalid JSON in security_context, proceeding without context"
                )

        # Build review context
        context_builder = CodeReviewContextBuilder()
        review_context = context_builder.build_review_context(
            code=code,
            file_path=file_path if file_path else None,
            security_context=parsed_context,
        )

        # Build response with all context needed for AI review
        response = {
            "success": True,
            "review_type": "ai_powered_security_review",
            "instructions": (
                "IMPORTANT: You (the AI agent) must now perform the security review. "
                "Analyze the code below using the provided checklist and focus areas. "
                "Report all security issues found with severity ratings and fixes."
            ),
            "review_prompt": review_context.review_prompt,
            "context": {
                "file_path": file_path if file_path else "not_specified",
                "technologies_detected": review_context.technologies_detected,
                "security_categories": review_context.security_categories,
                "risk_level": review_context.risk_level,
            },
            "security_checklist": review_context.security_checklist,
            "focus_areas": review_context.review_focus_areas,
            "code_to_review": code,
            "expected_response": {
                "format": "structured_security_review",
                "required_sections": [
                    "overall_assessment",
                    "findings_list",
                    "checklist_results",
                    "recommended_fixes",
                ],
            },
        }

        # Add prior requirements if context was provided
        if parsed_context:
            response["prior_requirements"] = {
                "from_assessment": True,
                "security_categories": parsed_context.get("security_categories", []),
                "technologies": parsed_context.get("technologies", []),
                "risk_level": parsed_context.get("risk_level", "medium"),
                "note": "Verify the code meets these previously identified security requirements.",
            }

        return json.dumps(response, indent=2, ensure_ascii=False)

    except Exception as e:
        error_message = str(e)
        logger.error(f"Failed to build security review context: {error_message}")

        # Even on error, provide basic review guidance
        fallback_response = {
            "success": False,
            "review_type": "ai_powered_security_review",
            "error": error_message,
            "instructions": (
                "Context building failed, but you should still review the code. "
                "Perform a general security review checking for common vulnerabilities."
            ),
            "fallback_checklist": [
                "No hardcoded passwords, API keys, or secrets",
                "No SQL injection vulnerabilities (use parameterized queries)",
                "No XSS vulnerabilities (sanitize user input in HTML)",
                "No command injection (avoid shell=True, validate inputs)",
                "Proper input validation on all user data",
                "Sensitive data not logged or exposed in errors",
                "Proper error handling without information disclosure",
                "Secure cryptographic practices (no MD5, SHA1 for security)",
            ],
            "code_to_review": code,
            "expected_response": {
                "format": "structured_security_review",
                "required_sections": [
                    "overall_assessment",
                    "findings_list",
                    "recommended_fixes",
                ],
            },
        }

        return json.dumps(fallback_response, indent=2, ensure_ascii=False)
