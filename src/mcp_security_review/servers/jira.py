"""Jira FastMCP server instance and tool definitions."""

import json
import logging
from typing import Annotated, Any

from fastmcp import Context, FastMCP
from pydantic import Field
from requests.exceptions import HTTPError

from mcp_security_review.exceptions import MCPAtlassianAuthenticationError
from mcp_security_review.models.atlassian.jira.common import JiraUser
from mcp_security_review.providers.atlassian.jira.constants import (
    DEFAULT_READ_JIRA_FIELDS,
)
from mcp_security_review.security import SecurityAssessment
from mcp_security_review.servers.dependencies import get_jira_fetcher
from mcp_security_review.utils.decorators import check_write_access

logger = logging.getLogger(__name__)

jira_mcp = FastMCP(
    name="Jira MCP Service",
    description="Provides tools for interacting with Atlassian Jira.",
)


@jira_mcp.tool(tags={"jira", "read"})
async def get_user_profile(
    ctx: Context,
    user_identifier: Annotated[
        str,
        Field(
            description="Identifier for the user (e.g., email address 'user@example.com', username 'johndoe', account ID 'accountid:...', or key for Server/DC)."
        ),
    ],
) -> str:
    """
    Retrieve profile information for a specific Jira user.

    Args:
        ctx: The FastMCP context.
        user_identifier: User identifier (email, username, key, or account ID).

    Returns:
        JSON string representing the Jira user profile object, or an error object if not found.

    Raises:
        ValueError: If the Jira client is not configured or available.
    """
    jira = await get_jira_fetcher(ctx)
    try:
        user: JiraUser = jira.get_user_profile_by_identifier(user_identifier)
        result = user.to_simplified_dict()
        response_data = {"success": True, "user": result}
    except Exception as e:
        error_message = ""
        log_level = logging.ERROR
        if isinstance(e, ValueError) and "not found" in str(e).lower():
            log_level = logging.WARNING
            error_message = str(e)
        elif isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        else:
            error_message = (
                "An unexpected error occurred while fetching the user profile."
            )
            logger.exception(
                f"Unexpected error in get_user_profile for '{user_identifier}':"
            )
        error_result = {
            "success": False,
            "error": str(e),
            "user_identifier": user_identifier,
        }
        logger.log(
            log_level,
            f"get_user_profile failed for '{user_identifier}': {error_message}",
        )
        response_data = error_result
    return json.dumps(response_data, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "read"})
async def get_issue(
    ctx: Context,
    issue_key: Annotated[str, Field(description="Jira issue key (e.g., 'PROJ-123')")],
    fields: Annotated[
        str,
        Field(
            description=(
                "(Optional) Comma-separated list of fields to return (e.g., 'summary,status,customfield_10010'). "
                "You may also provide a single field as a string (e.g., 'duedate'). "
                "Use '*all' for all fields (including custom fields), or omit for essential fields only."
            ),
            default=",".join(DEFAULT_READ_JIRA_FIELDS),
        ),
    ] = ",".join(DEFAULT_READ_JIRA_FIELDS),
    expand: Annotated[
        str | None,
        Field(
            description=(
                "(Optional) Fields to expand. Examples: 'renderedFields' (for rendered content), "
                "'transitions' (for available status transitions), 'changelog' (for history)"
            ),
            default=None,
        ),
    ] = None,
    comment_limit: Annotated[
        int,
        Field(
            description="Maximum number of comments to include (0 or null for no comments)",
            default=10,
            ge=0,
            le=100,
        ),
    ] = 10,
    properties: Annotated[
        str | None,
        Field(
            description="(Optional) A comma-separated list of issue properties to return",
            default=None,
        ),
    ] = None,
    update_history: Annotated[
        bool,
        Field(
            description="Whether to update the issue view history for the requesting user",
            default=True,
        ),
    ] = True,
) -> str:
    """Get details of a specific Jira issue including its Epic links and relationship information.

    Args:
        ctx: The FastMCP context.
        issue_key: Jira issue key.
        fields: Comma-separated list of fields to return (e.g., 'summary,status,customfield_10010'), a single field as a string (e.g., 'duedate'), '*all' for all fields, or omitted for essentials.
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


@jira_mcp.tool(tags={"jira", "read"})
async def search(
    ctx: Context,
    jql: Annotated[
        str,
        Field(
            description=(
                "JQL query string (Jira Query Language). Examples:\n"
                '- Find Epics: "issuetype = Epic AND project = PROJ"\n'
                '- Find issues in Epic: "parent = PROJ-123"\n'
                "- Find by status: \"status = 'In Progress' AND project = PROJ\"\n"
                '- Find by assignee: "assignee = currentUser()"\n'
                '- Find recently updated: "updated >= -7d AND project = PROJ"\n'
                '- Find by label: "labels = frontend AND project = PROJ"\n'
                '- Find by priority: "priority = High AND project = PROJ"'
            )
        ),
    ],
    fields: Annotated[
        str,
        Field(
            description=(
                "(Optional) Comma-separated fields to return in the results. "
                "Use '*all' for all fields, or specify individual fields like 'summary,status,assignee,priority'"
            ),
            default=",".join(DEFAULT_READ_JIRA_FIELDS),
        ),
    ] = ",".join(DEFAULT_READ_JIRA_FIELDS),
    limit: Annotated[
        int,
        Field(description="Maximum number of results (1-50)", default=10, ge=1),
    ] = 10,
    start_at: Annotated[
        int,
        Field(description="Starting index for pagination (0-based)", default=0, ge=0),
    ] = 0,
    projects_filter: Annotated[
        str | None,
        Field(
            description=(
                "(Optional) Comma-separated list of project keys to filter results by. "
                "Overrides the environment variable JIRA_PROJECTS_FILTER if provided."
            ),
            default=None,
        ),
    ] = None,
    expand: Annotated[
        str | None,
        Field(
            description=(
                "(Optional) fields to expand. Examples: 'renderedFields', 'transitions', 'changelog'"
            ),
            default=None,
        ),
    ] = None,
) -> str:
    """Search Jira issues using JQL (Jira Query Language).

    Args:
        ctx: The FastMCP context.
        jql: JQL query string.
        fields: Comma-separated fields to return.
        limit: Maximum number of results.
        start_at: Starting index for pagination.
        projects_filter: Comma-separated list of project keys to filter by.
        expand: Optional fields to expand.

    Returns:
        JSON string representing the search results including pagination info.
    """
    jira = await get_jira_fetcher(ctx)
    fields_list: str | list[str] | None = fields
    if fields and fields != "*all":
        fields_list = [f.strip() for f in fields.split(",")]

    search_result = jira.search_issues(
        jql=jql,
        fields=fields_list,
        limit=limit,
        start=start_at,
        expand=expand,
        projects_filter=projects_filter,
    )
    result = search_result.to_simplified_dict()
    return json.dumps(result, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "read"})
async def get_transitions(
    ctx: Context,
    issue_key: Annotated[str, Field(description="Jira issue key (e.g., 'PROJ-123')")],
) -> str:
    """Get available status transitions for a Jira issue.

    Args:
        ctx: The FastMCP context.
        issue_key: Jira issue key.

    Returns:
        JSON string representing a list of available transitions.
    """
    jira = await get_jira_fetcher(ctx)
    # Underlying method returns list[dict] in the desired format
    transitions = jira.get_available_transitions(issue_key)
    return json.dumps(transitions, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "read"})
async def download_attachments(
    ctx: Context,
    issue_key: Annotated[str, Field(description="Jira issue key (e.g., 'PROJ-123')")],
    target_dir: Annotated[
        str, Field(description="Directory where attachments should be saved")
    ],
) -> str:
    """Download attachments from a Jira issue.

    Args:
        ctx: The FastMCP context.
        issue_key: Jira issue key.
        target_dir: Directory to save attachments.

    Returns:
        JSON string indicating the result of the download operation.
    """
    jira = await get_jira_fetcher(ctx)
    result = jira.download_issue_attachments(issue_key=issue_key, target_dir=target_dir)
    return json.dumps(result, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "read"})
async def get_link_types(ctx: Context) -> str:
    """Get all available issue link types.

    Args:
        ctx: The FastMCP context.

    Returns:
        JSON string representing a list of issue link type objects.
    """
    jira = await get_jira_fetcher(ctx)
    link_types = jira.get_issue_link_types()
    formatted_link_types = [link_type.to_simplified_dict() for link_type in link_types]
    return json.dumps(formatted_link_types, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "write"})
@check_write_access
async def create_issue(
    ctx: Context,
    project_key: Annotated[
        str,
        Field(
            description=(
                "The JIRA project key (e.g. 'PROJ', 'DEV', 'SUPPORT'). "
                "This is the prefix of issue keys in your project. "
                "Never assume what it might be, always ask the user."
            )
        ),
    ],
    summary: Annotated[str, Field(description="Summary/title of the issue")],
    issue_type: Annotated[
        str,
        Field(
            description=(
                "Issue type (e.g. 'Task', 'Bug', 'Story', 'Epic', 'Subtask'). "
                "The available types depend on your project configuration. "
                "For subtasks, use 'Subtask' (not 'Sub-task') and include parent in additional_fields."
            ),
        ),
    ],
    assignee: Annotated[
        str | None,
        Field(
            description="(Optional) Assignee's user identifier (string): Email, display name, or account ID (e.g., 'user@example.com', 'John Doe', 'accountid:...')",
            default=None,
        ),
    ] = None,
    description: Annotated[
        str | None, Field(description="Issue description", default=None)
    ] = None,
    components: Annotated[
        str | None,
        Field(
            description="(Optional) Comma-separated list of component names to assign (e.g., 'Frontend,API')",
            default=None,
        ),
    ] = None,
    additional_fields: Annotated[
        dict[str, Any] | None,
        Field(
            description=(
                "(Optional) Dictionary of additional fields to set. Examples:\n"
                "- Set priority: {'priority': {'name': 'High'}}\n"
                "- Add labels: {'labels': ['frontend', 'urgent']}\n"
                "- Link to parent (for any issue type): {'parent': 'PROJ-123'}\n"
                "- Set Fix Version/s: {'fixVersions': [{'id': '10020'}]}\n"
                "- Custom fields: {'customfield_10010': 'value'}"
            ),
            default=None,
        ),
    ] = None,
) -> str:
    """Create a new Jira issue with optional Epic link or parent for subtasks.

    Args:
        ctx: The FastMCP context.
        project_key: The JIRA project key.
        summary: Summary/title of the issue.
        issue_type: Issue type (e.g., 'Task', 'Bug', 'Story', 'Epic', 'Subtask').
        assignee: Assignee's user identifier (string): Email, display name, or account ID (e.g., 'user@example.com', 'John Doe', 'accountid:...').
        description: Issue description.
        components: Comma-separated list of component names.
        additional_fields: Dictionary of additional fields.

    Returns:
        JSON string representing the created issue object.

    Raises:
        ValueError: If in read-only mode or Jira client is unavailable.
    """
    jira = await get_jira_fetcher(ctx)
    # Parse components from comma-separated string to list
    components_list = None
    if components and isinstance(components, str):
        components_list = [
            comp.strip() for comp in components.split(",") if comp.strip()
        ]

    # Use additional_fields directly as dict
    extra_fields = additional_fields or {}
    if not isinstance(extra_fields, dict):
        raise ValueError("additional_fields must be a dictionary.")

    issue = jira.create_issue(
        project_key=project_key,
        summary=summary,
        issue_type=issue_type,
        description=description,
        assignee=assignee,
        components=components_list,
        **extra_fields,
    )
    result = issue.to_simplified_dict()
    return json.dumps(
        {"message": "Issue created successfully", "issue": result},
        indent=2,
        ensure_ascii=False,
    )


@jira_mcp.tool(tags={"jira", "write"})
@check_write_access
async def batch_create_issues(
    ctx: Context,
    issues: Annotated[
        str,
        Field(
            description=(
                "JSON array of issue objects. Each object should contain:\n"
                "- project_key (required): The project key (e.g., 'PROJ')\n"
                "- summary (required): Issue summary/title\n"
                "- issue_type (required): Type of issue (e.g., 'Task', 'Bug')\n"
                "- description (optional): Issue description\n"
                "- assignee (optional): Assignee username or email\n"
                "- components (optional): Array of component names\n"
                "Example: [\n"
                '  {"project_key": "PROJ", "summary": "Issue 1", "issue_type": "Task"},\n'
                '  {"project_key": "PROJ", "summary": "Issue 2", "issue_type": "Bug", "components": ["Frontend"]}\n'
                "]"
            )
        ),
    ],
    validate_only: Annotated[
        bool,
        Field(
            description="If true, only validates the issues without creating them",
            default=False,
        ),
    ] = False,
) -> str:
    """Create multiple Jira issues in a batch.

    Args:
        ctx: The FastMCP context.
        issues: JSON array string of issue objects.
        validate_only: If true, only validates without creating.

    Returns:
        JSON string indicating success and listing created issues (or validation result).

    Raises:
        ValueError: If in read-only mode, Jira client unavailable, or invalid JSON.
    """
    jira = await get_jira_fetcher(ctx)
    # Parse issues from JSON string
    try:
        issues_list = json.loads(issues)
        if not isinstance(issues_list, list):
            raise ValueError("Input 'issues' must be a JSON array string.")
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON in issues")
    except Exception as e:
        raise ValueError(f"Invalid input for issues: {e}") from e

    # Create issues in batch
    created_issues = jira.batch_create_issues(issues_list, validate_only=validate_only)

    message = (
        "Issues validated successfully"
        if validate_only
        else "Issues created successfully"
    )
    result = {
        "message": message,
        "issues": [issue.to_simplified_dict() for issue in created_issues],
    }
    return json.dumps(result, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "read"})
async def batch_get_changelogs(
    ctx: Context,
    issue_ids_or_keys: Annotated[
        list[str],
        Field(
            description="List of Jira issue IDs or keys, e.g. ['PROJ-123', 'PROJ-124']"
        ),
    ],
    fields: Annotated[
        list[str] | None,
        Field(
            description="(Optional) Filter the changelogs by fields, e.g. ['status', 'assignee']. Default to None for all fields.",
            default=None,
        ),
    ] = None,
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum number of changelogs to return in result for each issue. "
                "Default to -1 for all changelogs. "
                "Notice that it only limits the results in the response, "
                "the function will still fetch all the data."
            ),
            default=-1,
        ),
    ] = -1,
) -> str:
    """Get changelogs for multiple Jira issues (Cloud only).

    Args:
        ctx: The FastMCP context.
        issue_ids_or_keys: List of issue IDs or keys.
        fields: List of fields to filter changelogs by. None for all fields.
        limit: Maximum changelogs per issue (-1 for all).

    Returns:
        JSON string representing a list of issues with their changelogs.

    Raises:
        NotImplementedError: If run on Jira Server/Data Center.
        ValueError: If Jira client is unavailable.
    """
    jira = await get_jira_fetcher(ctx)
    # Ensure this runs only on Cloud, as per original function docstring
    if not jira.config.is_cloud:
        raise NotImplementedError(
            "Batch get issue changelogs is only available on Jira Cloud."
        )

    # Call the underlying method
    issues_with_changelogs = jira.batch_get_changelogs(
        issue_ids_or_keys=issue_ids_or_keys, fields=fields
    )

    # Format the response
    results = []
    limit_val = None if limit == -1 else limit
    for issue in issues_with_changelogs:
        results.append(
            {
                "issue_id": issue.id,
                "changelogs": [
                    changelog.to_simplified_dict()
                    for changelog in issue.changelogs[:limit_val]
                ],
            }
        )
    return json.dumps(results, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "write"})
@check_write_access
async def update_issue(
    ctx: Context,
    issue_key: Annotated[str, Field(description="Jira issue key (e.g., 'PROJ-123')")],
    fields: Annotated[
        dict[str, Any],
        Field(
            description=(
                "Dictionary of fields to update. For 'assignee', provide a string identifier (email, name, or accountId). "
                "Example: `{'assignee': 'user@example.com', 'summary': 'New Summary'}`"
            )
        ),
    ],
    additional_fields: Annotated[
        dict[str, Any] | None,
        Field(
            description="(Optional) Dictionary of additional fields to update. Use this for custom fields or more complex updates.",
            default=None,
        ),
    ] = None,
    attachments: Annotated[
        str | None,
        Field(
            description=(
                "(Optional) JSON string array or comma-separated list of file paths to attach to the issue. "
                "Example: '/path/to/file1.txt,/path/to/file2.txt' or ['/path/to/file1.txt','/path/to/file2.txt']"
            ),
            default=None,
        ),
    ] = None,
) -> str:
    """Update an existing Jira issue including changing status, adding Epic links, updating fields, etc.

    Args:
        ctx: The FastMCP context.
        issue_key: Jira issue key.
        fields: Dictionary of fields to update.
        additional_fields: Optional dictionary of additional fields.
        attachments: Optional JSON array string or comma-separated list of file paths.

    Returns:
        JSON string representing the updated issue object and attachment results.

    Raises:
        ValueError: If in read-only mode or Jira client unavailable, or invalid input.
    """
    jira = await get_jira_fetcher(ctx)
    # Use fields directly as dict
    if not isinstance(fields, dict):
        raise ValueError("fields must be a dictionary.")
    update_fields = fields

    # Use additional_fields directly as dict
    extra_fields = additional_fields or {}
    if not isinstance(extra_fields, dict):
        raise ValueError("additional_fields must be a dictionary.")

    # Parse attachments
    attachment_paths = []
    if attachments:
        if isinstance(attachments, str):
            try:
                parsed = json.loads(attachments)
                if isinstance(parsed, list):
                    attachment_paths = [str(p) for p in parsed]
                else:
                    raise ValueError("attachments JSON string must be an array.")
            except json.JSONDecodeError:
                # Assume comma-separated if not valid JSON array
                attachment_paths = [
                    p.strip() for p in attachments.split(",") if p.strip()
                ]
        else:
            raise ValueError(
                "attachments must be a JSON array string or comma-separated string."
            )

    # Combine fields and additional_fields
    all_updates = {**update_fields, **extra_fields}
    if attachment_paths:
        all_updates["attachments"] = attachment_paths

    try:
        issue = jira.update_issue(issue_key=issue_key, **all_updates)
        result = issue.to_simplified_dict()
        if (
            hasattr(issue, "custom_fields")
            and "attachment_results" in issue.custom_fields
        ):
            result["attachment_results"] = issue.custom_fields["attachment_results"]
        return json.dumps(
            {"message": "Issue updated successfully", "issue": result},
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        logger.error(f"Error updating issue {issue_key}: {str(e)}", exc_info=True)
        raise ValueError(f"Failed to update issue {issue_key}: {str(e)}")


@jira_mcp.tool(tags={"jira", "write"})
@check_write_access
async def delete_issue(
    ctx: Context,
    issue_key: Annotated[str, Field(description="Jira issue key (e.g. PROJ-123)")],
) -> str:
    """Delete an existing Jira issue.

    Args:
        ctx: The FastMCP context.
        issue_key: Jira issue key.

    Returns:
        JSON string indicating success.

    Raises:
        ValueError: If in read-only mode or Jira client unavailable.
    """
    jira = await get_jira_fetcher(ctx)
    deleted = jira.delete_issue(issue_key)
    result = {"message": f"Issue {issue_key} has been deleted successfully."}
    # The underlying method raises on failure, so if we reach here, it's success.
    return json.dumps(result, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "write"})
@check_write_access
async def add_comment(
    ctx: Context,
    issue_key: Annotated[str, Field(description="Jira issue key (e.g., 'PROJ-123')")],
    comment: Annotated[str, Field(description="Comment text in Markdown format")],
) -> str:
    """Add a comment to a Jira issue.

    Args:
        ctx: The FastMCP context.
        issue_key: Jira issue key.
        comment: Comment text in Markdown.

    Returns:
        JSON string representing the added comment object.

    Raises:
        ValueError: If in read-only mode or Jira client unavailable.
    """
    jira = await get_jira_fetcher(ctx)
    # add_comment returns dict
    result = jira.add_comment(issue_key, comment)
    return json.dumps(result, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "write"})
@check_write_access
async def link_to_epic(
    ctx: Context,
    issue_key: Annotated[
        str, Field(description="The key of the issue to link (e.g., 'PROJ-123')")
    ],
    epic_key: Annotated[
        str, Field(description="The key of the epic to link to (e.g., 'PROJ-456')")
    ],
) -> str:
    """Link an existing issue to an epic.

    Args:
        ctx: The FastMCP context.
        issue_key: The key of the issue to link.
        epic_key: The key of the epic to link to.

    Returns:
        JSON string representing the updated issue object.

    Raises:
        ValueError: If in read-only mode or Jira client unavailable.
    """
    jira = await get_jira_fetcher(ctx)
    issue = jira.link_issue_to_epic(issue_key, epic_key)
    result = {
        "message": f"Issue {issue_key} has been linked to epic {epic_key}.",
        "issue": issue.to_simplified_dict(),
    }
    return json.dumps(result, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "write"})
@check_write_access
async def transition_issue(
    ctx: Context,
    issue_key: Annotated[str, Field(description="Jira issue key (e.g., 'PROJ-123')")],
    transition_id: Annotated[
        str,
        Field(
            description=(
                "ID of the transition to perform. Use the jira_get_transitions tool first "
                "to get the available transition IDs for the issue. Example values: '11', '21', '31'"
            )
        ),
    ],
    fields: Annotated[
        dict[str, Any] | None,
        Field(
            description=(
                "(Optional) Dictionary of fields to update during the transition. "
                "Some transitions require specific fields to be set (e.g., resolution). "
                "Example: {'resolution': {'name': 'Fixed'}}"
            ),
            default=None,
        ),
    ] = None,
    comment: Annotated[
        str | None,
        Field(
            description=(
                "(Optional) Comment to add during the transition. "
                "This will be visible in the issue history."
            ),
        ),
    ] = None,
) -> str:
    """Transition a Jira issue to a new status.

    Args:
        ctx: The FastMCP context.
        issue_key: Jira issue key.
        transition_id: ID of the transition.
        fields: Optional dictionary of fields to update during transition.
        comment: Optional comment for the transition.

    Returns:
        JSON string representing the updated issue object.

    Raises:
        ValueError: If required fields missing, invalid input, in read-only mode, or Jira client unavailable.
    """
    jira = await get_jira_fetcher(ctx)
    if not issue_key or not transition_id:
        raise ValueError("issue_key and transition_id are required.")

    # Use fields directly as dict
    update_fields = fields or {}
    if not isinstance(update_fields, dict):
        raise ValueError("fields must be a dictionary.")

    issue = jira.transition_issue(
        issue_key=issue_key,
        transition_id=transition_id,
        fields=update_fields,
        comment=comment,
    )

    result = {
        "message": f"Issue {issue_key} transitioned successfully",
        "issue": issue.to_simplified_dict() if issue else None,
    }
    return json.dumps(result, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "read"})
async def get_all_projects(
    ctx: Context,
    include_archived: Annotated[
        bool,
        Field(
            description="Whether to include archived projects in the results",
            default=False,
        ),
    ] = False,
) -> str:
    """Get all Jira projects accessible to the current user.

    Args:
        ctx: The FastMCP context.
        include_archived: Whether to include archived projects.

    Returns:
        JSON string representing a list of project objects accessible to the user.
        Project keys are always returned in uppercase.
        If JIRA_PROJECTS_FILTER is configured, only returns projects matching those keys.

    Raises:
        ValueError: If the Jira client is not configured or available.
    """
    try:
        jira = await get_jira_fetcher(ctx)
        projects = jira.get_all_projects(include_archived=include_archived)
    except (MCPAtlassianAuthenticationError, HTTPError, OSError, ValueError) as e:
        error_message = ""
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"get_all_projects failed: {error_message}")
        return json.dumps(error_result, indent=2, ensure_ascii=False)

    # Ensure all project keys are uppercase
    for project in projects:
        if "key" in project:
            project["key"] = project["key"].upper()

    # Apply project filter if configured
    if jira.config.projects_filter:
        # Split projects filter by commas and handle possible whitespace
        allowed_project_keys = {
            p.strip().upper() for p in jira.config.projects_filter.split(",")
        }
        projects = [
            project
            for project in projects
            if project.get("key") in allowed_project_keys
        ]

    return json.dumps(projects, indent=2, ensure_ascii=False)


@jira_mcp.tool(tags={"jira", "read", "security"})
async def assess_ticket_security(
    ctx: Context,
    issue_key: Annotated[str, Field(description="Jira issue key (e.g., 'PROJ-123')")],
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
    """Perform a comprehensive security assessment of a Jira ticket.

    This tool analyzes a Jira ticket for security implications and generates
    security requirements that can be injected into code generation prompts.
    It identifies technologies, security risks, and provides specific guidelines
    following OWASP and industry best practices.

    💡 TIP: For quick security guidance without a Jira ticket, use 'lightweight_security_review' instead.
    This tool is best when you have a specific Jira issue that needs thorough security analysis.

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
            fields="*all",  # Get all fields for comprehensive analysis
            expand="renderedFields,changelog",  # Include rendered content and history
            comment_limit=20,  # Include recent comments
        )

        # Convert issue to dict for analysis
        issue_data = issue.to_simplified_dict()

        # Perform security assessment
        security_assessment = SecurityAssessment()
        requirements = security_assessment.assess_ticket(issue_data)

        # Build response
        response = {
            "success": True,
            "issue_key": issue_key,
            "assessment": {
                "risk_level": requirements.risk_level,
                "security_categories": requirements.security_categories,
                "technologies": requirements.technologies,
                "summary": requirements.summary,
            },
        }

        # Add detailed guidelines if requested
        if include_guidelines:
            response["assessment"]["guidelines"] = requirements.guidelines

        # Add prompt injection if requested
        if include_prompt_injection:
            response["assessment"]["prompt_injection"] = requirements.prompt_injection

        # Add metadata
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

    except Exception as e:
        error_message = str(e)
        logger.error(f"Security assessment failed for {issue_key}: {error_message}")

        error_response = {
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
