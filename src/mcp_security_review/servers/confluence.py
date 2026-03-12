"""Confluence FastMCP server instance and tool definitions.

Provides only security-relevant Confluence tools: search for finding
previous threat models/security docs, and get_page for reading content.
"""

import json
import logging
from typing import Annotated

from fastmcp import Context, FastMCP
from pydantic import Field

from mcp_security_review.servers.dependencies import get_confluence_fetcher

logger = logging.getLogger(__name__)

confluence_mcp = FastMCP(
    name="Confluence MCP Service",
    description=(
        "Provides security-focused tools for Atlassian Confluence integration."
    ),
)


@confluence_mcp.tool(tags={"confluence", "read"})
async def search(
    ctx: Context,
    query: Annotated[
        str,
        Field(
            description=(
                "Search query - can be either a simple text "
                "(e.g. 'threat model auth') or a CQL query string. "
                "Simple queries use 'siteSearch' by default. "
                "Examples of CQL:\n"
                "- By label: 'label=threat-model'\n"
                "- By title: 'title~\"Threat Model\"'\n"
                "- By space: 'type=page AND space=SEC'\n"
                "- Recent: 'lastModified > startOfMonth(\"-1M\")'\n"
                "- Combined: 'label=threat-model AND space=DEV'"
            )
        ),
    ],
    limit: Annotated[
        int,
        Field(
            description="Maximum number of results (1-50)",
            default=10,
            ge=1,
            le=50,
        ),
    ] = 10,
    spaces_filter: Annotated[
        str | None,
        Field(
            description=(
                "(Optional) Comma-separated list of space keys to filter results by."
            ),
            default=None,
        ),
    ] = None,
) -> str:
    """Search Confluence content using simple terms or CQL.

    Args:
        ctx: The FastMCP context.
        query: Search query - simple text or CQL query string.
        limit: Maximum number of results (1-50).
        spaces_filter: Comma-separated space keys to filter by.

    Returns:
        JSON string representing a list of simplified Confluence
        page objects.
    """
    confluence_fetcher = await get_confluence_fetcher(ctx)
    if query and not any(
        x in query
        for x in [
            "=",
            "~",
            ">",
            "<",
            " AND ",
            " OR ",
            "currentUser()",
        ]
    ):
        original_query = query
        try:
            query = f'siteSearch ~ "{original_query}"'
            logger.info(
                f"Converting simple search term to CQL using siteSearch: {query}"
            )
            pages = confluence_fetcher.search(
                query, limit=limit, spaces_filter=spaces_filter
            )
        except (ValueError, OSError, KeyError) as e:
            logger.warning(f"siteSearch failed ('{e}'), falling back to text search.")
            query = f'text ~ "{original_query}"'
            logger.info(f"Falling back to text search with CQL: {query}")
            pages = confluence_fetcher.search(
                query, limit=limit, spaces_filter=spaces_filter
            )
    else:
        pages = confluence_fetcher.search(
            query, limit=limit, spaces_filter=spaces_filter
        )
    search_results = [page.to_simplified_dict() for page in pages]
    return json.dumps(search_results, indent=2, ensure_ascii=False)


@confluence_mcp.tool(tags={"confluence", "read"})
async def get_page(
    ctx: Context,
    page_id: Annotated[
        str | None,
        Field(
            description=(
                "Confluence page ID (numeric, from the page URL). "
                "Provide this OR both 'title' and 'space_key'."
            ),
            default=None,
        ),
    ] = None,
    title: Annotated[
        str | None,
        Field(
            description=(
                "The exact title of the Confluence page. "
                "Use with 'space_key' if 'page_id' is not known."
            ),
            default=None,
        ),
    ] = None,
    space_key: Annotated[
        str | None,
        Field(
            description=(
                "The key of the Confluence space "
                "(e.g., 'DEV', 'TEAM'). "
                "Required if using 'title'."
            ),
            default=None,
        ),
    ] = None,
    include_metadata: Annotated[  # noqa: FBT002
        bool,
        Field(
            description=(
                "Whether to include page metadata such as "
                "creation date, last update, version, and labels."
            ),
            default=True,
        ),
    ] = True,
    convert_to_markdown: Annotated[  # noqa: FBT002
        bool,
        Field(
            description=(
                "Whether to convert page to markdown (true) or keep raw HTML (false)."
            ),
            default=True,
        ),
    ] = True,
) -> str:
    """Get content of a specific Confluence page.

    Retrieve by page ID, or by title and space key.

    Args:
        ctx: The FastMCP context.
        page_id: Confluence page ID.
        title: Exact page title. Must be used with 'space_key'.
        space_key: Space key. Must be used with 'title'.
        include_metadata: Whether to include page metadata.
        convert_to_markdown: Convert to markdown or keep raw HTML.

    Returns:
        JSON string representing page content and/or metadata.
    """
    confluence_fetcher = await get_confluence_fetcher(ctx)
    page_object = None

    if page_id:
        if title or space_key:
            logger.warning(
                "page_id was provided; title and space_key parameters will be ignored."
            )
        try:
            page_object = confluence_fetcher.get_page_content(
                page_id, convert_to_markdown=convert_to_markdown
            )
        except (ValueError, OSError, KeyError) as e:
            logger.error(f"Error fetching page by ID '{page_id}': {e}")
            return json.dumps(
                {"error": (f"Failed to retrieve page by ID '{page_id}': {e}")},
                indent=2,
                ensure_ascii=False,
            )
    elif title and space_key:
        page_object = confluence_fetcher.get_page_by_title(
            space_key,
            title,
            convert_to_markdown=convert_to_markdown,
        )
        if not page_object:
            return json.dumps(
                {
                    "error": (
                        f"Page with title '{title}' not found in space '{space_key}'."
                    )
                },
                indent=2,
                ensure_ascii=False,
            )
    else:
        raise ValueError(
            "Either 'page_id' OR both 'title' and 'space_key' must be provided."
        )

    if not page_object:
        return json.dumps(
            {"error": "Page not found with the provided identifiers."},
            indent=2,
            ensure_ascii=False,
        )

    if include_metadata:
        result = {"metadata": page_object.to_simplified_dict()}
    else:
        result = {"content": {"value": page_object.content}}

    return json.dumps(result, indent=2, ensure_ascii=False)
