"""Unit tests for the Jira FastMCP server implementation."""

import json
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import Client, FastMCP
from fastmcp.client import FastMCPTransport
from fastmcp.exceptions import ToolError
from starlette.requests import Request

from mcp_security_review.providers.atlassian.jira import JiraFetcher
from mcp_security_review.providers.atlassian.jira.config import JiraConfig
from mcp_security_review.servers.context import MainAppContext
from mcp_security_review.servers.main import SecurityReviewMCP
from mcp_security_review.utils.oauth import OAuthConfig
from tests.fixtures.jira_mocks import (
    MOCK_JIRA_ISSUE_RESPONSE_SIMPLIFIED,
)

logger = logging.getLogger(__name__)


@pytest.fixture
def mock_jira_fetcher():
    """Create a mock JiraFetcher using predefined responses from fixtures."""
    mock_fetcher = MagicMock(spec=JiraFetcher)
    mock_fetcher.config = MagicMock()
    mock_fetcher.config.read_only = False
    mock_fetcher.config.url = "https://test.atlassian.net"
    mock_fetcher.config.projects_filter = None

    mock_fetcher.get_current_user_account_id.return_value = "test-account-id"
    mock_fetcher.jira = MagicMock()

    def mock_get_issue(
        issue_key,
        fields=None,
        expand=None,
        comment_limit=10,
        properties=None,
        update_history=True,
    ):
        if not issue_key:
            raise ValueError("Issue key is required")
        mock_issue = MagicMock()
        response_data = MOCK_JIRA_ISSUE_RESPONSE_SIMPLIFIED.copy()
        response_data["key"] = issue_key
        response_data["fields_queried"] = fields
        response_data["expand_param"] = expand
        response_data["comment_limit"] = comment_limit
        response_data["properties_param"] = properties
        response_data["update_history"] = update_history
        response_data["id"] = MOCK_JIRA_ISSUE_RESPONSE_SIMPLIFIED["id"]
        response_data["summary"] = MOCK_JIRA_ISSUE_RESPONSE_SIMPLIFIED["fields"][
            "summary"
        ]
        response_data["status"] = {
            "name": MOCK_JIRA_ISSUE_RESPONSE_SIMPLIFIED["fields"]["status"]["name"]
        }
        mock_issue.to_simplified_dict.return_value = response_data
        return mock_issue

    mock_fetcher.get_issue.side_effect = mock_get_issue

    return mock_fetcher


@pytest.fixture
def mock_base_jira_config():
    """Create a mock base JiraConfig for MainAppContext."""
    mock_oauth_config = OAuthConfig(
        client_id="server_client_id",
        client_secret="server_client_secret",
        redirect_uri="http://localhost",
        scope="read:jira-work",
        cloud_id="mock_jira_cloud_id",
    )
    return JiraConfig(
        url="https://mock-jira.atlassian.net",
        auth_type="oauth",
        oauth_config=mock_oauth_config,
    )


@pytest.fixture
def test_jira_mcp(mock_jira_fetcher, mock_base_jira_config):
    """Create a test FastMCP instance with standard configuration."""

    @asynccontextmanager
    async def test_lifespan(
        app: FastMCP,
    ) -> AsyncGenerator[MainAppContext, None]:
        try:
            yield MainAppContext(
                full_jira_config=mock_base_jira_config, read_only=False
            )
        finally:
            pass

    test_mcp = SecurityReviewMCP(
        "TestJira",
        description="Test Jira MCP Server",
        lifespan=test_lifespan,
    )
    from mcp_security_review.servers.jira import (
        assess_ticket_security,
        get_issue,
    )

    jira_sub_mcp = FastMCP(name="TestJiraSubMCP")
    jira_sub_mcp.tool()(get_issue)
    jira_sub_mcp.tool()(assess_ticket_security)
    test_mcp.mount("jira", jira_sub_mcp)
    return test_mcp


@pytest.fixture
def no_fetcher_test_jira_mcp(mock_base_jira_config):
    """Create a test FastMCP instance that simulates missing Jira fetcher."""

    @asynccontextmanager
    async def no_fetcher_test_lifespan(
        app: FastMCP,
    ) -> AsyncGenerator[MainAppContext, None]:
        try:
            yield MainAppContext(full_jira_config=None, read_only=False)
        finally:
            pass

    test_mcp = SecurityReviewMCP(
        "NoFetcherTestJira",
        description="No Fetcher Test Jira MCP Server",
        lifespan=no_fetcher_test_lifespan,
    )
    from mcp_security_review.servers.jira import get_issue

    jira_sub_mcp = FastMCP(name="NoFetcherTestJiraSubMCP")
    jira_sub_mcp.tool()(get_issue)
    test_mcp.mount("jira", jira_sub_mcp)
    return test_mcp


@pytest.fixture
def mock_request():
    """Provides a mock Starlette Request object with a state."""
    request = MagicMock(spec=Request)
    request.state = MagicMock()
    request.state.jira_fetcher = None
    request.state.user_atlassian_auth_type = None
    request.state.user_atlassian_token = None
    request.state.user_atlassian_email = None
    return request


@pytest.fixture
async def jira_client(test_jira_mcp, mock_jira_fetcher, mock_request):
    """Create a FastMCP client with mocked Jira fetcher and request state."""
    with (
        patch(
            "mcp_security_review.servers.jira.get_jira_fetcher",
            AsyncMock(return_value=mock_jira_fetcher),
        ),
        patch(
            "mcp_security_review.servers.dependencies.get_http_request",
            return_value=mock_request,
        ),
    ):
        async with Client(transport=FastMCPTransport(test_jira_mcp)) as client_instance:
            yield client_instance


@pytest.fixture
async def no_fetcher_client_fixture(no_fetcher_test_jira_mcp, mock_request):
    """Create a client that simulates missing Jira fetcher configuration."""
    async with Client(
        transport=FastMCPTransport(no_fetcher_test_jira_mcp)
    ) as client_for_no_fetcher:
        yield client_for_no_fetcher


@pytest.mark.anyio
async def test_get_issue(jira_client, mock_jira_fetcher):
    """Test the get_issue tool with fixture data."""
    response = await jira_client.call_tool(
        "jira_get_issue",
        {
            "issue_key": "TEST-123",
            "fields": "summary,description,status",
        },
    )
    assert isinstance(response, list)
    assert len(response) > 0
    text_content = response[0]
    assert text_content.type == "text"
    content = json.loads(text_content.text)
    assert content["key"] == "TEST-123"
    assert content["summary"] == "Test Issue Summary"
    mock_jira_fetcher.get_issue.assert_called_once_with(
        issue_key="TEST-123",
        fields=["summary", "description", "status"],
        expand=None,
        comment_limit=10,
        properties=None,
        update_history=True,
    )


@pytest.mark.anyio
async def test_no_fetcher_get_issue(no_fetcher_client_fixture, mock_request):
    """Test that get_issue fails when Jira client is not configured."""

    async def mock_get_fetcher_error(*args, **kwargs):
        raise ValueError("Mocked: Jira client (fetcher) not available.")

    with (
        patch(
            "mcp_security_review.servers.jira.get_jira_fetcher",
            AsyncMock(side_effect=mock_get_fetcher_error),
        ),
        patch(
            "mcp_security_review.servers.dependencies.get_http_request",
            return_value=mock_request,
        ),
    ):
        with pytest.raises(ToolError) as excinfo:
            await no_fetcher_client_fixture.call_tool(
                "jira_get_issue",
                {"issue_key": "TEST-123"},
            )
    assert "Error calling tool 'get_issue'" in str(excinfo.value)


@pytest.mark.anyio
async def test_get_issue_with_user_specific_fetcher_in_state(
    test_jira_mcp, mock_jira_fetcher, mock_base_jira_config
):
    """Test get_issue uses fetcher from request.state if provided."""
    _mock_request_with_fetcher_in_state = MagicMock(spec=Request)
    _mock_request_with_fetcher_in_state.state = MagicMock()
    _mock_request_with_fetcher_in_state.state.jira_fetcher = mock_jira_fetcher
    _mock_request_with_fetcher_in_state.state.user_atlassian_auth_type = "oauth"
    _mock_request_with_fetcher_in_state.state.user_atlassian_token = (
        "user_specific_token"
    )

    test_fields_str = "summary,status,issuetype"
    expected_fields_list = ["summary", "status", "issuetype"]

    from mcp_security_review.servers.dependencies import (
        get_jira_fetcher as get_jira_fetcher_real,
    )

    with (
        patch(
            "mcp_security_review.servers.dependencies.get_http_request",
            return_value=_mock_request_with_fetcher_in_state,
        ) as mock_get_http,
        patch(
            "mcp_security_review.servers.jira.get_jira_fetcher",
            side_effect=AsyncMock(wraps=get_jira_fetcher_real),
        ),
    ):
        async with Client(transport=FastMCPTransport(test_jira_mcp)) as client_instance:
            response = await client_instance.call_tool(
                "jira_get_issue",
                {
                    "issue_key": "USER-STATE-1",
                    "fields": test_fields_str,
                },
            )

    mock_get_http.assert_called()
    mock_jira_fetcher.get_issue.assert_called_with(
        issue_key="USER-STATE-1",
        fields=expected_fields_list,
        expand=None,
        comment_limit=10,
        properties=None,
        update_history=True,
    )
    result_data = json.loads(response[0].text)
    assert result_data["key"] == "USER-STATE-1"
