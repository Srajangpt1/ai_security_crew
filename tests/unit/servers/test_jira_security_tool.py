"""Tests for Jira security assessment tool."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_security_review.security import SecurityRequirements


class TestJiraSecurityTool:
    """Test cases for Jira security assessment tool."""

    @pytest.fixture
    def mock_jira_fetcher(self) -> MagicMock:
        """Create a mock Jira fetcher."""
        mock_fetcher = MagicMock()
        mock_issue = MagicMock()
        mock_issue.to_simplified_dict.return_value = {
            "key": "TEST-123",
            "summary": "Test security issue",
            "description": "Implement authentication with JWT tokens",
            "fields": {
                "issuetype": {"name": "Story"},
                "status": {"name": "In Progress"},
                "labels": ["security", "authentication"],
            },
            "updated": "2024-01-01T00:00:00.000Z",
        }
        mock_fetcher.get_issue.return_value = mock_issue
        return mock_fetcher

    @pytest.fixture
    def mock_security_assessment(self) -> MagicMock:
        """Create a mock security assessment."""
        mock_assessment = MagicMock()
        mock_requirements = SecurityRequirements(
            risk_level="high",
            security_categories=["authentication", "api_security"],
            technologies=["python", "javascript"],
            guidelines=[
                {
                    "category": "authentication",
                    "title": "JWT Token Security",
                    "description": "Implement secure JWT token handling",
                    "priority": "high",
                    "implementation": "Use proper token validation",
                    "examples": ["Validate token signature", "Check token expiration"],
                    "references": ["OWASP JWT Guidelines"],
                }
            ],
            prompt_injection="🔒 SECURITY REQUIREMENTS:\n\n⚠️ HIGH SECURITY RISK DETECTED",
            summary="High risk authentication implementation with JWT tokens",
        )
        mock_assessment.assess_ticket.return_value = mock_requirements
        return mock_assessment

    @pytest.mark.asyncio
    async def test_assess_ticket_security_success(
        self, mock_jira_fetcher, mock_security_assessment
    ) -> None:
        """Test successful security assessment."""
        from mcp_security_review.servers.jira import assess_ticket_security

        # Mock the dependencies
        with (
            patch(
                "mcp_security_review.servers.jira.get_jira_fetcher",
                return_value=mock_jira_fetcher,
            ),
            patch(
                "mcp_security_review.servers.jira.SecurityAssessment",
                return_value=mock_security_assessment,
            ),
        ):
            # Mock the context
            mock_ctx = AsyncMock()

            # Call the function
            result = await assess_ticket_security(mock_ctx, "TEST-123")

            # Parse the result
            result_data = json.loads(result)

            # Verify the response structure
            assert result_data["success"] is True
            assert result_data["issue_key"] == "TEST-123"
            assert "assessment" in result_data
            assert "metadata" in result_data

            # Verify assessment data
            assessment = result_data["assessment"]
            assert assessment["risk_level"] == "high"
            assert "authentication" in assessment["security_categories"]
            assert "api_security" in assessment["security_categories"]
            assert "python" in assessment["technologies"]
            assert "javascript" in assessment["technologies"]
            assert (
                assessment["summary"]
                == "High risk authentication implementation with JWT tokens"
            )
            assert "guidelines" in assessment
            assert "prompt_injection" in assessment

            # Verify metadata
            metadata = result_data["metadata"]
            assert metadata["total_guidelines"] == 1
            assert metadata["issue_type"] == "Story"
            assert metadata["issue_status"] == "In Progress"

    @pytest.mark.asyncio
    async def test_assess_ticket_security_without_guidelines(
        self, mock_jira_fetcher, mock_security_assessment
    ) -> None:
        """Test security assessment without detailed guidelines."""
        from mcp_security_review.servers.jira import assess_ticket_security

        with (
            patch(
                "mcp_security_review.servers.jira.get_jira_fetcher",
                return_value=mock_jira_fetcher,
            ),
            patch(
                "mcp_security_review.servers.jira.SecurityAssessment",
                return_value=mock_security_assessment,
            ),
        ):
            mock_ctx = AsyncMock()

            # Call with include_guidelines=False
            result = await assess_ticket_security(
                mock_ctx, "TEST-123", include_guidelines=False
            )

            result_data = json.loads(result)

            assert result_data["success"] is True
            assert "guidelines" not in result_data["assessment"]
            assert "prompt_injection" in result_data["assessment"]

    @pytest.mark.asyncio
    async def test_assess_ticket_security_without_prompt_injection(
        self, mock_jira_fetcher, mock_security_assessment
    ) -> None:
        """Test security assessment without prompt injection."""
        from mcp_security_review.servers.jira import assess_ticket_security

        with (
            patch(
                "mcp_security_review.servers.jira.get_jira_fetcher",
                return_value=mock_jira_fetcher,
            ),
            patch(
                "mcp_security_review.servers.jira.SecurityAssessment",
                return_value=mock_security_assessment,
            ),
        ):
            mock_ctx = AsyncMock()

            # Call with include_prompt_injection=False
            result = await assess_ticket_security(
                mock_ctx, "TEST-123", include_prompt_injection=False
            )

            result_data = json.loads(result)

            assert result_data["success"] is True
            assert "guidelines" in result_data["assessment"]
            assert "prompt_injection" not in result_data["assessment"]

    @pytest.mark.asyncio
    async def test_assess_ticket_security_error(self, mock_jira_fetcher) -> None:
        """Test security assessment with error."""
        from mcp_security_review.servers.jira import assess_ticket_security

        # Make the fetcher raise an exception
        mock_jira_fetcher.get_issue.side_effect = Exception("Issue not found")

        with patch(
            "mcp_security_review.servers.jira.get_jira_fetcher",
            return_value=mock_jira_fetcher,
        ):
            mock_ctx = AsyncMock()

            # Call the function
            result = await assess_ticket_security(mock_ctx, "TEST-123")

            # Parse the result
            result_data = json.loads(result)

            # Verify error response
            assert result_data["success"] is False
            assert result_data["issue_key"] == "TEST-123"
            assert "error" in result_data
            assert result_data["error"] == "Issue not found"

            # Verify fallback assessment data
            assessment = result_data["assessment"]
            assert assessment["risk_level"] == "unknown"
            assert assessment["security_categories"] == []
            assert assessment["technologies"] == []
            assert assessment["summary"] == "Assessment failed due to error"

    @pytest.mark.asyncio
    async def test_assess_ticket_security_critical_risk(
        self, mock_jira_fetcher
    ) -> None:
        """Test security assessment for critical risk ticket."""
        from mcp_security_review.servers.jira import assess_ticket_security

        # Mock critical risk requirements
        critical_requirements = SecurityRequirements(
            risk_level="critical",
            security_categories=["authentication", "database", "data_validation"],
            technologies=["python", "postgresql"],
            guidelines=[
                {
                    "category": "database",
                    "title": "SQL Injection Prevention",
                    "description": "Prevent SQL injection attacks",
                    "priority": "critical",
                    "implementation": "Use parameterized queries",
                    "examples": ["Use ORM frameworks", "Validate all inputs"],
                    "references": ["OWASP SQL Injection Prevention"],
                }
            ],
            prompt_injection="🔒 SECURITY REQUIREMENTS:\n\n🚨 CRITICAL SECURITY RISK DETECTED",
            summary="Critical SQL injection vulnerability requires immediate attention",
        )

        mock_assessment = MagicMock()
        mock_assessment.assess_ticket.return_value = critical_requirements

        with (
            patch(
                "mcp_security_review.servers.jira.get_jira_fetcher",
                return_value=mock_jira_fetcher,
            ),
            patch(
                "mcp_security_review.servers.jira.SecurityAssessment",
                return_value=mock_assessment,
            ),
        ):
            mock_ctx = AsyncMock()

            result = await assess_ticket_security(mock_ctx, "TEST-123")

            result_data = json.loads(result)

            assert result_data["success"] is True
            assert result_data["assessment"]["risk_level"] == "critical"
            assert "database" in result_data["assessment"]["security_categories"]
            assert "data_validation" in result_data["assessment"]["security_categories"]
            assert "postgresql" in result_data["assessment"]["technologies"]
            assert (
                "🚨 CRITICAL SECURITY RISK DETECTED"
                in result_data["assessment"]["prompt_injection"]
            )

    @pytest.mark.asyncio
    async def test_assess_ticket_security_low_risk(self, mock_jira_fetcher) -> None:
        """Test security assessment for low risk ticket."""
        from mcp_security_review.servers.jira import assess_ticket_security

        # Mock low risk requirements
        low_risk_requirements = SecurityRequirements(
            risk_level="low",
            security_categories=[],
            technologies=[],
            guidelines=[],
            prompt_injection="🔒 SECURITY REQUIREMENTS:\n\nGeneral security reminders",
            summary="Low risk ticket with minimal security implications",
        )

        mock_assessment = MagicMock()
        mock_assessment.assess_ticket.return_value = low_risk_requirements

        with (
            patch(
                "mcp_security_review.servers.jira.get_jira_fetcher",
                return_value=mock_jira_fetcher,
            ),
            patch(
                "mcp_security_review.servers.jira.SecurityAssessment",
                return_value=mock_assessment,
            ),
        ):
            mock_ctx = AsyncMock()

            result = await assess_ticket_security(mock_ctx, "TEST-123")

            result_data = json.loads(result)

            assert result_data["success"] is True
            assert result_data["assessment"]["risk_level"] == "low"
            assert result_data["assessment"]["security_categories"] == []
            assert result_data["assessment"]["technologies"] == []
            assert result_data["metadata"]["total_guidelines"] == 0
