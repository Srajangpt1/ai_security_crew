"""Atlassian Models Package.

This package contains Pydantic models for Atlassian API responses
(Jira and Confluence).
"""

# Re-export models from the reorganized structure
from .confluence import (
    ConfluenceAttachment,
    ConfluenceComment,
    ConfluenceLabel,
    ConfluencePage,
    ConfluenceSearchResult,
    ConfluenceSpace,
    ConfluenceUser,
    ConfluenceVersion,
)
from .jira import (
    JiraAttachment,
    JiraBoard,
    JiraComment,
    JiraIssue,
    JiraIssueType,
    JiraPriority,
    JiraProject,
    JiraResolution,
    JiraSearchResult,
    JiraSprint,
    JiraStatus,
    JiraStatusCategory,
    JiraTimetracking,
    JiraTransition,
    JiraUser,
    JiraWorklog,
)

__all__ = [
    # Confluence models
    "ConfluenceAttachment",
    "ConfluenceComment",
    "ConfluenceLabel",
    "ConfluencePage",
    "ConfluenceSearchResult",
    "ConfluenceSpace",
    "ConfluenceUser",
    "ConfluenceVersion",
    # Jira models
    "JiraAttachment",
    "JiraBoard",
    "JiraComment",
    "JiraIssue",
    "JiraIssueType",
    "JiraPriority",
    "JiraProject",
    "JiraResolution",
    "JiraSearchResult",
    "JiraSprint",
    "JiraStatus",
    "JiraStatusCategory",
    "JiraTimetracking",
    "JiraTransition",
    "JiraUser",
    "JiraWorklog",
]
