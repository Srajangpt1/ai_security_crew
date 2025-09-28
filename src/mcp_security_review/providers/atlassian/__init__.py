"""Atlassian Provider Package.

This package contains integrations with Atlassian services
(Jira and Confluence) for security review workflows.
"""

# Re-export main classes for easier imports
from .confluence import ConfluenceFetcher
from .jira import JiraFetcher

__all__ = ["JiraFetcher", "ConfluenceFetcher"]
