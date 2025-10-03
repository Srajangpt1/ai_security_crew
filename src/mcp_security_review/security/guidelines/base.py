"""Base classes for security guidelines."""

from dataclasses import dataclass


@dataclass
class SecurityGuideline:
    """A security guideline with category, priority, and implementation details."""

    category: str
    title: str
    description: str
    priority: str  # "critical", "high", "medium", "low"
    implementation: str
    examples: list[str]
    references: list[str]
    tags: list[str] = None  # Additional tags for filtering

    def __post_init__(self) -> None:
        """Initialize default values."""
        if self.tags is None:
            self.tags = []
