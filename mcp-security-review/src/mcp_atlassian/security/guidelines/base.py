"""Base classes for security guidelines."""

from dataclasses import dataclass
from typing import List


@dataclass
class SecurityGuideline:
    """A security guideline with category, priority, and implementation details."""
    
    category: str
    title: str
    description: str
    priority: str  # "critical", "high", "medium", "low"
    implementation: str
    examples: List[str]
    references: List[str]
    tags: List[str] = None  # Additional tags for filtering
    
    def __post_init__(self):
        """Initialize default values."""
        if self.tags is None:
            self.tags = []
