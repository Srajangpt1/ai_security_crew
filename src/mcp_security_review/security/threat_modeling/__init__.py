"""Threat modeling module for developer-focused threat analysis.

Provides structured threat model generation with reference support
and file output capabilities.
"""

from .analyzer import ThreatModelAnalyzer
from .template import (
    ThreatEntry,
    ThreatModelOutput,
    ThreatModelTemplate,
)

__all__ = [
    "ThreatModelAnalyzer",
    "ThreatEntry",
    "ThreatModelOutput",
    "ThreatModelTemplate",
]
