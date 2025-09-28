"""Tests for security guidelines functionality."""

import pytest
from mcp_security_review.security.guidelines import SecurityGuidelinesLoader, SecurityGuideline


class TestSecurityGuidelinesLoader:
    """Test cases for SecurityGuidelinesLoader."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.guidelines = SecurityGuidelinesLoader()

    def test_guidelines_loader_initialization(self) -> None:
        """Test that guidelines loader initializes properly."""
        assert isinstance(self.guidelines, SecurityGuidelinesLoader)
        assert hasattr(self.guidelines, 'get_all_guidelines')
        assert hasattr(self.guidelines, 'get_guidelines_by_category')
        assert hasattr(self.guidelines, 'search_guidelines')

    def test_guideline_structure(self) -> None:
        """Test that guidelines have the expected structure."""
        all_guidelines = self.guidelines.get_all_guidelines()
        
        for guideline in all_guidelines:
            assert isinstance(guideline, SecurityGuideline)
            assert isinstance(guideline.title, str)
            assert isinstance(guideline.category, str)
            assert isinstance(guideline.priority, str)
            assert isinstance(guideline.description, str)
            assert isinstance(guideline.implementation, str)
            assert isinstance(guideline.examples, list)
            assert isinstance(guideline.references, list)
            
            assert guideline.priority in ["critical", "high", "medium", "low"]
    
    def test_guidelines_loading(self) -> None:
        """Test that guidelines are loaded properly."""
        all_guidelines = self.guidelines.get_all_guidelines()
        
        assert len(all_guidelines) > 0
        
        # Check that we have guidelines from different categories
        categories = self.guidelines.get_all_categories()
        assert len(categories) > 0
        
        # Check that we can search guidelines
        search_results = self.guidelines.search_guidelines("authentication")
        assert isinstance(search_results, list)
    
    def test_guidelines_by_category(self) -> None:
        """Test getting guidelines by category."""
        categories = self.guidelines.get_all_categories()
        
        for category in categories:
            guidelines = self.guidelines.get_guidelines_by_category(category)
            assert isinstance(guidelines, list)
            for guideline in guidelines:
                assert guideline.category == category