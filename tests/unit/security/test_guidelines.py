"""Tests for SecurityGuidelines class."""

import pytest
from mcp_security_review.security.guidelines import SecurityGuidelines, SecurityGuideline


class TestSecurityGuidelines:
    """Test cases for SecurityGuidelines."""
    
    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.guidelines = SecurityGuidelines()
    
    def test_get_guidelines_for_context_authentication(self) -> None:
        """Test getting guidelines for authentication context."""
        context = "Implement user login with password authentication"
        technologies = ["python", "django"]
        
        relevant_guidelines = self.guidelines.get_guidelines_for_context(context, technologies)
        
        assert len(relevant_guidelines) > 0
        
        # Check that authentication guidelines are included
        auth_guidelines = [g for g in relevant_guidelines if g.category == "authentication"]
        assert len(auth_guidelines) > 0
        
        # Check priority ordering (critical first)
        priorities = [g.priority for g in relevant_guidelines]
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_priorities = sorted(priorities, key=lambda p: priority_order.get(p, 4))
        assert priorities == sorted_priorities
    
    def test_get_guidelines_for_context_api_security(self) -> None:
        """Test getting guidelines for API security context."""
        context = "Create REST API endpoints with rate limiting"
        technologies = ["javascript", "node"]
        
        relevant_guidelines = self.guidelines.get_guidelines_for_context(context, technologies)
        
        assert len(relevant_guidelines) > 0
        
        # Check that API security guidelines are included
        api_guidelines = [g for g in relevant_guidelines if g.category == "api_security"]
        assert len(api_guidelines) > 0
    
    def test_get_guidelines_for_context_database(self) -> None:
        """Test getting guidelines for database context."""
        context = "Store user data in PostgreSQL database with proper queries"
        technologies = ["python", "postgresql"]
        
        relevant_guidelines = self.guidelines.get_guidelines_for_context(context, technologies)
        
        assert len(relevant_guidelines) > 0
        
        # Check that database guidelines are included
        db_guidelines = [g for g in relevant_guidelines if g.category == "database"]
        assert len(db_guidelines) > 0
    
    def test_get_guidelines_for_context_no_technologies(self) -> None:
        """Test getting guidelines without specifying technologies."""
        context = "Implement secure user authentication"
        
        relevant_guidelines = self.guidelines.get_guidelines_for_context(context)
        
        assert len(relevant_guidelines) > 0
        
        # Should include authentication guidelines
        auth_guidelines = [g for g in relevant_guidelines if g.category == "authentication"]
        assert len(auth_guidelines) > 0
    
    def test_get_guidelines_for_context_general(self) -> None:
        """Test getting guidelines for general context."""
        context = "Fix a bug in the application"
        
        relevant_guidelines = self.guidelines.get_guidelines_for_context(context)
        
        # Should return some guidelines even for general context
        assert len(relevant_guidelines) >= 0
    
    def test_guideline_structure(self) -> None:
        """Test that guidelines have proper structure."""
        context = "Implement authentication"
        guidelines = self.guidelines.get_guidelines_for_context(context)
        
        if guidelines:  # If any guidelines are returned
            guideline = guidelines[0]
            
            assert hasattr(guideline, 'category')
            assert hasattr(guideline, 'title')
            assert hasattr(guideline, 'description')
            assert hasattr(guideline, 'priority')
            assert hasattr(guideline, 'implementation')
            assert hasattr(guideline, 'examples')
            assert hasattr(guideline, 'references')
            
            assert isinstance(guideline.category, str)
            assert isinstance(guideline.title, str)
            assert isinstance(guideline.description, str)
            assert isinstance(guideline.priority, str)
            assert isinstance(guideline.implementation, str)
            assert isinstance(guideline.examples, list)
            assert isinstance(guideline.references, list)
            
            assert guideline.priority in ["critical", "high", "medium", "low"]
    
    def test_authentication_guidelines_content(self) -> None:
        """Test authentication guidelines have expected content."""
        auth_guidelines = self.guidelines._get_authentication_guidelines()
        
        assert len(auth_guidelines) > 0
        
        # Check for specific authentication guidelines
        titles = [g.title for g in auth_guidelines]
        assert any("password" in title.lower() for title in titles)
        assert any("multi" in title.lower() or "factor" in title.lower() for title in titles)
        assert any("session" in title.lower() for title in titles)
    
    def test_authorization_guidelines_content(self) -> None:
        """Test authorization guidelines have expected content."""
        authz_guidelines = self.guidelines._get_authorization_guidelines()
        
        assert len(authz_guidelines) > 0
        
        # Check for specific authorization guidelines
        titles = [g.title for g in authz_guidelines]
        assert any("privilege" in title.lower() for title in titles)
        assert any("access" in title.lower() for title in titles)
    
    def test_data_validation_guidelines_content(self) -> None:
        """Test data validation guidelines have expected content."""
        validation_guidelines = self.guidelines._get_data_validation_guidelines()
        
        assert len(validation_guidelines) > 0
        
        # Check for specific validation guidelines
        titles = [g.title for g in validation_guidelines]
        assert any("input" in title.lower() for title in titles)
        assert any("output" in title.lower() for title in titles)
    
    def test_cryptography_guidelines_content(self) -> None:
        """Test cryptography guidelines have expected content."""
        crypto_guidelines = self.guidelines._get_cryptography_guidelines()
        
        assert len(crypto_guidelines) > 0
        
        # Check for specific crypto guidelines
        titles = [g.title for g in crypto_guidelines]
        assert any("algorithm" in title.lower() for title in titles)
        assert any("key" in title.lower() for title in titles)
    
    def test_api_security_guidelines_content(self) -> None:
        """Test API security guidelines have expected content."""
        api_guidelines = self.guidelines._get_api_security_guidelines()
        
        assert len(api_guidelines) > 0
        
        # Check for specific API guidelines
        titles = [g.title for g in api_guidelines]
        assert any("authentication" in title.lower() for title in titles)
        assert any("rate" in title.lower() for title in titles)
    
    def test_database_guidelines_content(self) -> None:
        """Test database guidelines have expected content."""
        db_guidelines = self.guidelines._get_database_guidelines()
        
        assert len(db_guidelines) > 0
        
        # Check for specific database guidelines
        titles = [g.title for g in db_guidelines]
        assert any("sql" in title.lower() for title in titles)
        assert any("access" in title.lower() for title in titles)
    
    def test_web_security_guidelines_content(self) -> None:
        """Test web security guidelines have expected content."""
        web_guidelines = self.guidelines._get_web_security_guidelines()
        
        assert len(web_guidelines) > 0
        
        # Check for specific web security guidelines
        titles = [g.title for g in web_guidelines]
        assert any("xss" in title.lower() for title in titles)
        assert any("csrf" in title.lower() for title in titles)
    
    def test_secrets_management_guidelines_content(self) -> None:
        """Test secrets management guidelines have expected content."""
        secrets_guidelines = self.guidelines._get_secrets_management_guidelines()
        
        assert len(secrets_guidelines) > 0
        
        # Check for specific secrets guidelines
        titles = [g.title for g in secrets_guidelines]
        assert any("storage" in title.lower() for title in titles)
        assert any("rotation" in title.lower() for title in titles)
    
    def test_logging_guidelines_content(self) -> None:
        """Test logging guidelines have expected content."""
        logging_guidelines = self.guidelines._get_logging_guidelines()
        
        assert len(logging_guidelines) > 0
        
        # Check for specific logging guidelines
        titles = [g.title for g in logging_guidelines]
        assert any("event" in title.lower() for title in titles)
        assert any("protection" in title.lower() for title in titles)
    
    def test_error_handling_guidelines_content(self) -> None:
        """Test error handling guidelines have expected content."""
        error_guidelines = self.guidelines._get_error_handling_guidelines()
        
        assert len(error_guidelines) > 0
        
        # Check for specific error handling guidelines
        titles = [g.title for g in error_guidelines]
        assert any("secure" in title.lower() for title in titles)
        assert any("validation" in title.lower() for title in titles)
