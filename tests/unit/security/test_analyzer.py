"""Tests for SecurityAnalyzer class."""

import pytest
from mcp_security_review.security.analyzer import SecurityAnalyzer, SecurityContext


class TestSecurityAnalyzer:
    """Test cases for SecurityAnalyzer."""
    
    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.analyzer = SecurityAnalyzer()
    
    def test_analyze_ticket_basic(self) -> None:
        """Test basic ticket analysis."""
        ticket_data = {
            "summary": "Fix login bug",
            "description": "User cannot login with correct password",
            "fields": {
                "issuetype": {"name": "Bug"},
                "labels": ["authentication", "security"]
            }
        }
        
        context = self.analyzer.analyze_ticket(ticket_data)
        
        assert isinstance(context, SecurityContext)
        assert "authentication" in context.security_categories
        assert "login" in context.security_keywords
        assert context.risk_level in ["low", "medium", "high", "critical"]
    
    def test_identify_technologies(self) -> None:
        """Test technology identification."""
        text_content = "We need to implement this in Python using Django and PostgreSQL database"
        
        technologies = self.analyzer._identify_technologies(text_content)
        
        assert "python" in technologies
        assert "django" in technologies
        assert "database" in technologies
    
    def test_identify_security_keywords(self) -> None:
        """Test security keyword identification."""
        text_content = "Implement authentication with JWT tokens and password hashing"
        
        keywords = self.analyzer._identify_security_keywords(text_content)
        
        assert "authentication" in keywords
        assert "jwt" in keywords
        assert "password" in keywords
        assert "hash" in keywords
    
    def test_identify_sensitive_data(self) -> None:
        """Test sensitive data identification."""
        text_content = "Store user email addresses and phone numbers securely"
        
        sensitive_data = self.analyzer._identify_sensitive_data(text_content)
        
        assert "personal_data" in sensitive_data
    
    def test_identify_attack_vectors(self) -> None:
        """Test attack vector identification."""
        text_content = "Prevent SQL injection and XSS attacks in the web form"
        
        attack_vectors = self.analyzer._identify_attack_vectors(text_content)
        
        assert "sql_injection" in attack_vectors
        assert "xss" in attack_vectors
    
    def test_determine_security_categories(self) -> None:
        """Test security category determination."""
        security_keywords = {"login", "password", "token", "permission", "admin"}
        sensitive_data_types = {"personal_data"}
        attack_vectors = {"sql_injection"}
        
        categories = self.analyzer._determine_security_categories(
            security_keywords, sensitive_data_types, attack_vectors
        )
        
        assert "authentication" in categories
        assert "authorization" in categories
        assert "data_validation" in categories
        assert "database" in categories
    
    def test_determine_risk_level_low(self) -> None:
        """Test low risk level determination."""
        security_keywords = {"form", "input"}
        sensitive_data_types = set()
        attack_vectors = set()
        security_categories = {"data_validation"}
        
        risk_level = self.analyzer._determine_risk_level(
            security_keywords, sensitive_data_types, attack_vectors, security_categories
        )
        
        assert risk_level == "low"
    
    def test_determine_risk_level_high(self) -> None:
        """Test high risk level determination."""
        security_keywords = {"password", "token", "admin", "encrypt", "auth"}
        sensitive_data_types = {"personal_data", "credentials"}
        attack_vectors = {"sql_injection", "xss"}
        security_categories = {"authentication", "authorization", "database"}
        
        risk_level = self.analyzer._determine_risk_level(
            security_keywords, sensitive_data_types, attack_vectors, security_categories
        )
        
        assert risk_level in ["high", "critical"]
    
    def test_extract_text_content(self) -> None:
        """Test text content extraction from ticket data."""
        ticket_data = {
            "summary": "Test summary",
            "description": "Test description",
            "comments": [
                {"body": "Test comment 1"},
                {"body": "Test comment 2"}
            ],
            "fields": {
                "customfield_10001": "Custom field value"
            }
        }
        
        text_content = self.analyzer._extract_text_content(ticket_data)
        
        assert "test summary" in text_content
        assert "test description" in text_content
        assert "test comment 1" in text_content
        assert "test comment 2" in text_content
        assert "custom field value" in text_content
    
    def test_analyze_ticket_with_comments(self) -> None:
        """Test ticket analysis with comments."""
        ticket_data = {
            "summary": "API security enhancement",
            "description": "Add rate limiting to API endpoints",
            "comments": [
                {"body": "Need to implement JWT authentication"},
                {"body": "Also add input validation for SQL injection prevention"}
            ],
            "fields": {
                "issuetype": {"name": "Story"},
                "labels": ["api", "security", "python"]
            }
        }
        
        context = self.analyzer.analyze_ticket(ticket_data)
        
        assert "api_security" in context.security_categories
        assert "authentication" in context.security_categories
        assert "data_validation" in context.security_categories
        assert "python" in context.technologies
        assert "jwt" in context.security_keywords
        assert "sql" in context.security_keywords
    
    def test_analyze_ticket_critical_risk(self) -> None:
        """Test ticket analysis for critical security risk."""
        ticket_data = {
            "summary": "Critical: SQL injection vulnerability in user authentication",
            "description": """
            We have discovered a critical SQL injection vulnerability in our 
            authentication system. Attackers can bypass login by injecting 
            malicious SQL queries. This affects all user accounts including 
            admin accounts with elevated privileges.
            
            The vulnerability is in the login form where user input is directly 
            concatenated into SQL queries without proper parameterization.
            
            Immediate action required:
            1. Implement parameterized queries
            2. Add input validation and sanitization
            3. Review all database access patterns
            4. Audit admin account access
            """,
            "fields": {
                "issuetype": {"name": "Bug"},
                "priority": {"name": "Critical"},
                "labels": ["security", "critical", "sql", "authentication", "admin"]
            }
        }
        
        context = self.analyzer.analyze_ticket(ticket_data)
        
        assert context.risk_level == "critical"
        assert "authentication" in context.security_categories
        assert "database" in context.security_categories
        assert "data_validation" in context.security_categories
        assert "authorization" in context.security_categories
        assert "sql_injection" in context.attack_vectors
        assert "authentication_bypass" in context.attack_vectors
        assert "privilege_escalation" in context.attack_vectors
    
    def test_analyze_ticket_minimal_data(self) -> None:
        """Test ticket analysis with minimal data."""
        ticket_data = {
            "summary": "Update documentation"
        }
        
        context = self.analyzer.analyze_ticket(ticket_data)
        
        assert context.risk_level == "low"
        assert len(context.security_categories) == 0
        assert len(context.technologies) == 0
        assert len(context.security_keywords) == 0
        assert len(context.sensitive_data_types) == 0
        assert len(context.attack_vectors) == 0
