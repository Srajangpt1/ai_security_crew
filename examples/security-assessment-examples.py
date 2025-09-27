"""Examples of using the MCP Atlassian Security Assessment Tool.

This file demonstrates how to use the security assessment tool to analyze
Jira tickets and generate security requirements for code generation.
"""

import asyncio
import json
from typing import Dict, Any

# Example ticket data for testing
EXAMPLE_TICKETS = {
    "authentication_ticket": {
        "summary": "Implement user authentication with JWT tokens",
        "description": """
        We need to implement secure user authentication for our web application.
        Requirements:
        - Use JWT tokens for authentication
        - Implement password hashing with bcrypt
        - Add session management
        - Support multi-factor authentication (MFA)
        - Implement proper logout functionality
        
        Security considerations:
        - Prevent brute force attacks
        - Secure token storage
        - Implement rate limiting for login attempts
        """,
        "fields": {
            "issuetype": {"name": "Story"},
            "priority": {"name": "High"},
            "labels": ["authentication", "security", "jwt", "mfa"]
        }
    },
    
    "api_security_ticket": {
        "summary": "Add rate limiting and input validation to REST API",
        "description": """
        Our REST API needs security enhancements:
        - Implement rate limiting to prevent abuse
        - Add input validation for all endpoints
        - Implement proper error handling
        - Add API key authentication
        - Support CORS configuration
        
        Technologies: Python, FastAPI, PostgreSQL
        """,
        "fields": {
            "issuetype": {"name": "Task"},
            "priority": {"name": "Medium"},
            "labels": ["api", "security", "python", "fastapi"]
        }
    },
    
    "database_security_ticket": {
        "summary": "Fix SQL injection vulnerability in user queries",
        "description": """
        CRITICAL: SQL injection vulnerability discovered in user search functionality.
        
        The vulnerability allows attackers to execute arbitrary SQL queries by
        manipulating the search parameters. This affects all user data including
        sensitive information.
        
        Immediate actions required:
        1. Replace string concatenation with parameterized queries
        2. Implement input validation and sanitization
        3. Review all database access patterns
        4. Add database access logging
        5. Implement query timeout limits
        
        Technologies: Python, Django, PostgreSQL
        """,
        "fields": {
            "issuetype": {"name": "Bug"},
            "priority": {"name": "Critical"},
            "labels": ["security", "critical", "sql-injection", "database", "python", "django"]
        }
    },
    
    "web_security_ticket": {
        "summary": "Implement XSS and CSRF protection for web forms",
        "description": """
        Add comprehensive web security measures:
        - Implement Content Security Policy (CSP)
        - Add CSRF tokens to all forms
        - Sanitize user input to prevent XSS
        - Implement secure headers (HSTS, X-Frame-Options)
        - Add input validation on both client and server side
        
        Technologies: JavaScript, React, Node.js, Express
        """,
        "fields": {
            "issuetype": {"name": "Story"},
            "priority": {"name": "High"},
            "labels": ["web-security", "xss", "csrf", "javascript", "react"]
        }
    },
    
    "secrets_management_ticket": {
        "summary": "Implement secure secrets management for production deployment",
        "description": """
        Replace hardcoded secrets with secure secrets management:
        - Move API keys to environment variables
        - Implement secrets rotation
        - Use AWS Secrets Manager or similar service
        - Add secrets scanning to CI/CD pipeline
        - Implement proper key management for encryption
        
        Technologies: AWS, Kubernetes, Docker, Python
        """,
        "fields": {
            "issuetype": {"name": "Task"},
            "priority": {"name": "High"},
            "labels": ["secrets", "security", "aws", "kubernetes", "devops"]
        }
    }
}


async def demonstrate_security_assessment() -> None:
    """Demonstrate the security assessment tool with example tickets."""
    print("🔒 MCP Atlassian Security Assessment Tool Demo")
    print("=" * 50)
    
    # Note: In a real implementation, you would use the actual MCP tool
    # This is a demonstration of what the tool would return
    
    for ticket_name, ticket_data in EXAMPLE_TICKETS.items():
        print(f"\n📋 Analyzing Ticket: {ticket_name}")
        print("-" * 30)
        
        # Simulate security assessment (in real usage, call the MCP tool)
        assessment_result = simulate_security_assessment(ticket_data)
        
        # Display results
        display_assessment_results(assessment_result)
        
        print("\n" + "=" * 50)


def simulate_security_assessment(ticket_data: Dict[str, Any]) -> Dict[str, Any]:
    """Simulate security assessment results for demonstration."""
    # This simulates what the actual MCP tool would return
    summary = ticket_data["summary"].lower()
    description = ticket_data["description"].lower()
    labels = [label.lower() for label in ticket_data["fields"]["labels"]]
    
    # Determine risk level based on content
    risk_level = "low"
    if "critical" in summary or "critical" in description:
        risk_level = "critical"
    elif "high" in summary or "high" in description or "vulnerability" in description:
        risk_level = "high"
    elif "security" in labels or "authentication" in labels:
        risk_level = "medium"
    
    # Identify technologies
    technologies = []
    if "python" in description:
        technologies.append("python")
    if "javascript" in description or "react" in description:
        technologies.append("javascript")
    if "django" in description:
        technologies.append("django")
    if "fastapi" in description:
        technologies.append("fastapi")
    if "postgresql" in description or "postgres" in description:
        technologies.append("postgresql")
    if "aws" in description:
        technologies.append("aws")
    if "kubernetes" in description:
        technologies.append("kubernetes")
    
    # Identify security categories
    security_categories = []
    if "authentication" in summary or "jwt" in summary or "login" in description:
        security_categories.append("authentication")
    if "api" in summary or "rest" in description:
        security_categories.append("api_security")
    if "sql" in description or "database" in description:
        security_categories.append("database")
    if "xss" in description or "csrf" in description or "web" in summary:
        security_categories.append("web_security")
    if "secrets" in summary or "key" in description:
        security_categories.append("secrets_management")
    
    # Generate sample guidelines
    guidelines = generate_sample_guidelines(security_categories)
    
    # Generate prompt injection
    prompt_injection = generate_prompt_injection(risk_level, technologies, security_categories, guidelines)
    
    return {
        "success": True,
        "assessment": {
            "risk_level": risk_level,
            "security_categories": security_categories,
            "technologies": technologies,
            "summary": f"{risk_level.title()} risk ticket with {len(security_categories)} security categories",
            "guidelines": guidelines,
            "prompt_injection": prompt_injection
        },
        "metadata": {
            "total_guidelines": len(guidelines),
            "issue_type": ticket_data["fields"]["issuetype"]["name"],
            "priority": ticket_data["fields"]["priority"]["name"]
        }
    }


def generate_sample_guidelines(security_categories: list) -> list:
    """Generate sample security guidelines based on categories."""
    guidelines = []
    
    if "authentication" in security_categories:
        guidelines.append({
            "category": "authentication",
            "title": "JWT Token Security",
            "description": "Implement secure JWT token handling",
            "priority": "high",
            "implementation": "Use proper token validation, expiration, and secure storage",
            "examples": [
                "Validate token signature and expiration",
                "Use secure token storage (httpOnly cookies)",
                "Implement token refresh mechanism"
            ],
            "references": ["OWASP JWT Guidelines", "RFC 7519"]
        })
    
    if "api_security" in security_categories:
        guidelines.append({
            "category": "api_security",
            "title": "API Rate Limiting",
            "description": "Implement rate limiting to prevent abuse",
            "priority": "high",
            "implementation": "Use Redis or similar for distributed rate limiting",
            "examples": [
                "Implement different rate limits for different user tiers",
                "Use exponential backoff for failed requests",
                "Monitor and alert on rate limit violations"
            ],
            "references": ["OWASP Rate Limiting Cheat Sheet"]
        })
    
    if "database" in security_categories:
        guidelines.append({
            "category": "database",
            "title": "SQL Injection Prevention",
            "description": "Prevent SQL injection attacks using parameterized queries",
            "priority": "critical",
            "implementation": "Always use parameterized queries or prepared statements",
            "examples": [
                "Use ORM frameworks that handle parameterization",
                "Validate and sanitize all database inputs",
                "Use database connection pooling with limited privileges"
            ],
            "references": ["OWASP SQL Injection Prevention Cheat Sheet"]
        })
    
    if "web_security" in security_categories:
        guidelines.append({
            "category": "web_security",
            "title": "XSS Prevention",
            "description": "Prevent XSS attacks through proper input validation and output encoding",
            "priority": "high",
            "implementation": "Validate and sanitize all user inputs, encode output data",
            "examples": [
                "Use CSP headers to restrict script execution",
                "Implement XSS filters in web frameworks",
                "Use template engines that auto-escape output"
            ],
            "references": ["OWASP XSS Prevention Cheat Sheet"]
        })
    
    if "secrets_management" in security_categories:
        guidelines.append({
            "category": "secrets_management",
            "title": "Secure Secrets Storage",
            "description": "Never store secrets in source code or configuration files",
            "priority": "critical",
            "implementation": "Use dedicated secrets management services",
            "examples": [
                "Use AWS Secrets Manager or Azure Key Vault",
                "Store secrets in environment variables with proper access controls",
                "Use encrypted configuration files with key rotation"
            ],
            "references": ["OWASP Secrets Management Cheat Sheet"]
        })
    
    return guidelines


def generate_prompt_injection(risk_level: str, technologies: list, security_categories: list, guidelines: list) -> str:
    """Generate formatted prompt injection for code generation."""
    injection_parts = []
    
    # Add security header
    injection_parts.append("🔒 SECURITY REQUIREMENTS:")
    injection_parts.append("")
    
    # Add risk level warning
    if risk_level in ["critical", "high"]:
        risk_emoji = "🚨" if risk_level == "critical" else "⚠️"
        injection_parts.append(f"{risk_emoji} {risk_level.upper()} SECURITY RISK DETECTED")
        injection_parts.append("")
    
    # Add technology-specific requirements
    if technologies:
        injection_parts.append("🛠️  TECHNOLOGY-SPECIFIC SECURITY:")
        for tech in technologies:
            injection_parts.append(f"   • {tech.title()}: Follow secure coding practices")
        injection_parts.append("")
    
    # Add security categories
    if security_categories:
        injection_parts.append("🔐 SECURITY CATEGORIES TO ADDRESS:")
        for category in security_categories:
            category_name = category.replace("_", " ").title()
            injection_parts.append(f"   • {category_name}")
        injection_parts.append("")
    
    # Add specific guidelines
    if guidelines:
        injection_parts.append("📋 MANDATORY SECURITY GUIDELINES:")
        injection_parts.append("")
        
        for guideline in guidelines[:3]:  # Limit to top 3 guidelines
            priority_emoji = {
                "critical": "🚨",
                "high": "⚠️",
                "medium": "📌",
                "low": "ℹ️"
            }.get(guideline["priority"], "📌")
            
            injection_parts.append(f"{priority_emoji} {guideline['title']}")
            injection_parts.append(f"   {guideline['description']}")
            injection_parts.append(f"   Implementation: {guideline['implementation']}")
            
            if guideline["examples"]:
                injection_parts.append("   Examples:")
                for example in guideline["examples"][:2]:  # Limit examples
                    injection_parts.append(f"     • {example}")
            
            injection_parts.append("")
    
    # Add general security reminders
    injection_parts.append("🔍 GENERAL SECURITY REMINDERS:")
    injection_parts.append("   • Validate all inputs")
    injection_parts.append("   • Use parameterized queries")
    injection_parts.append("   • Implement proper error handling")
    injection_parts.append("   • Follow principle of least privilege")
    injection_parts.append("   • Use secure defaults")
    injection_parts.append("   • Implement proper logging and monitoring")
    injection_parts.append("")
    
    injection_parts.append("⚠️  IMPORTANT: Review all generated code for security vulnerabilities before deployment!")
    
    return "\n".join(injection_parts)


def display_assessment_results(result: Dict[str, Any]) -> None:
    """Display security assessment results in a formatted way."""
    assessment = result["assessment"]
    metadata = result["metadata"]
    
    print(f"Risk Level: {assessment['risk_level'].upper()}")
    print(f"Technologies: {', '.join(assessment['technologies']) if assessment['technologies'] else 'None identified'}")
    print(f"Security Categories: {', '.join(assessment['security_categories']) if assessment['security_categories'] else 'None identified'}")
    print(f"Guidelines Applied: {metadata['total_guidelines']}")
    print(f"Issue Type: {metadata['issue_type']}")
    print(f"Priority: {metadata['priority']}")
    
    if assessment['guidelines']:
        print("\nKey Security Guidelines:")
        for guideline in assessment['guidelines'][:2]:  # Show top 2
            priority_emoji = {
                "critical": "🚨",
                "high": "⚠️",
                "medium": "📌",
                "low": "ℹ️"
            }.get(guideline["priority"], "📌")
            print(f"  {priority_emoji} {guideline['title']}")
    
    print(f"\nPrompt Injection Preview:")
    preview = assessment['prompt_injection'][:200] + "..." if len(assessment['prompt_injection']) > 200 else assessment['prompt_injection']
    print(f"  {preview}")


def demonstrate_integration_workflow() -> None:
    """Demonstrate how to integrate the security assessment into a code generation workflow."""
    print("\n🔄 Integration Workflow Example")
    print("=" * 50)
    
    # Example ticket
    ticket = EXAMPLE_TICKETS["authentication_ticket"]
    
    print("1. 📋 Original Jira Ticket:")
    print(f"   Summary: {ticket['summary']}")
    print(f"   Description: {ticket['description'][:100]}...")
    
    print("\n2. 🔒 Security Assessment:")
    assessment = simulate_security_assessment(ticket)
    print(f"   Risk Level: {assessment['assessment']['risk_level'].upper()}")
    print(f"   Categories: {', '.join(assessment['assessment']['security_categories'])}")
    
    print("\n3. 📝 Generated Prompt Injection:")
    prompt_injection = assessment['assessment']['prompt_injection']
    print(f"   Length: {len(prompt_injection)} characters")
    print(f"   Preview: {prompt_injection[:150]}...")
    
    print("\n4. 🤖 Code Generation Prompt:")
    code_prompt = f"""
Generate secure authentication code for the following requirements:

{prompt_injection}

Original Ticket Requirements:
- Summary: {ticket['summary']}
- Description: {ticket['description']}

Please generate:
1. User authentication service
2. JWT token management
3. Password hashing implementation
4. Session management
5. Security middleware

Ensure all code follows the security requirements above.
"""
    
    print(f"   Total prompt length: {len(code_prompt)} characters")
    print("   ✅ Security requirements automatically injected!")
    
    print("\n5. 🔍 Next Steps:")
    print("   • Generate code using the enhanced prompt")
    print("   • Review generated code for security compliance")
    print("   • Run security tests and validation")
    print("   • Deploy with confidence!")


if __name__ == "__main__":
    # Run the demonstration
    asyncio.run(demonstrate_security_assessment())
    demonstrate_integration_workflow()
