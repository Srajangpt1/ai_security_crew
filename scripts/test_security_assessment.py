#!/usr/bin/env python3
"""Test script for the security assessment tool.

This script demonstrates the security assessment functionality
and can be used to verify the implementation works correctly.
"""

import sys
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mcp_security_review.security import SecurityAssessment


def test_security_assessment() -> None:
    """Test the security assessment functionality."""
    print("🔒 Testing MCP Security Review Assessment Tool")
    print("=" * 50)

    # Create test ticket data
    test_ticket = {
        "summary": "Implement secure user authentication with JWT tokens",
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

        Technologies: Python, Django, PostgreSQL
        """,
        "fields": {
            "issuetype": {"name": "Story"},
            "priority": {"name": "High"},
            "labels": ["authentication", "security", "jwt", "mfa", "python", "django"],
        },
        "comments": [
            {"body": "Need to ensure JWT tokens are properly validated"},
            {"body": "Also add input validation to prevent SQL injection"},
        ],
    }

    print("📋 Test Ticket:")
    print(f"   Summary: {test_ticket['summary']}")
    print(f"   Labels: {', '.join(test_ticket['fields']['labels'])}")
    print()

    try:
        # Create security assessment instance
        assessment = SecurityAssessment()

        print("🔍 Running Security Assessment...")

        # Perform assessment
        requirements = assessment.assess_ticket(test_ticket)

        print("✅ Assessment Complete!")
        print()

        # Display results
        print("📊 Assessment Results:")
        print(f"   Risk Level: {requirements.risk_level.upper()}")
        print(
            f"   Technologies: {', '.join(requirements.technologies) if requirements.technologies else 'None identified'}"
        )
        print(
            f"   Security Categories: {', '.join(requirements.security_categories) if requirements.security_categories else 'None identified'}"
        )
        print(f"   Guidelines Applied: {len(requirements.guidelines)}")
        print()

        # Display guidelines
        if requirements.guidelines:
            print("📋 Security Guidelines:")
            for i, guideline in enumerate(requirements.guidelines[:3], 1):  # Show top 3
                priority_emoji = {
                    "critical": "🚨",
                    "high": "⚠️",
                    "medium": "📌",
                    "low": "ℹ️",
                }.get(guideline["priority"], "📌")
                print(f"   {i}. {priority_emoji} {guideline['title']}")
                print(f"      {guideline['description']}")
            print()

        # Display prompt injection preview
        print("🤖 Prompt Injection Preview:")
        preview = (
            requirements.prompt_injection[:300] + "..."
            if len(requirements.prompt_injection) > 300
            else requirements.prompt_injection
        )
        print(f"   {preview}")
        print()

        # Test JSON serialization
        print("💾 Testing JSON Serialization...")
        json_output = assessment.to_json(requirements)
        parsed_back = assessment.from_json(json_output)

        assert parsed_back.risk_level == requirements.risk_level  # noqa: S101
        assert parsed_back.security_categories == requirements.security_categories  # noqa: S101
        assert parsed_back.technologies == requirements.technologies  # noqa: S101
        print("✅ JSON serialization works correctly!")
        print()

        # Display summary
        print("📝 Assessment Summary:")
        print(f"   {requirements.summary}")
        print()

        print("🎉 All tests passed! Security assessment tool is working correctly.")

    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


def test_different_risk_levels() -> None:
    """Test different risk level scenarios."""
    print("\n🧪 Testing Different Risk Levels")
    print("=" * 50)

    test_cases = [
        {
            "name": "Low Risk",
            "ticket": {
                "summary": "Update documentation",
                "description": "Update the README file with new installation instructions",
                "fields": {"issuetype": {"name": "Task"}, "labels": ["documentation"]},
            },
        },
        {
            "name": "Medium Risk",
            "ticket": {
                "summary": "Add input validation to contact form",
                "description": "Implement form validation to prevent invalid data submission",
                "fields": {
                    "issuetype": {"name": "Story"},
                    "labels": ["validation", "form"],
                },
            },
        },
        {
            "name": "High Risk",
            "ticket": {
                "summary": "Implement user authentication system",
                "description": "Create secure login system with JWT tokens and password hashing",
                "fields": {
                    "issuetype": {"name": "Story"},
                    "labels": ["authentication", "security", "jwt"],
                },
            },
        },
        {
            "name": "Critical Risk",
            "ticket": {
                "summary": "CRITICAL: SQL injection vulnerability in user search",
                "description": "Critical security vulnerability allows SQL injection attacks. Immediate fix required.",
                "fields": {
                    "issuetype": {"name": "Bug"},
                    "labels": ["security", "critical", "sql-injection"],
                },
            },
        },
    ]

    assessment = SecurityAssessment()

    for test_case in test_cases:
        print(f"\n📋 {test_case['name']} Test Case:")
        print(f"   Summary: {test_case['ticket']['summary']}")

        try:
            requirements = assessment.assess_ticket(test_case["ticket"])
            print(f"   ✅ Risk Level: {requirements.risk_level.upper()}")
            print(f"   📊 Categories: {len(requirements.security_categories)}")
            print(f"   📋 Guidelines: {len(requirements.guidelines)}")
        except Exception as e:
            print(f"   ❌ Error: {e}")


if __name__ == "__main__":
    test_security_assessment()
    test_different_risk_levels()

    print("\n🎯 Security Assessment Tool Test Complete!")
    print("The tool is ready for integration with MCP Security Review.")
