#!/usr/bin/env python3
"""Test script for the file-based security guidelines system."""

import sys
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mcp_security_review.security.guidelines import SecurityGuidelinesLoader


def test_guidelines_loader() -> None:
    """Test the file-based guidelines loader."""
    print("🔒 Testing File-Based Security Guidelines Loader")
    print("=" * 50)

    # Create loader instance
    loader = SecurityGuidelinesLoader()

    # Test loading all guidelines
    print(f"📁 Guidelines directory: {loader.guidelines_dir}")
    print(f"📋 Total guidelines loaded: {len(loader.get_all_guidelines())}")
    print()

    # Show all categories
    categories = loader.get_all_categories()
    print(f"📂 Available categories: {', '.join(categories)}")
    print()

    # Test context-based filtering
    print("🔍 Testing context-based filtering:")

    # Test authentication context
    auth_guidelines = loader.get_guidelines_for_context(
        "authentication", ["python", "django"]
    )
    print(f"   Authentication guidelines: {len(auth_guidelines)}")
    for guideline in auth_guidelines[:2]:  # Show first 2
        print(f"     - {guideline.title} ({guideline.priority})")

    # Test database context
    db_guidelines = loader.get_guidelines_for_context("database", ["python", "django"])
    print(f"   Database guidelines: {len(db_guidelines)}")
    for guideline in db_guidelines[:2]:  # Show first 2
        print(f"     - {guideline.title} ({guideline.priority})")

    print()

    # Test priority filtering
    print("⚡ Testing priority filtering:")
    critical_guidelines = loader.get_guidelines_by_priority("critical")
    print(f"   Critical guidelines: {len(critical_guidelines)}")
    for guideline in critical_guidelines:
        print(f"     - {guideline.title} ({guideline.category})")

    print()

    # Test search functionality
    print("🔎 Testing search functionality:")
    jwt_guidelines = loader.search_guidelines("jwt")
    print(f"   JWT-related guidelines: {len(jwt_guidelines)}")
    for guideline in jwt_guidelines:
        print(f"     - {guideline.title} ({guideline.category})")

    print()

    # Show detailed example
    if auth_guidelines:
        print("📝 Detailed example - First authentication guideline:")
        guideline = auth_guidelines[0]
        print(f"   Title: {guideline.title}")
        print(f"   Category: {guideline.category}")
        print(f"   Priority: {guideline.priority}")
        print(f"   Description: {guideline.description[:100]}...")
        print(f"   Tags: {', '.join(guideline.tags)}")
        print(f"   Examples: {len(guideline.examples)}")
        if guideline.examples:
            print(f"     - {guideline.examples[0]}")
        print(f"   References: {len(guideline.references)}")
        if guideline.references:
            print(f"     - {guideline.references[0]}")

    print()
    print("✅ File-based guidelines system is working correctly!")
    print()
    print("💡 To add new guidelines:")
    print(
        "   1. Create a new .md or .txt file in src/mcp_security_review/security/guidelines/"
    )
    print("   2. Include metadata like category, priority, and tags")
    print("   3. The system will automatically load and parse the file")
    print("   4. Use loader.reload_guidelines() to refresh without restarting")


if __name__ == "__main__":
    test_guidelines_loader()
