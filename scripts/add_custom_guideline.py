#!/usr/bin/env python3
"""Helper script to easily add custom security guidelines with auto-generated metadata.

This script makes it easy for users to add custom guidelines without manually
specifying category, priority, and tags. It automatically infers them from content.

Usage:
    # Interactive mode
    python3 scripts/add_custom_guideline.py

    # From file
    python3 scripts/add_custom_guideline.py --file my_guideline.md

    # Quick add
    python3 scripts/add_custom_guideline.py --title "API Key Rotation" --content "..."
"""

import argparse
import re
from pathlib import Path


def extract_keywords(text: str) -> list[str]:
    """Extract important keywords from text for tag generation."""
    # Common security-related keywords
    security_keywords = {
        "authentication",
        "authorization",
        "encryption",
        "password",
        "token",
        "api",
        "database",
        "sql",
        "injection",
        "xss",
        "csrf",
        "session",
        "cookie",
        "oauth",
        "jwt",
        "mfa",
        "2fa",
        "ssl",
        "tls",
        "https",
        "cors",
        "validation",
        "sanitization",
        "logging",
        "monitoring",
        "audit",
        "compliance",
        "gdpr",
        "hipaa",
        "pci",
        "cloud",
        "aws",
        "azure",
        "gcp",
        "kubernetes",
        "docker",
        "container",
        "microservices",
        "api key",
        "secret",
        "credential",
        "vulnerability",
        "threat",
        "risk",
        "security",
        "attack",
        "defense",
        "protection",
    }

    text_lower = text.lower()
    found_keywords = set()

    for keyword in security_keywords:
        if keyword in text_lower:
            found_keywords.add(keyword.replace(" ", "_"))

    return sorted(found_keywords)[:10]  # Limit to top 10


def infer_category(title: str, content: str) -> str:
    """Automatically infer the most appropriate category from content."""
    text = (title + " " + content).lower()

    # Category detection rules (ordered by specificity)
    category_rules = [
        # Compliance & Audit
        (
            ["compliance", "gdpr", "hipaa", "pci", "regulation", "audit", "legal"],
            "compliance_security",
        ),
        # Authentication
        (
            [
                "authentication",
                "login",
                "password",
                "credential",
                "session",
                "oauth",
                "jwt",
                "sso",
                "mfa",
                "2fa",
            ],
            "authentication",
        ),
        # Authorization
        (
            ["authorization", "permission", "role", "rbac", "acl", "access control"],
            "authorization",
        ),
        # API Security
        (
            ["api", "rest", "graphql", "endpoint", "webhook", "rate limit"],
            "api_security",
        ),
        # Database
        (
            [
                "database",
                "sql",
                "nosql",
                "query",
                "injection",
                "orm",
                "mongodb",
                "redis",
            ],
            "database",
        ),
        # Cryptography
        (
            [
                "encryption",
                "decrypt",
                "crypto",
                "hash",
                "ssl",
                "tls",
                "certificate",
                "key management",
            ],
            "cryptography",
        ),
        # Web Security
        (
            ["xss", "csrf", "cors", "csp", "clickjacking", "web", "http", "browser"],
            "web_security",
        ),
        # Data Validation
        (
            ["validation", "sanitization", "input", "output", "encoding", "escaping"],
            "data_validation",
        ),
        # Cloud Security
        (
            [
                "cloud",
                "aws",
                "azure",
                "gcp",
                "kubernetes",
                "docker",
                "container",
                "serverless",
            ],
            "cloud_security",
        ),
        # Infrastructure
        (
            ["infrastructure", "network", "firewall", "vpn", "dns", "ddos"],
            "infrastructure_security",
        ),
        # Supply Chain
        (
            ["dependency", "npm", "package", "supply chain", "vulnerability", "cve"],
            "supply_chain_security",
        ),
        # Secrets Management
        (["secret", "key", "vault", "credential storage", "env"], "secrets_management"),
        # Mobile
        (["mobile", "android", "ios", "app"], "mobile_security"),
        # Logging
        (["logging", "log", "monitoring", "siem", "audit trail"], "logging"),
        # Error Handling
        (["error", "exception", "handling", "stack trace"], "error_handling"),
    ]

    # Check each rule
    for keywords, category in category_rules:
        if any(keyword in text for keyword in keywords):
            return category

    # Default fallback
    return "general"


def infer_priority(title: str, content: str) -> str:
    """Automatically infer priority level from content."""
    text = (title + " " + content).lower()

    # Critical indicators
    critical_keywords = [
        "critical",
        "urgent",
        "immediate",
        "sql injection",
        "authentication bypass",
        "remote code execution",
        "data breach",
        "password",
        "credential",
        "secret",
        "encryption",
    ]

    # High priority indicators
    high_keywords = [
        "important",
        "essential",
        "required",
        "must",
        "xss",
        "csrf",
        "injection",
        "vulnerability",
        "security risk",
        "exploit",
    ]

    # Low priority indicators
    low_keywords = [
        "optional",
        "nice to have",
        "recommendation",
        "best practice",
        "consider",
        "suggestion",
    ]

    # Check for priority indicators
    if any(keyword in text for keyword in critical_keywords):
        return "critical"
    elif any(keyword in text for keyword in high_keywords):
        return "high"
    elif any(keyword in text for keyword in low_keywords):
        return "low"
    else:
        return "medium"  # Default


def format_guideline(
    title: str,
    content: str,
    category: str = None,
    priority: str = None,
    tags: list[str] = None,
) -> str:
    """Format a guideline with metadata header."""
    # Auto-infer if not provided
    if category is None:
        category = infer_category(title, content)

    if priority is None:
        priority = infer_priority(title, content)

    if tags is None:
        tags = extract_keywords(title + " " + content)

    # Build metadata header
    metadata = f"""category: {category}
priority: {priority}
tags: {", ".join(tags)}

"""

    # Ensure content starts with a title
    if not content.strip().startswith("#"):
        content = f"# {title}\n\n{content}"

    return metadata + content


def save_guideline(
    title: str,
    content: str,
    category: str = None,
    priority: str = None,
    tags: list[str] = None,
    output_dir: Path = None,
) -> Path:
    """Save a guideline to the appropriate category directory."""
    # Auto-infer metadata
    if category is None:
        category = infer_category(title, content)

    if priority is None:
        priority = infer_priority(title, content)

    if tags is None:
        tags = extract_keywords(title + " " + content)

    # Determine output directory
    if output_dir is None:
        output_dir = (
            Path(__file__).parent.parent
            / "src"
            / "mcp_security_review"
            / "security"
            / "guidelines"
            / "docs"
        )

    # Create category directory if it doesn't exist
    category_dir = output_dir / category
    category_dir.mkdir(parents=True, exist_ok=True)

    # Generate filename from title
    filename = title.lower().replace(" ", "_").replace("-", "_")
    filename = re.sub(r"[^a-z0-9_]", "", filename)
    filename = f"{filename}.md"

    # Format and save
    formatted_content = format_guideline(title, content, category, priority, tags)
    output_path = category_dir / filename

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(formatted_content)

    return output_path


def interactive_mode() -> None:
    """Interactive mode for adding guidelines."""
    print("🔒 Add Custom Security Guideline")
    print("=" * 60)
    print()

    # Get title
    title = input("📝 Guideline Title: ").strip()
    if not title:
        print("❌ Title is required!")
        return

    print()
    print("📄 Guideline Content (press Ctrl+D or Ctrl+Z when done):")
    print("   You can write in markdown format.")
    print()

    # Get multi-line content
    lines = []
    try:
        while True:
            line = input()
            lines.append(line)
    except EOFError:
        pass

    content = "\n".join(lines).strip()
    if not content:
        print("❌ Content is required!")
        return

    print()
    print("🤖 Auto-detecting metadata...")

    # Infer metadata
    category = infer_category(title, content)
    priority = infer_priority(title, content)
    tags = extract_keywords(title + " " + content)

    print(f"   Category: {category}")
    print(f"   Priority: {priority}")
    print(f"   Tags: {', '.join(tags)}")
    print()

    # Confirm
    confirm = input("✅ Save guideline? (y/n): ").strip().lower()
    if confirm != "y":
        print("❌ Cancelled")
        return

    # Save
    output_path = save_guideline(title, content, category, priority, tags)
    print()
    print(f"✅ Guideline saved to: {output_path}")
    print()
    print("💡 The guideline will be automatically loaded on next use!")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Add custom security guidelines with auto-generated metadata"
    )
    parser.add_argument("--file", type=str, help="Load guideline from file")
    parser.add_argument("--title", type=str, help="Guideline title")
    parser.add_argument("--content", type=str, help="Guideline content")
    parser.add_argument("--category", type=str, help="Override auto-detected category")
    parser.add_argument("--priority", type=str, help="Override auto-detected priority")
    parser.add_argument(
        "--tags", type=str, help="Override auto-detected tags (comma-separated)"
    )

    args = parser.parse_args()

    # File mode
    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"❌ File not found: {args.file}")
            return

        content = file_path.read_text(encoding="utf-8")

        # Extract title from content if not provided
        title = args.title
        if not title:
            title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
            if title_match:
                title = title_match.group(1).strip()
            else:
                title = file_path.stem.replace("_", " ").title()

        tags = args.tags.split(",") if args.tags else None
        output_path = save_guideline(title, content, args.category, args.priority, tags)
        print(f"✅ Guideline saved to: {output_path}")

    # Quick mode
    elif args.title and args.content:
        tags = args.tags.split(",") if args.tags else None
        output_path = save_guideline(
            args.title, args.content, args.category, args.priority, tags
        )
        print(f"✅ Guideline saved to: {output_path}")

    # Interactive mode
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
