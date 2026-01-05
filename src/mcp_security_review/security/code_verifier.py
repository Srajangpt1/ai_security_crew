"""Code security review context builder for AI-powered analysis.

This module prepares security context and review prompts for the AI agent
to perform security analysis on generated code.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SecurityReviewContext:
    """Context for AI-powered security review."""

    code: str
    file_path: str | None
    technologies_detected: list[str] = field(default_factory=list)
    security_categories: list[str] = field(default_factory=list)
    risk_level: str = "medium"
    review_focus_areas: list[str] = field(default_factory=list)
    security_checklist: list[str] = field(default_factory=list)
    review_prompt: str = ""


class CodeReviewContextBuilder:
    """Builds context for AI-powered security code review."""

    def __init__(self) -> None:
        self._technology_patterns = self._load_technology_patterns()
        self._category_checklists = self._load_category_checklists()

    def build_review_context(
        self,
        code: str,
        file_path: str | None = None,
        security_context: dict[str, Any] | None = None,
    ) -> SecurityReviewContext:
        """Build context for AI security review.

        Args:
            code: The source code to review.
            file_path: Optional file path for context.
            security_context: Optional security requirements from prior assessment.

        Returns:
            SecurityReviewContext with all information needed for AI review.
        """
        # Detect technologies from the code
        technologies = self._detect_technologies(code, file_path)

        # Get security categories from context or infer from code
        security_categories = []
        risk_level = "medium"
        if security_context:
            security_categories = security_context.get("security_categories", [])
            risk_level = security_context.get("risk_level", "medium")

        # Build focus areas based on technologies and categories
        focus_areas = self._build_focus_areas(technologies, security_categories)

        # Build security checklist for the AI to verify
        checklist = self._build_security_checklist(technologies, security_categories)

        # Build the review prompt for the AI
        review_prompt = self._build_review_prompt(
            code=code,
            file_path=file_path,
            technologies=technologies,
            security_categories=security_categories,
            risk_level=risk_level,
            focus_areas=focus_areas,
            checklist=checklist,
        )

        return SecurityReviewContext(
            code=code,
            file_path=file_path,
            technologies_detected=technologies,
            security_categories=security_categories,
            risk_level=risk_level,
            review_focus_areas=focus_areas,
            security_checklist=checklist,
            review_prompt=review_prompt,
        )

    def _detect_technologies(
        self, code: str, file_path: str | None = None
    ) -> list[str]:
        """Detect technologies used in the code."""
        technologies = []
        code_lower = code.lower()

        # Check file extension
        if file_path:
            ext_tech_map = {
                ".py": "python",
                ".js": "javascript",
                ".ts": "typescript",
                ".jsx": "react",
                ".tsx": "react",
                ".java": "java",
                ".go": "go",
                ".rb": "ruby",
                ".php": "php",
                ".cs": "csharp",
                ".rs": "rust",
                ".sql": "sql",
            }
            for ext, tech in ext_tech_map.items():
                if file_path.endswith(ext) and tech not in technologies:
                    technologies.append(tech)

        # Check code patterns
        for tech, patterns in self._technology_patterns.items():
            for pattern in patterns:
                if re.search(pattern, code_lower):
                    if tech not in technologies:
                        technologies.append(tech)
                    break

        return technologies

    def _build_focus_areas(
        self, technologies: list[str], categories: list[str]
    ) -> list[str]:
        """Build list of security focus areas based on context."""
        focus_areas = []

        # Technology-specific focus areas
        tech_focus = {
            "python": [
                "Command injection via os.system/subprocess",
                "SQL injection in database queries",
                "Unsafe deserialization (pickle)",
                "eval/exec usage",
            ],
            "javascript": [
                "XSS vulnerabilities (innerHTML, document.write)",
                "Prototype pollution",
                "eval() and Function() usage",
                "Insecure DOM manipulation",
            ],
            "typescript": [
                "Type safety bypasses",
                "XSS in template literals",
                "Unsafe type assertions",
            ],
            "react": [
                "dangerouslySetInnerHTML usage",
                "XSS in JSX",
                "Unsafe refs and state handling",
            ],
            "java": [
                "SQL injection with Statement",
                "XML External Entity (XXE)",
                "Unsafe deserialization",
                "Command injection via Runtime.exec",
            ],
            "sql": [
                "SQL injection patterns",
                "Privilege escalation queries",
                "Data exposure (SELECT *)",
                "Missing WHERE clauses on UPDATE/DELETE",
            ],
            "go": [
                "SQL injection",
                "Command injection",
                "Path traversal",
                "Race conditions",
            ],
        }

        for tech in technologies:
            if tech in tech_focus:
                focus_areas.extend(tech_focus[tech])

        # Category-specific focus areas
        category_focus = {
            "authentication": [
                "Password handling and storage",
                "Session management",
                "Token validation",
                "Brute force protection",
            ],
            "authorization": [
                "Access control checks",
                "Role validation",
                "Privilege escalation risks",
                "IDOR vulnerabilities",
            ],
            "data_validation": [
                "Input validation presence",
                "Output encoding",
                "Sanitization of user data",
                "Type checking",
            ],
            "cryptography": [
                "Algorithm strength (avoid MD5, SHA1, DES)",
                "Key management",
                "Secure random number generation",
                "Proper encryption modes",
            ],
            "api_security": [
                "Rate limiting",
                "Input validation on endpoints",
                "Authentication on all endpoints",
                "Proper error responses",
            ],
            "database": [
                "Parameterized queries",
                "Connection security",
                "Credential management",
                "Query result handling",
            ],
            "secrets_management": [
                "No hardcoded credentials",
                "Environment variable usage",
                "Secure storage of secrets",
                "No secrets in logs",
            ],
            "logging": [
                "No sensitive data in logs",
                "Proper error logging",
                "Audit trail for security events",
            ],
        }

        for category in categories:
            if category in category_focus:
                focus_areas.extend(category_focus[category])

        # Remove duplicates while preserving order
        seen = set()
        unique_focus = []
        for item in focus_areas:
            if item not in seen:
                seen.add(item)
                unique_focus.append(item)

        return unique_focus

    def _build_security_checklist(
        self, technologies: list[str], categories: list[str]
    ) -> list[str]:
        """Build a security checklist for the AI to verify."""
        checklist = [
            "No hardcoded passwords, API keys, or secrets",
            "No SQL queries built with string concatenation",
            "All user inputs are validated before use",
            "Sensitive data is not logged or exposed in errors",
            "Proper error handling without information disclosure",
        ]

        # Add technology-specific checks
        if "python" in technologies:
            checklist.extend(
                [
                    "No use of eval() or exec() with user input",
                    "No pickle.loads() on untrusted data",
                    "subprocess calls use shell=False",
                ]
            )

        if "javascript" in technologies or "typescript" in technologies:
            checklist.extend(
                [
                    "No innerHTML with unsanitized content",
                    "No document.write() usage",
                    "No eval() or new Function() with dynamic content",
                ]
            )

        if "react" in technologies:
            checklist.extend(
                [
                    "dangerouslySetInnerHTML is sanitized if used",
                    "User input in JSX is properly escaped",
                ]
            )

        if "java" in technologies:
            checklist.extend(
                [
                    "PreparedStatement used instead of Statement for SQL",
                    "No Runtime.exec() with user-controlled input",
                ]
            )

        # Add category-specific checks
        if "authentication" in categories:
            checklist.extend(
                [
                    "Passwords are hashed with strong algorithms (bcrypt, argon2)",
                    "Password comparison is timing-safe",
                    "Session tokens are securely generated",
                ]
            )

        if "cryptography" in categories:
            checklist.extend(
                [
                    "No weak algorithms (MD5, SHA1, DES, RC4)",
                    "Cryptographic keys are not hardcoded",
                    "Using secure random number generator for crypto",
                ]
            )

        if "authorization" in categories:
            checklist.extend(
                [
                    "Access control checks before sensitive operations",
                    "User permissions are validated server-side",
                ]
            )

        return checklist

    def _build_review_prompt(
        self,
        code: str,
        file_path: str | None,
        technologies: list[str],
        security_categories: list[str],
        risk_level: str,
        focus_areas: list[str],
        checklist: list[str],
    ) -> str:
        """Build a comprehensive review prompt for the AI agent."""
        prompt_parts = []

        # Header
        prompt_parts.append("## SECURITY CODE REVIEW REQUEST")
        prompt_parts.append("")

        # Context
        if file_path:
            prompt_parts.append(f"**File:** `{file_path}`")
        if technologies:
            prompt_parts.append(f"**Technologies:** {', '.join(technologies)}")
        if security_categories:
            prompt_parts.append(
                f"**Security Categories:** {', '.join(security_categories)}"
            )
        prompt_parts.append(f"**Risk Level:** {risk_level.upper()}")
        prompt_parts.append("")

        # Instructions
        prompt_parts.append("### Review Instructions")
        prompt_parts.append("")
        prompt_parts.append(
            "Analyze the code below for security vulnerabilities. For each issue found:"
        )
        prompt_parts.append(
            "1. Identify the vulnerability type and severity (Critical/High/Medium/Low)"
        )
        prompt_parts.append("2. Explain why it's a security risk")
        prompt_parts.append("3. Show the problematic code snippet")
        prompt_parts.append("4. Provide a secure code fix")
        prompt_parts.append("")

        # Focus areas
        if focus_areas:
            prompt_parts.append("### Focus Areas")
            prompt_parts.append("")
            prompt_parts.append("Pay special attention to:")
            for area in focus_areas[:10]:  # Limit to top 10
                prompt_parts.append(f"- {area}")
            prompt_parts.append("")

        # Checklist
        prompt_parts.append("### Security Checklist")
        prompt_parts.append("")
        prompt_parts.append("Verify each item and report violations:")
        for item in checklist:
            prompt_parts.append(f"- [ ] {item}")
        prompt_parts.append("")

        # Code to review
        prompt_parts.append("### Code to Review")
        prompt_parts.append("")
        prompt_parts.append("```")
        prompt_parts.append(code)
        prompt_parts.append("```")
        prompt_parts.append("")

        # Expected output format
        prompt_parts.append("### Expected Response Format")
        prompt_parts.append("")
        prompt_parts.append("Provide your security review with:")
        prompt_parts.append(
            "1. **Summary:** Overall assessment (Secure/Needs Attention/Insecure)"
        )
        prompt_parts.append(
            "2. **Findings:** List of security issues with severity and fixes"
        )
        prompt_parts.append("3. **Checklist Results:** Which items pass/fail")
        prompt_parts.append("4. **Recommendations:** Prioritized list of actions")

        return "\n".join(prompt_parts)

    def _load_technology_patterns(self) -> dict[str, list[str]]:
        """Load technology detection patterns."""
        return {
            "python": [
                r"\bimport\s+\w+",
                r"\bdef\s+\w+\s*\(",
                r"\bclass\s+\w+\s*[:\(]",
                r"__init__",
                r"self\.",
            ],
            "javascript": [
                r"\bfunction\s+\w+\s*\(",
                r"\bconst\s+\w+\s*=",
                r"\blet\s+\w+\s*=",
                r"\bvar\s+\w+\s*=",
                r"=>\s*\{",
                r"require\s*\(",
                r"module\.exports",
            ],
            "typescript": [
                r":\s*(string|number|boolean|any)\b",
                r"interface\s+\w+",
                r"type\s+\w+\s*=",
            ],
            "java": [
                r"\bpublic\s+class\b",
                r"\bprivate\s+\w+\s+\w+",
                r"\bSystem\.out\.",
                r"\bimport\s+java\.",
            ],
            "sql": [
                r"\bSELECT\s+.+\s+FROM\b",
                r"\bINSERT\s+INTO\b",
                r"\bUPDATE\s+.+\s+SET\b",
                r"\bDELETE\s+FROM\b",
                r"\bCREATE\s+TABLE\b",
            ],
            "react": [
                r"\bReact\.",
                r"\buseState\b",
                r"\buseEffect\b",
                r"<\w+\s+\w+\s*=",
            ],
            "go": [
                r"\bpackage\s+\w+",
                r"\bfunc\s+\w+\s*\(",
                r"\bimport\s+\(",
                r":=",
            ],
        }

    def _load_category_checklists(self) -> dict[str, list[str]]:
        """Load category-specific security checklists."""
        return {
            "authentication": [
                "Passwords are never stored in plain text",
                "Strong password hashing (bcrypt, scrypt, argon2)",
                "Secure session management",
                "Protection against brute force attacks",
                "Secure password reset flow",
            ],
            "authorization": [
                "Principle of least privilege applied",
                "Access controls on all protected resources",
                "No direct object reference vulnerabilities",
                "Role-based access properly implemented",
            ],
            "data_validation": [
                "All inputs validated on server-side",
                "Proper output encoding based on context",
                "File upload validation (type, size, content)",
                "No reliance on client-side validation alone",
            ],
            "cryptography": [
                "Strong encryption algorithms used",
                "Proper key management",
                "No hardcoded encryption keys",
                "Secure random number generation",
            ],
            "api_security": [
                "Authentication required for sensitive endpoints",
                "Rate limiting implemented",
                "Input validation on all parameters",
                "Proper error handling without data leakage",
            ],
        }
