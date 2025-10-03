"""Security guidelines loader for file-based guideline management."""

import re
import logging
from pathlib import Path
from typing import Dict, List, Optional

from .base import SecurityGuideline

logger = logging.getLogger(__name__)


class SecurityGuidelinesLoader:
    """Loads security guidelines from text/markdown files in a directory."""
    
    def __init__(self, guidelines_dir: Optional[str] = None) -> None:
        """Initialize the guidelines loader.
        
        Args:
            guidelines_dir: Path to the guidelines directory. If None, uses default location.
        """
        if guidelines_dir is None:
            # Default to the 'docs' subdirectory under guidelines
            self.guidelines_dir = Path(__file__).parent / "docs"
        else:
            self.guidelines_dir = Path(guidelines_dir)
        
        self._guidelines_cache: List[SecurityGuideline] = []
        self._load_all_guidelines()
    
    def _load_all_guidelines(self) -> None:
        """Load all guidelines from text/markdown files."""
        self._guidelines_cache.clear()
        
        if not self.guidelines_dir.exists():
            logger.warning(f"Guidelines directory does not exist: {self.guidelines_dir}")
            return
        
        # Load guidelines from text and markdown files
        for file_path in self.guidelines_dir.glob("*"):
            if (file_path.is_file() and 
                file_path.suffix.lower() in ['.txt', '.md', '.markdown'] and
                not file_path.name.lower().startswith('readme')):
                try:
                    guideline = self._load_guideline_from_file(file_path)
                    if guideline:
                        self._guidelines_cache.append(guideline)
                except Exception as e:
                    logger.error(f"Error loading guideline from {file_path}: {e}")
        
        logger.info(f"Loaded {len(self._guidelines_cache)} guidelines")
    
    def _load_guideline_from_file(self, file_path: Path) -> Optional[SecurityGuideline]:
        """Load a guideline from a text/markdown file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse the file content to extract guideline information
            return self._parse_guideline_from_content(content, file_path.stem)
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    def _parse_guideline_from_content(self, content: str, filename: str) -> Optional[SecurityGuideline]:
        """Parse a guideline from file content."""
        try:
            # Extract metadata from the content
            title = self._extract_title(content, filename)
            category = self._extract_category(content)
            priority = self._extract_priority(content)
            description = self._extract_description(content)
            implementation = self._extract_implementation(content)
            examples = self._extract_examples(content)
            references = self._extract_references(content)
            tags = self._extract_tags(content)
            
            return SecurityGuideline(
                category=category,
                title=title,
                description=description,
                priority=priority,
                implementation=implementation,
                examples=examples,
                references=references,
                tags=tags
            )
        except Exception as e:
            logger.error(f"Error parsing guideline content: {e}")
            return None
    
    def _extract_title(self, content: str, filename: str) -> str:
        """Extract title from content or use filename."""
        # Look for markdown headers
        title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        if title_match:
            return title_match.group(1).strip()
        
        # Look for title in metadata
        title_match = re.search(r'^title:\s*(.+)$', content, re.MULTILINE | re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()
        
        # Use filename as fallback
        return filename.replace('_', ' ').replace('-', ' ').title()
    
    def _extract_category(self, content: str) -> str:
        """Extract category from content."""
        category_match = re.search(r'^category:\s*(.+)$', content, re.MULTILINE | re.IGNORECASE)
        if category_match:
            return category_match.group(1).strip().lower()
        
        # Try to infer from content
        content_lower = content.lower()
        if any(keyword in content_lower for keyword in ['auth', 'login', 'password', 'token']):
            return 'authentication'
        elif any(keyword in content_lower for keyword in ['sql', 'database', 'query', 'injection']):
            return 'database'
        elif any(keyword in content_lower for keyword in ['api', 'endpoint', 'rest', 'graphql']):
            return 'api_security'
        elif any(keyword in content_lower for keyword in ['encrypt', 'hash', 'crypto', 'ssl']):
            return 'cryptography'
        elif any(keyword in content_lower for keyword in ['xss', 'csrf', 'web', 'http']):
            return 'web_security'
        else:
            return 'general'
    
    def _extract_priority(self, content: str) -> str:
        """Extract priority from content."""
        priority_match = re.search(r'^priority:\s*(.+)$', content, re.MULTILINE | re.IGNORECASE)
        if priority_match:
            priority = priority_match.group(1).strip().lower()
            if priority in ['critical', 'high', 'medium', 'low']:
                return priority
        
        # Try to infer from content
        content_lower = content.lower()
        if any(keyword in content_lower for keyword in ['critical', 'urgent', 'immediate']):
            return 'critical'
        elif any(keyword in content_lower for keyword in ['high', 'important', 'essential']):
            return 'high'
        elif any(keyword in content_lower for keyword in ['low', 'optional', 'nice to have']):
            return 'low'
        else:
            return 'medium'
    
    def _extract_description(self, content: str) -> str:
        """Extract description from content."""
        # Look for description in metadata
        desc_match = re.search(r'^description:\s*(.+)$', content, re.MULTILINE | re.IGNORECASE)
        if desc_match:
            return desc_match.group(1).strip()
        
        # Use first paragraph as description
        paragraphs = content.split('\n\n')
        for paragraph in paragraphs:
            paragraph = paragraph.strip()
            if paragraph and not paragraph.startswith('#') and not paragraph.startswith('title:') and not paragraph.startswith('category:'):
                return paragraph[:200] + '...' if len(paragraph) > 200 else paragraph
        
        return "Security guideline"
    
    def _extract_implementation(self, content: str) -> str:
        """Extract implementation details from content."""
        # Look for implementation section
        impl_match = re.search(r'##?\s*Implementation\s*\n(.*?)(?=\n##|\Z)', content, re.DOTALL | re.IGNORECASE)
        if impl_match:
            return impl_match.group(1).strip()
        
        # Look for how to section
        howto_match = re.search(r'##?\s*How to\s*\n(.*?)(?=\n##|\Z)', content, re.DOTALL | re.IGNORECASE)
        if howto_match:
            return howto_match.group(1).strip()
        
        return "Follow the guidelines in the content"
    
    def _extract_examples(self, content: str) -> List[str]:
        """Extract examples from content."""
        examples = []
        
        # Look for examples section
        examples_match = re.search(r'##?\s*Examples?\s*\n(.*?)(?=\n##|\Z)', content, re.DOTALL | re.IGNORECASE)
        if examples_match:
            examples_text = examples_match.group(1)
            # Extract bullet points or numbered items
            example_items = re.findall(r'[-*]\s*(.+)$', examples_text, re.MULTILINE)
            examples.extend([item.strip() for item in example_items])
        
        # Look for code blocks
        code_blocks = re.findall(r'```[\s\S]*?```', content)
        examples.extend([f"Code example: {block[:100]}..." for block in code_blocks[:3]])
        
        return examples[:5]  # Limit to 5 examples
    
    def _extract_references(self, content: str) -> List[str]:
        """Extract references from content."""
        references = []
        
        # Look for references section
        refs_match = re.search(r'##?\s*References?\s*\n(.*?)(?=\n##|\Z)', content, re.DOTALL | re.IGNORECASE)
        if refs_match:
            refs_text = refs_match.group(1)
            # Extract bullet points or numbered items
            ref_items = re.findall(r'[-*]\s*(.+)$', refs_text, re.MULTILINE)
            references.extend([item.strip() for item in ref_items])
        
        # Look for links
        links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content)
        references.extend([f"{text}: {url}" for text, url in links[:3]])
        
        return references[:5]  # Limit to 5 references
    
    def _extract_tags(self, content: str) -> List[str]:
        """Extract tags from content."""
        tags = []
        
        # Look for tags in metadata
        tags_match = re.search(r'^tags:\s*(.+)$', content, re.MULTILINE | re.IGNORECASE)
        if tags_match:
            tags_text = tags_match.group(1).strip()
            tags.extend([tag.strip() for tag in tags_text.split(',')])
        
        # Extract common security keywords from content
        content_lower = content.lower()
        security_keywords = [
            'authentication', 'authorization', 'encryption', 'validation', 'injection',
            'xss', 'csrf', 'sql', 'api', 'jwt', 'oauth', 'ssl', 'tls', 'mfa', '2fa'
        ]
        
        for keyword in security_keywords:
            if keyword in content_lower:
                tags.append(keyword)
        
        return list(set(tags))  # Remove duplicates
    
    def get_guidelines_for_context(self, context: str, technologies: List[str] = None) -> List[SecurityGuideline]:
        """Get relevant security guidelines for a given context and technology stack."""
        relevant_guidelines = []
        
        # Get all guidelines
        for guideline in self._guidelines_cache:
            if self._is_relevant_to_context(guideline, context, technologies):
                relevant_guidelines.append(guideline)
        
        # Sort by priority (critical first)
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        relevant_guidelines.sort(key=lambda g: priority_order.get(g.priority, 4))
        
        return relevant_guidelines
    
    def get_guidelines_by_category(self, category: str) -> List[SecurityGuideline]:
        """Get all guidelines for a specific category."""
        return [g for g in self._guidelines_cache if g.category == category]
    
    def get_all_categories(self) -> List[str]:
        """Get all available guideline categories."""
        categories = set(g.category for g in self._guidelines_cache)
        return list(categories)
    
    def get_guidelines_by_priority(self, priority: str) -> List[SecurityGuideline]:
        """Get all guidelines with a specific priority level."""
        return [g for g in self._guidelines_cache if g.priority == priority]
    
    def search_guidelines(self, query: str) -> List[SecurityGuideline]:
        """Search guidelines by title, description, or tags."""
        query_lower = query.lower()
        matching_guidelines = []
        
        for guideline in self._guidelines_cache:
            if (query_lower in guideline.title.lower() or
                query_lower in guideline.description.lower() or
                any(query_lower in tag.lower() for tag in guideline.tags)):
                matching_guidelines.append(guideline)
        
        return matching_guidelines
    
    def get_all_guidelines(self) -> List[SecurityGuideline]:
        """Get all loaded guidelines."""
        return self._guidelines_cache.copy()
    
    def reload_guidelines(self) -> None:
        """Reload all guidelines from the directory structure."""
        self._load_all_guidelines()
    
    def _is_relevant_to_context(self, guideline: SecurityGuideline, context: str, technologies: List[str] = None) -> bool:
        """Check if a guideline is relevant to the given context and technologies."""
        context_lower = context.lower()
        
        # Check for technology-specific relevance
        if technologies:
            for tech in technologies:
                tech_lower = tech.lower()
                if (tech_lower in context_lower or 
                    tech_lower in guideline.description.lower() or
                    any(tech_lower in tag.lower() for tag in guideline.tags)):
                    return True
        
        # Check for general relevance based on context keywords
        relevant_keywords = {
            "authentication": ["auth", "login", "user", "password", "token", "session"],
            "authorization": ["permission", "role", "access", "admin", "privilege"],
            "data_validation": ["input", "form", "data", "validation", "sanitize"],
            "cryptography": ["encrypt", "hash", "crypto", "ssl", "tls", "certificate"],
            "api_security": ["api", "endpoint", "rest", "graphql", "webhook"],
            "database": ["database", "sql", "query", "db", "mongo", "redis"],
            "web_security": ["web", "http", "https", "cors", "csrf", "xss"],
            "secrets_management": ["secret", "key", "credential", "password", "token"],
            "logging": ["log", "audit", "monitor", "trace"],
            "error_handling": ["error", "exception", "fail", "handling"],
        }
        
        # Check if guideline category matches context
        if guideline.category in relevant_keywords:
            for keyword in relevant_keywords[guideline.category]:
                if keyword in context_lower:
                    return True
        
        # Check tags for relevance
        for tag in guideline.tags:
            if tag.lower() in context_lower:
                return True
        
        return False
