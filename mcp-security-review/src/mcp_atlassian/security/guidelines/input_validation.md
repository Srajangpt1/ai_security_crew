# Input Validation and Sanitization

category: data_validation
priority: critical
tags: input, validation, sanitization, security, xss, injection

## Description

Validate and sanitize all user inputs to prevent injection attacks, XSS, and other security vulnerabilities. Input validation is the first line of defense against many attacks.

## Implementation

- Implement strict input validation using allowlists where possible
- Validate data types, ranges, and formats
- Sanitize inputs before processing
- Use parameterized queries to prevent SQL injection
- Encode output data to prevent XSS attacks
- Implement server-side validation (never trust client-side validation)

## Examples

- Use parameterized queries to prevent SQL injection
- Validate file uploads for type, size, and content
- Sanitize HTML inputs to prevent XSS attacks
- Validate email addresses, phone numbers, and other formats
- Implement rate limiting for input endpoints

## References

- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

## Code Example

```python
import re
from html import escape

def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_html_input(user_input: str) -> str:
    # Remove potentially dangerous HTML tags
    dangerous_tags = ['script', 'iframe', 'object', 'embed']
    for tag in dangerous_tags:
        user_input = re.sub(f'<{tag}[^>]*>.*?</{tag}>', '', user_input, flags=re.IGNORECASE | re.DOTALL)
    
    # Escape remaining HTML
    return escape(user_input)

def validate_file_upload(filename: str, content_type: str, size: int) -> bool:
    # Check file extension
    allowed_extensions = ['.jpg', '.png', '.pdf', '.txt']
    if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
        return False
    
    # Check content type
    allowed_types = ['image/jpeg', 'image/png', 'application/pdf', 'text/plain']
    if content_type not in allowed_types:
        return False
    
    # Check file size (5MB limit)
    if size > 5 * 1024 * 1024:
        return False
    
    return True
```
