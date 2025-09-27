# Strong Password Requirements

category: authentication
priority: high
tags: password, authentication, security, policy, validation

## Description

Implement strong password policies with minimum complexity requirements to prevent brute force attacks and password-based compromises.

## Implementation

- Enforce minimum 12 characters with mixed case, numbers, and special characters
- Use password strength meters and prevent common passwords
- Implement password history to prevent reuse
- Set maximum password age and require periodic changes
- Implement account lockout after failed attempts
- Use secure password hashing algorithms

## Examples

- Use libraries like zxcvbn for password strength validation
- Implement password history to prevent reuse
- Set maximum password age and require periodic changes
- Prevent common passwords and dictionary words
- Implement account lockout after failed attempts

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B - Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## Code Example

```python
import bcrypt
import re

def validate_password_strength(password: str) -> bool:
    # Check minimum length
    if len(password) < 12:
        return False
    
    # Check for mixed case
    if not (re.search(r'[a-z]', password) and re.search(r'[A-Z]', password)):
        return False
    
    # Check for numbers
    if not re.search(r'\d', password):
        return False
    
    # Check for special characters
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    
    return True

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
```
