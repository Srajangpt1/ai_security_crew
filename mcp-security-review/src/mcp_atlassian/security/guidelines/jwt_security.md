# JWT Token Security

category: authentication
priority: high
tags: jwt, token, authentication, security, api

## Description

Implement secure JWT token handling with proper validation, expiration, and secure storage. JWT tokens are commonly used for API authentication and session management.

## Implementation

- Use proper token validation on every request
- Implement secure token storage (httpOnly cookies for web, secure storage for mobile)
- Set appropriate token expiration times (short-lived access tokens, longer refresh tokens)
- Handle token revocation for logout and security incidents
- Use strong secret keys and consider key rotation
- Validate token signature and claims

## Examples

- Validate token signature and expiration on every request
- Use httpOnly cookies for web applications to prevent XSS attacks
- Implement token refresh mechanism with short-lived access tokens
- Handle token revocation for logout and security incidents
- Use environment variables for JWT secrets, never hardcode them

## References

- [OWASP JWT Guidelines](https://owasp.org/www-community/attacks/JSON_Web_Token_(JWT)_Attacks)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## Code Example

```python
import jwt
from datetime import datetime, timedelta

def generate_jwt_token(user_id: str, secret: str) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, secret, algorithm='HS256')

def validate_jwt_token(token: str, secret: str) -> dict:
    try:
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token has expired")
    except jwt.InvalidTokenError:
        raise AuthenticationError("Invalid token")
```
