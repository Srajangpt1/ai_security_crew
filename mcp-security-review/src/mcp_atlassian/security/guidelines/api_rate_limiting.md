# API Rate Limiting

category: api_security
priority: high
tags: api, rate, limiting, security, dos, throttling

## Description

Implement rate limiting for API endpoints to prevent abuse, DoS attacks, and ensure fair usage of resources. Rate limiting helps protect your API from being overwhelmed by too many requests.

## Implementation

- Implement rate limiting based on IP address, user ID, or API key
- Use different rate limits for different user tiers or endpoints
- Implement exponential backoff for failed requests
- Monitor and alert on rate limit violations
- Use Redis or similar for distributed rate limiting
- Implement graceful degradation when limits are exceeded

## Examples

- Use Redis for distributed rate limiting across multiple servers
- Implement different rate limits for different user tiers (free, premium, enterprise)
- Monitor and alert on rate limit violations for security analysis
- Use sliding window or token bucket algorithms for rate limiting
- Implement rate limiting middleware for easy integration

## References

- [OWASP Rate Limiting Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Rate_Limiting_Cheat_Sheet.html)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [NIST SP 800-53 - Security Controls](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)

## Code Example

```python
import redis
import time
from functools import wraps

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def rate_limit(requests_per_minute=60):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get client IP or user ID
            client_id = get_client_identifier()
            
            # Create rate limit key
            key = f"rate_limit:{client_id}:{func.__name__}"
            
            # Check current request count
            current_requests = redis_client.get(key)
            
            if current_requests is None:
                # First request in the window
                redis_client.setex(key, 60, 1)
            elif int(current_requests) >= requests_per_minute:
                # Rate limit exceeded
                return {"error": "Rate limit exceeded"}, 429
            else:
                # Increment request count
                redis_client.incr(key)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

@rate_limit(requests_per_minute=100)
def api_endpoint():
    return {"message": "Success"}
```
