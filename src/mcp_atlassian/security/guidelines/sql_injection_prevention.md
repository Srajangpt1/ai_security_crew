# SQL Injection Prevention

category: database
priority: critical
tags: sql, injection, database, security, parameterized, orm

## Description

Prevent SQL injection attacks using parameterized queries and proper input validation. SQL injection is one of the most critical security vulnerabilities and can lead to data breaches.

## Implementation

- Always use parameterized queries or prepared statements
- Never concatenate user input directly into SQL queries
- Validate and sanitize all database inputs
- Use ORM frameworks that handle parameterization automatically
- Implement database access logging and monitoring
- Use stored procedures with proper parameter validation

## Examples

- Use ORM frameworks like Django ORM, SQLAlchemy, or Hibernate
- Validate and sanitize all database inputs before processing
- Use database connection pooling with limited privileges
- Implement database audit logging for security monitoring
- Use stored procedures with proper parameter validation

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 - A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)

## Code Example

```python
# BAD - Vulnerable to SQL injection
def get_user_bad(username: str):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return execute_query(query)

# GOOD - Using parameterized queries
def get_user_good(username: str):
    query = "SELECT * FROM users WHERE username = %s"
    return execute_query(query, (username,))

# GOOD - Using ORM
def get_user_orm(username: str):
    return User.objects.filter(username=username).first()
```
