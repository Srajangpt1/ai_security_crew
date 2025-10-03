# OAuth 2.0 Security

category: api_security
priority: high
tags: oauth2, tokens, authorization, scopes, refresh tokens, pkce

## Description

Securely implement OAuth 2.0 authorization flows to protect user data and
service APIs. Prefer authorization code flow with PKCE for public clients,
proper token lifetime management, scope minimization, and secure storage.

## Implementation

- Prefer Authorization Code Flow with PKCE for public/native/SPA clients
- Always validate redirect URIs (exact match) and use HTTPS
- Use short-lived access tokens and rotate refresh tokens
- Store tokens only in secure storage; avoid third-party accessible contexts
- Minimize scopes to least privilege required for the task
- Bind tokens to client and audience where supported
- Revoke on logout and when anomalous token use is detected
- Protect token introspection and revocation endpoints

## Examples

- Validate token audience and issuer before use
- Enforce PKCE (S256) for untrusted/public clients
- Scope set: `read:jira-work` not `*` for read-only flows

## References

- [OWASP Cheat Sheet: OAuth2](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
