# Multi-Factor Authentication (MFA)

category: authentication
priority: critical
tags: mfa, 2fa, authentication, security, totp, webauthn

## Description

Implement Multi-Factor Authentication (MFA) for all user accounts, especially privileged ones. MFA significantly reduces the risk of account compromise even if passwords are stolen.

## Implementation

- Require MFA for all user accounts
- Support TOTP (Time-based One-Time Password) apps like Google Authenticator
- Implement backup codes for account recovery
- Consider WebAuthn for passwordless authentication
- Make MFA mandatory for admin accounts and sensitive operations
- Implement MFA bypass for emergency access with proper audit logging

## Examples

- Use TOTP apps like Google Authenticator or Authy
- Implement backup codes for account recovery
- Consider WebAuthn for passwordless authentication
- Require MFA for admin account access
- Implement MFA bypass for emergency access with proper audit logging

## References

- [OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B - Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## Code Example

```python
import pyotp
import qrcode

def setup_mfa(user_id: str) -> dict:
    # Generate secret key
    secret = pyotp.random_base32()

    # Create TOTP object
    totp = pyotp.TOTP(secret)

    # Generate QR code URI
    qr_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="Your App"
    )

    return {
        'secret': secret,
        'qr_code': qr_uri
    }

def verify_mfa_token(user_id: str, token: str) -> bool:
    user = User.objects.get(id=user_id)
    totp = pyotp.TOTP(user.mfa_secret)
    return totp.verify(token, valid_window=1)
```
