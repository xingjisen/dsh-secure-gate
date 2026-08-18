# Changelog

## [1.0.0] - 2025

### Added
- Initial release

### Security Features
- Argon2id password hashing (OWASP recommended parameters)
- TOTP two-factor authentication
- Backup recovery codes (SHA-256 hashed)
- CSRF double-submit cookie protection
- Account lockout after N failed attempts
- Permanent lockout after consecutive lockout periods
- IP allowlist / blocklist
- Rate limiting (per-username + IP)
- Audit logging (JSONL format)
- HMAC-SHA256 signed session cookies
- Session management (view / revoke active sessions)
- Password strength enforcement
- Password expiry policy (90 days)
- Security response headers (CSP / HSTS / XFO / XSS)
- Glassmorphism login page UI
- Bilingual (Chinese / English)
- Zero-config first boot wizard
