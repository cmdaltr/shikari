# Shikari Security Features Documentation

## Overview

Shikari implements comprehensive security features to protect user accounts and data. This document outlines all implemented security measures, configuration options, and best practices.

## Table of Contents

1. [Authentication & Authorization](#authentication--authorization)
2. [Password Security](#password-security)
3. [Session Management](#session-management)
4. [Rate Limiting & Brute Force Protection](#rate-limiting--brute-force-protection)
5. [CSRF Protection](#csrf-protection)
6. [Account Lockout](#account-lockout)
7. [Audit Logging](#audit-logging)
8. [Email Security](#email-security)
9. [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
10. [API Key Encryption](#api-key-encryption)
11. [Admin User Management](#admin-user-management)
12. [Security Best Practices](#security-best-practices)

---

## Authentication & Authorization

### Overview
Shikari uses cookie-based session authentication with role-based access control (RBAC).

### User Roles
- **Admin**: Full system access, user management capabilities
- **Standard**: Regular user access, cannot manage other users

### Implementation Details
- **Location**: `shikari/auth/session.py`, `shikari/app.py`
- **Session Storage**: SQLite database
- **Session Duration**:
  - Default: 16 hours
  - Remember Me: 7 days
- **Session ID**: 64-character UUID

### Default Credentials
```
Email: admin@shikari.app
Password: BigGameHunter
```

**⚠️ IMPORTANT**: Change the default admin password immediately after first login!

---

## Password Security

### Password Hashing
- **Algorithm**: bcrypt with automatic salt generation
- **Work Factor**: Configured for optimal security/performance balance
- **Location**: `shikari/auth/password.py`

### Password Requirements
- **Minimum Length**: 12 characters
- **Complexity Requirements**:
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one digit
  - At least one special character (!@#$%^&*(),.?":{}|<>)

### Password Validation
```python
from shikari.auth.password import validate_password_strength

# Returns (is_valid, error_message)
is_valid, message = validate_password_strength("MyP@ssw0rd123")
```

### Password Reset Flow
1. User requests password reset via email
2. System generates unique reset token (1-hour expiration)
3. Token sent via email
4. User clicks link, validates token, sets new password
5. Token marked as used (single-use only)

**Implementation**: `shikari/auth/password_reset.py`

---

## Session Management

### Session Creation
- Sessions created on successful login
- Session ID stored in secure HTTP-only cookie
- Cookie name: `shikari_session`

### Session Validation
- Checked on every authenticated request
- Validates:
  - Session exists in database
  - Session hasn't expired
  - User account is active
  - User hasn't been locked out

### Session Termination
- Manual logout
- Session expiration
- User deactivation
- Password change (optional: invalidate all sessions)

**Implementation**: `shikari/auth/session.py`

---

## Rate Limiting & Brute Force Protection

### Configuration
```python
MAX_LOGIN_ATTEMPTS = 5      # Maximum attempts
LOGIN_WINDOW_SECONDS = 300  # 5 minutes
LOCKOUT_DURATION_SECONDS = 900  # 15 minutes
```

### How It Works
1. Track login attempts per email address
2. If 5 failed attempts within 5 minutes:
   - Account temporarily locked for 15 minutes
   - All subsequent login attempts rejected
3. Successful login resets counter
4. Automatic cleanup of old entries

### Implementation
- **Location**: `shikari/security/rate_limit.py`
- **Storage**: In-memory (for single-server deployments)
- **Production Note**: Consider Redis for multi-server deployments

### Usage Example
```python
from shikari.security.rate_limit import check_rate_limit, record_attempt

# Check if allowed
is_allowed, attempts_remaining = check_rate_limit(email)

if not is_allowed:
    return "Too many attempts. Try again later."

# Record failed attempt
record_attempt(email)
```

---

## CSRF Protection

### Overview
Cross-Site Request Forgery (CSRF) protection prevents unauthorized commands from being transmitted from a user that the application trusts.

### Implementation
- **Token Generation**: Cryptographically secure random tokens
- **Token Validation**: Tied to specific session
- **Token Expiry**: 1 hour
- **Storage**: In-memory dictionary (thread-safe)

Tokens are random and stored per process, not signed, so run a single worker (the default) or put sticky sessions in front of multiple workers.

### Usage in Forms
```html
<form method="POST">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <!-- form fields -->
</form>
```

### API Usage
```python
from shikari.security.csrf import generate_csrf_token, validate_csrf_token

# Generate token
token = generate_csrf_token(session_id)

# Validate token
if not validate_csrf_token(token, session_id):
    raise HTTPException(status_code=403, detail="Invalid CSRF token")
```

**Implementation**: `shikari/security/csrf.py`

---

## Account Lockout

### Lockout Triggers
- 5 failed login attempts within 5 minutes
- Manual admin action (future feature)

### Lockout Behavior
- **Duration**: 15 minutes (configurable)
- **Effect**: All login attempts rejected during lockout
- **Database Field**: `locked_until` timestamp in User model
- **Counter**: `failed_login_attempts` in User model

### Lockout Release
- Automatic after lockout duration expires
- Manual unlock by admin (future feature)
- Successful login resets counter to 0

### Database Schema
```python
class User(Base):
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
```

**Implementation**: `shikari/database/models.py`, `shikari/app.py`

---

## Audit Logging

### Overview
All security-sensitive operations are logged to the database for compliance and security monitoring.

### Logged Events
- **Authentication**:
  - `login_success`
  - `login_failure`
  - `logout`
- **Password Operations**:
  - `password_change`
  - `password_reset_request`
  - `password_reset_complete`
- **Profile Changes**:
  - `profile_update`
  - `api_key_update`
- **Admin Operations**:
  - `user_created`
  - `user_updated`
  - `user_deactivated`
- **Security Events**:
  - `account_locked`
  - `account_unlocked`
  - `session_revoked`

### Audit Log Fields
```python
class AuditLog(Base):
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, index=True)
    user_id = Column(Integer, index=True)
    email = Column(String(64), index=True)
    event_type = Column(String(50), index=True)
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    success = Column(Boolean)
    details = Column(Text)  # JSON
```

### Usage
```python
from shikari.database.audit import log_audit_event, EVENT_LOGIN_SUCCESS

log_audit_event(
    db=db,
    event_type=EVENT_LOGIN_SUCCESS,
    user_id=user.id,
    email=user.email,
    ip_address=request.client.host,
    user_agent=request.headers.get("user-agent"),
    success=True
)
```

### Viewing Audit Logs
```python
from shikari.database.audit import get_audit_logs

# Get last 100 logs for a user
logs = get_audit_logs(db, user_id=user_id, limit=100)

# Get failed login attempts
failed_attempts = get_failed_login_attempts(db, email=email, since_minutes=15)
```

**Implementation**: `shikari/database/audit.py`

---

## Email Security

### SMTP Configuration
```bash
# Environment Variables
export EMAIL_ENABLED=true
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USERNAME=your-email@example.com
export SMTP_PASSWORD=your-app-password
export SMTP_FROM_EMAIL=noreply@shikari.app
export SMTP_FROM_NAME="Shikari Security Platform"
export SMTP_USE_TLS=true
export BASE_URL=https://your-domain.com
```

### Development Mode
When `EMAIL_ENABLED=false`:
- Emails logged to console instead of sending
- Useful for local development/testing
- Shows full email content in logs

### Email Types
1. **Password Reset Emails**
   - Branded HTML template
   - Plain text fallback
   - 1-hour expiration notice
   - Security warnings included

### Email Security Features
- HTML and plain text versions
- Secure reset links
- Time-limited tokens
- Clear security warnings
- Branded templates

**Implementation**: `shikari/auth/email.py`

---

## Multi-Factor Authentication (MFA)

### Overview
Time-based One-Time Password (TOTP) implementation for enhanced security.

### Database Fields
```python
class User(Base):
    mfa_secret = Column(String(32))      # TOTP secret
    mfa_enabled = Column(Boolean)         # MFA status
    backup_codes = Column(Text)           # Hashed backup codes (JSON)
```

### MFA Flow
1. User enables MFA in profile
2. System generates TOTP secret
3. QR code displayed for authenticator app
4. User confirms setup with TOTP code
5. Backup codes generated and displayed once
6. Future logins require TOTP code

### Supported Authenticator Apps
- Google Authenticator
- Microsoft Authenticator
- Authy
- 1Password
- Any TOTP-compatible app

**Implementation**: `shikari/auth/mfa.py`

---

## API Key Encryption

### Overview
User API keys for external services (Splunk, Microsoft Defender, OpenAI, etc.) are encrypted at rest.

### Encryption Method
- **Algorithm**: Fernet (symmetric encryption)
- **Key Derivation**: PBKDF2 from master password
- **Storage**: Encrypted keys in database

### Supported Platforms
- Splunk
- Microsoft Defender (MDE)
- Elastic
- OpenAI
- Anthropic Claude
- Atomic Red Team

### Database Schema
```python
class APIKey(Base):
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    platform = Column(String(50))
    encrypted_key = Column(Text)  # Fernet encrypted
```

### Usage
```python
from shikari.auth.encryption import encrypt_api_key, decrypt_api_key

# Encrypt
encrypted = encrypt_api_key(plain_key, master_password)

# Decrypt
plain_key = decrypt_api_key(encrypted, master_password)
```

**Implementation**: `shikari/auth/encryption.py`

---

## Admin User Management

### Admin Endpoints

#### 1. List All Users
```http
GET /api/admin/users
```

**Response**:
```json
{
  "users": [
    {
      "id": 1,
      "email": "admin@shikari.app",
      "full_name": "Admin User",
      "role": "admin",
      "is_active": true,
      "created_at": "2025-01-20T12:00:00",
      "updated_at": "2025-01-20T12:00:00"
    }
  ]
}
```

#### 2. Create User
```http
POST /api/admin/users
Content-Type: application/json

{
  "email": "user@example.com",
  "full_name": "New User",
  "password": "SecureP@ssw0rd123",
  "role": "standard"
}
```

#### 3. Update User
```http
PUT /api/admin/users/{user_id}
Content-Type: application/json

{
  "email": "newemail@example.com",
  "full_name": "Updated Name",
  "role": "admin",
  "is_active": true
}
```

#### 4. Deactivate User
```http
DELETE /api/admin/users/{user_id}
```

**Note**: Soft delete - sets `is_active` to `false` and invalidates all sessions.

### Admin UI
- Located in Profile page, "Users" tab
- Only visible to admin users
- Real-time user management
- View all user accounts
- Create, update, deactivate users
- Reset user passwords

**Implementation**: `shikari/app.py` (lines 4578-4847)

---

## Security Best Practices

### For Administrators

1. **Change Default Credentials**
   - Change admin password immediately
   - Use strong, unique password
   - Enable MFA for admin account

2. **Regular Security Audits**
   - Review audit logs regularly
   - Monitor failed login attempts
   - Check for unusual activity patterns

3. **User Management**
   - Disable inactive accounts
   - Use principle of least privilege
   - Regular access reviews

4. **Email Configuration**
   - Use application-specific passwords
   - Enable TLS for SMTP
   - Configure proper FROM address
   - Test email delivery

5. **Session Management**
   - Set appropriate session timeouts
   - Enforce session invalidation on password change
   - Monitor active sessions

### For Users

1. **Password Hygiene**
   - Use strong, unique passwords
   - Never share passwords
   - Change password if compromised
   - Don't reuse passwords across services

2. **Enable MFA**
   - Enable TOTP-based MFA
   - Store backup codes securely
   - Use reputable authenticator app

3. **Session Security**
   - Log out when finished
   - Don't use "Remember Me" on shared computers
   - Review active sessions regularly

4. **API Key Security**
   - Rotate API keys regularly
   - Use least-privilege API keys
   - Never commit API keys to git
   - Delete unused API keys

### For Developers

1. **Code Security**
   - Never log passwords or tokens
   - Use parameterized queries (SQLAlchemy ORM)
   - Validate all user input
   - Use CSRF protection on all forms

2. **Dependency Management**
   - Keep dependencies updated
   - Use `pip-audit` for vulnerability scanning
   - Review security advisories

3. **Environment Variables**
   - Never commit `.env` files
   - Use strong secret keys
   - Rotate secrets regularly

4. **Testing**
   - Write security tests
   - Test authentication/authorization
   - Test rate limiting
   - Test password validation

---

## Security Checklist

### Initial Setup
- [ ] Change default admin password
- [ ] Configure SMTP for email delivery
- [ ] Set strong CSRF secret key
- [ ] Review rate limiting settings
- [ ] Enable MFA for admin accounts

### Regular Maintenance
- [ ] Review audit logs monthly
- [ ] Check for failed login patterns
- [ ] Disable inactive user accounts
- [ ] Update dependencies
- [ ] Backup database regularly

### Before Production Deployment
- [ ] Change all default credentials
- [ ] Configure production SMTP server
- [ ] Set production BASE_URL
- [ ] Enable HTTPS/TLS
- [ ] Review all environment variables
- [ ] Test password reset flow
- [ ] Test MFA flow
- [ ] Run security tests
- [ ] Review audit logging

---

## Security Incident Response

### Suspected Account Compromise

1. **Immediate Actions**:
   - Lock the affected account
   - Invalidate all active sessions
   - Review audit logs for unauthorized activity
   - Change password

2. **Investigation**:
   - Check audit logs for:
     - Failed login attempts
     - Successful logins from unusual IPs
     - Profile/API key changes
   - Review timeline of events
   - Identify scope of compromise

3. **Recovery**:
   - Reset password with strong credential
   - Enable MFA if not already enabled
   - Review and rotate API keys
   - Notify user if necessary

### Brute Force Attack Detection

**Indicators**:
- Multiple failed login attempts
- Attempts from same IP across multiple accounts
- Pattern in audit logs

**Response**:
- Rate limiting automatically engages
- Review `audit_logs` table
- Consider IP blocking at firewall level
- Monitor for distributed attacks

### Data Breach Response

1. **Contain**: Immediately identify and stop the breach
2. **Assess**: Determine what data was accessed
3. **Notify**: Inform affected users
4. **Remediate**: Fix vulnerability, rotate secrets
5. **Review**: Update security measures

---

## Compliance Considerations

### GDPR
- User data stored in database
- Users can request data deletion
- Audit logs track data access
- Password reset via email

### SOC 2
- Comprehensive audit logging
- Access controls (RBAC)
- Password complexity requirements
- Session management
- Encryption at rest (API keys)

### HIPAA/PCI-DSS
- Not currently compliant
- Additional measures required for healthcare/payment data
- Consult security professionals

---

## Support & Resources

### Documentation
- `README.md`: Installation and setup
- `GETTING_STARTED.md`: User guide
- `SECURITY_FEATURES.md`: This document

### Code References
- Authentication: `shikari/auth/`
- Security: `shikari/security/`
- Database Models: `shikari/database/models.py`
- Audit Logging: `shikari/database/audit.py`

### Getting Help
- GitHub Issues: https://github.com/your-org/shikari/issues
- Security Issues: Report privately to security@shikari.app

---

**Last Updated**: 2025-01-20
**Version**: 1.0
**Maintained By**: Shikari Development Team
