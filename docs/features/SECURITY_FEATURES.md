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
Each role has everything the one below it has (`UserRole` in `shikari/database/models.py`):
- **Admin** (`admin`): user management, secrets and integration settings
- **Operational analyst** (`operator`): the lab (own machines), telemetry rebuilds, source edits
- **Analyst** (`standard`): hunt, view, author detections, watchlists

### Implementation Details
- **Location**: `shikari/auth/session.py`, `shikari/app.py`
- **Session Storage**: SQLite database
- **Session Duration**:
  - Default: 16 hours
  - Remember Me: 7 days
- **Session ID**: 64-character UUID

### First admin

A **local** Shikari (the desktop app, or `shikari start` from a checkout) seeds a default admin into an empty database:

```
Sign in as: admin
Password:   BigGameHunter
```

`admin` is a username: the one account whose login isn't an email, stored as exactly `admin`, which no validated email can be, so no invitation or admin edit can give it to anyone else. It's seeded only while Shikari listens on loopback, and the seeding is audited (`default_admin_seeded`). The bind is read as uvicorn decides it: the `--host` it was given (every launcher passes one: `shikari start`/`serve`/`app`, the systemd unit, the Windows service and Scheduled Task, the Dockerfile, `python -m shikari.app`; `--reload` and `--workers` children inherit the same command line), else `UVICORN_HOST`, else `SHIKARI_HOST`; the desktop app's in-process server is always `127.0.0.1`. A socket passed with `--fd` or `--uds` isn't seen. On a network address there's no default admin and the log says to use `shikari first-admin`. An older database's `admin@shikari.app` is renamed to `admin` on a local start (audited as `default_admin_renamed`). **Change its password after the first sign-in.**

A **team server** (`SHIKARI_MODE=server`, set by `docker-compose.yml`, `deploy/linux/install.sh` and the Windows service) seeds no account. With no active admin, its first start issues `SHIKARI_ADMIN_EMAIL` a one-time first-admin invitation (24 hours, the token after `#`) and logs the link; `shikari first-admin <email>` (or `scripts/admin/create_admin.py <email>`) issues one on demand, refused (exit status 5) once an active admin exists unless `--force`, and only the newest works; each replaced one is audited as `invitation_revoked` with `reason: replaced`. Links name `BASE_URL`; without it the command line and the start-up message name localhost and warn on stderr every time they print one. If a server still has an account with the public default password, every start logs a warning.

*Decided 19 November 2026 (Ben), the same across Ostraka, Rowanholt and Shikari: a known-password default admin only on a local install listening on loopback; every team server's first admin by one-time invitation; the server flag explicit (`SHIKARI_MODE=server`, since `SHIKARI_SERVER` is already the desktop app's server URL), keying both the closed `/register` and the absence of a seeded account. A server's existing `admin@shikari.app` is neither renamed nor removed, only warned about while its password is still the default.*

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

### Forgot Password (self-service reset access)
**Forgot password** on the sign-in page emails the account a reset-access link, the same link an admin issues (see Reset Access below): one use, within 24 hours, a new password and a new authenticator, fresh backup codes. It works only with email sending set up (`EMAIL_ENABLED=true` and the `SMTP_*` settings) and `BASE_URL` set; without them the page says to ask an administrator and `POST /api/auth/reset-access/request` answers 503. `BASE_URL` is required because an emailed link built from the request's `Host` header would point wherever the person asking chose.

- The answer is the same whether or not an account matched ("If that address has an account, a link is on its way"), and the email is sent after the response, so its timing doesn't tell either.
- Limited to 3 requests an hour per address and 20 per IP (429 beyond).
- Asking ends no sessions, revokes no tokens and clears no lockout, since anyone can ask; the link's completion does the first two.
- A new request replaces an earlier open self-service link, never an open admin-issued one (that request is audited as a failed `access_reset_issued` and sends nothing).
- Audited as `access_reset_issued` with `via: self-service`.

The old 1-hour `?token=` password-only reset (`/reset-password`, `/api/auth/request-reset`, `/api/auth/reset-password`, `shikari/auth/password_reset.py`) is gone; rows it left in `password_resets` (kind NULL) are never accepted.

**Implementation**: `shikari/auth/reset_access.py`

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
- User deactivation (`PUT /api/admin/users/{id}` with `is_active: false`, or `DELETE`): sessions end and API tokens are revoked, audited as `user_deactivated` with `tokens_revoked`
- Reset access: issued by an admin or the server, and completed
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
- **Effect**: All login attempts rejected during lockout, with HTTP 429 (the attempt that locks it too), at sign-in and on a reset-access link alike
- **Wrong codes on a reset-access link** count towards the same lockout
- **Audited** as `account_locked` (with `via`: `sign-in` or `reset-access`) wherever a lock is applied
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
  - `access_reset_issued` (`via`: `admin`, `cli` or `self-service`, and `tokens_revoked`; a failure when a self-service request meets an open admin-issued reset)
  - `access_reset_completed` (with `via`, admin, cli or self-service, and `tokens_revoked`)
  - `access_reset_failed` (each wrong authenticator code, and attempts while the account is locked)
  - `invitation_created`, `invitation_revoked` (`reason: replaced` when a newer invitation replaced it), `account_created` (invitations)
  - `invitation_wrong_code` (each wrong code on an invitation, with `attempt`) and `invitation_closed` (the fifth)
  - `default_admin_seeded`, `default_admin_renamed` (a local Shikari's `admin`)
- **Profile Changes**:
  - `profile_update`
  - `api_key_update`
- **Admin Operations**:
  - `user_created`
  - `user_updated`
  - `user_deactivated` (with `tokens_revoked`)
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
- Forgot password isn't offered: the page says to ask an administrator, and `POST /api/auth/reset-access/request` answers 503
- Any other email (watchlist digests) is logged to the console instead of sent, with its full content

### Email Types
1. **Reset-access emails** (Forgot password)
   - Branded HTML template
   - Plain text fallback
   - The link's 24-hour, one-use notice
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

An invited account, and an account whose access was reset, enrols its authenticator at the link, so MFA is on from the start; the self-registered accounts of a local Shikari and its default `admin` turn it on here.

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
User API keys for external services (Splunk, Defender XDR, OpenAI, etc.) are encrypted at rest.

### Encryption Method
- **Algorithm**: Fernet (symmetric encryption)
- **Key Derivation**: PBKDF2 from master password
- **Storage**: Encrypted keys in database

### Supported Platforms
- Splunk
- Defender XDR
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
      "email": "boss@example.org",
      "full_name": "Admin User",
      "role": "admin",
      "is_active": true,
      "created_at": "2025-01-20T12:00:00",
      "updated_at": "2025-01-20T12:00:00"
    }
  ]
}
```

#### 2. Invite a User
```http
POST /api/admin/invitations
Content-Type: application/json

{
  "email": "user@example.com",
  "role": "standard",
  "full_name": "New User"
}
```

**Response**: `{"success": true, "link": "<BASE_URL>/accept-invite#<token>", "expires_in_hours": 24, "invitation": {...}}`

Permanent admins only. There's no account until the person accepts: at the link they give their name, choose a password and enrol an authenticator (MFA is always on for an invited account), and the account is made with the invited role once a code from it verifies; they're signed in and shown backup codes once. The link works once, within 24 hours, and an earlier open invitation for the same email stops working. The token is in the URL fragment and only its SHA-256 hash is stored. Opening the link again shows the same authenticator (the secret is made on the first start and reused), and a later name or password replaces the earlier one. Each wrong code is audited (`invitation_wrong_code`); the fifth closes the invitation (`invitation_closed`, what was chosen cleared) and the admin must issue a new one. An expired link answers 410 with its own "has expired" message (for as long as its row is kept); a used, revoked, replaced, closed or unknown one answers 404 with the same "isn't valid" message whichever it was. Anything chosen on a link is cleared when it's replaced, revoked, used, closed or found expired. Refused (409) for an email that already has an account (use Reset access), and (402) when the licence's seats are full, counting open invitations; seats are checked again on acceptance, as is the inviter, who must still be an active admin. `GET /api/admin/invitations` lists the open ones and `DELETE /api/admin/invitations/{id}` revokes one. Audited as `invitation_created`, `invitation_revoked` and `account_created`. From the server: `shikari invite <email> --role …`, and `scripts/admin/create_admin.py <email>` for an admin when none can sign in.

There's no admin route that creates an account with a password the admin types (the old `POST /api/admin/users`), and on a team server (`SHIKARI_MODE=server`), or a local Shikari listening on a network address, there's no self-registration: `/register` redirects to `/login?invite_only=1`. Only a local Shikari on loopback keeps `/register`: the same guard as seeding the default admin.

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

Setting `is_active` to `false` here is a deactivation: the account's sessions end and its API tokens are revoked, as with `DELETE`.

#### 4. Deactivate User
```http
DELETE /api/admin/users/{user_id}
```

**Note**: Soft delete - sets `is_active` to `false`, ends all sessions and revokes the account's API tokens (audited as `user_deactivated`).

#### 5. Reset Access
```http
POST /api/admin/users/{user_id}/reset-access
```

**Response**: `{"success": true, "link": "<BASE_URL>/reset-access#<token>", "email": "...", "expires_in_hours": 24}`

Permanent admins only (not a temporary grant). Ends the user's sessions, revokes their API tokens, makes any earlier reset link (a self-service one too) useless, clears a lockout, and returns a one-time link for the admin to pass on. The old password and authenticator keep working until the link is completed: nothing refuses sign-in because a reset is open (Ben's decision, 20 November 2026). Opening the link again shows the same authenticator; an expired link says so (410), a used or replaced one gets the generic "isn't valid" (404). At the link the user chooses a new password and enrols a new authenticator (required, even though MFA is otherwise optional); only once a code from it verifies are the password, MFA secret and a fresh set of backup codes saved, and the user is signed in; API tokens made since the link was issued are revoked then too. Wrong codes count towards the sign-in lockout (5 wrong, then locked for 15 minutes; a locked account is refused, 429, before the code is checked). The token is in the URL fragment, so browsers never send it to the server, and only its SHA-256 hash is stored. Both audit events record `tokens_revoked`. `shikari reset-access <email>` does the same from the server. This replaces the old `POST /api/admin/reset-password`, where the admin chose the new password.

### Admin UI
- Located in Profile page, "Users" tab
- Only visible to admin users
- Real-time user management
- View all user accounts
- Invite users (with pending invitations listed and revocable), update, deactivate
- Reset access (a one-time link to a new password and authenticator)

**Implementation**: `shikari/app.py` (`/api/admin/users`, `/api/admin/invitations`), `shikari/auth/invitations.py`, `shikari/auth/reset_access.py`

---

## Security Best Practices

### For Administrators

1. **Change Default Credentials**
   - On a local Shikari, change the default `admin` password immediately (a team server has no default account)
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
- [ ] Local Shikari: change the default `admin` password. Team server: set `SHIKARI_ADMIN_EMAIL` (or run `shikari first-admin <email>`) and accept the first admin's invitation
- [ ] Configure SMTP for email delivery (Forgot password needs it, and `BASE_URL`)
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
- [ ] Change all default credentials (a server still holding `admin@shikari.app` or `admin` with the default password logs a warning at every start)
- [ ] Configure production SMTP server
- [ ] Set production BASE_URL
- [ ] Enable HTTPS/TLS
- [ ] Review all environment variables
- [ ] Test an invitation, Reset access and Forgot password
- [ ] Test MFA flow
- [ ] Run security tests
- [ ] Review audit logging

---

## Security Incident Response

### Suspected Account Compromise

1. **Immediate Actions**:
   - Deactivate the account (Settings → Users), which ends its sessions and revokes its API tokens, or reset its access
   - Review audit logs for unauthorised activity

2. **Investigation**:
   - Check audit logs for:
     - Failed login attempts
     - Successful logins from unusual IPs
     - Profile/API key changes
   - Review timeline of events
   - Identify scope of compromise

3. **Recovery**:
   - Reset access (Settings → Users → Reset access, or `shikari reset-access <email>`): their sessions end at once, and the one-time link sets a new password and a new authenticator, with fresh backup codes
   - Their API tokens are revoked by the reset; they make new ones (Profile → Security) once signed in
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

**Last Updated**: 2026-11-02
**Version**: 1.0
**Maintained By**: Shikari Development Team
