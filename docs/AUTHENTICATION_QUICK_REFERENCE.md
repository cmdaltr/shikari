# Authentication System - Quick Reference

## Overview
Archer implements a full-featured authentication system with session-based login, encrypted API key storage, and password reset capabilities.

## Key Features

### Implemented ✅
- **Secure Password Storage**: bcrypt hashing with 12 rounds
- **Session Management**: UUID-based sessions with configurable duration (16 hours default, 7 days with Remember Me)
- **API Key Encryption**: Fernet symmetric encryption for API keys at rest
- **Password Reset**: Token-based reset flow with 1-hour expiry
- **Admin Functions**: Admin-initiated password resets
- **Role-Based Access**: Admin and Standard user roles
- **Profile Management**: User-specific profile and API key storage

### Database Schema
- **User**: id, email (unique), full_name, hashed_password, role, is_active, timestamps
- **Session**: id (UUID), user_id, created_at, expires_at, is_active
- **APIKey**: id, user_id, key_name, encrypted_key, timestamps
- **PasswordReset**: id, user_id, token, expires_at, is_used, used_at
- **SecurityQuestion**: id, user_id, question, hashed_answer, created_at (for future use)

## Quick Start

### 1. Create Admin User
```bash
python3 create_admin.py
```
Enter:
- Email: `admin@archer.com`
- Full Name: `Admin User`
- Password: Must meet requirements (8-40 chars, letter, number, special char)

### 2. Start Server
```bash
source .venv/bin/activate
python3 -m uvicorn archer.app:app --host 127.0.0.1 --port 8000
```

### 3. Login
Navigate to: `http://localhost:8000/login`

## File Organization

### Backend
```
archer/
├── auth/
│   ├── password.py           # Password hashing & validation
│   ├── session.py            # Session management
│   ├── encryption.py         # API key encryption
│   └── password_reset.py     # Password reset flows
├── database/
│   ├── db.py                 # Database connection
│   └── models.py             # SQLAlchemy models
└── app.py                    # Authentication routes
```

### Frontend
```
templates/
├── login.html                # Login page
├── profile.html              # Profile management
└── reset_password.html       # Password reset (TODO)

static/
├── css/
│   ├── login.css            # Login page styles
│   └── profile.css          # Profile page styles
└── js/
    ├── login.js             # Login form handling
    └── profile.js           # Profile form & API keys
```

## API Endpoints

### Public (No Auth)
- `POST /api/auth/login` - User login
- `POST /api/auth/request-reset` - Request password reset
- `POST /api/auth/reset-password` - Reset with token

### Authenticated
- `POST /api/auth/logout` - Logout
- `POST /api/profile` - Update profile
- `GET /api/profile/apikeys` - Get API keys
- `POST /api/profile/apikeys` - Save API keys

### Admin Only
- `POST /api/admin/reset-password` - Reset user password

## Password Requirements
- 8-40 characters
- At least one letter
- At least one number
- At least one special character: `!@£$%^&()-_+=[]{}:|<>?`

## Session Configuration
- **Cookie Name**: `archer_session`
- **Default Duration**: 16 hours
- **Remember Me Duration**: 7 days
- **Cookie Flags**: httponly=True, samesite='lax'

## Security Features
- bcrypt password hashing (12 rounds)
- Fernet encryption for API keys
- Secure random token generation
- Token expiry validation
- Session expiry validation
- Role-based access control
- httponly cookies (prevents XSS)
- samesite cookies (CSRF protection)

## Testing Authentication

### Login Test
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@archer.com","password":"Password1!","remember_me":false}'
```

### Request Password Reset
```bash
curl -X POST http://localhost:8000/api/auth/request-reset \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@archer.com"}'
```

### Save API Keys (requires session cookie)
```bash
curl -X POST http://localhost:8000/api/profile/apikeys \
  -H "Content-Type: application/json" \
  -b "archer_session=YOUR_SESSION_ID" \
  -d '{"splunk":"your-key","openai":"your-key"}'
```

## Troubleshooting

### Issue: "Internal Server Error" after login
- Check that database exists: `ls -la data/archer.db`
- Verify encryption key exists: `ls -la data/encryption.key`
- Check server logs for specific error

### Issue: Session expires too quickly
- Default is 16 hours
- Use "Remember Me" for 7-day sessions
- Adjust in `archer/auth/session.py` if needed

### Issue: Cannot create admin user
- Check database permissions
- Verify virtual environment is activated
- Ensure all dependencies installed: `pip3 install -r requirements.txt`

### Issue: API keys not saving
- Verify user is logged in
- Check browser console for errors
- Verify database has APIKey table: `python3 -c "from archer.database.db import init_db; init_db()"`

## Future Enhancements
- Password reset UI page
- Email sending for password reset tokens
- Admin user management interface
- Security questions implementation
- Two-factor authentication (2FA)
- Rate limiting on auth endpoints
- CSRF token protection
- Session management UI (view/revoke sessions)

## Related Documentation
- Full implementation details: [AUTHENTICATION_AND_PROFILE_IMPLEMENTATION.md](AUTHENTICATION_AND_PROFILE_IMPLEMENTATION.md)
- Database models: `archer/database/models.py`
- Security guide: [SECURITY.md](SECURITY.md)
