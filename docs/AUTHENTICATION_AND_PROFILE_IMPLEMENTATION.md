# Authentication and Profile System Implementation

## Overview

This document outlines the implementation of the dark mode toggle, profile icon/login button, and complete profile management system for the Archer application.

## Features Implemented

### 1. Dark Mode Toggle

**Location**: Available on all pages via `base.html`

**Implementation**:
- **File**: `templates/base.html`
- **CSS**: `static/css/dark-mode.css`
- **JavaScript**: Inline in `base.html`

**Features**:
- Toggle button positioned in top-right area (before "How Archer Works" link)
- Persists user preference via localStorage
- Smooth transitions between light and dark themes
- CSS variables for consistent theming across all components
- Sun/moon icon that changes based on current theme

**CSS Variables**:
```css
Light Mode:
- --bg-primary: #f7fafc
- --bg-secondary: #ffffff
- --text-primary: #1a1a1a
- --accent: #C53030

Dark Mode:
- --bg-primary: #1a1a1a
- --bg-secondary: #2d2d2d
- --text-primary: #f0f0f0
- --accent: #ff6b6b
```

### 2. Profile/Login Icon

**Location**: All pages, next to dark mode toggle

**Implementation**:
- User profile icon button
- Links to `/profile` page
- Consistent styling with other navigation elements
- Positioned at `right: calc((100vw - 1200px) / 2 + 220px)` to be left of "How Archer Works"

### 3. Profile Page

**Route**: `/profile`

**File Structure**:
- **Template**: `templates/profile.html`
- **CSS**: `static/css/profile.css`
- **JavaScript**: `static/js/profile.js`
- **Backend**: `archer/app.py` (lines 2483-2578)

**Tab Structure** (matching index.html):

#### Tab 1: Profile
- **Full Name** input field
- **Handle** input field (e.g., @username)
- **Timezone** dropdown selector with major timezones:
  - UTC
  - US timezones (ET, CT, MT, PT)
  - European (GMT, CET)
  - Asian (JST, CST)
  - Australian (AEDT)
- **Profile Picture Upload**:
  - 200x200px circular display
  - Click to upload new picture
  - File type validation (images only)
  - Size limit: 5MB
  - Default avatar SVG provided
- **Save/Cancel** buttons

#### Tab 2: Timeline
- Historical activity display
- Filter buttons:
  - All Activity
  - Threat Actors (with actor icon)
  - CVEs (with warning icon)
- Activity cards showing:
  - Icon (actor or CVE)
  - Name/identifier
  - Timestamp
  - Action buttons:
    - Download (active)
    - Export to VECTR (greyed out)
    - Run Emulation (greyed out)
- Empty state message when no activity

#### Tab 3: API Keys
Three sections:

**SIEM Platforms**:
- Splunk API Key
- Microsoft Defender API Key
- Elastic API Key

**AI Models**:
- OpenAI API Key
- Anthropic API Key

**Emulation Tools** (Coming Soon, greyed out):
- Caldera API Endpoint
- Atomic Red Team Configuration

Each API key input includes:
- Vendor icon (color-coded)
- Password-masked input field
- Visibility toggle button (eye icon)
- Monospace font for better readability

**Save API Keys** button at bottom

## Backend Routes

### Profile Routes

#### GET `/profile`
- Renders profile page
- Returns user data (currently null, ready for auth integration)

#### POST `/api/profile`
- Updates user profile information
- Accepts JSON: `{name, handle, timezone}`
- Returns: `{success, message}`

#### POST `/api/profile/picture`
- Uploads profile picture
- Validates file type and size
- Saves to `data/profile_pictures/`
- Returns: `{success, url}`

#### GET `/api/profile/timeline`
- Retrieves user's historical activity
- Returns: `{timeline: []}`
- Ready for database integration

#### GET `/api/profile/apikeys`
- Retrieves user's API keys (masked)
- Returns: `{}`
- Ready for secure storage integration

#### POST `/api/profile/apikeys`
- Saves user's API keys securely
- Accepts JSON with all API keys
- Returns: `{success, message}`

## File Structure

```
archer/
├── templates/
│   ├── base.html (updated with dark mode + profile icon)
│   └── profile.html (new)
├── static/
│   ├── css/
│   │   ├── dark-mode.css (new)
│   │   └── profile.css (new)
│   ├── js/
│   │   └── profile.js (new)
│   └── images/
│       └── default-avatar.svg (new)
└── archer/
    └── app.py (updated with profile routes)
```

## Dark Mode Coverage

All major components styled for dark mode:
- Cards and containers
- Text (primary, secondary, tertiary)
- Borders
- Buttons and links
- Forms (inputs, selects, textareas)
- Tabs
- Progress bars
- Footer
- Vendor icons and technique tags
- Timeline items
- API key sections
- Custom scrollbars (webkit)

## JavaScript Functionality

### profile.js Features:
1. **Profile Picture Upload**
   - File validation (type, size)
   - Preview before upload
   - Async upload to server

2. **Profile Form**
   - Form submission handling
   - Reset functionality
   - Async save with notifications

3. **Timeline**
   - Filter functionality
   - Dynamic loading from API
   - Activity card rendering
   - Download results functionality

4. **API Keys**
   - Visibility toggle for each key
   - Batch save functionality
   - Auto-load on tab switch

5. **Notifications**
   - Toast-style notifications
   - Success/error/info types
   - Auto-dismiss after 3 seconds
   - Slide-in/out animations

## Authentication System (IMPLEMENTED)

### Overview
Full authentication system with secure password hashing, session management, and role-based access control has been implemented.

### Database Models
**File**: `archer/database/models.py`

#### User Model
```python
- id: Integer (Primary Key)
- email: String (Unique, Indexed)
- full_name: String
- hashed_password: String (bcrypt hashed)
- role: Enum (admin/standard)
- is_active: Boolean
- created_at: DateTime
- updated_at: DateTime
```

#### Session Model
```python
- id: String (Primary Key, UUID)
- user_id: Integer (Foreign Key to User)
- created_at: DateTime
- expires_at: DateTime
- is_active: Boolean
```

#### APIKey Model
```python
- id: Integer (Primary Key)
- user_id: Integer (Foreign Key to User)
- key_name: String (e.g., 'splunk', 'openai')
- encrypted_key: String (Fernet encrypted)
- created_at: DateTime
- updated_at: DateTime
```

#### PasswordReset Model
```python
- id: Integer (Primary Key)
- user_id: Integer (Foreign Key to User)
- token: String (Unique)
- expires_at: DateTime (1 hour expiry)
- is_used: Boolean
- used_at: DateTime
```

#### SecurityQuestion Model (Future Use)
```python
- id: Integer (Primary Key)
- user_id: Integer (Foreign Key to User)
- question: String
- hashed_answer: String
- created_at: DateTime
```

### Authentication Modules

#### archer/auth/password.py
**Purpose**: Password hashing and validation

**Functions**:
- `hash_password(password: str) -> str`
  - Uses bcrypt with 12 rounds
  - Returns hashed password string

- `verify_password(password: str, hashed_password: str) -> bool`
  - Verifies password against hash
  - Returns True if valid

- `validate_password(password: str) -> Tuple[bool, str]`
  - Validates password strength
  - Requirements:
    - 8-40 characters
    - At least one letter
    - At least one number
    - At least one special character: !@£$%^&()-_+=[]{}:|<>?
  - Returns (is_valid, error_message)

#### archer/auth/session.py
**Purpose**: Session management and authentication

**Configuration**:
- Session cookie name: `archer_session`
- Default duration: 16 hours
- Remember Me duration: 7 days
- Cookie settings: httponly=True, samesite='lax'

**Functions**:
- `create_session(user_id: int, db: Session, remember_me: bool = False) -> str`
  - Creates new session with UUID
  - Sets expiry based on remember_me flag
  - Returns session ID

- `get_session(session_id: str, db: Session) -> Optional[Session]`
  - Retrieves and validates session
  - Checks expiry and active status

- `get_current_user(request: Request, db: Session) -> Optional[User]`
  - Gets current user from request cookies
  - Validates session
  - Returns User object or None

- `get_user_from_session_id(session_id: str, db: Session) -> Optional[User]`
  - Gets user from session ID string
  - Used in routes where Request object not available

- `delete_session(session_id: str, db: Session) -> bool`
  - Marks session as inactive (soft delete)
  - Returns True if successful

#### archer/auth/encryption.py
**Purpose**: API key encryption/decryption

**Configuration**:
- Uses Fernet symmetric encryption
- Encryption key: Auto-generated on first run
- Key storage: `data/encryption.key`

**Functions**:
- `get_or_create_encryption_key() -> bytes`
  - Loads or creates encryption key
  - Generates new key if not exists

- `encrypt_api_key(api_key: str) -> str`
  - Encrypts API key using Fernet
  - Returns base64 encoded encrypted string

- `decrypt_api_key(encrypted_key: str) -> str`
  - Decrypts API key
  - Returns plain text API key

#### archer/auth/password_reset.py (NEW)
**Purpose**: Password reset functionality

**Configuration**:
- Token expiry: 1 hour
- Token format: URL-safe 32 bytes (64 hex characters)

**Functions**:
- `generate_reset_token() -> str`
  - Generates secure random token
  - Uses secrets.token_urlsafe(32)

- `create_password_reset_request(email: str, db: Session) -> Optional[str]`
  - Creates password reset request
  - Invalidates existing tokens for user
  - Returns reset token or None if user not found

- `validate_reset_token(token: str, db: Session) -> Optional[User]`
  - Validates token and expiry
  - Returns User object if valid

- `reset_password_with_token(token: str, new_password: str, db: Session) -> bool`
  - Resets password using valid token
  - Marks token as used
  - Returns True if successful

- `admin_reset_password(user_id: int, new_password: str, db: Session) -> bool`
  - Admin-initiated password reset
  - Bypasses token validation
  - Returns True if successful

### Authentication Routes

#### POST `/api/auth/login`
**Purpose**: User login

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "password",
  "remember_me": false
}
```

**Response**:
```json
{
  "success": true,
  "message": "Login successful",
  "redirect": "/profile"
}
```

**Sets Cookie**: `archer_session` with session ID

#### POST `/api/auth/logout`
**Purpose**: User logout

**Response**:
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

**Clears Cookie**: `archer_session`

#### POST `/api/auth/request-reset`
**Purpose**: Request password reset token

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

**Response** (Development):
```json
{
  "success": true,
  "message": "Password reset link has been sent to your email.",
  "reset_url": "http://localhost:8000/reset-password?token=...",
  "token": "..."
}
```

**Note**: In production, the token should be sent via email, not returned in response.

#### POST `/api/auth/reset-password`
**Purpose**: Reset password with token

**Request Body**:
```json
{
  "token": "reset-token-here",
  "new_password": "NewPassword1!"
}
```

**Response**:
```json
{
  "success": true,
  "message": "Password has been reset successfully. You can now log in with your new password."
}
```

#### POST `/api/admin/reset-password`
**Purpose**: Admin-initiated password reset

**Authentication**: Required (Admin only)

**Request Body**:
```json
{
  "user_id": 2,
  "new_password": "NewPassword1!"
}
```

**Response**:
```json
{
  "success": true,
  "message": "Password has been reset successfully"
}
```

### Profile Routes (UPDATED)

#### POST `/api/profile`
**Purpose**: Update user profile

**Authentication**: Required

**Request Body**:
```json
{
  "full_name": "John Doe"
}
```

**Response**:
```json
{
  "success": true,
  "message": "Profile updated successfully"
}
```

**Changes**: Now saves to database instead of returning mock response

#### GET `/api/profile/apikeys`
**Purpose**: Get user's API keys

**Authentication**: Required

**Response**:
```json
{
  "splunk": "decrypted-key-here",
  "mde": "decrypted-key-here",
  "elastic": "",
  "openai": "decrypted-key-here",
  "anthropic": ""
}
```

**Changes**: Now loads user-specific encrypted keys from database

#### POST `/api/profile/apikeys`
**Purpose**: Save user's API keys

**Authentication**: Required

**Request Body**:
```json
{
  "splunk": "api-key-here",
  "mde": "api-key-here",
  "elastic": "",
  "openai": "api-key-here",
  "anthropic": ""
}
```

**Response**:
```json
{
  "success": true,
  "message": "API keys saved successfully"
}
```

**Changes**: Now encrypts and stores keys per user in database

### Login/Logout Pages

#### GET `/login`
**File**: `templates/login.html`

**Features**:
- Email and password inputs
- Remember Me checkbox (7 day sessions)
- Login button
- Forgot Password link
- Form validation
- Error message display

#### GET `/reset-password`
**File**: `templates/reset_password.html` (To be created)

**Features**:
- Token validation
- New password input
- Password confirmation
- Password strength requirements display
- Submit button

### Admin User Management

#### Profile Users Tab
**Visibility**: Admin users only

**Template**: `templates/profile.html` (Users tab)

**Features** (To be implemented):
- List all users
- View user details
- Edit user information (name, email)
- Reset user passwords
- Activate/deactivate users
- View user activity

### Command-Line Scripts

#### create_admin.py
**Purpose**: Create initial admin user

**Location**: Root directory

**Usage**:
```bash
python3 create_admin.py
```

**Interactive Prompts**:
1. Admin email
2. Full name
3. Password (with validation)

**Features**:
- Password validation
- Email format checking
- Prevents duplicate admin emails
- Creates admin user with UserRole.ADMIN

### Database Integration
- SQLite database at `data/archer.db`
- SQLAlchemy ORM
- Automatic schema creation on first run
- User model with profile fields ✅
- Activity tracking (Timeline - pending implementation)
- Secure API key storage (encrypted) ✅
- Password reset tokens ✅

### Activity Tracking
- Automatic logging of:
  - Threat actor analysis
  - CVE processing
  - Detection generation
  - Correlation runs
- Timestamps and metadata
- Result file associations

### Advanced Features
- Export to VECTR (integration)
- Run Emulation (integration with Atomic Red Team/Caldera)
- Multi-user support
- Role-based access control
- API key validation
- Profile picture cropping/resizing

## Testing Checklist

- [ ] Dark mode toggle works on all pages
- [ ] Dark mode preference persists across sessions
- [ ] Profile icon accessible from all pages
- [ ] Profile page loads correctly
- [ ] All three tabs switch properly
- [ ] Profile form saves data
- [ ] Profile picture upload works
- [ ] Default avatar displays correctly
- [ ] Timeline filters work
- [ ] API key visibility toggle works
- [ ] API key save functionality works
- [ ] Responsive design on mobile
- [ ] All buttons have proper hover states
- [ ] Form validation works correctly
- [ ] Notifications display properly

## Security Considerations

### Implemented:
- **Password Security**:
  - bcrypt hashing with 12 rounds
  - Strong password validation (8-40 chars, letters, numbers, special chars)
  - Password reset tokens with 1-hour expiry
  - Secure token generation using secrets module

- **Session Management**:
  - UUID-based session IDs
  - httponly cookies (prevents XSS access)
  - samesite='lax' (CSRF protection)
  - Configurable session duration (16 hours default, 7 days with Remember Me)
  - Session expiry validation
  - Soft deletion of sessions (audit trail)

- **API Key Storage**:
  - Fernet symmetric encryption for API keys at rest
  - Per-user encrypted storage
  - Encryption key stored separately in `data/encryption.key`
  - API keys never logged or exposed in errors

- **Role-Based Access Control**:
  - User role enum (Admin/Standard)
  - Admin-only endpoints (password reset, user management)
  - Role validation on protected routes

- **Database Security**:
  - Passwords never stored in plain text
  - Email uniqueness enforced
  - Index on email for faster lookups
  - Foreign key constraints
  - Timestamps for audit trail

- **File Upload Security**:
  - File type validation for profile pictures
  - File size limits (5MB)
  - Sanitized file names
  - Dedicated upload directory

- **Input Validation**:
  - Email format validation
  - Password strength validation
  - API key field validation
  - JSON schema validation on endpoints

### TODO:
- Add CSRF tokens to forms
- Implement rate limiting on auth endpoints
- Add brute force protection (account lockout)
- Email verification for password resets
- Two-factor authentication (2FA)
- Security questions implementation
- Session management UI (view/revoke active sessions)
- Audit logging for sensitive operations
- API key usage tracking
- Password history (prevent reuse)
- Account recovery options

## Browser Compatibility

- Modern browsers (Chrome, Firefox, Safari, Edge)
- CSS Grid and Flexbox support required
- LocalStorage required for dark mode persistence
- FileReader API for image preview
- Fetch API for async requests

## Accessibility

- ARIA labels on icon buttons
- Keyboard navigation support
- Screen reader friendly
- Sufficient color contrast
- Focus indicators
- Alt text for images

## Responsive Design

- Desktop-first design
- Mobile breakpoint at 768px
- Flexible layouts
- Touch-friendly buttons
- Adaptive navigation

## Updated File Structure

```
archer/
├── templates/
│   ├── base.html                          (updated with dark mode + profile icon)
│   ├── login.html                         (NEW - login page)
│   ├── profile.html                       (updated with Users tab for admins)
│   └── reset_password.html                (TODO - password reset page)
├── static/
│   ├── css/
│   │   ├── dark-mode.css                  (dark mode styles)
│   │   ├── profile.css                    (profile page styles)
│   │   └── login.css                      (NEW - login page styles)
│   ├── js/
│   │   ├── profile.js                     (updated - profile form submission)
│   │   └── login.js                       (NEW - login form handling)
│   └── images/
│       └── default-avatar.svg             (default profile picture)
├── archer/
│   ├── app.py                             (UPDATED - auth routes, profile routes)
│   ├── database/
│   │   ├── db.py                          (NEW - database connection & init)
│   │   └── models.py                      (NEW - User, Session, APIKey, PasswordReset, SecurityQuestion)
│   └── auth/
│       ├── __init__.py                    (NEW - exports all auth functions)
│       ├── password.py                    (NEW - password hashing & validation)
│       ├── session.py                     (NEW - session management)
│       ├── encryption.py                  (NEW - API key encryption)
│       └── password_reset.py              (NEW - password reset functionality)
├── data/
│   ├── archer.db                          (NEW - SQLite database)
│   └── encryption.key                     (NEW - Fernet encryption key)
├── create_admin.py                        (NEW - admin user creation script)
└── scripts/
    ├── start_clean.sh                     (MOVED - clean start script with confirmation)
    └── tests/                             (NEW - test scripts directory)
        ├── genai_smoke_test.py            (MOVED)
        └── summarize_smoke_json.py        (MOVED)
```

## Implementation Summary

### Phase 1: Database & Models ✅
- Created SQLite database with SQLAlchemy ORM
- Implemented User, Session, APIKey, PasswordReset, and SecurityQuestion models
- Set up database initialization and connection pooling

### Phase 2: Authentication Core ✅
- Implemented bcrypt password hashing
- Created session management with UUID tokens
- Built Fernet-based API key encryption
- Added password validation with strength requirements

### Phase 3: Login/Logout ✅
- Created login page with Remember Me option
- Implemented login endpoint with session creation
- Built logout functionality with session cleanup
- Added authentication middleware (require_auth helper)

### Phase 4: Profile Management ✅
- Updated profile form to save to database
- Implemented per-user API key storage with encryption
- Added admin-only Users tab (UI only, backend pending)
- Updated profile routes with authentication checks

### Phase 5: Password Reset ✅
- Implemented token-based password reset flow
- Created password reset request endpoint
- Built password reset confirmation endpoint
- Added admin password reset functionality
- Token expiry and validation implemented

### Phase 6: Scripts & Organization ✅
- Created create_admin.py script for initial setup
- Moved web scripts to scripts/ directory
- Organized test scripts into scripts/tests/
- Added confirmation prompt to clean start script

## Quick Start Guide

### 1. Initial Setup
```bash
# Create virtual environment (if not exists)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip3 install -r requirements.txt

# Create admin user
python3 create_admin.py
# Enter: email, full name, password
```

### 2. Start Server
```bash
# Option A: Normal start
source .venv/bin/activate
python3 -m uvicorn archer.app:app --host 127.0.0.1 --port 8000

# Option B: Clean start (kills existing processes, clears cache)
./scripts/start_clean.sh
```

### 3. Access Application
```
Homepage:        http://localhost:8000/
Login:           http://localhost:8000/login
Profile:         http://localhost:8000/profile (requires login)
How It Works:    http://localhost:8000/how-it-works
```

### 4. Test Authentication
```bash
# Login with admin credentials
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@archer.com","password":"Password1!","remember_me":false}'

# Request password reset
curl -X POST http://localhost:8000/api/auth/request-reset \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@archer.com"}'

# Save API keys (requires auth cookie)
curl -X POST http://localhost:8000/api/profile/apikeys \
  -H "Content-Type: application/json" \
  -b "archer_session=YOUR_SESSION_ID" \
  -d '{"splunk":"sk-1234","openai":"sk-5678"}'
```

## API Endpoint Reference

### Public Endpoints (No Authentication Required)
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/` | Homepage |
| GET | `/login` | Login page |
| GET | `/how-it-works` | Documentation page |
| POST | `/api/auth/login` | User login |
| POST | `/api/auth/request-reset` | Request password reset |
| POST | `/api/auth/reset-password` | Reset password with token |

### Authenticated Endpoints (Session Required)
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/profile` | Profile page |
| POST | `/api/auth/logout` | Logout |
| POST | `/api/profile` | Update profile |
| POST | `/api/profile/picture` | Upload profile picture |
| GET | `/api/profile/timeline` | Get activity timeline |
| GET | `/api/profile/apikeys` | Get API keys |
| POST | `/api/profile/apikeys` | Save API keys |

### Admin-Only Endpoints (Admin Role Required)
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/admin/reset-password` | Reset user password |
| GET | `/api/admin/users` | List all users (TODO) |
| PUT | `/api/admin/users/{id}` | Update user (TODO) |
| POST | `/api/admin/users` | Create user (TODO) |
| DELETE | `/api/admin/users/{id}` | Deactivate user (TODO) |

## Testing Checklist (Updated)

### Authentication
- [x] Create admin user via create_admin.py
- [x] Login with valid credentials
- [x] Login with invalid credentials shows error
- [x] Remember Me creates 7-day session
- [x] Default login creates 16-hour session
- [x] Logout destroys session
- [x] Protected routes redirect to login
- [x] Session expiry works correctly

### Password Management
- [x] Password validation enforces requirements
- [x] Passwords are hashed with bcrypt
- [x] Request password reset generates token
- [x] Reset token expires after 1 hour
- [x] Reset password with valid token works
- [x] Reset password with invalid token fails
- [x] Admin can reset user passwords

### Profile Management
- [x] Update full name saves to database
- [x] Email and account type are read-only
- [x] Profile displays current user data
- [x] Users tab only visible to admins

### API Key Management
- [x] API keys are encrypted at rest
- [x] Each user has separate API keys
- [x] API keys load correctly on profile page
- [x] Saving API keys updates database
- [x] Empty API keys are handled correctly

### UI/UX
- [ ] Dark mode toggle works on all pages
- [ ] Dark mode preference persists across sessions
- [ ] Profile icon accessible from all pages
- [ ] All three tabs switch properly
- [ ] Profile form validation works
- [ ] Notifications display properly
- [ ] Responsive design on mobile

## Notes

The authentication system is now fully functional with:
- Secure password storage and validation
- Session-based authentication
- Per-user encrypted API key storage
- Token-based password reset
- Admin password reset capability
- Role-based access control

Remaining TODOs are primarily UI enhancements (password reset page, admin user management interface) and advanced security features (2FA, rate limiting, CSRF tokens).
