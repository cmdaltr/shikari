# 🔌 Archer API Reference


---

## 📌 Table of Contents

1. [Authentication APIs](#authentication-apis)
2. [User Management APIs (Admin Only)](#user-management-apis-admin-only)
3. [Profile & Security APIs](#profile--security-apis)
4. [Session Management APIs](#session-management-apis)
5. [Password Reset APIs](#password-reset-apis)
6. [API Keys Management](#api-keys-management)
7. [Activity Timeline APIs](#activity-timeline-apis)
8. [Response Formats](#response-formats)
9. [Error Handling](#error-handling)

---


---

## 🔌 Authentication APIs

### 📌 Login

Authenticate a user and create a new session.

**Endpoint**: `POST /login`

**Content-Type**: `application/x-www-form-urlencoded`

**Request Body**:
```bash
email=admin@archer.app
password=£missary_0f_the_G0rg0nite$
remember_me=true
```bash

**Response** (303 Redirect):
```bash
Location: /
Set-Cookie: archer_session={session_id}; HttpOnly; Path=/; SameSite=Lax
```bash

**Error Responses**:
- `401 Unauthorized`: Invalid credentials
- `403 Forbidden`: Account locked due to too many failed attempts
- `403 Forbidden`: Account is deactivated

**Rate Limiting**: 5 attempts per 5 minutes. Exceeding this limit results in a 15-minute account lockout.

**Audit Log**: All login attempts (success and failure) are logged.

---

### 📌 Logout

Terminate the current session.

**Endpoint**: `GET /logout`

**Authentication**: Required (cookie: `archer_session`)

**Response** (303 Redirect):
```bash
Location: /login
Set-Cookie: archer_session=; Max-Age=0
```bash

**Audit Log**: Logout events are logged.

---


---

## 🔌 User Management APIs (Admin Only)

All endpoints in this section require admin authentication.

### 📌 List All Users

Get a list of all users in the system.

**Endpoint**: `GET /api/admin/users`

**Authentication**: Required (Admin role)

**Response** (200 OK):
```json
{
  "users": [
    {
      "id": 1,
      "email": "admin@archer.app",
      "full_name": "Admin User",
      "role": "admin",
      "is_active": true,
      "created_at": "2025-01-20T12:00:00",
      "updated_at": "2025-01-20T12:00:00"
    },
    {
      "id": 2,
      "email": "user@example.com",
      "full_name": "Standard User",
      "role": "standard",
      "is_active": true,
      "created_at": "2025-01-21T10:30:00",
      "updated_at": "2025-01-21T10:30:00"
    }
  ]
}
```bash

**Error Responses**:
- `401 Unauthorized`: Not authenticated
- `403 Forbidden`: Not an admin user
- `500 Internal Server Error`: Database error

---

### 📌 Create User

Create a new user account.

**Endpoint**: `POST /api/admin/users`

**Authentication**: Required (Admin role)

**Content-Type**: `application/json`

**Request Body**:
```json
{
  "email": "newuser@example.com",
  "full_name": "New User Name",
  "password": "SecureP@ssw0rd123",
  "role": "standard"
}
```bash

**Field Validation**:
- `email`: Valid email format, must be unique
- `full_name`: Non-empty string
- `password`: Minimum 12 characters, must include uppercase, lowercase, digit, and special character
- `role`: Either "admin" or "standard"

**Response** (200 OK):
```json
{
  "message": "User created successfully",
  "user": {
    "id": 3,
    "email": "newuser@example.com",
    "full_name": "New User Name",
    "role": "standard",
    "is_active": true
  }
}
```bash

**Error Responses**:
- `400 Bad Request`: Missing required fields or validation failure
- `400 Bad Request`: Email already exists
- `401 Unauthorized`: Not authenticated
- `403 Forbidden`: Not an admin user

**Audit Log**: User creation is logged.

---

### 📌 Update User

Update an existing user's details.

**Endpoint**: `PUT /api/admin/users/{user_id}`

**Authentication**: Required (Admin role)

**Content-Type**: `application/json`

**Request Body** (all fields optional):
```json
{
  "email": "updated@example.com",
  "full_name": "Updated Name",
  "role": "admin",
  "is_active": false
}
```bash

**Response** (200 OK):
```json
{
  "message": "User updated successfully",
  "user": {
    "id": 2,
    "email": "updated@example.com",
    "full_name": "Updated Name",
    "role": "admin",
    "is_active": false,
    "updated_at": "2025-01-21T15:45:00"
  }
}
```bash

**Error Responses**:
- `400 Bad Request`: Invalid field values
- `400 Bad Request`: Email already exists (when changing email)
- `401 Unauthorized`: Not authenticated
- `403 Forbidden`: Not an admin user
- `404 Not Found`: User does not exist

**Note**: Password cannot be updated via this endpoint. Use the password reset flow instead.

**Audit Log**: User updates are logged.

---

### 📌 Deactivate User

Deactivate a user account (soft delete).

**Endpoint**: `DELETE /api/admin/users/{user_id}`

**Authentication**: Required (Admin role)

**Response** (200 OK):
```json
{
  "message": "User deactivated successfully"
}
```bash

**Behavior**:
- Sets `is_active` to `false`
- Invalidates all active sessions for the user
- Admin cannot deactivate their own account

**Error Responses**:
- `400 Bad Request`: Attempting to deactivate own account
- `401 Unauthorized`: Not authenticated
- `403 Forbidden`: Not an admin user
- `404 Not Found`: User does not exist

**Audit Log**: Deactivation is logged.

---

### 📌 Reset User Password (Admin)

Reset a user's password as an administrator.

**Endpoint**: `POST /api/admin/users/{user_id}/reset-password`

**Authentication**: Required (Admin role)

**Content-Type**: `application/json`

**Request Body**:
```json
{
  "new_password": "NewSecureP@ssw0rd123"
}
```bash

**Response** (200 OK):
```json
{
  "message": "Password reset successfully"
}
```bash

**Error Responses**:
- `400 Bad Request`: Password doesn't meet complexity requirements
- `401 Unauthorized`: Not authenticated
- `403 Forbidden`: Not an admin user
- `404 Not Found`: User does not exist

**Audit Log**: Password reset is logged.

---


---

## 🔌 Profile & Security APIs

### 📌 Get Current User Profile

Get the authenticated user's profile information.

**Endpoint**: `GET /api/users`

**Authentication**: Required

**Response** (200 OK):
```json
{
  "id": 1,
  "email": "admin@archer.app",
  "full_name": "Admin User",
  "role": "admin",
  "is_active": true,
  "mfa_enabled": false,
  "created_at": "2025-01-20T12:00:00",
  "updated_at": "2025-01-20T12:00:00"
}
```bash

---

### 📌 Update Profile

Update the current user's profile information.

**Endpoint**: `POST /api/update-profile`

**Authentication**: Required

**Content-Type**: `application/json`

**Request Body**:
```json
{
  "full_name": "Updated Full Name",
  "email": "newemail@example.com"
}
```bash

**Response** (200 OK):
```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": 1,
    "email": "newemail@example.com",
    "full_name": "Updated Full Name",
    "role": "admin",
    "is_active": true,
    "updated_at": "2025-01-21T16:00:00"
  }
}
```bash

**Error Responses**:
- `400 Bad Request`: Invalid email format or email already exists
- `401 Unauthorized`: Not authenticated

**Audit Log**: Profile updates are logged.

---

### 📌 Change Password

Change the current user's password.

**Endpoint**: `POST /api/change-password`

**Authentication**: Required

**Content-Type**: `application/json`

**Request Body**:
```json
{
  "current_password": "OldP@ssw0rd123",
  "new_password": "NewSecureP@ssw0rd456",
  "confirm_password": "NewSecureP@ssw0rd456"
}
```bash

**Response** (200 OK):
```json
{
  "message": "Password changed successfully"
}
```bash

**Error Responses**:
- `400 Bad Request`: Current password is incorrect
- `400 Bad Request`: New passwords don't match
- `400 Bad Request`: New password doesn't meet complexity requirements
- `401 Unauthorized`: Not authenticated

**Audit Log**: Password changes are logged.

---


---

## 🔌 Session Management APIs

### 📌 Get Active Sessions

List all active sessions for the current user.

**Endpoint**: `GET /api/sessions`

**Authentication**: Required

**Response** (200 OK):
```json
{
  "sessions": [
    {
      "id": 1,
      "session_id": "a1b2c3d4e5f6...",
      "created_at": "2025-01-21T10:00:00",
      "expires_at": "2025-01-22T02:00:00",
      "remember_me": true,
      "is_current": true
    },
    {
      "id": 2,
      "session_id": "g7h8i9j0k1l2...",
      "created_at": "2025-01-20T14:30:00",
      "expires_at": "2025-01-21T06:30:00",
      "remember_me": false,
      "is_current": false
    }
  ]
}
```bash

**Note**: `is_current` indicates if the session is the one making the request.

---

### 📌 Revoke Session

Revoke (delete) a specific session.

**Endpoint**: `DELETE /api/sessions/{session_id}`

**Authentication**: Required

**Response** (200 OK):
```json
{
  "message": "Session revoked successfully"
}
```bash

**Error Responses**:
- `400 Bad Request`: Cannot revoke current session (use logout instead)
- `401 Unauthorized`: Not authenticated
- `404 Not Found`: Session does not exist or doesn't belong to user

**Audit Log**: Session revocations are logged.

---

### 📌 Revoke All Other Sessions

Revoke all sessions except the current one.

**Endpoint**: `POST /api/sessions/revoke-all`

**Authentication**: Required

**Response** (200 OK):
```json
{
  "message": "All other sessions revoked successfully",
  "revoked_count": 3
}
```bash

**Audit Log**: Batch session revocations are logged.

---


---

## 🔌 Password Reset APIs

### 📌 Request Password Reset

Request a password reset token to be sent via email.

**Endpoint**: `POST /api/password-reset/request`

**Content-Type**: `application/json`

**Request Body**:
```json
{
  "email": "user@example.com"
}
```bash

**Response** (200 OK):
```json
{
  "message": "If the email exists, a password reset link has been sent"
}
```bash

**Note**: For security, the response is the same whether the email exists or not.

**Behavior**:
- Generates a secure reset token
- Token expires in 1 hour
- Sends email with reset link
- In development mode (EMAIL_ENABLED=false), token is logged to console

**Rate Limiting**: Requests are rate-limited per IP address.

**Audit Log**: Password reset requests are logged.

---

### 📌 Validate Reset Token

Verify if a password reset token is valid (without consuming it).

**Endpoint**: `GET /api/password-reset/validate?token={token}`

**Response** (200 OK):
```json
{
  "valid": true,
  "email": "user@example.com"
}
```bash

**Error Response** (400 Bad Request):
```json
{
  "valid": false,
  "message": "Invalid or expired token"
}
```bash

---

### 📌 Reset Password

Complete the password reset process with a valid token.

**Endpoint**: `POST /api/password-reset/complete`

**Content-Type**: `application/json`

**Request Body**:
```json
{
  "token": "abc123def456...",
  "new_password": "NewSecureP@ssw0rd789",
  "confirm_password": "NewSecureP@ssw0rd789"
}
```bash

**Response** (200 OK):
```json
{
  "message": "Password reset successfully"
}
```bash

**Error Responses**:
- `400 Bad Request`: Invalid or expired token
- `400 Bad Request`: Passwords don't match
- `400 Bad Request`: Password doesn't meet complexity requirements

**Behavior**:
- Marks token as used (single-use only)
- Invalidates all active sessions (optional)
- Updates password hash

**Audit Log**: Completed password resets are logged.

---


---

## 🔌 API Keys Management

### 🔌 Get API Keys

Retrieve all API keys for the current user.

**Endpoint**: `GET /api/keys`

**Authentication**: Required

**Response** (200 OK):
```json
{
  "keys": {
    "splunk": {
      "host": "splunk.example.com",
      "username": "admin",
      "has_password": true
    },
    "mde": {
      "tenant_id": "abc-123-def-456",
      "client_id": "xyz-789-uvw-012",
      "has_secret": true
    },
    "openai": {
      "has_key": true
    },
    "anthropic": {
      "has_key": true
    }
  }
}
```bash

**Note**: Actual API keys are never returned, only indicators that they exist.

---

### 🔌 Save API Keys

Save or update API keys for various platforms.

**Endpoint**: `POST /api/keys`

**Authentication**: Required

**Content-Type**: `application/json`

**Request Body**:
```json
{
  "splunk_host": "splunk.example.com",
  "splunk_username": "admin",
  "splunk_password": "secret123",
  "mde_tenant_id": "abc-123",
  "mde_client_id": "xyz-789",
  "mde_client_secret": "secret456",
  "openai_key": "sk-...",
  "anthropic_key": "sk-ant-..."
}
```bash

**Response** (200 OK):
```json
{
  "message": "API keys saved successfully"
}
```bash

**Security**:
- All API keys are encrypted at rest using Fernet encryption
- Keys are never logged or displayed after saving

**Audit Log**: API key updates are logged (without the actual keys).

---


---

## 🔌 Activity Timeline APIs

### 📌 Get Activity Timeline

Retrieve activity history for the current user.

**Endpoint**: `GET /api/timeline`

**Authentication**: Required

**Query Parameters**:
- `limit` (optional): Maximum number of items to return (default: 50, max: 200)
- `offset` (optional): Pagination offset (default: 0)
- `type` (optional): Filter by activity type (generate, correlate, upload, library_save, library_export)

**Response** (200 OK):
```json
{
  "activities": [
    {
      "id": 1,
      "activity_type": "generate",
      "title": "Generated detections for APT29",
      "description": "Created 15 detection rules",
      "metadata": {
        "detection_count": 15,
        "correlation_count": 3,
        "platform": "Splunk"
      },
      "created_at": "2025-01-21T14:30:00"
    },
    {
      "id": 2,
      "activity_type": "library_save",
      "title": "Saved detection to library",
      "description": "PowerShell Encoded Command Execution",
      "metadata": {
        "detection_id": 42,
        "visibility": "private"
      },
      "created_at": "2025-01-21T15:00:00"
    }
  ],
  "total": 2,
  "limit": 50,
  "offset": 0
}
```bash

---


---

## 📌 Response Formats

### 📌 Success Response

Standard success response format:

```json
{
  "message": "Operation completed successfully",
  "data": {
    // Response-specific data
  }
}
```bash

### 📌 Error Response

Standard error response format:

```json
{
  "detail": "Error message describing what went wrong"
}
```bash

HTTP status codes used:
- `200 OK`: Successful request
- `201 Created`: Resource created successfully
- `303 See Other`: Redirect after successful operation
- `400 Bad Request`: Invalid input or validation failure
- `401 Unauthorized`: Not authenticated
- `403 Forbidden`: Authenticated but not authorized
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side error

---


---

## 📌 Error Handling

### 🔐 Authentication Errors

**401 Unauthorized**:
```json
{
  "detail": "Not authenticated. Please log in."
}
```bash

**403 Forbidden** (Account Locked):
```json
{
  "detail": "Account locked due to too many failed login attempts. Try again in 15 minutes."
}
```bash

**403 Forbidden** (Insufficient Permissions):
```json
{
  "detail": "Admin privileges required"
}
```bash

### 📌 Validation Errors

**400 Bad Request** (Password Validation):
```json
{
  "detail": "Password must be at least 12 characters and include uppercase, lowercase, digit, and special character"
}
```bash

**400 Bad Request** (Email Validation):
```json
{
  "detail": "Invalid email format"
}
```bash

**400 Bad Request** (Duplicate Email):
```json
{
  "detail": "Email already exists"
}
```bash

### 📌 Rate Limiting

**429 Too Many Requests**:
```json
{
  "detail": "Too many requests. Please try again in 300 seconds."
}
```bash

---


---

## ⭐ Best Practices

### 🔌 API Client Implementation

1. **Store Session Cookie**: Save the `archer_session` cookie after successful login
2. **Handle Redirects**: Follow 303 redirects appropriately
3. **Implement Retry Logic**: Handle rate limiting with exponential backoff
4. **Secure API Keys**: Never log or expose API keys in client-side code
5. **Validate Input**: Client-side validation before sending requests
6. **Error Handling**: Gracefully handle all error responses

### 🔒 Security Considerations

1. **Use HTTPS**: Always use HTTPS in production
2. **CSRF Protection**: Include CSRF tokens for form submissions
3. **Session Management**: Implement automatic logout on inactivity
4. **Password Storage**: Never store passwords client-side
5. **Rate Limiting**: Respect rate limits to avoid account lockout
6. **Audit Logging**: Monitor audit logs for suspicious activity

---


---

## 📝 Code Examples

### 📌 Python Example: Create User

```python
import requests

# Login first
session = requests.Session()
login_data = {
    "email": "admin@archer.app",
    "password": "£missary_0f_the_G0rg0nite$"
}
session.post("http://localhost:8000/login", data=login_data)

# Create new user
new_user = {
    "email": "newuser@example.com",
    "full_name": "New User",
    "password": "SecureP@ssw0rd123",
    "role": "standard"
}
response = session.post("http://localhost:8000/api/admin/users", json=new_user)
print(response.json())
```bash

### 📌 JavaScript Example: Get Activity Timeline

```javascript
async function getTimeline() {
  const response = await fetch('/api/timeline?limit=10&type=generate', {
    method: 'GET',
    credentials: 'include'  // Include session cookie
  });

  if (response.ok) {
    const data = await response.json();
    console.log(data.activities);
  } else {
    console.error('Failed to fetch timeline:', response.status);
  }
}
```bash

### 📌 cURL Example: Password Reset

```bash
# Request reset
curl -X POST http://localhost:8000/api/password-reset/request \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Complete reset (after receiving token via email)
curl -X POST http://localhost:8000/api/password-reset/complete \
  -H "Content-Type: application/json" \
  -d '{
    "token": "abc123...",
    "new_password": "NewP@ssw0rd123",
    "confirm_password": "NewP@ssw0rd123"
  }'
```bash

---

**Last Updated**: 2025-01-20
**API Version**: 1.0
**Maintained By**: Archer Development Team
