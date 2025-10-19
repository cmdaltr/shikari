# Input Validation and Sanitization

## Overview

All user inputs in the Archer application are validated and sanitized to prevent common security vulnerabilities including:
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Buffer Overflow
- Null Byte Injection

## Validation Functions

### Authentication & User Management

#### Email Validation
**Function**: `validate_email(email: str) -> tuple[bool, str]`

**Location**: `archer/security/validation.py`

**Requirements** (STRICT):
- **MUST contain @ symbol**
- **Maximum 64 characters total**
- Valid email format

**Normalization**:
- Strips whitespace
- Converts to lowercase

**Validation Rules**:
- Must contain @ symbol (enforced)
- Length: 3-64 characters (STRICT limit)
- Format: Standard email regex (`user@domain.tld`)
- No consecutive dots
- No dangerous characters: `< > ( ) [ ] \ , ; : " \n \r`

**Returns**: `(is_valid, normalized_email_or_error_message)`

**Example**:
```python
is_valid, result = validate_email("  User@Example.COM  ")
# Returns: (True, "user@example.com")

is_valid, error = validate_email("no-at-sign.com")
# Returns: (False, "Email must contain @ symbol")

is_valid, error = validate_email("verylongemailaddress12345678901234567890123456789012345@test.com")
# Returns: (False, "Email is too long (maximum 64 characters)") # This is 65 chars

is_valid, result = validate_email("shortone@test.com")  # 17 chars - Valid
# Returns: (True, "shortone@test.com")
```

#### Full Name Validation
**Function**: `sanitize_full_name(full_name: str) -> tuple[bool, str]`

**Requirements** (STRICT):
- **ONLY uppercase and lowercase letters (a-z, A-Z)**
- **Hyphens/dashes (-)**
- **Spaces**
- **Maximum 64 characters**

**Normalization**:
- Strips leading/trailing whitespace
- Collapses multiple spaces to single space

**Validation Rules**:
- Length: 1-64 characters (STRICT limit)
- Allowed characters ONLY:
  - Letters: `a-z, A-Z`
  - Hyphens: `-`
  - Spaces
- NO numbers, NO apostrophes, NO dots, NO other special characters

**Returns**: `(is_valid, sanitized_name_or_error_message)`

**Example**:
```python
is_valid, result = sanitize_full_name("  John   Doe  ")
# Returns: (True, "John Doe")

is_valid, result = sanitize_full_name("Mary-Jane Smith")
# Returns: (True, "Mary-Jane Smith")

is_valid, error = sanitize_full_name("John O'Brien")
# Returns: (False, "Full name can only contain letters, hyphens, and spaces")

is_valid, error = sanitize_full_name("John123")
# Returns: (False, "Full name can only contain letters, hyphens, and spaces")

is_valid, error = sanitize_full_name("A" * 65)
# Returns: (False, "Full name is too long (maximum 64 characters)")
```

#### API Key Validation
**Function**: `sanitize_api_key(api_key: str, key_name: str = "API key") -> tuple[bool, str]`

**Normalization**:
- Strips whitespace
- Empty keys are allowed (returns empty string)

**Validation Rules**:
- Length: 10-500 characters (if not empty)
- Allowed characters: `a-zA-Z0-9_-.=+/`
- No placeholder values: `test`, `example`, `placeholder`, `your-api-key`

**Returns**: `(is_valid, sanitized_key_or_error_message)`

**Example**:
```python
is_valid, result = sanitize_api_key("  sk-1234567890abcdef  ", "OpenAI")
# Returns: (True, "sk-1234567890abcdef")

is_valid, error = sanitize_api_key("test", "Splunk")
# Returns: (False, "Splunk appears to be a placeholder value")
```

### General Text Input
**Function**: `sanitize_text_input(text: str, field_name: str = "Input", max_length: int = 1000) -> tuple[bool, str]`

**Normalization**:
- Strips whitespace

**Validation Rules**:
- Configurable max length (default 1000 characters)
- No null bytes (`\x00`)
- No dangerous control characters (except newlines/tabs for multi-line input)

**Returns**: `(is_valid, sanitized_text_or_error_message)`

###File & Path Security

#### Filename Sanitization
**Function**: `sanitize_filename(filename: str) -> str`

**Processing**:
- Removes path components (keeps only basename)
- Allows only: alphanumeric, spaces, hyphens, underscores, periods
- Strips leading/trailing spaces and dots
- Prevents empty filenames (returns 'unnamed_file')

**Example**:
```python
safe = sanitize_filename("../../etc/passwd")
# Returns: ".._.._etc_passwd"

safe = sanitize_filename("my document.pdf")
# Returns: "my document.pdf"
```

#### Path Component Sanitization
**Function**: `sanitize_path_component(component: str) -> str`

**Processing**:
- Replaces path separators (`/`, `\`) with underscores
- Removes parent directory references (`..`)
- Allows only: alphanumeric, hyphens, periods
- Limits length to 200 characters
- Prevents empty components (returns 'default')

**Example**:
```python
safe = sanitize_path_component("../../../etc")
# Returns: "_"

safe = sanitize_path_component("group_name/test")
# Returns: "group_name_test"
```

#### Path Validation
**Function**: `validate_safe_path(base_dir: str, requested_path: str) -> Optional[str]`

**Purpose**: Prevents path traversal attacks

**Returns**: Validated absolute path if safe, None if unsafe

**Example**:
```python
safe_path = validate_safe_path("/app/data", "/app/data/file.txt")
# Returns: "/app/data/file.txt"

safe_path = validate_safe_path("/app/data", "/etc/passwd")
# Returns: None
```

### URL & Data Validation

#### URL Validation
**Function**: `validate_url(url: str) -> bool`

**Validation Rules**:
- Must use http or https scheme
- Must have hostname
- Max length: 2048 characters

#### JSON Size Validation
**Function**: `validate_json_size(data: bytes, max_size_mb: int = 10) -> bool`

**Purpose**: Prevent DoS attacks via large payloads

**Default**: 10MB limit

## Current Implementation Status

### Backend Validation

#### ✅ Already Implemented (archer/auth/password.py)
- **Password validation**:
  - Length: 8-40 characters
  - Must contain: letter, number, special character
  - Allowed special chars: `!@£$%^&()-_+=[]{}:|<>?`

#### ✅ Available (archer/security/validation.py)
- Email validation with normalization
- Full name sanitization
- API key validation
- General text input sanitization
- Filename/path sanitization
- URL validation

#### 🔄 Integration Needed
The validation functions exist but need to be integrated into all authentication endpoints in `archer/app.py`:

**Endpoints to Update**:
1. `POST /api/auth/login` - Use `validate_email()`
2. `POST /api/profile` - Use `sanitize_full_name()`
3. `POST /api/profile/apikeys` - Use `sanitize_api_key()` for each key
4. `POST /api/auth/request-reset` - Use `validate_email()`
5. Admin user creation (`create_admin.py`) - Use `validate_email()` and `sanitize_full_name()`

### Frontend Validation

#### ✅ Already Implemented
- Password field validation in login form
- Basic email format validation (HTML5 `type="email"`)

#### 📋 Recommended Additions
1. **Email field validation** (login.html, reset forms):
   ```javascript
   function validateEmail(email) {
       const re = /^[a-z0-9][a-z0-9._+-]*@[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/;
       return re.test(String(email).toLowerCase());
   }
   ```

2. **Full name validation** (profile.html):
   ```javascript
   function validateFullName(name) {
       if (name.length < 1 || name.length > 100) return false;
       const re = /^[a-zA-ZÀ-ÿ\s.'\-]+$/;
       return re.test(name);
   }
   ```

3. **API key validation** (profile.html):
   ```javascript
   function validateApiKey(key) {
       if (!key) return true; // Empty is OK
       if (key.length < 10 || key.length > 500) return false;
       const re = /^[a-zA-Z0-9_\-\.=+/]+$/;
       return re.test(key);
   }
   ```

## Security Best Practices

### Defense in Depth
1. **Client-side validation**: Immediate feedback to users
2. **Server-side validation**: Security enforcement (never trust client)
3. **Database constraints**: Last line of defense

### Normalization Before Validation
Always normalize input before validation:
1. Trim whitespace
2. Convert case (if applicable)
3. Collapse multiple spaces
4. Remove control characters

### Error Messages
- ✅ **Do**: "Invalid email format"
- ❌ **Don't**: "Email 'user@<script>' contains script tags"
- Avoid revealing system internals in error messages
- Don't expose whether user exists (e.g., password reset)

### Logging
```python
# Good
logger.warning(f"Invalid login attempt for email")

# Bad - don't log sensitive data
logger.warning(f"Invalid login attempt: {email} / {password}")
```

## Integration Examples

### Example 1: Login Endpoint
```python
from archer.security import validate_email

@app.post("/api/auth/login")
async def login(request: Request):
    data = await request.json()
    email = data.get("email", "")

    # Validate and normalize email
    is_valid, result = validate_email(email)
    if not is_valid:
        return {"success": False, "error": result}

    email = result  # Use normalized email
    # ... rest of login logic
```

### Example 2: Profile Update
```python
from archer.security import sanitize_full_name

@app.post("/api/profile")
async def update_profile(request: Request):
    data = await request.json()
    full_name = data.get("full_name", "")

    # Validate and sanitize
    is_valid, result = sanitize_full_name(full_name)
    if not is_valid:
        return {"success": False, "error": result}

    full_name = result  # Use sanitized name
    # ... update database
```

### Example 3: API Keys
```python
from archer.security import sanitize_api_key

@app.post("/api/profile/apikeys")
async def save_api_keys(request: Request):
    data = await request.json()

    keys_to_validate = {
        "splunk": "Splunk API Key",
        "openai": "OpenAI API Key",
        # ... etc
    }

    for field, display_name in keys_to_validate.items():
        key_value = data.get(field, "")
        is_valid, result = sanitize_api_key(key_value, display_name)
        if not is_valid:
            return {"success": False, "error": result}
        data[field] = result  # Use sanitized value

    # ... save to database
```

## Testing Validation

### Test Cases

#### Email Validation
```python
# Valid
validate_email("user@example.com")         # (True, "user@example.com")
validate_email("  USER@TEST.COM  ")        # (True, "user@test.com")
validate_email("test@test.co")             # (True, "test@test.co")

# Invalid
validate_email("not-an-email")             # (False, "Email must contain @ symbol")
validate_email("user@")                    # (False, "Invalid email format")
validate_email("user@test")                # (False, "Invalid email format")
validate_email("<script>@test.com")        # (False, "Email contains invalid characters")
validate_email("a" * 50 + "@test.com")     # (False, "Email is too long (maximum 64 characters)")
```

#### Full Name Validation
```python
# Valid
sanitize_full_name("John Doe")             # (True, "John Doe")
sanitize_full_name("Mary-Jane Smith")      # (True, "Mary-Jane Smith")
sanitize_full_name("Jean-Paul")            # (True, "Jean-Paul")
sanitize_full_name("A" * 64)               # (True, "AAA...") - Exactly 64 chars

# Invalid
sanitize_full_name("Mary O'Connor")        # (False, "Full name can only contain letters, hyphens, and spaces")
sanitize_full_name("John123")              # (False, "Full name can only contain letters, hyphens, and spaces")
sanitize_full_name("Test.User")            # (False, "Full name can only contain letters, hyphens, and spaces")
sanitize_full_name("A" * 65)               # (False, "Full name is too long (maximum 64 characters)")
```

#### API Key Validation
```python
# Valid
sanitize_api_key("sk-1234567890abcdef")   # (True, "sk-1234567890abcdef")
sanitize_api_key("")                      # (True, "")
sanitize_api_key("  ")                    # (True, "")

# Invalid
sanitize_api_key("short")                 # (False, "API key is too short (minimum 10 characters)")
sanitize_api_key("test")                  # (False, "API key appears to be a placeholder value")
sanitize_api_key("key<>with<>brackets")   # (False, "API key contains invalid characters")
```

## Summary

### What's Protected

| Input Type | Validation | Normalization | XSS Protection | Injection Protection |
|------------|-----------|---------------|----------------|---------------------|
| Email | ✅ | ✅ | ✅ | ✅ |
| Full Name | ✅ | ✅ | ✅ | ✅ |
| Password | ✅ | ❌ | N/A | ✅ |
| API Keys | ✅ | ✅ | N/A | ✅ |
| Filenames | ✅ | ✅ | ✅ | ✅ |
| Paths | ✅ | ✅ | ✅ | ✅ |
| URLs | ✅ | ❌ | N/A | ✅ |

### Next Steps

1. ✅ Create validation functions
2. 🔄 Integrate into authentication endpoints
3. 📋 Add frontend validation
4. 📋 Add integration tests
5. 📋 Security audit
