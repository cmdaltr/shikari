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

## Future Enhancements (TODOs in Code)

### Authentication System
- User registration and login
- Session management
- Password hashing and security
- OAuth integration options

### Database Integration
- User model with profile fields
- Activity tracking
- Secure API key storage (encrypted)
- Timeline history

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
- File type validation for profile pictures
- File size limits
- Sanitized file names
- Password masking for API keys

### TODO:
- Implement authentication middleware
- Encrypt API keys at rest
- Add CSRF protection
- Implement rate limiting
- Add input sanitization
- Secure session management
- API key encryption in database
- User role permissions

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

## Notes

All TODO comments in the code indicate where authentication checks and database integration should be added. The current implementation provides a fully functional UI with mock backend endpoints ready for production authentication and database systems.
