# New Features Roadmap

## Overview

This document outlines the implementation plan for three major new features:
1. **CVE Hunting** - Research CVEs, find/generate PoCs, build detection queries
2. **Authentication & Profile System** - User profiles, API key management, activity timeline
3. **Theme Customization** - Color themes and accessibility options

---

## Feature 1: CVE Hunting

### Overview

Allow users to input CVE IDs and automatically:
1. Research the CVE (NVD, MITRE, Exploit-DB)
2. Find existing Proof-of-Concept exploits
3. Generate synthetic PoC if none exists
4. Map to MITRE ATT&CK techniques
5. Extract IOCs from exploit code
6. Generate detection queries (Splunk, MDE)

### Architecture

```
CVE Input (UI)
    ↓
CVE Hunter Module
    ├─→ NVD API (CVE details, CVSS, CWE)
    ├─→ GitHub Search (PoC repositories)
    ├─→ Exploit-DB (known exploits)
    └─→ LLM (synthetic PoC if needed)
    ↓
Technique Mapping (CWE → ATT&CK)
    ↓
IOC Extraction (from PoC code)
    ↓
Query Generation (existing engine)
    ↓
Detection Rules (YAML output)
```

### Implementation Files

**Created:**
- ✅ `archer/intelligence/cve_hunter.py` - Main CVE research module

**Need to Create:**
1. `archer/build/cve_queries.py` - CVE-specific query generation
2. `data/cve_cache/` - Cache directory for CVE research
3. `data/mappings/cve_to_attack.json` - CWE → ATT&CK technique mappings

**Need to Modify:**
1. `templates/index.html` - Add CVE input to Generate tab
2. `archer/app.py` - Add `/generate/cve` endpoint
3. `static/js/index.js` - Handle CVE form submission
4. `static/css/tabs.css` - Style OR separator

### UI Design

**Generate Tab Layout:**

```
┌─────────────────────────────────────────┐
│  Threat Group Name                      │
│  [APT29, Scattered Spider]              │
└─────────────────────────────────────────┘
              OR
┌─────────────────────────────────────────┐
│  CVE Identifier                         │
│  [CVE-2024-1234, CVE-2023-5678]         │
│  💡 Supports multiple CVEs (comma-sep)  │
└─────────────────────────────────────────┘

[Advanced Options ▼]

[Generate Detections]
```

### API Endpoints

```python
# New endpoint
POST /generate/cve
{
    "cve_ids": ["CVE-2024-1234"],
    "run_correlation": true,
    "use_openai": false
}

Response:
{
    "group_name": "CVE_2024_1234_Hunt",
    "redirect_url": "/progress?group_name=CVE_2024_1234_Hunt"
}
```

### Required API Keys (Optional)

- **NVD_API_KEY** - Increases rate limit from 5/30sec to 50/30sec
- **GITHUB_TOKEN** - Better PoC search results
- Both stored in `.env` or Profile page

### Splunk Index/Field Mappings Needed

New schema mappings for vulnerability exploitation detection:

**schemaSplunk.json additions:**

```json
{
    "exploit": {
        "web_logs": "| fields _time src_ip dest_ip url http_method user_agent response_code payload",
        "application_logs": "| fields _time host application error_message stack_trace",
        "waf_logs": "| fields _time src_ip blocked_reason attack_type payload signature_id"
    },
    "vulnerability_scan": {
        "nessus": "| fields _time host plugin_id severity cve vuln_name",
        "qualys": "| fields _time ip_address qid severity cve"
    }
}
```

### Implementation Steps

1. ✅ Create CVE Hunter module with NVD API integration
2. ⬜ Add GitHub PoC search
3. ⬜ Implement synthetic PoC generation (LLM)
4. ⬜ Create CWE → ATT&CK mapping database
5. ⬜ Integrate with existing query generation
6. ⬜ Add UI with OR separator
7. ⬜ Create `/generate/cve` endpoint
8. ⬜ Add CVE-specific detection templates
9. ⬜ Test with real CVEs (Log4Shell, Spring4Shell, ProxyLogon)

---

## Feature 2: Authentication & Profile System

### Overview

Add user authentication with:
- API key storage (Splunk, MDE, OpenAI, NVD, GitHub)
- Activity timeline showing all past generations
- Downloadable history
- User preferences

### Architecture

```
Login/Session Management
    ↓
Profile Page
    ├─→ API Keys Section (encrypted storage)
    ├─→ Activity Timeline (chronological list)
    ├─→ Preferences (theme, default options)
    └─→ Download History
```

### UI Design

**Profile Tab Layout:**

```
┌──────────────────────────────────────────────┐
│ 👤 Profile                                   │
├──────────────────────────────────────────────┤
│                                              │
│  API Keys & Credentials                     │
│  ┌────────────────────────────────────────┐ │
│  │ 🔑 OpenAI API Key                      │ │
│  │ [sk-...hidden...] [Show] [Update]      │ │
│  ├────────────────────────────────────────┤ │
│  │ 📊 Splunk Credentials                  │ │
│  │ [configured] [Update]                  │ │
│  ├────────────────────────────────────────┤ │
│  │ 🛡️ Microsoft Defender                  │ │
│  │ [not configured] [Add]                 │ │
│  ├────────────────────────────────────────┤ │
│  │ 🔍 NVD API Key (CVE Research)          │ │
│  │ [optional] [Add]                       │ │
│  └────────────────────────────────────────┘ │
│                                              │
│  Activity Timeline               [Download] │
│  ┌────────────────────────────────────────┐ │
│  │ 🎯 APT29                  2h ago        │ │
│  │ ├─ 150 detections generated            │ │
│  │ ├─ 12 correlations found               │ │
│  │ └─ [Download Results]                  │ │
│  ├────────────────────────────────────────┤ │
│  │ 🔍 CVE-2024-1234         5h ago        │ │
│  │ ├─ PoC found on GitHub                 │ │
│  │ ├─ 8 detections generated              │ │
│  │ └─ [Download Results]                  │ │
│  ├────────────────────────────────────────┤ │
│  │ 📄 Scattered Spider      1d ago        │ │
│  │ ├─ 45 TTPs extracted                   │ │
│  │ ├─ 200 detections generated            │ │
│  │ └─ [Download Results]                  │ │
│  └────────────────────────────────────────┘ │
│                                              │
│  Preferences                                 │
│  ┌────────────────────────────────────────┐ │
│  │ Theme: [🔴 Red (Default) ▼]            │ │
│  │ Default Correlation: [✓] Enabled       │ │
│  │ Auto-save Results: [✓] Enabled         │ │
│  └────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

### Implementation Files

**Need to Create:**
1. `archer/auth/` - Authentication module
   - `session.py` - Session management
   - `encryption.py` - API key encryption
2. `archer/models/user.py` - User model
3. `archer/models/activity.py` - Activity tracking
4. `templates/profile.html` - Profile page
5. `static/css/profile.css` - Profile styling
6. `static/js/profile.js` - Profile interactions
7. `data/users/` - User data storage (encrypted)
8. `data/activity/` - Activity logs

**Need to Modify:**
1. `archer/app.py` - Add auth middleware, profile routes
2. `templates/base.html` - Add login/logout UI
3. All form submissions - Track activity

### Database Schema

**users.json (encrypted):**
```json
{
    "user_id": "uuid-here",
    "created_at": "2025-01-15T10:00:00Z",
    "api_keys": {
        "openai": "encrypted_key",
        "splunk": {
            "url": "https://splunk.company.com",
            "token": "encrypted_token"
        },
        "mde": {
            "tenant_id": "...",
            "client_id": "...",
            "client_secret": "encrypted_secret"
        },
        "nvd": "encrypted_key",
        "github": "encrypted_token"
    },
    "preferences": {
        "theme": "red",
        "default_correlation": true,
        "auto_save": true
    }
}
```

**activity.json:**
```json
{
    "user_id": "uuid-here",
    "activities": [
        {
            "id": "activity-uuid",
            "timestamp": "2025-01-15T12:00:00Z",
            "type": "threat_group",
            "input": "APT29",
            "results": {
                "detections": 150,
                "correlations": 12,
                "techniques": 45,
                "output_path": "data/generate/APT29_*.yaml"
            },
            "icon": "🎯"
        }
    ]
}
```

### Icons for Activity Types

- 🎯 Threat Group Generation
- 🔍 CVE Hunting
- 📄 File Upload/Extraction
- ⚡ Emulation (future)

### Security Considerations

1. **API Key Encryption**:
   - Use `cryptography` library (Fernet)
   - Store encryption key in environment variable
   - Never log or display full keys

2. **Session Management**:
   - HTTP-only cookies
   - CSRF protection
   - Session timeout

3. **Data Privacy**:
   - Activity logs stored locally
   - No external tracking
   - Optional cloud backup (encrypted)

---

## Feature 3: Theme Customization

### Overview

Allow users to customize the UI appearance:
- **Color Themes**: Red (default), Green, Blue, Purple, Pink
- **Display Modes**: Sepia, Dark, High Contrast
- **Accessibility**: Font size, reduced motion

### UI Design

**Theme Selector (in Profile tab):**

```
Theme Settings
┌────────────────────────────────────────┐
│ Color Theme                            │
│ ○ 🔴 Red (Default)                     │
│ ○ 🟢 Green                             │
│ ○ 🔵 Blue                              │
│ ○ 🟣 Purple                            │
│ ○ 🌸 Pink                              │
│                                        │
│ Display Mode                           │
│ ○ ☀️ Light (Default)                   │
│ ○ 📜 Sepia                             │
│ ○ 🌙 Dark                              │
│ ○ ⚡ High Contrast                     │
│                                        │
│ Accessibility                          │
│ Font Size: [100%] [▼]                 │
│ ☐ Reduce Motion                       │
│ ☐ Increase Contrast                   │
└────────────────────────────────────────┘
```

### Implementation

**CSS Variables Approach:**

```css
/* static/css/themes.css */

:root {
    /* Default Red Theme */
    --primary-color: #C53030;
    --primary-dark: #8B0000;
    --primary-light: #E57373;
    --bg-color: #ffffff;
    --text-color: #333333;
}

[data-theme="green"] {
    --primary-color: #2E7D32;
    --primary-dark: #1B5E20;
    --primary-light: #66BB6A;
}

[data-theme="blue"] {
    --primary-color: #1976D2;
    --primary-dark: #0D47A1;
    --primary-light: #64B5F6;
}

[data-theme="purple"] {
    --primary-color: #7B1FA2;
    --primary-dark: #4A148C;
    --primary-light: #BA68C8;
}

[data-theme="pink"] {
    --primary-color: #C2185B;
    --primary-dark: #880E4F;
    --primary-light: #F06292;
}

[data-mode="dark"] {
    --bg-color: #1a1a1a;
    --text-color: #e0e0e0;
    --bg-secondary: #2d2d2d;
}

[data-mode="sepia"] {
    --bg-color: #f4ecd8;
    --text-color: #5c4a3a;
    --bg-secondary: #e8dcc4;
}

[data-mode="high-contrast"] {
    --bg-color: #000000;
    --text-color: #ffffff;
    --primary-color: #ffff00;
}
```

**JavaScript Theme Switcher:**

```javascript
// static/js/theme.js

function setTheme(color, mode) {
    document.documentElement.setAttribute('data-theme', color);
    document.documentElement.setAttribute('data-mode', mode);

    // Save to localStorage
    localStorage.setItem('archer_theme_color', color);
    localStorage.setItem('archer_theme_mode', mode);
}

function loadTheme() {
    const color = localStorage.getItem('archer_theme_color') || 'red';
    const mode = localStorage.getItem('archer_theme_mode') || 'light';
    setTheme(color, mode);
}

// Load on page load
document.addEventListener('DOMContentLoaded', loadTheme);
```

### Implementation Files

**Need to Create:**
1. `static/css/themes.css` - Theme definitions
2. `static/js/theme.js` - Theme switcher
3. Theme preview component

**Need to Modify:**
1. `templates/base.html` - Load themes.css, theme.js
2. `templates/profile.html` - Add theme selector
3. All CSS files - Use CSS variables instead of hardcoded colors

---

## Implementation Priority

### Phase 1: CVE Hunting (High Priority)
- **Week 1-2**: Core CVE research module
- **Week 2-3**: UI integration and testing
- **Week 3-4**: PoC generation and IOC extraction

### Phase 2: Profile System (Medium Priority)
- **Week 5-6**: Authentication and session management
- **Week 6-7**: API key storage and encryption
- **Week 7-8**: Activity timeline and download

### Phase 3: Theme Customization (Low Priority)
- **Week 9**: CSS variable refactoring
- **Week 10**: Theme switcher implementation
- **Week 11**: Accessibility features

---

## Testing Plan

### CVE Hunting Tests
- Test with known CVEs: CVE-2021-44228 (Log4j), CVE-2022-22965 (Spring4Shell)
- Verify PoC discovery from GitHub
- Test synthetic PoC generation
- Validate detection query accuracy

### Profile System Tests
- API key encryption/decryption
- Session timeout and security
- Activity tracking accuracy
- Download functionality

### Theme Tests
- All themes render correctly
- No visual bugs in dark mode
- High contrast meets WCAG AAA
- Theme persistence across sessions

---

## Dependencies to Add

```bash
# requirements.txt additions

# CVE Hunting
requests>=2.31.0          # API calls
beautifulsoup4>=4.12.0    # Web scraping (Exploit-DB)

# Authentication
cryptography>=41.0.0      # API key encryption
python-jose>=3.3.0        # JWT tokens
passlib>=1.7.4            # Password hashing

# Already have:
# fastapi, uvicorn, jinja2, openai
```

---

## Configuration

### Environment Variables

```bash
# .env additions

# CVE Hunting (optional)
NVD_API_KEY=your-nvd-api-key-here
GITHUB_TOKEN=ghp_your-github-token-here

# Authentication
SECRET_KEY=your-secret-key-for-encryption
SESSION_SECRET=your-session-secret

# Existing
OPENAI_API_KEY=...
```

---

## Questions to Address

1. **Authentication Method**:
   - Simple API key for single user?
   - Or full multi-user auth with login?

2. **CVE PoC Ethics**:
   - Should we limit PoC generation to patched CVEs only?
   - Add disclaimer about responsible use?

3. **Data Storage**:
   - Keep activity logs locally or offer cloud sync?
   - Data retention policy?

4. **Theme Scope**:
   - Start with basic color themes?
   - Add advanced customization later?

---

## Next Steps

To begin implementation:

1. **Review this document** and confirm priorities
2. **Set up API keys** (NVD, GitHub) in `.env`
3. **Start with CVE Hunter module** (already created)
4. **Add schema mappings** for vulnerability/exploit detection
5. **Build UI incrementally** starting with CVE input field

Let me know which feature you'd like to prioritize first!
