# Disabled Features - Coming Soon

## Overview
The Emulate and VECTR features have been disabled and marked as "Coming Soon" to indicate they are under development and will be available in future releases.

## Changes Made

### 1. Emulate Tab - Disabled

**Location**: Main navigation tabs

**Changes**:
- Tab button disabled with visual indicator
- Added "(Coming Soon)" label below tab name
- Tab is greyed out (50% opacity)
- Cursor shows "not-allowed" when hovering
- Cannot be clicked or activated

**Visual Display**:
```
[Emulate]
(Coming Soon)
```

**Inside Tab Content**:
- Large "Coming Soon" message box with icon
- Explanation text: "Adversary emulation capabilities using Atomic Red Team will be available in an upcoming release."
- All form fields disabled and greyed out (40% opacity)
- Form is non-interactive (pointer-events: none)
- Submit button remains disabled

### 2. VECTR Integration - Disabled

**Location**: Generate Tab → Advanced Options → VECTR Integration

**Changes**:
- Section header shows "(Coming Soon)" label
- Entire section greyed out (60% opacity)
- "Export to VECTR" checkbox disabled
- "Campaign Name" input field disabled
- Hint text updated to mention "Available in upcoming release"

**Visual Display**:
```
VECTR Integration (Coming Soon)
  ☐ Export to VECTR
  Hunt tracking and validation - Available in upcoming release

  Campaign Name (Optional)
  [________________________] (disabled)
```

### 3. JavaScript Protection

**Location**: [static/js/tabs.js](static/js/tabs.js:11-15)

Added check to prevent disabled tabs from being activated:
```javascript
button.addEventListener('click', function() {
    // Don't switch tabs if button is disabled
    if (this.disabled || this.hasAttribute('disabled')) {
        return;
    }
    // ... rest of tab switching logic
});
```

## Files Modified

1. **[templates/index.html](templates/index.html)**
   - Lines 50-56: Disabled Emulate tab button with "Coming Soon" label
   - Lines 322-331: Added "Coming Soon" message box in Emulate tab
   - Lines 333-400: Disabled all Emulate form fields
   - Lines 118-132: Disabled VECTR Integration section with label

2. **[static/js/tabs.js](static/js/tabs.js:11-15)**
   - Added disabled tab check to prevent activation

## User Experience

### What Users See:

1. **Emulate Tab**:
   - Greyed out tab button with "(Coming Soon)" text
   - Cannot click or navigate to it
   - If they somehow access it, they see a clear message explaining it's coming soon
   - All controls are visually disabled

2. **VECTR Integration**:
   - Section is visible but clearly marked as unavailable
   - All controls disabled and greyed out
   - Hint text explains it will be available in upcoming release

### What Users Cannot Do:

- ❌ Click on the Emulate tab
- ❌ Submit the emulation form
- ❌ Enable VECTR export
- ❌ Enter VECTR campaign name
- ❌ Accidentally trigger these features

## Benefits

1. **Transparency**: Users know these features exist and are coming
2. **Consistency**: Features remain in UI for familiarity
3. **No Confusion**: Clear "Coming Soon" labeling prevents frustration
4. **Professional**: Shows planned roadmap and development progress
5. **Safe**: No risk of users triggering incomplete features

## Future Activation

To re-enable these features in the future:

### Emulate Tab:
1. Remove `disabled` attribute from tab button (line 50)
2. Remove "(Coming Soon)" label (line 55)
3. Remove "Coming Soon" message box (lines 322-331)
4. Remove `style="opacity: 0.4; pointer-events: none;"` from form (line 333)
5. Remove `disabled` attributes from all form inputs

### VECTR Integration:
1. Remove `style="opacity: 0.6;"` from details section (line 118)
2. Remove "(Coming Soon)" label from summary (line 119)
3. Remove `disabled` attributes from checkbox and input (lines 122, 129)
4. Update hint text to remove "Available in upcoming release"

## Testing

All changes verified:
- ✅ Emulate tab button is disabled
- ✅ Emulate tab has "Coming Soon" label
- ✅ Emulate tab has "Coming Soon" message box
- ✅ Emulate form is visually disabled (opacity + pointer-events)
- ✅ VECTR section has "Coming Soon" label
- ✅ VECTR checkbox is disabled
- ✅ VECTR campaign name input is disabled
- ✅ JavaScript prevents disabled tab activation

## Summary

Both Emulate and VECTR features are now properly disabled with clear "Coming Soon" indicators. The UI remains professional and informative while preventing users from accessing incomplete functionality.
