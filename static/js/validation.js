/**
 * Input Validation Functions for Shikari
 *
 * Client-side validation matching backend validation rules.
 * All functions return {valid: boolean, error: string}
 */

/**
 * Validate email address
 * Requirements:
 * - MUST contain @ symbol
 * - Maximum 64 characters
 * - Valid email format
 */
function validateEmail(email) {
    if (!email || typeof email !== 'string') {
        return { valid: false, error: 'Email is required' };
    }

    // Normalize
    email = email.trim().toLowerCase();

    // MUST have @ symbol
    if (!email.includes('@')) {
        return { valid: false, error: 'Email must contain @ symbol' };
    }

    // Check length - MUST be limited to 64 characters
    if (email.length > 64) {
        return { valid: false, error: 'Email is too long (maximum 64 characters)' };
    }

    if (email.length < 3) {
        return { valid: false, error: 'Email is too short' };
    }

    // Basic email format validation
    const emailPattern = /^[a-z0-9][a-z0-9._+-]*@[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/;
    if (!emailPattern.test(email)) {
        return { valid: false, error: 'Invalid email format' };
    }

    // Prevent consecutive dots
    if (email.includes('..')) {
        return { valid: false, error: 'Invalid email format' };
    }

    // Check for dangerous patterns
    const dangerousChars = ['<', '>', '(', ')', '[', ']', '\\', ',', ';', ':', '"', '\n', '\r'];
    for (const char of dangerousChars) {
        if (email.includes(char)) {
            return { valid: false, error: 'Email contains invalid characters' };
        }
    }

    return { valid: true, error: '', value: email };
}

/**
 * Validate full name
 * Requirements:
 * - ONLY uppercase and lowercase letters (a-z, A-Z)
 * - Hyphens (-)
 * - Spaces
 * - Maximum 64 characters
 */
function validateFullName(fullName) {
    if (!fullName || typeof fullName !== 'string') {
        return { valid: false, error: 'Full name is required' };
    }

    // Normalize: trim and collapse multiple spaces
    fullName = fullName.trim().replace(/\s+/g, ' ');

    // Check length
    if (fullName.length < 1) {
        return { valid: false, error: 'Full name is required' };
    }

    // MUST be limited to 64 characters
    if (fullName.length > 64) {
        return { valid: false, error: 'Full name is too long (maximum 64 characters)' };
    }

    // ONLY allow uppercase/lowercase letters, hyphens, and spaces
    const allowedPattern = /^[a-zA-Z\s\-]+$/;
    if (!allowedPattern.test(fullName)) {
        return { valid: false, error: 'Full name can only contain letters, hyphens, and spaces' };
    }

    return { valid: true, error: '', value: fullName };
}

/**
 * Validate password
 * Requirements:
 * - 8-40 characters
 * - At least one letter
 * - At least one number
 * - At least one special character from: !@£$%^&()-_+=[]{}:|<>?
 */
function validatePassword(password) {
    if (!password || typeof password !== 'string') {
        return { valid: false, error: 'Password is required' };
    }

    // Check length
    if (password.length < 16) {
        return { valid: false, error: 'Password must be at least 16 characters' };
    }

    if (password.length > 40) {
        return { valid: false, error: 'Password is too long (maximum 40 characters)' };
    }

    // Check for at least one letter
    if (!/[a-zA-Z]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one letter' };
    }

    // Check for at least one number
    if (!/[0-9]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one number' };
    }

    // Check for at least one special character
    const specialChars = /[!@£$%^&()\-_+=\[\]{}:|<>?]/;
    if (!specialChars.test(password)) {
        return { valid: false, error: 'Password must contain at least one special character (!@£$%^&()-_+=[]{}:|<>?)' };
    }

    return { valid: true, error: '' };
}

/**
 * Show inline error message for a form field
 */
function showFieldError(fieldId, errorMessage) {
    const field = document.getElementById(fieldId);
    if (!field) return;

    // Remove any existing error message
    removeFieldError(fieldId);

    // Add error class to field
    field.classList.add('input-error');

    // Create and insert error message
    const errorDiv = document.createElement('div');
    errorDiv.className = 'field-error-message';
    errorDiv.id = `${fieldId}-error`;
    errorDiv.textContent = errorMessage;
    errorDiv.style.color = 'var(--error, #C53030)';
    errorDiv.style.fontSize = '0.875rem';
    errorDiv.style.marginTop = '4px';
    errorDiv.style.display = 'block';

    field.parentNode.insertBefore(errorDiv, field.nextSibling);
}

/**
 * Remove error message from a form field
 */
function removeFieldError(fieldId) {
    const field = document.getElementById(fieldId);
    if (!field) return;

    // Remove error class
    field.classList.remove('input-error');

    // Remove error message element
    const errorDiv = document.getElementById(`${fieldId}-error`);
    if (errorDiv) {
        errorDiv.remove();
    }
}

/**
 * Get password requirements as HTML for display
 */
function getPasswordRequirementsHTML() {
    return `
        <div class="password-requirements" style="margin-top: 8px; font-size: 0.875rem; color: var(--text-secondary);">
            <div style="font-weight: 500; margin-bottom: 4px;">Password requirements:</div>
            <ul style="margin: 0; padding-left: 20px; line-height: 1.6;">
                <li>8-40 characters</li>
                <li>At least one letter</li>
                <li>At least one number</li>
                <li>At least one special character: !@£$%^&()-_+=[]{}:|<>?</li>
            </ul>
        </div>
    `;
}

/**
 * Validate API key
 * Requirements:
 * - 10-500 characters (if not empty)
 * - Alphanumeric and common API key characters only
 */
function validateApiKey(apiKey, keyName = 'API key') {
    // Empty is allowed
    if (!apiKey || apiKey.trim() === '') {
        return { valid: true, error: '', value: '' };
    }

    apiKey = apiKey.trim();

    // Check length
    if (apiKey.length < 10) {
        return { valid: false, error: `${keyName} is too short (minimum 10 characters)` };
    }

    if (apiKey.length > 500) {
        return { valid: false, error: `${keyName} is too long (maximum 500 characters)` };
    }

    // Allow alphanumeric, hyphens, underscores, and common API key characters
    const allowedPattern = /^[a-zA-Z0-9_\-\.=+\/]+$/;
    if (!allowedPattern.test(apiKey)) {
        return { valid: false, error: `${keyName} contains invalid characters` };
    }

    // Prevent placeholder values
    const placeholders = ['test', 'example', 'placeholder', 'your-api-key', 'your_api_key'];
    if (placeholders.includes(apiKey.toLowerCase())) {
        return { valid: false, error: `${keyName} appears to be a placeholder value` };
    }

    return { valid: true, error: '', value: apiKey };
}
