/**
 * Common JavaScript utilities for Archer
 */

/**
 * Initialize password toggle functionality for all password fields on the page
 * Wraps password inputs with a toggle button to show/hide password
 */
function initPasswordToggles() {
  // Find all password inputs that aren't already wrapped
  const passwordInputs = document.querySelectorAll('input[type="password"]:not(.password-toggle-initialized)');

  passwordInputs.forEach(input => {
    // Mark as initialized to prevent double-wrapping
    input.classList.add('password-toggle-initialized');

    // Create wrapper if not already wrapped
    if (!input.parentElement.classList.contains('password-wrapper')) {
      const wrapper = document.createElement('div');
      wrapper.className = 'password-wrapper';

      // Insert wrapper before input
      input.parentNode.insertBefore(wrapper, input);
      wrapper.appendChild(input);

      // Create toggle button
      const toggleBtn = document.createElement('button');
      toggleBtn.type = 'button';
      toggleBtn.className = 'password-toggle';
      toggleBtn.setAttribute('aria-label', 'Toggle password visibility');
      toggleBtn.innerHTML = `
        <svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
          <circle cx="12" cy="12" r="3"></circle>
        </svg>
        <svg class="eye-off-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: none;">
          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
          <line x1="1" y1="1" x2="23" y2="23"></line>
        </svg>
      `;

      // Add click handler
      toggleBtn.addEventListener('click', function(e) {
        e.preventDefault();
        togglePasswordVisibility(input, toggleBtn);
      });

      wrapper.appendChild(toggleBtn);
    }
  });
}

/**
 * Toggle password visibility for a specific input
 */
function togglePasswordVisibility(input, toggleBtn) {
  const eyeIcon = toggleBtn.querySelector('.eye-icon');
  const eyeOffIcon = toggleBtn.querySelector('.eye-off-icon');

  if (input.type === 'password') {
    input.type = 'text';
    eyeIcon.style.display = 'none';
    eyeOffIcon.style.display = 'block';
  } else {
    input.type = 'password';
    eyeIcon.style.display = 'block';
    eyeOffIcon.style.display = 'none';
  }
}

/**
 * Create a password input modal for admin functions
 */
function showPasswordInputModal(title, description, callback) {
  // Create modal overlay
  const modal = document.createElement('div');
  modal.style.cssText = 'display: flex; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); z-index: 10000; align-items: center; justify-content: center;';

  // Create modal content
  modal.innerHTML = `
    <div style="background: var(--bg-secondary, #fff); border-radius: 8px; padding: 32px; max-width: 500px; width: 90%; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
      <h3 style="margin-top: 0; margin-bottom: 8px; color: var(--text-primary, #1a1a1a); font-size: 1.5em;">${title}</h3>
      <p style="color: var(--text-secondary, #666); margin-bottom: 24px;">${description}</p>

      <div style="margin-bottom: 20px;">
        <label style="display: block; margin-bottom: 8px; font-weight: 600; color: var(--text-primary, #1a1a1a);">Password</label>
        <div class="password-wrapper">
          <input type="password" id="modal-password-input" style="width: 100%; padding: 12px; border: 2px solid var(--border-color, #e2e8f0); border-radius: 6px; font-size: 1rem; background: var(--bg-primary, #f7fafc); color: var(--text-primary, #1a1a1a); box-sizing: border-box; padding-right: 45px;">
          <button type="button" class="password-toggle" aria-label="Toggle password visibility">
            <svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
            <svg class="eye-off-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: none;">
              <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
              <line x1="1" y1="1" x2="23" y2="23"></line>
            </svg>
          </button>
        </div>
        <p style="font-size: 0.9em; color: var(--text-secondary, #666); margin-top: 8px; line-height: 1.5;">
          Password must be 16-40 characters and include:<br>
          • At least one letter<br>
          • At least one number<br>
          • At least one special character (!@£$%^&()-_+=[]{}:|<>?)
        </p>
      </div>

      <div style="display: flex; gap: 12px;">
        <button type="button" class="modal-cancel-btn" style="flex: 1; padding: 12px 20px; border: 2px solid var(--border-color, #e2e8f0); border-radius: 6px; background: transparent; color: var(--text-primary, #1a1a1a); font-weight: 600; cursor: pointer; font-size: 1em;">
          Cancel
        </button>
        <button type="button" class="modal-submit-btn" style="flex: 1; padding: 12px 20px; border: 2px solid #C53030; border-radius: 6px; background: #C53030; color: white; font-weight: 600; cursor: pointer; font-size: 1em;">
          Confirm
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  const passwordInput = modal.querySelector('#modal-password-input');
  const toggleBtn = modal.querySelector('.password-toggle');
  const cancelBtn = modal.querySelector('.modal-cancel-btn');
  const submitBtn = modal.querySelector('.modal-submit-btn');

  // Setup password toggle
  toggleBtn.addEventListener('click', function(e) {
    e.preventDefault();
    togglePasswordVisibility(passwordInput, toggleBtn);
  });

  // Focus input
  passwordInput.focus();

  // Handle cancel
  cancelBtn.addEventListener('click', function() {
    document.body.removeChild(modal);
    callback(null);
  });

  // Handle submit
  const handleSubmit = function() {
    const password = passwordInput.value; // Don't trim - passwords can have leading/trailing spaces

    if (!password) {
      alert('Password cannot be empty');
      return;
    }

    if (password.length < 16) {
      alert('Password must be at least 16 characters long');
      return;
    }

    if (password.length > 40) {
      alert('Password is too long (maximum 40 characters)');
      return;
    }

    if (!/[a-zA-Z]/.test(password)) {
      alert('Password must contain at least one letter');
      return;
    }

    if (!/[0-9]/.test(password)) {
      alert('Password must contain at least one number');
      return;
    }

    if (!/[!@£$%^&()\-_+=\[\]{}:|<>?]/.test(password)) {
      alert('Password must contain at least one special character (!@£$%^&()-_+=[]{}:|<>?)');
      return;
    }

    document.body.removeChild(modal);
    callback(password);
  };

  submitBtn.addEventListener('click', handleSubmit);

  // Allow Enter key to submit
  passwordInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSubmit();
    }
  });

  // Close on background click
  modal.addEventListener('click', function(e) {
    if (e.target === modal) {
      document.body.removeChild(modal);
      callback(null);
    }
  });
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
  initPasswordToggles();

  // Re-initialize when new content is added dynamically
  const observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(mutation) {
      if (mutation.addedNodes.length) {
        initPasswordToggles();
      }
    });
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
});

/**
 * Dark Mode Toggle Functionality
 * Initializes dark mode based on localStorage and provides toggle functionality
 */
document.addEventListener('DOMContentLoaded', function() {
  const darkModeToggle = document.getElementById('dark-mode-toggle');

  if (!darkModeToggle) {
    return; // Dark mode toggle not present on this page
  }

  const sunIcon = darkModeToggle.querySelector('.sun-icon');
  const moonIcon = darkModeToggle.querySelector('.moon-icon');
  const html = document.documentElement;

  // Update icon visibility based on theme
  function updateIcons(theme) {
    if (theme === 'dark') {
      sunIcon.style.display = 'none';
      moonIcon.style.display = 'block';
    } else {
      sunIcon.style.display = 'block';
      moonIcon.style.display = 'none';
    }
  }

  // Initialize theme from localStorage, else follow the OS (matching the early
  // bootstrap in base.html). Must agree with that bootstrap, or this would
  // override it back to light for a dark-mode user who hasn't toggled.
  const currentTheme = localStorage.getItem('theme')
    || (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  html.setAttribute('data-theme', currentTheme);
  updateIcons(currentTheme);

  // Toggle dark mode on button click
  darkModeToggle.addEventListener('click', function() {
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';

    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateIcons(newTheme);
  });
});

// Option info tooltips (the "i" beside a home-page option): placed in the viewport when
// shown, so a card that clips its overflow can't cut them off near the page edge
document.addEventListener('mouseover', e => {
  const icon = e.target.closest && e.target.closest('.option-info-icon');
  const tip = icon && icon.querySelector('.option-info-tooltip');
  if (!tip || window.matchMedia('(max-width: 768px)').matches) return;
  const r = icon.getBoundingClientRect();
  tip.style.position = 'fixed';
  tip.style.transform = 'none';
  tip.style.bottom = 'auto';
  const w = tip.offsetWidth, h = tip.offsetHeight, gap = 8;
  const left = Math.min(Math.max(gap, r.left + r.width / 2 - w / 2), window.innerWidth - w - gap);
  const above = r.top - h - gap >= gap;
  tip.style.left = `${left}px`;
  tip.style.top = `${above ? r.top - h - gap : r.bottom + gap}px`;
  tip.style.setProperty('--arrow-x', `${r.left + r.width / 2 - left}px`);
  tip.classList.toggle('is-below', !above);
});

// Keep the scroll position stable when a filter re-renders part of a page, so changing a
// filter updates only the affected area instead of jumping the view to the top. `update` does
// the re-render (sync, or returns a Promise for an async reload); `hold` is the element that
// shrinks/reloads — it's pinned at its current height across the update so the page can't
// collapse and clamp the scroll. Works whichever element actually scrolls (the viewport, or a
// container with its own overflow, as on the app's body).
window.archerPreserveScroll = function (update, hold) {
  const scroller = (function (el) {
    for (; el; el = el.parentElement) {
      const s = getComputedStyle(el);
      if ((s.overflowY === 'auto' || s.overflowY === 'scroll') && el.scrollHeight - el.clientHeight > 1) return el;
    }
    return document.scrollingElement || document.documentElement;
  })(hold || document.body);
  const y = scroller.scrollTop;
  if (hold) hold.style.minHeight = hold.offsetHeight + 'px';
  const restore = () => { if (hold) hold.style.minHeight = ''; scroller.scrollTop = y; };
  let result;
  try { result = update(); } catch (e) { restore(); throw e; }
  if (result && typeof result.then === 'function') return result.then(v => { restore(); return v; }, e => { restore(); throw e; });
  restore();
  return result;
};
