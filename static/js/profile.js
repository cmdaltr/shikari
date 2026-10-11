// Profile Page JavaScript

// Profile Picture Upload
function handleProfilePictureChange(event) {
  const file = event.target.files[0];
  if (file) {
    // Validate file size (max 5MB)
    const maxSize = 5 * 1024 * 1024;
    if (file.size > maxSize) {
      alert('File size must be less than 5MB');
      event.target.value = ''; // Clear the input
      return;
    }

    // Validate file type - ONLY JPG and PNG
    const allowedTypes = ['image/jpeg', 'image/png'];
    if (!allowedTypes.includes(file.type)) {
      alert('Only JPG and PNG images are allowed');
      event.target.value = ''; // Clear the input
      return;
    }

    // Validate file extension
    const fileName = file.name.toLowerCase();
    const validExtensions = ['.jpg', '.jpeg', '.png'];
    const hasValidExtension = validExtensions.some(ext => fileName.endsWith(ext));

    if (!hasValidExtension) {
      alert('Invalid file extension. Only .jpg, .jpeg, and .png files are allowed');
      event.target.value = ''; // Clear the input
      return;
    }

    // Verify magic bytes (file signature) for extra security
    const reader = new FileReader();
    reader.onload = function(e) {
      const arr = new Uint8Array(e.target.result).subarray(0, 8);

      // Check for JPEG magic bytes (FF D8 FF)
      const isJPEG = arr[0] === 0xFF && arr[1] === 0xD8 && arr[2] === 0xFF;

      // Check for PNG magic bytes (89 50 4E 47 0D 0A 1A 0A)
      const isPNG = arr[0] === 0x89 && arr[1] === 0x50 && arr[2] === 0x4E &&
                    arr[3] === 0x47 && arr[4] === 0x0D && arr[5] === 0x0A &&
                    arr[6] === 0x1A && arr[7] === 0x0A;

      if (!isJPEG && !isPNG) {
        alert('Invalid image file. File content does not match a valid JPG or PNG image');
        event.target.value = ''; // Clear the input
        return;
      }

      // All client-side validation passed - preview and upload
      const dataReader = new FileReader();
      dataReader.onload = function(e) {
        document.getElementById('profile-picture-preview').src = e.target.result;

        // Upload to server (server will do additional validation)
        uploadProfilePicture(file);
      };
      dataReader.readAsDataURL(file);
    };
    reader.readAsArrayBuffer(file);
  }
}

async function uploadProfilePicture(file) {
  const formData = new FormData();
  formData.append('profile_picture', file);

  try {
    const response = await fetch('/api/profile/picture', {
      method: 'POST',
      body: formData
    });

    if (response.ok) {
      const data = await response.json();
      showNotification('Profile picture updated successfully', 'success');
    } else {
      showNotification('Failed to upload profile picture', 'error');
    }
  } catch (error) {
    console.error('Error uploading profile picture:', error);
    showNotification('An error occurred while uploading', 'error');
  }
}

// Profile Form Submission
document.getElementById('profile-form')?.addEventListener('submit', async function(e) {
  e.preventDefault();

  const fullNameInput = document.getElementById('full_name');
  const teamInput = document.getElementById('team');
  const fullName = fullNameInput?.value;
  const team = teamInput?.value || '';

  // Validate full name using validation.js
  const validation = validateFullName(fullName);
  if (!validation.valid) {
    showFieldError('full_name', validation.error);
    showNotification(validation.error, 'error');
    return;
  }

  // Clear any existing errors
  removeFieldError('full_name');

  const formData = {
    full_name: validation.value,  // Use the sanitized value
    team: team.trim()  // Include team field
  };

  try {
    const response = await fetch('/api/profile', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formData)
    });

    const data = await response.json();

    if (data.success) {
      showNotification(data.message || 'Profile updated successfully', 'success');
    } else {
      showNotification(data.error || 'Failed to update profile', 'error');
    }
  } catch (error) {
    console.error('Error updating profile:', error);
    showNotification('An error occurred while saving', 'error');
  }
});

// Real-time validation for full name field
const fullNameInput = document.getElementById('full_name');
const fullNameCounter = document.getElementById('fullname-counter');

if (fullNameInput) {
  // Initialize counter with current value length
  if (fullNameCounter) {
    const currentLength = fullNameInput.value.length;
    fullNameCounter.textContent = `${currentLength}/64 characters`;
  }

  // Update character counter as user types
  fullNameInput.addEventListener('input', function() {
    if (fullNameCounter) {
      const length = this.value.length;
      fullNameCounter.textContent = `${length}/64 characters`;

      if (length > 64) {
        fullNameCounter.style.color = 'var(--error, #C53030)';
      } else if (length >= 60) {
        fullNameCounter.style.color = '#ed8936';
      } else {
        fullNameCounter.style.color = 'var(--text-tertiary)';
      }
    }

    removeFieldError('full_name');
  });

  // Validate on blur (when user leaves the field)
  fullNameInput.addEventListener('blur', function() {
    const validation = validateFullName(this.value);
    if (!validation.valid) {
      showFieldError('full_name', validation.error);
    } else {
      removeFieldError('full_name');
    }
  });
}

function resetForm() {
  if (confirm('Are you sure you want to discard your changes?')) {
    document.getElementById('profile-form').reset();
  }
}

// Timeline Filtering
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', function() {
    // Remove active class from all buttons
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));

    // Add active class to clicked button
    this.classList.add('active');

    // Filter timeline items
    const filter = this.dataset.filter;
    filterTimelineItems(filter);
  });
});

function filterTimelineItems(filter) {
  const items = document.querySelectorAll('.timeline-item');

  items.forEach(item => {
    if (filter === 'all' || item.dataset.type === filter) {
      item.style.display = 'flex';
    } else {
      item.style.display = 'none';
    }
  });
}

// Load Timeline Data
async function loadTimelineData() {
  try {
    const response = await fetch('/api/profile/timeline');

    if (response.ok) {
      const data = await response.json();
      renderTimelineItems(data.timeline);
    } else {
      console.error('Failed to load timeline data');
    }
  } catch (error) {
    console.error('Error loading timeline:', error);
  }
}

function renderTimelineItems(items) {
  const container = document.getElementById('timeline-items');

  if (!items || items.length === 0) {
    return; // Keep empty state
  }

  // Clear empty state
  container.innerHTML = '';

  items.forEach(item => {
    const itemEl = createTimelineItem(item);
    container.appendChild(itemEl);
  });
}

function createTimelineItem(item) {
  const div = document.createElement('div');
  div.className = 'timeline-item';
  div.dataset.type = item.type;

  const iconSvg = item.type === 'actor'
    ? '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>'
    : '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>';

  div.innerHTML = `
    <div class="timeline-icon ${item.type}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        ${iconSvg}
      </svg>
    </div>
    <div class="timeline-content">
      <div class="timeline-title">${item.name}</div>
      <div class="timeline-date">${formatDate(item.timestamp)}</div>
    </div>
    <div class="timeline-actions">
      <button class="timeline-action-btn" onclick="downloadResults('${item.id}')">Download</button>
      <button class="timeline-action-btn" disabled>Export to VECTR</button>
      <button class="timeline-action-btn" disabled>Run Emulation</button>
    </div>
  `;

  return div;
}

function formatDate(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

async function downloadResults(id) {
  try {
    const response = await fetch(`/api/download/${id}`);

    if (response.ok) {
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `archer-results-${id}.zip`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      showNotification('Download started', 'success');
    } else {
      showNotification('Failed to download results', 'error');
    }
  } catch (error) {
    console.error('Error downloading results:', error);
    showNotification('An error occurred during download', 'error');
  }
}

// API Keys Management
function toggleApiKeyVisibility(inputId) {
  const input = document.getElementById(inputId);
  const button = input.parentElement.querySelector('.toggle-visibility');

  if (input.type === 'password') {
    input.type = 'text';
    button.innerHTML = `
      <svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
        <line x1="1" y1="1" x2="23" y2="23"/>
      </svg>
    `;
  } else {
    input.type = 'password';
    button.innerHTML = `
      <svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>
    `;
  }
}

const API_KEY_FIELDS = ['splunk', 'mde', 'elastic', 'shodan', 'securitytrails', 'github',
  'openai', 'anthropic', 'google', 'deepseek', 'qwen', 'grok', 'local'];
let apiKeysLoaded = false;   // a cleared field only removes a key once the saved ones were shown
let aiState = null;          // GET /api/profile/ai-settings

async function saveApiKeys() {
  const apiKeys = { _loaded: apiKeysLoaded };
  API_KEY_FIELDS.forEach(name => {
    const el = document.getElementById(`${name}-key`);
    if (el) apiKeys[name] = el.value;
  });

  try {
    const response = await fetch('/api/profile/apikeys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(apiKeys)
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || result.success === false) {
      showNotification(`Failed to save API keys${result.error ? ': ' + result.error : ''}`, 'error');
      return;
    }
    // The local endpoint and model belong to the AI settings, not the key store
    const saved = await postAiSettings({ local: {
      endpoint: document.getElementById('local-endpoint').value,
      model: document.getElementById('local-model').value,
    } });
    if (saved) showNotification('API keys saved', 'success');
  } catch (error) {
    console.error('Error saving API keys:', error);
    showNotification('An error occurred while saving', 'error');
  }
}

async function loadApiKeys() {
  try {
    const response = await fetch('/api/profile/apikeys');
    if (response.ok) {
      const data = await response.json();
      if (!data.error) {
        API_KEY_FIELDS.forEach(name => {
          const el = document.getElementById(`${name}-key`);
          if (el && data[name]) el.value = data[name];
        });
        apiKeysLoaded = true;
      }
    }
  } catch (error) {
    console.error('Error loading API keys:', error);
  }
  await loadAiSettings();
}

// --- AI settings: local model, assignment, remembered Hunt choice (GitHub #10) ---

async function loadAiSettings() {
  try {
    const response = await fetch('/api/profile/ai-settings');
    if (!response.ok) return;
    aiState = await response.json();
    const local = aiState.settings.local || {};
    document.getElementById('local-endpoint').value = local.endpoint || '';
    setLocalModels(local.model ? [local.model] : [], local.model);
    renderAssignment();
  } catch (error) {
    console.error('Error loading AI settings:', error);
  }
}

async function postAiSettings(update) {
  const response = await fetch('/api/profile/ai-settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(update)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.success) {
    showNotification(result.error || 'Failed to save AI settings', 'error');
    return false;
  }
  aiState.settings = result.settings;
  aiState.providers = result.providers;
  renderAssignment();
  return true;
}

function setLocalModels(models, selected) {
  const select = document.getElementById('local-model');
  select.innerHTML = '';
  if (!models.length) {
    select.add(new Option('Test the endpoint to list its models', ''));
    return;
  }
  models.forEach(m => select.add(new Option(m, m, false, m === selected)));
}

async function probeLocalModel() {
  const status = document.getElementById('local-status');
  const endpoint = document.getElementById('local-endpoint').value.trim();
  if (!endpoint) { status.textContent = 'Enter the server URL first, e.g. http://localhost:11434'; return; }
  status.textContent = 'Testing…';
  status.className = 'apikey-hint';
  try {
    const response = await fetch('/api/profile/ai-settings/probe-local', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ endpoint, api_key: document.getElementById('local-key').value })
    });
    const result = await response.json();
    if (!result.ok) {
      status.textContent = result.error || 'Not reachable';
      status.className = 'apikey-hint ai-status-error';
      return;
    }
    const current = document.getElementById('local-model').value || (aiState && aiState.settings.local.model);
    setLocalModels(result.models, current);
    status.textContent = `Reachable (${result.kind === 'ollama' ? 'Ollama' : 'OpenAI API'}): ${result.models.length} model${result.models.length === 1 ? '' : 's'}. Save API Keys to keep it.`;
    status.className = 'apikey-hint ai-status-ok';
  } catch (error) {
    status.textContent = 'Test failed';
    status.className = 'apikey-hint ai-status-error';
  }
}

function renderAssignment() {
  if (!aiState) return;
  const { settings, providers } = aiState;
  ['ask', 'detection'].forEach(job => {
    const select = document.getElementById(`assign-${job}-provider`);
    const modelInput = document.getElementById(`assign-${job}-model`);
    const assigned = settings[job] || {};
    select.innerHTML = '';
    select.add(new Option(job === 'ask' ? 'Not assigned (first available)' : 'None (no AI)', ''));
    providers.forEach(p => {
      const opt = new Option(p.label, p.id, false, p.id === assigned.provider);
      if (job === 'detection' && !p.detection) {
        opt.disabled = true;
        opt.textContent = `${p.label} (Ask only, #9)`;
      }
      select.add(opt);
    });
    modelInput.value = assigned.model || '';
    syncModelHints(job);
    select.onchange = () => { modelInput.value = ''; syncModelHints(job); };
  });
  document.getElementById('assign-max-calls').value = settings.max_detection_calls || 25;
  const remember = settings.remember;
  const label = document.getElementById('assign-remember');
  const forget = document.getElementById('assign-forget');
  if (!remember) {
    label.textContent = 'Asks on every hunt';
    forget.hidden = true;
  } else {
    const p = providers.find(x => x.id === remember.provider);
    label.textContent = remember.provider ? `Always uses ${p ? p.label : remember.provider}${remember.model ? ' / ' + remember.model : ''}` : 'Always runs without AI';
    forget.hidden = false;
  }
}

function syncModelHints(job) {
  const pid = document.getElementById(`assign-${job}-provider`).value;
  const p = (aiState.providers || []).find(x => x.id === pid);
  const input = document.getElementById(`assign-${job}-model`);
  const list = document.getElementById(`assign-${job}-models`);
  input.disabled = !pid;
  input.placeholder = p && p.model ? `Default: ${p.model}` : 'Model (blank = provider default)';
  list.innerHTML = '';
  if (pid === 'local') {
    Array.from(document.getElementById('local-model').options).filter(o => o.value)
      .forEach(o => list.appendChild(new Option(o.value)));
  }
}

async function saveAiAssignment() {
  const update = { max_detection_calls: Number(document.getElementById('assign-max-calls').value) };
  ['ask', 'detection'].forEach(job => {
    const provider = document.getElementById(`assign-${job}-provider`).value;
    update[job] = provider ? { provider, model: document.getElementById(`assign-${job}-model`).value } : null;
  });
  if (await postAiSettings(update)) showNotification('AI assignment saved', 'success');
}

async function forgetHuntChoice() {
  if (await postAiSettings({ remember: null })) showNotification('The Hunt page will ask again', 'success');
}

// Notification System
function showNotification(message, type = 'info') {
  // Remove existing notification if present
  const existing = document.querySelector('.notification');
  if (existing) {
    existing.remove();
  }

  const notification = document.createElement('div');
  notification.className = `notification notification-${type}`;
  notification.textContent = message;
  notification.style.cssText = `
    position: fixed;
    top: 80px;
    right: 20px;
    padding: 16px 24px;
    background: ${type === 'success' ? '#4caf50' : type === 'error' ? '#f44336' : '#2196f3'};
    color: white;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 10000;
    font-weight: 600;
    animation: slideIn 0.3s ease-out;
  `;

  document.body.appendChild(notification);

  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease-out';
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
  // Load timeline data if on timeline tab
  const timelineTab = document.getElementById('tab-timeline');
  if (timelineTab) {
    // Load on initial page load if timeline tab is active
    if (timelineTab.classList.contains('active')) {
      loadTimelineData();
    }

    // Load when switching to timeline tab
    const timelineButton = document.querySelector('[data-tab="timeline"]');
    if (timelineButton) {
      timelineButton.addEventListener('click', loadTimelineData);
    }
  }

  // Load API keys if on API keys tab
  const apikeysTab = document.getElementById('tab-apikeys');
  if (apikeysTab) {
    // Load on initial page load if API keys tab is active
    if (apikeysTab.classList.contains('active')) {
      loadApiKeys();
    }

    // Load when switching to API keys tab
    const apikeysButton = document.querySelector('[data-tab="apikeys"]');
    if (apikeysButton) {
      apikeysButton.addEventListener('click', loadApiKeys);
    }
  }
});

// Add CSS animation styles
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from {
      transform: translateX(400px);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }

  @keyframes slideOut {
    from {
      transform: translateX(0);
      opacity: 1;
    }
    to {
      transform: translateX(400px);
      opacity: 0;
    }
  }
`;
document.head.appendChild(style);
