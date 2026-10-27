// Profile Page JavaScript

// Per-tab "On this page" TOC: smooth-scroll to the section without touching tab routing
(function () {
  document.querySelectorAll('.tab-toc a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      const el = document.getElementById(a.getAttribute('href').slice(1));
      if (!el) return;
      e.preventDefault();
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      history.replaceState(null, '', a.getAttribute('href'));
    });
  });
})();

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
  const country = document.getElementById('country')?.value || '';

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
    team: team.trim(),  // Include team field
    country
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
      <button class="timeline-action-btn" disabled title="Coming soon">Run Emulation (coming soon)</button>
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

// SIEM and OSINT keys: one input each. AI keys are the provider rows below.
const API_KEY_FIELDS = ['secops', 'splunk', 'mde', 'elastic', 'shodan', 'securitytrails', 'hibp', 'github'];
const AI_PROVIDERS = [
  { id: 'anthropic', label: 'Anthropic Claude', placeholder: 'sk-ant-...' },
  { id: 'openai', label: 'OpenAI', placeholder: 'sk-...' },
  { id: 'google', label: 'Google Gemini', placeholder: 'AIza...' },
  { id: 'deepseek', label: 'DeepSeek', placeholder: 'sk-...' },
  { id: 'qwen', label: 'Qwen (DashScope)', placeholder: 'sk-...' },
  { id: 'grok', label: 'Grok (xAI)', placeholder: 'xai-...' },
  { id: 'local', label: 'Local model (OpenAI-compatible)', placeholder: 'API key (optional)' },
];
let apiKeysLoaded = false;   // a cleared key is only removed once the saved ones were shown
let savedKeys = {};          // GET /api/profile/apikeys
let aiState = null;          // GET /api/profile/ai-settings
let localModels = [];        // from the last endpoint test

async function saveApiKeys() {
  const apiKeys = { _loaded: apiKeysLoaded };
  API_KEY_FIELDS.forEach(name => {
    const el = document.getElementById(`${name}-key`);
    if (el) apiKeys[name] = el.value;
  });
  if (await postApiKeys(apiKeys)) showNotification('API keys saved', 'success');
}

async function postApiKeys(payload) {
  try {
    const response = await fetch('/api/profile/apikeys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || result.success === false) {
      showNotification(`Failed to save API keys${result.error ? ': ' + result.error : ''}`, 'error');
      return false;
    }
    return true;
  } catch (error) {
    console.error('Error saving API keys:', error);
    showNotification('An error occurred while saving', 'error');
    return false;
  }
}

async function loadApiKeys() {
  try {
    const response = await fetch('/api/profile/apikeys');
    if (response.ok) {
      const data = await response.json();
      if (!data.error) {
        savedKeys = data;
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

// --- Key-type tabs: AI Models | OSINT Sources | SIEM Platforms | Emulation Tools ---

function initKeyTabs() {
  document.querySelectorAll('.key-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.key-tab').forEach(t => {
        const on = t === tab;
        t.classList.toggle('active', on);
        t.setAttribute('aria-selected', on);
      });
      document.querySelectorAll('.key-panel').forEach(panel => {
        panel.hidden = panel.dataset.keypanel !== tab.dataset.keytab;
      });
    });
  });
}

// --- AI providers: one row per provider, + adds another (GitHub #10) ---

async function loadAiSettings() {
  try {
    const response = await fetch('/api/profile/ai-settings');
    if (!response.ok) return;
    aiState = await response.json();
    const local = aiState.settings.local || {};
    if (local.model) localModels = [local.model];
    const rows = AI_PROVIDERS
      .filter(p => p.id === 'local' ? local.endpoint : savedKeys[p.id])
      .map(p => ({ provider: p.id, key: savedKeys[p.id] || '', endpoint: local.endpoint, model: local.model }));
    renderProviderRows(rows.length ? rows : [{ provider: unusedProviders([])[0] }]);
  } catch (error) {
    console.error('Error loading AI settings:', error);
  }
}

function unusedProviders(used) {
  return AI_PROVIDERS.map(p => p.id).filter(id => !used.includes(id));
}

function providerRows() {
  return Array.from(document.querySelectorAll('#ai-provider-rows .ai-provider-row'));
}

function rowValues(row) {
  return {
    provider: row.querySelector('.ai-row-provider').value,
    key: row.querySelector('.ai-row-key').value.trim(),
    endpoint: (row.querySelector('.ai-row-endpoint') || {}).value || '',
    model: (row.querySelector('.ai-row-model') || {}).value || '',
  };
}

function renderProviderRows(rows) {
  const box = document.getElementById('ai-provider-rows');
  box.innerHTML = '';
  rows.forEach(r => box.appendChild(buildProviderRow(r)));
  syncProviderRows();
}

function buildProviderRow(r) {
  const row = document.createElement('div');
  row.className = 'ai-provider-row';
  row.innerHTML = `
    <div class="ai-row-main">
      <select class="form-input ai-row-provider" aria-label="AI provider"></select>
      <div class="apikey-input-group">
        <input type="password" class="form-input apikey-input ai-row-key" aria-label="API key" autocomplete="off">
      </div>
      <button type="button" class="ai-row-btn ai-row-remove" title="Remove this provider" aria-label="Remove this provider">&times;</button>
      <button type="button" class="ai-row-btn ai-row-add" title="Add another provider" aria-label="Add another provider">+</button>
    </div>
    <div class="ai-row-local" hidden>
      <input type="url" class="form-input ai-row-endpoint" placeholder="http://localhost:11434" aria-label="Local server URL">
      <button type="button" class="btn-secondary ai-row-test">Test</button>
      <select class="form-input ai-row-model" aria-label="Local model"></select>
      <div class="apikey-hint ai-row-status"></div>
    </div>`;
  const select = row.querySelector('.ai-row-provider');
  AI_PROVIDERS.forEach(p => select.add(new Option(p.label, p.id, false, p.id === r.provider)));
  row.querySelector('.ai-row-key').value = r.key || '';
  row.querySelector('.ai-row-endpoint').value = r.endpoint || '';
  setRowModels(row, localModels, r.model);

  const keyInput = row.querySelector('.ai-row-key');
  select.addEventListener('change', () => {
    keyInput.value = savedKeys[select.value] || '';
    syncProviderRows();
  });
  keyInput.addEventListener('input', renderAssignment);
  row.querySelector('.ai-row-endpoint').addEventListener('input', renderAssignment);
  row.querySelector('.ai-row-model').addEventListener('change', renderAssignment);
  row.querySelector('.ai-row-test').addEventListener('click', () => probeLocalModel(row));
  row.querySelector('.ai-row-remove').addEventListener('click', () => {
    row.remove();
    if (!providerRows().length) renderProviderRows([{ provider: 'anthropic' }]);
    syncProviderRows();
  });
  row.querySelector('.ai-row-add').addEventListener('click', () => {
    const used = providerRows().map(x => x.querySelector('.ai-row-provider').value);
    const next = unusedProviders(used)[0];
    if (!next) return;
    document.getElementById('ai-provider-rows').appendChild(buildProviderRow({ provider: next }));
    syncProviderRows();
  });
  return row;
}

// One row per provider: each dropdown hides the ones other rows use; + only on the last row
function syncProviderRows() {
  const rows = providerRows();
  const used = rows.map(r => r.querySelector('.ai-row-provider').value);
  rows.forEach((row, i) => {
    const select = row.querySelector('.ai-row-provider');
    Array.from(select.options).forEach(o => { o.disabled = o.value !== select.value && used.includes(o.value); });
    const p = AI_PROVIDERS.find(x => x.id === select.value);
    row.querySelector('.ai-row-key').placeholder = p ? p.placeholder : 'API key';
    row.querySelector('.ai-row-local').hidden = select.value !== 'local';
    row.querySelector('.ai-row-add').style.visibility =
      i === rows.length - 1 && used.length < AI_PROVIDERS.length ? 'visible' : 'hidden';
  });
  renderAssignment();
}

function setRowModels(row, models, selected) {
  const select = row.querySelector('.ai-row-model');
  select.innerHTML = '';
  if (!models.length) {
    select.add(new Option('Test the server to list its models', ''));
    return;
  }
  models.forEach(m => select.add(new Option(m, m, false, m === selected)));
}

async function probeLocalModel(row) {
  const status = row.querySelector('.ai-row-status');
  const endpoint = row.querySelector('.ai-row-endpoint').value.trim();
  if (!endpoint) { status.textContent = 'Enter the server URL first, e.g. http://localhost:11434'; return; }
  status.textContent = 'Testing…';
  status.className = 'apikey-hint ai-row-status';
  try {
    const response = await fetch('/api/profile/ai-settings/probe-local', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ endpoint, api_key: row.querySelector('.ai-row-key').value })
    });
    const result = await response.json();
    if (!result.ok) {
      status.textContent = result.error || 'Not reachable';
      status.className = 'apikey-hint ai-row-status ai-status-error';
      return;
    }
    localModels = result.models;
    setRowModels(row, localModels, row.querySelector('.ai-row-model').value || (aiState && aiState.settings.local.model));
    status.textContent = `Reachable (${result.kind === 'ollama' ? 'Ollama' : 'OpenAI API'}): ${result.models.length} model${result.models.length === 1 ? '' : 's'}`;
    status.className = 'apikey-hint ai-row-status ai-status-ok';
    renderAssignment();
  } catch (error) {
    status.textContent = 'Test failed';
    status.className = 'apikey-hint ai-row-status ai-status-error';
  }
}

// --- Assignment: lists the providers in the rows above, saved or not ---

function rowProviders() {
  return providerRows().map(rowValues)
    .filter(v => v.provider === 'local' ? v.endpoint : v.key)
    .map(v => {
      const p = AI_PROVIDERS.find(x => x.id === v.provider);
      const known = ((aiState && aiState.providers) || []).find(x => x.id === v.provider);
      return {
        id: v.provider,
        label: v.provider === 'local' ? 'Local model' : p.label,
        model: v.provider === 'local' ? v.model : ((known && known.model) || ''),
        detection: v.provider !== 'local',
      };
    });
}

function renderAssignment() {
  if (!aiState) return;
  const settings = aiState.settings;
  const providers = rowProviders();
  ['ask', 'detection'].forEach(job => {
    const select = document.getElementById(`assign-${job}-provider`);
    const modelInput = document.getElementById(`assign-${job}-model`);
    // Keep what's on screen across re-renders; fall back to the saved assignment
    const current = select.dataset.touched ? select.value : (settings[job] || {}).provider;
    select.innerHTML = '';
    select.add(new Option(job === 'ask' ? 'Not assigned (first available)' : 'None (no AI)', ''));
    providers.forEach(p => {
      const opt = new Option(p.label, p.id, false, p.id === current);
      if (job === 'detection' && !p.detection) {
        opt.disabled = true;
        opt.textContent = `${p.label} (Ask only, #9)`;
      }
      select.add(opt);
    });
    if (!select.dataset.touched) modelInput.value = (settings[job] || {}).model || '';
    syncModelHints(job);
    select.onchange = () => { select.dataset.touched = '1'; modelInput.value = ''; syncModelHints(job); };
  });
  document.getElementById('assign-max-calls').value = settings.max_detection_calls || 25;
  const remember = settings.remember;
  const label = document.getElementById('assign-remember');
  const forget = document.getElementById('assign-forget');
  if (!remember) {
    label.textContent = 'Asks on every hunt';
    forget.hidden = true;
  } else {
    const p = AI_PROVIDERS.find(x => x.id === remember.provider);
    label.textContent = remember.provider ? `Always uses ${p ? p.label : remember.provider}${remember.model ? ' / ' + remember.model : ''}` : 'Always runs without AI';
    forget.hidden = false;
  }
}

function syncModelHints(job) {
  const pid = document.getElementById(`assign-${job}-provider`).value;
  const p = rowProviders().find(x => x.id === pid);
  const input = document.getElementById(`assign-${job}-model`);
  const list = document.getElementById(`assign-${job}-models`);
  input.disabled = !pid;
  input.placeholder = p && p.model ? `Default: ${p.model}` : 'Model (blank = provider default)';
  list.innerHTML = '';
  if (pid === 'local') localModels.forEach(m => list.appendChild(new Option(m)));
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
  return true;
}

// One Save for the tab: keys first (the assignment is validated against them), then the
// local endpoint and the assignment. Two buttons let an assignment go unsaved.
async function saveAiTab() {
  const rows = providerRows().map(rowValues);
  const keys = { _loaded: apiKeysLoaded };
  AI_PROVIDERS.forEach(p => {
    const row = rows.find(r => r.provider === p.id);
    keys[p.id] = row ? row.key : '';   // a removed row removes its key
  });
  if (!(await postApiKeys(keys))) return;
  const local = rows.find(r => r.provider === 'local');
  const update = {
    local: { endpoint: local ? local.endpoint : '', model: local ? local.model : '' },
    max_detection_calls: Number(document.getElementById('assign-max-calls').value),
  };
  ['ask', 'detection'].forEach(job => {
    const provider = document.getElementById(`assign-${job}-provider`).value;
    update[job] = provider ? { provider, model: document.getElementById(`assign-${job}-model`).value } : null;
  });
  if (await postAiSettings(update)) {
    savedKeys = Object.fromEntries(rows.filter(r => r.key).map(r => [r.provider, r.key]));
    document.querySelectorAll('#ai-assignment select').forEach(s => delete s.dataset.touched);
    renderAssignment();
    showNotification('AI settings saved', 'success');
  }
}

async function forgetHuntChoice() {
  if (await postAiSettings({ remember: null })) {
    renderAssignment();
    showNotification('The Hunt page will ask again', 'success');
  }
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

  initKeyTabs();

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

// API tokens (security tab): create (shown once), list, revoke
(function () {
  const form = document.getElementById('api-token-form');
  if (!form) return;
  const rows = document.getElementById('api-token-rows');
  const table = document.getElementById('api-token-table');
  const message = document.getElementById('api-token-message');
  const fresh = document.getElementById('api-token-new');
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const when = iso => iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'never';

  async function load() {
    const res = await fetch('/api/profile/tokens');
    const data = await res.json().catch(() => ({}));
    const tokens = data.tokens || [];
    table.hidden = !tokens.length;
    if (!tokens.length && !message.textContent) message.textContent = 'No tokens yet.';
    rows.innerHTML = tokens.map(t => `<tr><td>${esc(t.name)}</td><td><code>${esc(t.prefix)}…</code></td>`
      + `<td>${when(t.created)}</td><td>${when(t.last_used)}</td>`
      + `<td><button type="button" data-id="${t.id}">Revoke</button></td></tr>`).join('');
    rows.querySelectorAll('button').forEach(b => b.addEventListener('click', async () => {
      // Two clicks, no dialog: the first arms the button
      if (b.dataset.armed !== '1') { b.dataset.armed = '1'; b.textContent = 'Confirm revoke'; return; }
      b.disabled = true;
      const r = await fetch(`/api/profile/tokens/${b.dataset.id}`, { method: 'DELETE' });
      message.textContent = r.ok ? 'Token revoked: anything using it is signed out.' : 'Could not revoke the token.';
      if (r.ok) { fresh.hidden = true; document.getElementById('api-token-value').textContent = ''; }
      load();
    }));
  }

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const name = document.getElementById('api-token-name').value.trim();
    const res = await fetch('/api/profile/tokens', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { message.textContent = data.error || `HTTP ${res.status}`; return; }
    document.getElementById('api-token-value').textContent = data.token;
    fresh.hidden = false;
    message.textContent = '';
    form.reset();
    load();
  });

  document.getElementById('api-token-copy').addEventListener('click', () => {
    navigator.clipboard.writeText(document.getElementById('api-token-value').textContent)
      .then(() => { message.textContent = 'Copied.'; }, () => { message.textContent = 'Select the token and copy it.'; });
  });

  load();
})();


// Threat Feed industries (Profile tab)
(function () {
  const grid = document.getElementById('industries-grid');
  if (!grid) return;
  const status = document.getElementById('industries-status');
  fetch('/api/profile/industries').then(r => r.json()).then(data => {
    const chosen = new Set(data.industries || []);
    grid.innerHTML = (data.choices || []).map(c => `<label class="industry-option"><input type="checkbox" value="${c.id.replace(/"/g, '&quot;')}"${chosen.has(c.id) ? ' checked' : ''}> <span>${c.label.replace(/</g, '&lt;')}</span></label>`).join('');
  });
  document.getElementById('industries-save').addEventListener('click', async () => {
    const industries = Array.from(grid.querySelectorAll('input:checked')).map(i => i.value);
    const res = await fetch('/api/profile/industries', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ industries }),
    });
    const data = await res.json().catch(() => ({}));
    status.textContent = res.ok ? `Saved: ${industries.length ? industries.length + ' industr' + (industries.length === 1 ? 'y' : 'ies') : 'none'}` : (data.error || 'Not saved');
    status.className = 'industries-status ' + (res.ok ? 'is-ok' : 'is-error');
  });
})();


// Technology stack (Profile tab): products by category, and the ATT&CK platforms they bring
(function () {
  const grid = document.getElementById('tech-stack-grid');
  if (!grid) return;
  const status = document.getElementById('tech-stack-status');
  const platformsLine = document.getElementById('tech-stack-platforms');
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
  // Fixed 4:4:4 layout. Each row's four categories are of similar size so columns stay even.
  const TS_ROWS = [
    ['OS & virtualisation', 'Servers & databases', 'Firewalls & network', 'VPN & edge access'],
    ['Productivity & email', 'Cloud & containers', 'Development & CI/CD', 'Identity & access'],
    ['Collaboration & SaaS', 'Backup & security', 'Remote mgmt & endpoints', 'Apps & file transfer'],
  ];
  const TS_LABEL = {}; // catalogue names are already concise; legend falls back to the category name
  let choices = [];
  const showPlatforms = () => {
    const ticked = new Set(Array.from(grid.querySelectorAll('input:checked')).map(i => i.value));
    const platforms = [...new Set(choices.filter(c => ticked.has(c.id)).flatMap(c => c.platforms))].sort();
    platformsLine.textContent = ticked.size
      ? `ATT&CK platforms covered: ${platforms.join(', ') || 'none'}` + (platforms.some(p => ['Windows', 'Linux', 'macOS'].includes(p)) ? '' : '. No operating system is ticked, so endpoint techniques will be left out.')
      : 'Nothing ticked: every technique and procedure applies.';
  };
  const grpHtml = (cat, chosen) => {
    const items = choices.filter(c => c.category === cat);
    if (!items.length) return '';
    return `<fieldset class="tech-stack-group"><legend>${esc(TS_LABEL[cat] || cat)}</legend>` + items.map(c =>
      `<label class="industry-option" title="ATT&CK platforms: ${esc(c.platforms.join(', '))}"><input type="checkbox" value="${esc(c.id)}"${chosen.has(c.id) ? ' checked' : ''}> <span>${esc(c.label)}</span></label>`).join('') + '</fieldset>';
  };
  fetch('/api/profile/stack').then(r => r.json()).then(data => {
    const chosen = new Set(data.stack || []);
    choices = data.choices || [];
    const known = new Set(TS_ROWS.flat());
    const extra = (data.categories || []).filter(c => !known.has(c)); // anything not placed (e.g. 'Other')
    const rows = TS_ROWS.map(r => r.slice());
    if (extra.length) rows[rows.length - 1] = rows[rows.length - 1].concat(extra);
    grid.innerHTML = rows.map((row, i) => {
      const cells = row.map(cat => grpHtml(cat, chosen)).join('');
      return `<div class="ts-row ts-row-${row.length}">${cells}</div>`;
    }).join('');
    showPlatforms();
  });
  grid.addEventListener('change', showPlatforms);
  const setAll = on => {
    grid.querySelectorAll('.industry-option:not([hidden]) input[type="checkbox"]').forEach(i => {
      if (!i.closest('.tech-stack-group').hidden) i.checked = on;
    });
    showPlatforms();
  };
  document.getElementById('tech-stack-select-all')?.addEventListener('click', () => setAll(true));
  document.getElementById('tech-stack-clear-all')?.addEventListener('click', () => setAll(false));
  document.getElementById('tech-stack-filter').addEventListener('input', e => {
    const q = e.target.value.trim().toLowerCase();
    grid.querySelectorAll('.tech-stack-group').forEach(g => {
      let any = false;
      g.querySelectorAll('.industry-option').forEach(l => {
        const hit = !q || l.textContent.toLowerCase().includes(q);
        l.hidden = !hit;
        any = any || hit;
      });
      g.hidden = !any;
    });
    grid.querySelectorAll('.ts-row').forEach(r => {
      r.hidden = !r.querySelector('.tech-stack-group:not([hidden])');
    });
  });
  document.getElementById('tech-stack-save').addEventListener('click', async () => {
    const stack = Array.from(grid.querySelectorAll('input:checked')).map(i => i.value);
    const res = await fetch('/api/profile/stack', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ stack }),
    });
    const data = await res.json().catch(() => ({}));
    status.textContent = res.ok ? (stack.length ? `Saved: ${stack.length} product${stack.length === 1 ? '' : 's'}` : 'Saved: everything applies') : (data.error || 'Not saved');
    status.className = 'industries-status ' + (res.ok ? 'is-ok' : 'is-error');
  });
})();


// SIEM platforms every hunt generates for (Profile tab)
(function () {
  const grid = document.getElementById('siems-grid');
  if (!grid) return;
  const status = document.getElementById('siems-status');
  fetch('/api/profile/siems').then(r => r.json()).then(data => {
    const chosen = new Set(data.siems || []);
    const logo = c => `<img class="siem-logo siem-pick-logo" src="/static/images/siem/${c.id}.png" alt="">`;
    grid.innerHTML = (data.choices || []).map(c => c.soon
      ? `<label class="industry-option is-soon" title="Archer doesn't generate ${c.label.replace(/</g, '&lt;')} queries yet"><input type="checkbox" disabled> ${logo(c)}<span>${c.label.replace(/</g, '&lt;')}</span><span class="siem-soon">Coming soon</span></label>`
      : `<label class="industry-option"><input type="checkbox" value="${c.id}"${chosen.has(c.id) ? ' checked' : ''}> ${logo(c)}<span>${c.label.replace(/</g, '&lt;')}</span></label>`).join('');
  });
  document.getElementById('siems-save').addEventListener('click', async () => {
    const siems = Array.from(grid.querySelectorAll('input:checked')).map(i => i.value);
    const res = await fetch('/api/profile/siems', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ siems }),
    });
    const data = await res.json().catch(() => ({}));
    status.textContent = res.ok ? (siems.length ? 'Saved: hunts generate for ' + grid.querySelectorAll('input:checked + span').length + ' platform' + (siems.length === 1 ? '' : 's') : 'Saved: hunts generate for all platforms') : (data.error || 'Not saved');
    status.className = 'industries-status ' + (res.ok ? 'is-ok' : 'is-error');
  });
})();

// Country (Profile tab): a searchable list with each country's flag. Native options can't
// hold images, so the <select> stays (hidden) as the value the form saves, and this drives it
(function () {
  const select = document.getElementById('country'), box = select?.closest('.pf-country');
  if (!select || !box) return;
  const options = [...select.options].map(o => ({ value: o.value, name: o.textContent.trim(), flag: o.dataset.flag || '' }));
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const flagImg = url => url ? `<img class="pf-flag" src="${esc(url)}" alt="" width="20" height="15">` : '<span class="pf-flag is-none"></span>';

  box.classList.add('is-enhanced');
  box.insertAdjacentHTML('beforeend', `
    <button type="button" class="form-input pf-country-btn" id="country-btn" aria-haspopup="listbox" aria-expanded="false"></button>
    <div class="pf-country-pop" id="country-pop" hidden>
      <input type="search" class="pf-country-search" id="country-search" placeholder="Search countries" aria-label="Search countries" autocomplete="off">
      <ul class="pf-country-list" id="country-list" role="listbox" aria-label="Country"></ul>
    </div>`);
  const btn = document.getElementById('country-btn'), pop = document.getElementById('country-pop');
  const search = document.getElementById('country-search'), list = document.getElementById('country-list');
  let shown = [], active = 0;

  function label() {
    const o = options.find(o => o.value === select.value) || options[0];
    btn.innerHTML = `${flagImg(o.flag)}<span>${esc(o.name)}</span><svg class="pf-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>`;
  }
  function render() {
    const q = search.value.trim().toLowerCase();
    shown = options.filter(o => !q || o.name.toLowerCase().includes(q));
    active = Math.max(0, Math.min(active, shown.length - 1));
    list.innerHTML = shown.length ? shown.map((o, i) => `<li role="option" id="country-opt-${i}" data-i="${i}"
        aria-selected="${o.value === select.value}" class="${i === active ? 'is-active' : ''}">${flagImg(o.flag)}${esc(o.name)}</li>`).join('')
      : '<li class="pf-country-none">No country matches</li>';
    list.querySelector('.is-active')?.scrollIntoView({ block: 'nearest' });
  }
  function open() {
    pop.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    search.value = '';
    active = Math.max(0, options.findIndex(o => o.value === select.value));
    render();
    search.focus();
  }
  function close(focusBtn = true) {
    pop.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
    if (focusBtn) btn.focus();
  }
  function choose(i) {
    const o = shown[i];
    if (!o) return;
    select.value = o.value;
    select.dispatchEvent(new Event('change', { bubbles: true }));
    label();
    close();
  }

  btn.addEventListener('click', () => (pop.hidden ? open() : close()));
  search.addEventListener('input', () => { active = 0; render(); });
  search.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') { active = Math.min(active + 1, shown.length - 1); render(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { active = Math.max(active - 1, 0); render(); e.preventDefault(); }
    else if (e.key === 'Enter') { choose(active); e.preventDefault(); }
    else if (e.key === 'Escape') { close(); e.preventDefault(); }
  });
  list.addEventListener('mousedown', e => { const li = e.target.closest('[data-i]'); if (li) { e.preventDefault(); choose(+li.dataset.i); } });
  document.addEventListener('mousedown', e => { if (!pop.hidden && !box.contains(e.target)) close(false); });
  label();
})();
