// Profile Page JavaScript

// Profile Picture Upload
function handleProfilePictureChange(event) {
  const file = event.target.files[0];
  if (file) {
    // Validate file size (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
      alert('File size must be less than 5MB');
      return;
    }

    // Validate file type
    if (!file.type.startsWith('image/')) {
      alert('Please select an image file');
      return;
    }

    const reader = new FileReader();
    reader.onload = function(e) {
      document.getElementById('profile-picture-preview').src = e.target.result;

      // Upload to server
      uploadProfilePicture(file);
    };
    reader.readAsDataURL(file);
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

  const formData = {
    name: document.getElementById('name').value,
    handle: document.getElementById('handle').value,
    timezone: document.getElementById('timezone').value
  };

  try {
    const response = await fetch('/api/profile', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formData)
    });

    if (response.ok) {
      showNotification('Profile updated successfully', 'success');
    } else {
      showNotification('Failed to update profile', 'error');
    }
  } catch (error) {
    console.error('Error updating profile:', error);
    showNotification('An error occurred while saving', 'error');
  }
});

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

async function saveApiKeys() {
  const apiKeys = {
    splunk: document.getElementById('splunk-key').value,
    mde: document.getElementById('mde-key').value,
    elastic: document.getElementById('elastic-key').value,
    openai: document.getElementById('openai-key').value,
    anthropic: document.getElementById('anthropic-key').value
  };

  try {
    const response = await fetch('/api/profile/apikeys', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(apiKeys)
    });

    if (response.ok) {
      showNotification('API keys saved successfully', 'success');
    } else {
      showNotification('Failed to save API keys', 'error');
    }
  } catch (error) {
    console.error('Error saving API keys:', error);
    showNotification('An error occurred while saving', 'error');
  }
}

// Load API keys on page load
async function loadApiKeys() {
  try {
    const response = await fetch('/api/profile/apikeys');

    if (response.ok) {
      const data = await response.json();

      if (data.splunk) document.getElementById('splunk-key').value = data.splunk;
      if (data.mde) document.getElementById('mde-key').value = data.mde;
      if (data.elastic) document.getElementById('elastic-key').value = data.elastic;
      if (data.openai) document.getElementById('openai-key').value = data.openai;
      if (data.anthropic) document.getElementById('anthropic-key').value = data.anthropic;
    }
  } catch (error) {
    console.error('Error loading API keys:', error);
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
