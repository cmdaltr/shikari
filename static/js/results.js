// Results page functionality

// Toggle individual vendor section
function toggleVendor(vendorName) {
  const vendorGroup = document.querySelector(`.vendor-group[data-vendor="${vendorName}"]`);
  if (!vendorGroup) return;

  const isExpanded = vendorGroup.classList.contains('expanded');
  vendorGroup.classList.toggle('expanded');

  // Update expand/collapse all button text if needed
  updateExpandCollapseText();
}

// Toggle all vendors
function toggleAllVendors() {
  const vendorGroups = document.querySelectorAll('.vendor-group');
  const expandCollapseText = document.getElementById('expand-collapse-text');

  // Check if any are collapsed
  const anyCollapsed = Array.from(vendorGroups).some(group => !group.classList.contains('expanded'));

  if (anyCollapsed) {
    // Expand all
    vendorGroups.forEach(group => group.classList.add('expanded'));
    if (expandCollapseText) expandCollapseText.textContent = 'Collapse All';
  } else {
    // Collapse all
    vendorGroups.forEach(group => group.classList.remove('expanded'));
    if (expandCollapseText) expandCollapseText.textContent = 'Expand All';
  }
}

// Update expand/collapse button text based on current state
function updateExpandCollapseText() {
  const vendorGroups = document.querySelectorAll('.vendor-group');
  const expandCollapseText = document.getElementById('expand-collapse-text');
  if (!expandCollapseText) return;

  const anyCollapsed = Array.from(vendorGroups).some(group => !group.classList.contains('expanded'));
  expandCollapseText.textContent = anyCollapsed ? 'Expand All' : 'Collapse All';
}

// Copy detection content to clipboard
function copyDetection(filename) {
  fetch(`/api/detection/${encodeURIComponent(filename)}`)
    .then(response => response.text())
    .then(content => {
      navigator.clipboard.writeText(content).then(() => {
        showNotification('Detection copied to clipboard!', 'success');
      }).catch(err => {
        console.error('Failed to copy:', err);
        showNotification('Failed to copy to clipboard', 'error');
      });
    })
    .catch(err => {
      console.error('Failed to fetch detection:', err);
      showNotification('Failed to fetch detection content', 'error');
    });
}

// View detection in modal
function viewDetection(filename) {
  fetch(`/api/detection/${encodeURIComponent(filename)}`)
    .then(response => response.text())
    .then(content => {
      showModal('Detection Content', content, 'yaml');
    })
    .catch(err => {
      console.error('Failed to fetch detection:', err);
      showNotification('Failed to load detection', 'error');
    });
}

// Download individual detection
function downloadDetection(filename) {
  window.location.href = `/api/download/detection/${encodeURIComponent(filename)}`;
}

// Download all detections as zip
document.getElementById('download-all-btn')?.addEventListener('click', function() {
  const groupName = new URLSearchParams(window.location.search).get('group_name');
  if (!groupName) {
    showNotification('Group name not found', 'error');
    return;
  }

  showNotification('Preparing download...', 'info');
  window.location.href = `/api/download/all/${encodeURIComponent(groupName)}`;
});

// View attack flow
function viewAttackFlow(flowFile) {
  if (!flowFile) {
    showNotification('Attack flow file not found', 'error');
    return;
  }

  // Open attack flow HTML in new window
  window.open(`/api/attack-flow/${encodeURIComponent(flowFile)}`, '_blank');
}

// View complete actor flow
function viewCompleteFlow(groupName) {
  if (!groupName) {
    showNotification('Group name not found', 'error');
    return;
  }

  window.open(`/api/attack-flow/${encodeURIComponent(groupName)}_complete_flow.html`, '_blank');
}

// Download attack flow JSON
function downloadFlow(groupName) {
  if (!groupName) {
    showNotification('Group name not found', 'error');
    return;
  }

  window.location.href = `/api/download/flow/${encodeURIComponent(groupName)}_complete_flow.json`;
}

// Show notification toast
function showNotification(message, type = 'info') {
  // Remove existing notifications
  const existing = document.querySelectorAll('.notification-toast');
  existing.forEach(el => el.remove());

  // Create notification
  const notification = document.createElement('div');
  notification.className = `notification-toast notification-${type}`;
  notification.textContent = message;

  // Add icon based on type
  const icon = document.createElement('span');
  icon.className = 'notification-icon';
  icon.innerHTML = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
  notification.prepend(icon);

  document.body.appendChild(notification);

  // Animate in
  setTimeout(() => notification.classList.add('show'), 10);

  // Remove after 3 seconds
  setTimeout(() => {
    notification.classList.remove('show');
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

// Show modal with content
function showModal(title, content, language = 'text') {
  // Remove existing modal
  const existingModal = document.getElementById('content-modal');
  if (existingModal) existingModal.remove();

  // Create modal
  const modal = document.createElement('div');
  modal.id = 'content-modal';
  modal.className = 'modal-overlay';
  modal.innerHTML = `
    <div class="modal-content">
      <div class="modal-header">
        <h3>${escapeHtml(title)}</h3>
        <button class="modal-close" onclick="closeModal()">&times;</button>
      </div>
      <div class="modal-body">
        <pre><code class="language-${language}">${escapeHtml(content)}</code></pre>
      </div>
      <div class="modal-footer">
        <button class="btn-secondary" onclick="copyModalContent()">Copy</button>
        <button class="btn-outline" onclick="closeModal()">Close</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  // Close on background click
  modal.addEventListener('click', function(e) {
    if (e.target === modal) closeModal();
  });

  // Close on Escape key
  document.addEventListener('keydown', function escapeHandler(e) {
    if (e.key === 'Escape') {
      closeModal();
      document.removeEventListener('keydown', escapeHandler);
    }
  });
}

// Close modal
function closeModal() {
  const modal = document.getElementById('content-modal');
  if (modal) {
    modal.classList.add('closing');
    setTimeout(() => modal.remove(), 300);
  }
}

// Copy modal content to clipboard
function copyModalContent() {
  const modal = document.getElementById('content-modal');
  if (!modal) return;

  const codeElement = modal.querySelector('code');
  if (!codeElement) return;

  navigator.clipboard.writeText(codeElement.textContent).then(() => {
    showNotification('Content copied to clipboard!', 'success');
  }).catch(err => {
    console.error('Failed to copy:', err);
    showNotification('Failed to copy to clipboard', 'error');
  });
}

// Escape HTML for safe display
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Add notification toast styles dynamically
const notificationStyles = document.createElement('style');
notificationStyles.textContent = `
  .notification-toast {
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 1rem 1.5rem;
    background: white;
    border: 2px solid;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-weight: 600;
    z-index: 10000;
    opacity: 0;
    transform: translateY(-20px);
    transition: all 0.3s ease;
  }

  .notification-toast.show {
    opacity: 1;
    transform: translateY(0);
  }

  .notification-toast.notification-success {
    border-color: #28a745;
    color: #28a745;
  }

  .notification-toast.notification-error {
    border-color: #dc3545;
    color: #dc3545;
  }

  .notification-toast.notification-info {
    border-color: #0d6efd;
    color: #0d6efd;
  }

  .notification-icon {
    font-size: 1.25rem;
    font-weight: bold;
  }

  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10000;
    animation: fadeIn 0.3s ease;
  }

  .modal-overlay.closing {
    animation: fadeOut 0.3s ease;
  }

  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }

  @keyframes fadeOut {
    from { opacity: 1; }
    to { opacity: 0; }
  }

  .modal-content {
    background: white;
    border-radius: 12px;
    max-width: 900px;
    width: 90%;
    max-height: 80vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    animation: slideIn 0.3s ease;
  }

  @keyframes slideIn {
    from { transform: scale(0.9) translateY(20px); opacity: 0; }
    to { transform: scale(1) translateY(0); opacity: 1; }
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem;
    border-bottom: 2px solid #e2e8f0;
  }

  .modal-header h3 {
    margin: 0;
    font-size: 1.25rem;
    color: #1f2d35;
  }

  .modal-close {
    background: none;
    border: none;
    font-size: 2rem;
    color: #8B9AA3;
    cursor: pointer;
    line-height: 1;
    padding: 0;
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 4px;
    transition: all 0.2s;
  }

  .modal-close:hover {
    background: #f8fafc;
    color: #C53030;
  }

  .modal-body {
    padding: 1.5rem;
    overflow-y: auto;
    flex: 1;
  }

  .modal-body pre {
    margin: 0;
    background: #f8fafc;
    padding: 1rem;
    border-radius: 8px;
    overflow-x: auto;
  }

  .modal-body code {
    font-family: 'Courier New', monospace;
    font-size: 0.9rem;
    line-height: 1.6;
    color: #1f2d35;
  }

  .modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 1rem;
    padding: 1.5rem;
    border-top: 2px solid #e2e8f0;
  }
`;
document.head.appendChild(notificationStyles);

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
  console.log('Results page loaded');

  // Auto-expand first vendor
  const firstVendor = document.querySelector('.vendor-group');
  if (firstVendor) {
    firstVendor.classList.add('expanded');
  }
});
