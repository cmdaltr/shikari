/**
 * Tabs.js - Tab switching and file upload handling
 */

// Tab switching functionality
document.addEventListener('DOMContentLoaded', function() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabPanes = document.querySelectorAll('.tab-pane');

    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Don't switch tabs if button is disabled
            if (this.disabled || this.hasAttribute('disabled')) {
                return;
            }

            const tabId = this.getAttribute('data-tab');

            // Remove active class from all buttons and panes
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));

            // Add active class to clicked button and corresponding pane
            this.classList.add('active');
            document.getElementById('tab-' + tabId).classList.add('active');

            // Initialize validation panel when switching to emulate/validate tab
            if (tabId === 'emulate' && typeof initDetectionValidation === 'function') {
                const validationPanel = document.getElementById('validation-panel');
                if (validationPanel) {
                    validationPanel.style.display = 'block';
                }
                initDetectionValidation();
            }
        });
    });

    // File upload handling
    setupFileUpload();

    // Form validation
    setupFormValidation();

    // Remote execution toggle
    setupRemoteExecutionToggle();
});

/**
 * Setup file upload drag-and-drop and selection
 */
function setupFileUpload() {
    const dropzone = document.getElementById('upload-dropzone');
    const fileInput = document.getElementById('file-input');
    const fileSelected = document.getElementById('file-selected');
    const fileNameText = document.getElementById('file-name-text');
    const uploadBtn = document.getElementById('upload_btn');

    if (!dropzone || !fileInput) return;

    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    // Highlight drop area when item is dragged over it
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => {
            dropzone.classList.add('dragover');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => {
            dropzone.classList.remove('dragover');
        }, false);
    });

    // Handle dropped files
    dropzone.addEventListener('drop', function(e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length > 0) {
            fileInput.files = files;
            handleFileSelection(files[0]);
        }
    }, false);

    // Handle file selection via input
    fileInput.addEventListener('change', function(e) {
        if (this.files.length > 0) {
            handleFileSelection(this.files[0]);
        }
    });

    function handleFileSelection(file) {
        // Display file name
        fileNameText.textContent = file.name;
        fileSelected.style.display = 'block';

        // Enable upload button
        if (uploadBtn) {
            uploadBtn.disabled = false;
        }

        // Hide drop zone instructions
        const uploadText = dropzone.querySelector('.upload-text');
        const selectButton = dropzone.querySelector('.btn-secondary');
        if (uploadText) uploadText.style.display = 'none';
        if (selectButton) selectButton.style.display = 'none';
    }
}

/**
 * Clear file selection
 */
function clearFileSelection() {
    const fileInput = document.getElementById('file-input');
    const fileSelected = document.getElementById('file-selected');
    const uploadBtn = document.getElementById('upload_btn');
    const dropzone = document.getElementById('upload-dropzone');

    // Clear file input
    if (fileInput) {
        fileInput.value = '';
    }

    // Hide file info
    if (fileSelected) {
        fileSelected.style.display = 'none';
    }

    // Disable upload button
    if (uploadBtn) {
        uploadBtn.disabled = true;
    }

    // Show drop zone instructions
    const uploadText = dropzone.querySelector('.upload-text');
    const selectButton = dropzone.querySelector('.btn-secondary');
    if (uploadText) uploadText.style.display = 'block';
    if (selectButton) selectButton.style.display = 'inline-block';
}

/**
 * Setup form validation for all forms
 */
function setupFormValidation() {
    // Generate form validation
    const generateInput = document.getElementById('group_name_input');
    const generateBtn = document.getElementById('generate_btn');
    const groupNameError = document.getElementById('group-name-error');

    if (generateInput && generateBtn) {
        generateInput.addEventListener('input', function() {
            const value = this.value.trim();
            const isValid = value.length > 0 && value.length <= 30;

            generateBtn.disabled = !isValid;

            if (value.length > 30) {
                groupNameError.style.display = 'block';
            } else {
                groupNameError.style.display = 'none';
            }
        });
    }

    // Emulate form validation
    const emulateInput = document.getElementById('emulate_technique');
    const emulateBtn = document.getElementById('emulate_btn');

    if (emulateInput && emulateBtn) {
        emulateInput.addEventListener('input', function() {
            const value = this.value.trim();
            emulateBtn.disabled = value.length === 0;
        });
    }
}

/**
 * Setup remote execution config toggle
 */
function setupRemoteExecutionToggle() {
    const remoteCheckbox = document.querySelector('input[name="remote_execution"]');
    const remoteConfig = document.getElementById('remote-config');

    if (remoteCheckbox && remoteConfig) {
        remoteCheckbox.addEventListener('change', function() {
            remoteConfig.style.display = this.checked ? 'block' : 'none';
        });
    }
}

/**
 * Show loading overlay with message
 */
function showLoading(message) {
    const overlay = document.getElementById('loading-overlay');
    const messageEl = document.getElementById('loading-message');

    if (overlay) {
        overlay.style.display = 'flex';
    }

    if (messageEl && message) {
        messageEl.textContent = message;
    }
}

/**
 * Hide loading overlay
 */
function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

// Form submission handlers
document.addEventListener('DOMContentLoaded', function() {
    // Upload form submission
    const uploadForm = document.getElementById('upload-form');
    if (uploadForm) {
        uploadForm.addEventListener('submit', function(e) {
            e.preventDefault();
            showLoading('Processing file...');

            const formData = new FormData(this);

            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                hideLoading();
                if (data.success) {
                    // Redirect to progress or results page
                    window.location.href = data.redirect || '/progress';
                } else {
                    alert('Error: ' + (data.error || 'Unknown error occurred'));
                }
            })
            .catch(error => {
                hideLoading();
                alert('Error uploading file: ' + error.message);
            });
        });
    }

    // Emulate form submission
    const emulateForm = document.getElementById('emulate-form');
    if (emulateForm) {
        emulateForm.addEventListener('submit', function(e) {
            e.preventDefault();
            showLoading('Starting emulation...');

            const formData = new FormData(this);

            fetch('/emulate', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                hideLoading();
                if (data.success) {
                    window.location.href = data.redirect || '/progress';
                } else {
                    alert('Error: ' + (data.error || 'Unknown error occurred'));
                }
            })
            .catch(error => {
                hideLoading();
                alert('Error starting emulation: ' + error.message);
            });
        });
    }
});
