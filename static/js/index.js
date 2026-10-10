var loadingInterval;
var progressPollInterval;
function showLoading(groupName, enableProgressPolling) {
  var overlay = document.getElementById('loading-overlay');
  var spinnerEl = document.getElementById('loading-spinner');
  overlay.style.display = 'flex';

  // Detect animal from group name and set emoji
  var animalMap = {
    'spider': '🕷️',
    'panda': '🐼',
    'kitten': '🐱',
    'bear': '🐻',
    'fox': '🦊',
    'kitsune': '🦊',
    'tiger': '🐯',
    'mouse': '🐭',
    'smilodon': '🐱',
    'worm': '🪱',
    'eagle': '🦅',
    'falcon': '🦅',
    'wolf': '🐺',
    'rabbit': '🐰',
    'snake': '🐍',
    'dragon': '🐉',
    'lion': '🦁',
    'leopard': '🐆'
  };

  var selectedAnimal = null;
  if (groupName) {
    var groupLower = groupName.toLowerCase();
    for (var animal in animalMap) {
      if (groupLower.indexOf(animal) !== -1) {
        selectedAnimal = animalMap[animal];
        break;
      }
    }
  }

  // Set the animal emoji (or leave empty for default red ring)
  if (selectedAnimal && spinnerEl) {
    spinnerEl.setAttribute('data-emoji', selectedAnimal);
  } else if (spinnerEl) {
    spinnerEl.removeAttribute('data-emoji');
  }

  // If progress polling is enabled (for profiling), poll for progress messages
  if (enableProgressPolling && groupName) {
    var safeGroupName = groupName.replace(/\./g, '_').replace(/\//g, '_');

    progressPollInterval = setInterval(function () {
      fetch('/progress_status?group_name=' + encodeURIComponent(safeGroupName))
        .then(function (res) { return res.json(); })
        .then(function (data) {
          var p = data.progress || data.progress_state || data || {};
          var status = p.status || '';

          // Stop polling if complete
          if (status === 'complete' || status === 'profile_complete' || status === 'error') {
            if (progressPollInterval) {
              clearInterval(progressPollInterval);
              progressPollInterval = null;
            }
          }
        })
        .catch(function () {
          // Silently fail - keep existing state
        });
    }, 1000); // Poll every second
  }
}
function hideLoading() {
  document.getElementById('loading-overlay').style.display = 'none';
  if (loadingInterval) { clearInterval(loadingInterval); loadingInterval = null; }
  if (progressPollInterval) { clearInterval(progressPollInterval); progressPollInterval = null; }
  var spinnerEl = document.getElementById('loading-spinner');
  if (spinnerEl) spinnerEl.removeAttribute('data-emoji');
}

function showY2KWarning() {
  // Create overlay
  var overlay = document.createElement('div');
  overlay.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); z-index: 9999; display: flex; flex-direction: column; align-items: center; justify-content: center; cursor: pointer;';

  // Create content container
  var content = document.createElement('div');
  content.style.cssText = 'text-align: center; max-width: 600px; padding: 30px;';

  // Add warning text
  var title = document.createElement('h2');
  title.style.cssText = 'color: #ff6b6b; font-size: 2.5em; margin: 0 0 20px 0; font-family: "Courier New", monospace; text-shadow: 0 0 10px rgba(255,107,107,0.5);';
  title.textContent = '⚠️ Y2K WARNING ⚠️';

  var message = document.createElement('p');
  message.style.cssText = 'color: #fff; font-size: 1.3em; margin: 0 0 30px 0; line-height: 1.6;';
  message.innerHTML = 'A CVE from the 1990s?!<br>You have <strong>MUCH BIGGER PROBLEMS</strong> to deal with!';

  // Add GIF
  var gif = document.createElement('img');
  gif.src = 'https://media.giphy.com/media/HUkOv6BNWc1HO/giphy.gif'; // Fire/chaos GIF
  gif.style.cssText = 'max-width: 100%; border-radius: 10px; box-shadow: 0 0 30px rgba(255,107,107,0.3);';
  gif.alt = 'Chaos ensues';

  // Add close instruction
  var closeText = document.createElement('p');
  closeText.style.cssText = 'color: #aaa; font-size: 0.9em; margin: 20px 0 0 0;';
  closeText.textContent = '(Click anywhere to close)';

  content.appendChild(title);
  content.appendChild(message);
  content.appendChild(gif);
  content.appendChild(closeText);
  overlay.appendChild(content);

  // Close on click
  overlay.addEventListener('click', function() {
    document.body.removeChild(overlay);
  });

  document.body.appendChild(overlay);
}

document.addEventListener('DOMContentLoaded', function () {
  // Mutual exclusivity: Advanced Parsing and Semantic Analysis
  var semanticCheckbox = document.getElementById('semantic-checkbox');
  var advancedParsingCheckbox = document.getElementById('advanced-parsing-checkbox');

  if (semanticCheckbox && advancedParsingCheckbox) {
    // When Advanced Parsing is checked, uncheck Semantic Analysis
    advancedParsingCheckbox.addEventListener('change', function() {
      if (this.checked) {
        semanticCheckbox.checked = false;
      }
    });

    // When Semantic Analysis is checked, uncheck Advanced Parsing
    semanticCheckbox.addEventListener('change', function() {
      if (this.checked) {
        advancedParsingCheckbox.checked = false;
      }
    });
  }

  // Description popup
  var popup = document.getElementById('archer-desc-popup');
  var hideCheckbox = document.getElementById('hide-desc-popup-checkbox');
  var dontShowCheckbox = document.getElementById('dont-show-desc-popup-checkbox');
  var dontShow = localStorage.getItem('archerDontShowDescPopup');
  if (popup) {
    if (dontShow === 'true') {
      popup.style.display = 'none';
      if (dontShowCheckbox) dontShowCheckbox.checked = true;
    } else {
      popup.style.display = 'block';
      if (dontShowCheckbox) dontShowCheckbox.checked = false;
    }
    if (hideCheckbox) {
      hideCheckbox.checked = false;
      hideCheckbox.addEventListener('change', function () {
        if (this.checked) {
          popup.style.display = 'none';
        } else {
          if (!dontShowCheckbox || !dontShowCheckbox.checked) popup.style.display = 'block';
        }
      });
    }
    if (dontShowCheckbox) {
      dontShowCheckbox.addEventListener('change', function () {
        if (this.checked) {
          localStorage.setItem('archerDontShowDescPopup', 'true');
          popup.style.display = 'none';
        } else {
          localStorage.setItem('archerDontShowDescPopup', 'false');
          if (!hideCheckbox || !hideCheckbox.checked) popup.style.display = 'block';
        }
      });
    }
  }

  // Form validation and AJAX submit
  var form = document.getElementById('generate-form');
  var input = document.getElementById('group_name_input');
  var btn = document.getElementById('generate_btn');
  var errorSpan = document.getElementById('group-name-error');

  // Autocomplete functionality
  var autocompleteList = null;
  var selectedIndex = -1;
  var autocompleteItems = [];
  var fetchTimeout = null;

  function createAutocompleteList() {
    if (!autocompleteList) {
      autocompleteList = document.createElement('div');
      autocompleteList.className = 'autocomplete-list';
      autocompleteList.style.display = 'none';
      input.parentNode.appendChild(autocompleteList);
    }
  }

  function hideAutocomplete() {
    if (autocompleteList) {
      autocompleteList.style.display = 'none';
      selectedIndex = -1;
      autocompleteItems = [];
    }
  }

  function showAutocomplete(groups) {
    createAutocompleteList();
    autocompleteList.innerHTML = '';
    autocompleteItems = groups;

    if (groups.length === 0) {
      hideAutocomplete();
      return;
    }

    groups.forEach(function(group, index) {
      var item = document.createElement('div');
      item.className = 'autocomplete-item';

      var nameSpan = document.createElement('span');
      nameSpan.className = 'group-name';
      nameSpan.textContent = group.name;
      item.appendChild(nameSpan);

      if (group.is_alias && group.primary) {
        var aliasLabel = document.createElement('span');
        aliasLabel.className = 'alias-label';
        aliasLabel.textContent = ' (alias of ' + group.primary + ')';
        item.appendChild(aliasLabel);
      }

      item.addEventListener('click', function() {
        input.value = group.name;
        hideAutocomplete();
        validate();
      });

      item.addEventListener('mouseenter', function() {
        selectedIndex = index;
        updateSelection();
      });

      autocompleteList.appendChild(item);
    });

    autocompleteList.style.display = 'block';
    updateSelection();
  }

  function updateSelection() {
    var items = autocompleteList.querySelectorAll('.autocomplete-item');
    items.forEach(function(item, index) {
      if (index === selectedIndex) {
        item.classList.add('selected');
      } else {
        item.classList.remove('selected');
      }
    });
  }

  function fetchGroups(query) {
    if (query.length < 2) {
      hideAutocomplete();
      return;
    }

    fetch('/threat_groups?query=' + encodeURIComponent(query))
      .then(function(response) { return response.json(); })
      .then(function(data) {
        if (data.ok && data.groups) {
          showAutocomplete(data.groups);
        } else {
          hideAutocomplete();
        }
      })
      .catch(function(err) {
        console.error('Autocomplete error:', err);
        hideAutocomplete();
      });
  }

  if (input) {
    input.addEventListener('input', function() {
      validate();

      // Debounce API calls
      if (fetchTimeout) clearTimeout(fetchTimeout);
      fetchTimeout = setTimeout(function() {
        fetchGroups(input.value);
      }, 300);
    });

    input.addEventListener('keydown', function(e) {
      if (!autocompleteList || autocompleteList.style.display === 'none') return;

      // Arrow Down
      if (e.keyCode === 40) {
        e.preventDefault();
        selectedIndex = Math.min(selectedIndex + 1, autocompleteItems.length - 1);
        updateSelection();
      }
      // Arrow Up
      else if (e.keyCode === 38) {
        e.preventDefault();
        selectedIndex = Math.max(selectedIndex - 1, -1);
        updateSelection();
      }
      // Enter
      else if (e.keyCode === 13) {
        if (selectedIndex >= 0 && selectedIndex < autocompleteItems.length) {
          e.preventDefault();
          input.value = autocompleteItems[selectedIndex].name;
          hideAutocomplete();
          validate();
        }
      }
      // Escape
      else if (e.keyCode === 27) {
        hideAutocomplete();
      }
    });

    // Hide autocomplete when clicking outside
    document.addEventListener('click', function(e) {
      if (e.target !== input && (!autocompleteList || !autocompleteList.contains(e.target))) {
        hideAutocomplete();
      }
    });
  }

  function validate() {
    var val = (input && input.value) || '';
    var cveVal = (cveInput && cveInput.value) || '';

    if (val.length > 30) {
      if (errorSpan) errorSpan.style.display = 'inline';
      if (btn) btn.disabled = true;
      return;
    } else {
      if (errorSpan) errorSpan.style.display = 'none';
    }

    var trimmed = val.trim();
    var cveTrimmed = cveVal.trim();

    // Enable button if either group name OR CVE input has a value
    if (btn) btn.disabled = (trimmed === '' && cveTrimmed === '');

    // Enable threat briefing button only when group name is present
    var briefingBtn = document.getElementById('briefing-btn');
    if (briefingBtn) briefingBtn.disabled = (trimmed === '');
  }

  // Get CVE input reference before validate is called
  var cveInput = document.getElementById('cve_input');

  validate();

  // Mutual exclusion between group name and CVE inputs
  if (input && cveInput) {
    input.addEventListener('input', function() {
      if (this.value.trim()) {
        cveInput.disabled = true;
        cveInput.placeholder = 'Disabled (using Threat Group)';
        cveInput.style.opacity = '0.5';
      } else {
        cveInput.disabled = false;
        cveInput.placeholder = 'e.g., CVE-2024-1234 or CVE-2021-44228, CVE-2022-22965';
        cveInput.style.opacity = '1';
      }
      validate(); // Re-validate when group name changes
    });

    cveInput.addEventListener('input', function() {
      if (this.value.trim()) {
        input.disabled = true;
        input.placeholder = 'Disabled (using CVE)';
        input.style.opacity = '0.5';
      } else {
        input.disabled = false;
        input.placeholder = 'e.g., APT29, Scattered Spider';
        input.style.opacity = '1';
      }
      validate(); // Re-validate when CVE input changes
    });
  }

  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();

      // If the LLM choice modal is open, hold the submission until the user chooses
      if (window._llmChoicePending) {
        window._llmPendingSubmit = function() { form.dispatchEvent(new Event('submit', {bubbles: true})); };
        return false;
      }

      // Check if CVE input, technique input, or group name is provided
      var cveInput = document.getElementById('cve_input');
      var techniqueInput = document.getElementById('technique_input');
      var groupName = input ? input.value.trim() : '';
      var cveId = cveInput ? cveInput.value.trim() : '';
      var techniqueIds = techniqueInput ? techniqueInput.value.trim() : '';

      if (!groupName && !cveId && !techniqueIds) {
        alert('Please enter a Threat Group Name, CVE Identifier, or ATT&CK Technique IDs');
        return false;
      }

      // Validate CVE format if CVE input is used
      if (cveId) {
        var cvePattern = /^CVE-20\d{2}-\d{4,}$/i;
        var cve199Pattern = /^CVE-199\d-\d{4,}$/i;
        var cves = cveId.split(',').map(function(c) { return c.trim(); });
        var invalidCves = [];
        var has199CVE = false;

        for (var i = 0; i < cves.length; i++) {
          // Check for CVE-199x (1990s CVEs) - fun Easter egg
          if (cve199Pattern.test(cves[i])) {
            has199CVE = true;
            break;
          }

          if (!cvePattern.test(cves[i])) {
            invalidCves.push(cves[i]);
          }
        }

        // Show fun GIF for 1990s CVEs
        if (has199CVE) {
          showY2KWarning();
          return false;
        }

        if (invalidCves.length > 0) {
          alert('Invalid CVE format: ' + invalidCves.join(', ') + '\n\nCVE IDs must:\n- Start with "CVE-20" (case-insensitive)\n- Follow format: CVE-YYYY-NNNN (e.g., CVE-2021-44228)\n- Year must be 2000 or later');
          return false;
        }
      }

      // Validate Technique format if technique input is used
      if (techniqueIds) {
        var techniquePattern = /^T\d{4}(\.\d{3})?$/i;
        var techniques = techniqueIds.split(',').map(function(t) { return t.trim(); });
        var invalidTechniques = [];

        for (var i = 0; i < techniques.length; i++) {
          if (!techniquePattern.test(techniques[i])) {
            invalidTechniques.push(techniques[i]);
          }
        }

        if (invalidTechniques.length > 0) {
          alert('Invalid ATT&CK Technique format: ' + invalidTechniques.join(', ') + '\n\nTechnique IDs must:\n- Start with "T" followed by 4 digits (e.g., T1003)\n- Optionally include subtechnique: T1003.001\n- Multiple techniques separated by commas');
          return false;
        }
      }

      // Determine endpoint based on input priority: technique > CVE > group
      var endpoint = '/generate';
      var displayName = groupName;

      if (techniqueIds) {
        endpoint = '/hunt/technique';
        displayName = 'Hunt: ' + techniqueIds.split(',')[0].trim();
        if (techniqueIds.split(',').length > 1) {
          displayName += ' +' + (techniqueIds.split(',').length - 1);
        }
      } else if (cveId) {
        endpoint = '/generate/cve';
        displayName = cveId;
      }

      showLoading(displayName);

      var formData = new FormData(form);

      // Explicitly add osint_enhancement checkbox value (forms don't send unchecked checkboxes)
      var osintEnhancementCheckbox = document.getElementById('osint-enhancement-checkbox');
      if (osintEnhancementCheckbox) {
        // Remove existing value if present
        formData.delete('osint_enhancement');
        // Add explicit true/false value
        formData.append('osint_enhancement', osintEnhancementCheckbox.checked ? 'true' : 'false');
      }

      fetch(endpoint, {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
      })
      .then(function (response) {
        var contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) return response.json();
        return response.text();
      })
      .then(function (data) {
        if (typeof data === 'object' && data.redirect_url) {
          window.location = data.redirect_url;
          return;
        }
        var parser = new DOMParser();
        var doc = parser.parseFromString(data, 'text/html');
        var newContent = doc.getElementById('main-content');
        var oldContent = document.getElementById('main-content');
        if (newContent && oldContent) oldContent.innerHTML = newContent.innerHTML;
        hideLoading();
      })
      .catch(function (err) {
        hideLoading();
        alert('Error: ' + err.message);
      });
    });
  }
});

// Ensure overlay is hidden when navigating back/forward (bfcache restore)
window.addEventListener('pageshow', function () {
  if (typeof hideLoading === 'function') hideLoading();
});

// Also hide on history navigation events
window.addEventListener('popstate', function () {
  if (typeof hideLoading === 'function') hideLoading();
});

// Profile form validation
document.addEventListener('DOMContentLoaded', function () {
  var profileForm = document.getElementById('profile-form');
  var domainInput = document.getElementById('domain_input');
  var profileBtn = document.getElementById('profile_btn');

  function validateDomain() {
    var val = (domainInput && domainInput.value) || '';
    var trimmed = val.trim();
    // Basic domain regex: alphanumeric + hyphens, with TLD
    var domainPattern = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*\.[a-zA-Z]{2,}$/;
    if (profileBtn) {
      profileBtn.disabled = !domainPattern.test(trimmed);
    }
  }

  if (domainInput) {
    domainInput.addEventListener('input', validateDomain);
    validateDomain(); // Initial validation
  }

  if (profileForm) {
    profileForm.addEventListener('submit', function (e) {
      e.preventDefault();
      if (!domainInput || domainInput.value.trim() === '') {
        if (profileBtn) profileBtn.disabled = true;
        return false;
      }
      showLoading(domainInput.value.trim(), true); // Enable progress polling for profiling

      var formData = new FormData(profileForm);
      fetch('/profile', {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
      })
      .then(function (response) {
        var contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) return response.json();
        return response.text();
      })
      .then(function (data) {
        hideLoading();

        if (typeof data === 'object' && data.redirect_url) {
          window.location = data.redirect_url;
          return;
        }
        if (typeof data === 'object' && data.success) {
          // Show threat group selection if auto-generate was checked
          if (data.show_selection && data.recommended_groups && data.recommended_groups.length > 0) {
            showThreatGroupSelection(domainInput.value.trim(), data.recommended_groups, data.profile);
          } else {
            alert('Profile created successfully! Saved to: ' + data.profile_path);
          }
          return;
        }
        var parser = new DOMParser();
        var doc = parser.parseFromString(data, 'text/html');
        var newContent = doc.getElementById('main-content');
        var oldContent = document.getElementById('main-content');
        if (newContent && oldContent) oldContent.innerHTML = newContent.innerHTML;
        hideLoading();
      })
      .catch(function (err) {
        hideLoading();
        alert('Error: ' + err.message);
      });
    });
  }
});

// Upload form validation
document.addEventListener('DOMContentLoaded', function () {
  var uploadForm = document.getElementById('upload-form');
  var fileInput = document.getElementById('file-input');
  var uploadBtn = document.getElementById('upload_btn');
  var fileSelected = document.getElementById('file-selected');
  var fileNameText = document.getElementById('file-name-text');
  var dropzone = document.getElementById('upload-dropzone');

  function validateUpload() {
    if (uploadBtn) {
      var hasFile = fileInput && fileInput.files && fileInput.files.length > 0;
      var urlInput = document.getElementById('blog_url_input');
      var url = (urlInput && urlInput.value) || '';
      var hasUrl = url.trim() !== '' && (url.startsWith('http://') || url.startsWith('https://')) && url.replace(/^https?:\/\//, '').includes('.');
      uploadBtn.disabled = !hasFile && !hasUrl;
    }
  }

  if (fileInput) {
    fileInput.addEventListener('change', function () {
      if (this.files && this.files.length > 0) {
        if (fileNameText) fileNameText.textContent = this.files[0].name;
        if (fileSelected) fileSelected.style.display = 'block';
      } else {
        if (fileSelected) fileSelected.style.display = 'none';
      }
      validateUpload();
    });
    validateUpload(); // Initial validation
  }

  var blogUrlInput = document.getElementById('blog_url_input');
  if (blogUrlInput) {
    blogUrlInput.addEventListener('input', validateUpload);
  }

  // Drag and drop support
  if (dropzone) {
    dropzone.addEventListener('dragover', function (e) {
      e.preventDefault();
      e.stopPropagation();
      this.style.borderColor = '#0066cc';
      this.style.backgroundColor = '#f0f8ff';
    });

    dropzone.addEventListener('dragleave', function (e) {
      e.preventDefault();
      e.stopPropagation();
      this.style.borderColor = '#ddd';
      this.style.backgroundColor = '#f9f9f9';
    });

    dropzone.addEventListener('drop', function (e) {
      e.preventDefault();
      e.stopPropagation();
      this.style.borderColor = '#ddd';
      this.style.backgroundColor = '#f9f9f9';

      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        if (fileInput) {
          fileInput.files = e.dataTransfer.files;
          var event = new Event('change', { bubbles: true });
          fileInput.dispatchEvent(event);
        }
      }
    });
  }

  // Failed uploads return JSON {success:false, message}; surface it inline rather than alert(),
  // which blocks the page and previously never fired for HTTP error responses at all
  function showUploadError(msg) {
    var el = document.getElementById('upload-error');
    if (!el) return;
    el.textContent = msg || '';
    el.style.display = msg ? 'block' : 'none';
  }

  function uploadFailed(data) {
    if (typeof data !== 'object' || data === null || data.success !== false) return false;
    showUploadError(data.message || data.error || 'Processing failed. Please try again.');
    return true;
  }

  // Attach click handler to button instead of form submit
  if (uploadBtn && uploadForm) {
    uploadBtn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      showUploadError('');

      var urlInput = document.getElementById('blog_url_input');
      var url = (urlInput && urlInput.value) || '';
      var hasFile = fileInput && fileInput.files && fileInput.files.length > 0;
      var hasUrl = url.trim() !== '' && (url.startsWith('http://') || url.startsWith('https://')) && url.replace(/^https?:\/\//, '').includes('.');

      if (!hasFile && !hasUrl) {
        uploadBtn.disabled = true;
        return false;
      }

      if (hasUrl && !hasFile) {
        // Blog URL analysis
        showLoading('blog analysis');
        var blogFormData = new FormData();
        blogFormData.append('url', url.trim());
        var useOpenAI = document.getElementById('upload_use_openai');
        if (useOpenAI && useOpenAI.checked) blogFormData.append('use_openai', 'true');

        fetch('/analyze_blog', {
          method: 'POST',
          body: blogFormData,
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
        .then(function (response) {
          var contentType = response.headers.get('content-type') || '';
          if (contentType.includes('application/json')) return response.json();
          return response.text();
        })
        .then(function (data) {
          hideLoading();
          if (uploadFailed(data)) return;
          if (typeof data === 'object' && data.show_extraction) { showExtractionResults(data); return; }
          if (typeof data === 'object' && data.redirect_url) { window.location = data.redirect_url; return; }
          if (typeof data === 'object' && data.redirect) { window.location = data.redirect; return; }
          var parser = new DOMParser();
          var doc = parser.parseFromString(data, 'text/html');
          var newContent = doc.getElementById('main-content');
          var oldContent = document.getElementById('main-content');
          if (newContent && oldContent) oldContent.innerHTML = newContent.innerHTML;
        })
        .catch(function (err) { hideLoading(); showUploadError('Request failed: ' + err.message); });
        return;
      }

      // File upload
      showLoading('file upload');
      var formData = new FormData(uploadForm);

      fetch('/upload', {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
      })
      .then(function (response) {
        var contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) return response.json();
        return response.text();
      })
      .then(function (data) {
        hideLoading();
        if (uploadFailed(data)) return;
        if (typeof data === 'object' && data.show_extraction) {
          showExtractionResults(data);
          return;
        }
        if (typeof data === 'object' && data.redirect_url) {
          window.location = data.redirect_url;
          return;
        }
        if (typeof data === 'object' && data.redirect) {
          window.location = data.redirect;
          return;
        }
        var parser = new DOMParser();
        var doc = parser.parseFromString(data, 'text/html');
        var newContent = doc.getElementById('main-content');
        var oldContent = document.getElementById('main-content');
        if (newContent && oldContent) oldContent.innerHTML = newContent.innerHTML;
      })
      .catch(function (err) {
        hideLoading();
        showUploadError('Request failed: ' + err.message);
      });
    });
  }
});

// SECURITY: HTML escape function to prevent XSS
function escapeHtml(text) {
  var map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return String(text).replace(/[&<>"']/g, function(m) { return map[m]; });
}

// Function to show extraction results modal
function showExtractionResults(data) {
  var modal = document.createElement('div');
  modal.id = 'extraction-results-modal';
  modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:2000;display:flex;align-items:center;justify-content:center;';

  var modalContent = document.createElement('div');
  modalContent.style.cssText = 'background:white;border-radius:8px;max-width:900px;max-height:85vh;overflow-y:auto;padding:2em;box-shadow:0 4px 20px rgba(0,0,0,0.3);';

  var html = '<h2 style="margin-top:0;">Extraction Results - Select Items to Process</h2>';
  html += '<p style="color:#666;margin-bottom:1.5em;">Filename: <strong>' + escapeHtml(data.filename || 'Unknown') + '</strong></p>';

  // TTPs section with loading placeholder
  html += '<h3 style="color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:0.5em;">';
  html += 'TTPs Found (' + data.ttps_count + ') ';
  html += '<span style="font-size:0.8em;color:#666;font-weight:normal;">';
  html += '<input type="checkbox" id="select-all-ttps" style="margin-left:1em;vertical-align:middle;"> <label for="select-all-ttps" style="cursor:pointer;">Select All</label>';
  html += '</span></h3>';

  if (data.ttps && data.ttps.length > 0) {
    html += '<div id="ttps-container" style="background:#f8f9fa;padding:1em;border-radius:4px;margin-bottom:1.5em;max-height:250px;overflow-y:auto;">';
    html += '<p style="color:#999;font-style:italic;">Loading technique names...</p>';
    html += '</div>';
  } else {
    html += '<p style="color:#999;font-style:italic;margin-bottom:1.5em;">No TTPs extracted</p>';
  }

  // IOCs section with checkboxes
  html += '<h3 style="color:#2c3e50;border-bottom:2px solid #27ae60;padding-bottom:0.5em;">';
  html += 'IOCs Found (' + data.iocs_count + ') ';
  html += '<span style="font-size:0.8em;color:#666;font-weight:normal;">';
  html += '<input type="checkbox" id="select-all-iocs" style="margin-left:1em;vertical-align:middle;"> <label for="select-all-iocs" style="cursor:pointer;">Select All</label>';
  html += '</span></h3>';

  if (data.iocs && Object.keys(data.iocs).length > 0) {
    html += '<div style="background:#f8f9fa;padding:1em;border-radius:4px;margin-bottom:1.5em;max-height:350px;overflow-y:auto;">';

    // Display order: IP, Domain, Command, Hash, Registry, Event, Software, File
    var iocOrder = ['ip', 'domain', 'cmd', 'hash', 'reg', 'evt', 'sw', 'file'];
    var iocLabels = {
      'ip': 'IP Addresses',
      'domain': 'Domains',
      'cmd': 'Commands',
      'hash': 'File Hashes',
      'reg': 'Registry Keys',
      'evt': 'Event IDs',
      'sw': 'Software',
      'file': 'File Paths'
    };

    iocOrder.forEach(function(iocType) {
      if (data.iocs[iocType] && data.iocs[iocType].length > 0) {
        html += '<div style="margin-bottom:1em;"><strong style="color:#27ae60;">' + iocLabels[iocType] + ' (' + data.iocs[iocType].length + '):</strong>';
        html += '<div id="ioc-container-' + iocType + '" style="margin:0.5em 0 0 0;padding-left:0.5em;">';

        // Show first 10 IOCs
        data.iocs[iocType].slice(0, 10).forEach(function(ioc, idx) {
          var iocId = 'ioc-' + iocType + '-' + idx;
          html += '<div style="margin-bottom:0.3em;">';
          html += '<label style="cursor:pointer;display:flex;align-items:start;gap:0.5em;">';
          html += '<input type="checkbox" class="ioc-checkbox" data-ioc-type="' + iocType + '" value="' + escapeHtml(ioc) + '" checked style="margin-top:0.2em;flex-shrink:0;">';
          html += '<span style="font-family:monospace;font-size:0.9em;word-break:break-all;">' + escapeHtml(ioc) + '</span>';
          html += '</label></div>';
        });

        // Hidden container for remaining IOCs
        if (data.iocs[iocType].length > 10) {
          html += '<div id="ioc-hidden-' + iocType + '" style="display:none;">';
          data.iocs[iocType].slice(10).forEach(function(ioc, idx) {
            var iocId = 'ioc-' + iocType + '-' + (idx + 10);
            html += '<div style="margin-bottom:0.3em;">';
            html += '<label style="cursor:pointer;display:flex;align-items:start;gap:0.5em;">';
            html += '<input type="checkbox" class="ioc-checkbox" data-ioc-type="' + iocType + '" value="' + escapeHtml(ioc) + '" checked style="margin-top:0.2em;flex-shrink:0;">';
            html += '<span style="font-family:monospace;font-size:0.9em;word-break:break-all;">' + escapeHtml(ioc) + '</span>';
            html += '</label></div>';
          });
          html += '</div>';

          // Clickable "show more" link
          html += '<p style="margin:0.5em 0 0 1.5em;">';
          html += '<a href="#" id="show-more-' + iocType + '" style="color:#007bff;text-decoration:none;cursor:pointer;font-style:italic;">';
          html += '▼ Show ' + (data.iocs[iocType].length - 10) + ' more (all selected by default)';
          html += '</a>';
          html += '<a href="#" id="show-less-' + iocType + '" style="color:#007bff;text-decoration:none;cursor:pointer;font-style:italic;display:none;">';
          html += '▲ Show less';
          html += '</a>';
          html += '</p>';
        }

        html += '</div></div>';
      }
    });
    html += '</div>';
  } else {
    html += '<p style="color:#999;font-style:italic;margin-bottom:1.5em;">No IOCs extracted</p>';
  }

  // Buttons
  html += '<div style="display:flex;gap:1em;justify-content:flex-end;margin-top:2em;border-top:1px solid #dee2e6;padding-top:1.5em;">';
  html += '<button id="cancel-extraction" style="padding:0.75em 1.5em;border:1px solid #ced4da;background:white;color:#495057;border-radius:4px;cursor:pointer;font-size:1em;">Cancel</button>';

  if (data.auto_generate_requested && (data.ttps_count > 0 || data.iocs_count > 0)) {
    html += '<button id="proceed-generation" style="padding:0.75em 1.5em;border:none;background:#007bff;color:white;border-radius:4px;cursor:pointer;font-size:1em;font-weight:500;">Proceed with Selected Items</button>';
  } else {
    html += '<button id="close-extraction" style="padding:0.75em 1.5em;border:none;background:#28a745;color:white;border-radius:4px;cursor:pointer;font-size:1em;font-weight:500;">Close</button>';
  }
  html += '</div>';

  modalContent.innerHTML = html;
  modal.appendChild(modalContent);
  document.body.appendChild(modal);

  // Fetch technique names and populate TTPs
  if (data.ttps && data.ttps.length > 0) {
    fetch('/api/technique_names', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify({ technique_ids: data.ttps })
    })
    .then(function(response) { return response.json(); })
    .then(function(techniqueNames) {
      var ttpsContainer = document.getElementById('ttps-container');
      if (ttpsContainer) {
        var ttpsHtml = '<div style="padding-left:0.5em;">';
        data.ttps.forEach(function(ttp, idx) {
          var techName = techniqueNames[ttp] || 'Unknown Technique';
          var ttpId = 'ttp-' + idx;
          var attackUrl = 'https://attack.mitre.org/techniques/' + ttp.replace('.', '/');

          ttpsHtml += '<div style="margin-bottom:0.4em;">';
          ttpsHtml += '<label style="cursor:pointer;display:flex;align-items:start;gap:0.5em;">';
          ttpsHtml += '<input type="checkbox" class="ttp-checkbox" value="' + escapeHtml(ttp) + '" checked style="margin-top:0.2em;flex-shrink:0;">';
          ttpsHtml += '<span><a href="' + attackUrl + '" target="_blank" style="color:#3498db;text-decoration:none;font-weight:500;" title="View on MITRE ATT&CK">';
          ttpsHtml += escapeHtml(techName) + ' (<code style="background:#e9ecef;padding:2px 6px;border-radius:3px;">' + escapeHtml(ttp) + '</code>)';
          ttpsHtml += '</a></span>';
          ttpsHtml += '</label></div>';
        });
        ttpsHtml += '</div>';
        ttpsContainer.innerHTML = ttpsHtml;
      }
    })
    .catch(function(err) {
      console.error('Error fetching technique names:', err);
      var ttpsContainer = document.getElementById('ttps-container');
      if (ttpsContainer) {
        var ttpsHtml = '<div style="padding-left:0.5em;">';
        data.ttps.forEach(function(ttp, idx) {
          var ttpId = 'ttp-' + idx;
          var attackUrl = 'https://attack.mitre.org/techniques/' + ttp.replace('.', '/');

          ttpsHtml += '<div style="margin-bottom:0.4em;">';
          ttpsHtml += '<label style="cursor:pointer;display:flex;align-items:start;gap:0.5em;">';
          ttpsHtml += '<input type="checkbox" class="ttp-checkbox" value="' + escapeHtml(ttp) + '" checked style="margin-top:0.2em;flex-shrink:0;">';
          ttpsHtml += '<span><a href="' + attackUrl + '" target="_blank" style="color:#3498db;text-decoration:none;font-weight:500;">';
          ttpsHtml += '<code style="background:#e9ecef;padding:2px 6px;border-radius:3px;">' + escapeHtml(ttp) + '</code>';
          ttpsHtml += '</a></span>';
          ttpsHtml += '</label></div>';
        });
        ttpsHtml += '</div>';
        ttpsContainer.innerHTML = ttpsHtml;
      }
    });
  }

  // Select all checkboxes functionality
  var selectAllTtps = document.getElementById('select-all-ttps');
  if (selectAllTtps) {
    selectAllTtps.addEventListener('change', function() {
      var checkboxes = document.querySelectorAll('.ttp-checkbox');
      checkboxes.forEach(function(cb) { cb.checked = selectAllTtps.checked; });
    });
  }

  var selectAllIocs = document.getElementById('select-all-iocs');
  if (selectAllIocs) {
    selectAllIocs.addEventListener('change', function() {
      var checkboxes = document.querySelectorAll('.ioc-checkbox');
      checkboxes.forEach(function(cb) { cb.checked = selectAllIocs.checked; });
    });
  }

  // Show/Hide more IOCs functionality
  var iocOrder = ['ip', 'domain', 'cmd', 'hash', 'reg', 'evt', 'sw', 'file'];
  iocOrder.forEach(function(iocType) {
    var showMoreLink = document.getElementById('show-more-' + iocType);
    var showLessLink = document.getElementById('show-less-' + iocType);
    var hiddenContainer = document.getElementById('ioc-hidden-' + iocType);

    if (showMoreLink && hiddenContainer) {
      showMoreLink.addEventListener('click', function(e) {
        e.preventDefault();
        hiddenContainer.style.display = 'block';
        showMoreLink.style.display = 'none';
        if (showLessLink) showLessLink.style.display = 'inline';
      });
    }

    if (showLessLink && hiddenContainer) {
      showLessLink.addEventListener('click', function(e) {
        e.preventDefault();
        hiddenContainer.style.display = 'none';
        showLessLink.style.display = 'none';
        if (showMoreLink) showMoreLink.style.display = 'inline';
      });
    }
  });

  // Event listeners
  document.getElementById('cancel-extraction')?.addEventListener('click', function() {
    document.body.removeChild(modal);
  });

  document.getElementById('close-extraction')?.addEventListener('click', function() {
    document.body.removeChild(modal);
  });

  document.getElementById('proceed-generation')?.addEventListener('click', function() {
    // Collect selected TTPs
    var selectedTtps = [];
    document.querySelectorAll('.ttp-checkbox:checked').forEach(function(cb) {
      selectedTtps.push(cb.value);
    });

    // Collect selected IOCs (includes all IOCs, both visible and hidden)
    var selectedIocs = {};
    document.querySelectorAll('.ioc-checkbox:checked').forEach(function(cb) {
      var iocType = cb.getAttribute('data-ioc-type');
      if (!selectedIocs[iocType]) {
        selectedIocs[iocType] = [];
      }
      selectedIocs[iocType].push(cb.value);
    });

    if (selectedTtps.length === 0 && Object.keys(selectedIocs).length === 0) {
      alert('Please select at least one TTP or IOC to proceed.');
      return;
    }

    document.body.removeChild(modal);
    showLoading('generating detections');

    var formData = new FormData();
    formData.append('synthetic_group_name', data.synthetic_group_name);
    formData.append('selected_ttps', JSON.stringify(selectedTtps));
    formData.append('selected_iocs', JSON.stringify(selectedIocs));

    // Determine endpoint based on whether filename starts with "Blog:"
    var endpoint = (data.filename && data.filename.startsWith('Blog:')) ? '/blog/generate' : '/upload/generate';

    fetch(endpoint, {
      method: 'POST',
      body: formData,
      headers: { 'X-Requested-With': 'XMLHttpRequest' }
    })
    .then(function(response) {
      return response.json();
    })
    .then(function(result) {
      hideLoading();
      if (result.success && result.redirect) {
        window.location = result.redirect;
      } else if (result.error) {
        alert('Error: ' + result.error);
      }
    })
    .catch(function(err) {
      hideLoading();
      alert('Error: ' + err.message);
    });
  });
}


// Emulate form validation
document.addEventListener('DOMContentLoaded', function () {
  var emulateForm = document.getElementById('emulate-form');
  var techniqueInput = document.getElementById('emulate_technique');
  var emulateBtn = document.getElementById('emulate_btn');
  var remoteCheckbox = document.querySelector('input[name="remote_execution"]');
  var remoteConfig = document.getElementById('remote-config');

  function validateEmulate() {
    var val = (techniqueInput && techniqueInput.value) || '';
    var trimmed = val.trim();
    if (emulateBtn) {
      emulateBtn.disabled = trimmed === '';
    }
  }

  if (techniqueInput) {
    techniqueInput.addEventListener('input', validateEmulate);
    validateEmulate(); // Initial validation
  }

  // Show/hide remote config
  if (remoteCheckbox && remoteConfig) {
    remoteCheckbox.addEventListener('change', function () {
      remoteConfig.style.display = this.checked ? 'block' : 'none';
    });
  }

  if (emulateForm) {
    emulateForm.addEventListener('submit', function (e) {
      e.preventDefault();
      if (!techniqueInput || techniqueInput.value.trim() === '') {
        if (emulateBtn) emulateBtn.disabled = true;
        return false;
      }
      showLoading('emulation');

      var formData = new FormData(emulateForm);
      fetch('/emulate', {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
      })
      .then(function (response) {
        var contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) return response.json();
        return response.text();
      })
      .then(function (data) {
        if (typeof data === 'object' && data.redirect_url) {
          window.location = data.redirect_url;
          return;
        }
        var parser = new DOMParser();
        var doc = parser.parseFromString(data, 'text/html');
        var newContent = doc.getElementById('main-content');
        var oldContent = document.getElementById('main-content');
        if (newContent && oldContent) oldContent.innerHTML = newContent.innerHTML;
        hideLoading();
      })
      .catch(function (err) {
        hideLoading();
        alert('Error: ' + err.message);
      });
    });
  }
});

// Global function for clearing file selection
window.clearFileSelection = function () {
  var fileInput = document.getElementById('file-input');
  var fileSelected = document.getElementById('file-selected');
  if (fileInput) fileInput.value = '';
  if (fileSelected) fileSelected.style.display = 'none';
  var uploadBtn = document.getElementById('upload_btn');
  if (uploadBtn) uploadBtn.disabled = true;
};

// Threat Group Selection Modal
function showThreatGroupSelection(domain, recommendedGroups, profile) {
  // Create modal overlay
  var overlay = document.createElement('div');
  overlay.id = 'threat-group-selection-overlay';
  overlay.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 9999; display: flex; align-items: center; justify-content: center;';

  // Create modal
  var modal = document.createElement('div');
  modal.style.cssText = 'background: white; border-radius: 8px; padding: 2em; max-width: 700px; max-height: 80vh; overflow-y: auto; box-shadow: 0 4px 20px rgba(0,0,0,0.3);';

  // Modal content
  var html = '<h2 style="margin-top: 0;">🎯 Select Threat Groups for Detection Generation</h2>';
  html += '<p style="color: #666; margin-bottom: 1.5em;">Profile complete for <strong>' + domain + '</strong>. Select which threat groups you want to generate detections for:</p>';

  // Profile summary
  html += '<div style="background: #f8f9fa; padding: 1em; border-radius: 4px; margin-bottom: 1.5em;">';
  html += '<h3 style="margin: 0 0 0.5em 0; font-size: 1em;">Profile Summary</h3>';

  if (profile.threat_profile && profile.threat_profile.industry) {
    html += '<p style="margin: 0.3em 0;"><strong>Industry:</strong> ' + (profile.threat_profile.industry.sector || 'Unknown') + '</p>';
  }
  if (profile.threat_profile && profile.threat_profile.geography) {
    html += '<p style="margin: 0.3em 0;"><strong>Location:</strong> ' + (profile.threat_profile.geography.country || 'Unknown') + '</p>';
  }
  html += '<p style="margin: 0.3em 0;"><strong>Risk Score:</strong> ' + (profile.risk_score || 0) + '/100</p>';
  html += '<p style="margin: 0.3em 0;"><strong>Recommended Groups:</strong> ' + recommendedGroups.length + '</p>';
  html += '</div>';

  // Threat group checkboxes
  html += '<div style="max-height: 300px; overflow-y: auto; border: 1px solid #ddd; border-radius: 4px; padding: 1em;">';
  html += '<label style="display: block; margin-bottom: 0.5em;"><input type="checkbox" id="select-all-groups" style="margin-right: 0.5em;"><strong>Select All</strong></label>';
  html += '<hr style="margin: 0.5em 0;">';

  recommendedGroups.forEach(function(group, index) {
    html += '<label style="display: block; padding: 0.5em; margin: 0.3em 0; background: ' + (index % 2 === 0 ? '#f8f9fa' : 'white') + '; border-radius: 3px; cursor: pointer;">';
    html += '<input type="checkbox" class="group-checkbox" value="' + group + '" checked style="margin-right: 0.5em;">';
    html += '<span style="font-weight: 500;">' + group + '</span>';
    html += '</label>';
  });
  html += '</div>';

  // Correlation option
  html += '<div style="margin-top: 1em;">';
  html += '<label style="display: block;"><input type="checkbox" id="run-correlation" checked style="margin-right: 0.5em;"><strong>Generate correlations</strong> (recommended)</label>';
  html += '</div>';

  // Buttons
  html += '<div style="margin-top: 1.5em; display: flex; gap: 1em; justify-content: flex-end;">';
  html += '<button id="cancel-generation" style="padding: 0.7em 1.5em; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer;">Cancel</button>';
  html += '<button id="confirm-generation" style="padding: 0.7em 1.5em; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">Generate Detections</button>';
  html += '</div>';

  modal.innerHTML = html;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  // Event handlers
  document.getElementById('select-all-groups').addEventListener('change', function(e) {
    var checkboxes = document.querySelectorAll('.group-checkbox');
    checkboxes.forEach(function(cb) {
      cb.checked = e.target.checked;
    });
  });

  document.getElementById('cancel-generation').addEventListener('click', function() {
    document.body.removeChild(overlay);
  });

  document.getElementById('confirm-generation').addEventListener('click', function() {
    var selectedGroups = [];
    document.querySelectorAll('.group-checkbox:checked').forEach(function(cb) {
      selectedGroups.push(cb.value);
    });

    if (selectedGroups.length === 0) {
      alert('Please select at least one threat group');
      return;
    }

    var runCorrelation = document.getElementById('run-correlation').checked;

    // Close modal
    document.body.removeChild(overlay);

    // Show loading
    showLoading('generating detections for ' + selectedGroups.length + ' threat group(s)');

    // Submit to new endpoint
    var formData = new FormData();
    formData.append('domain', domain);
    formData.append('selected_groups', selectedGroups.join(','));
    formData.append('run_correlation', runCorrelation ? 'true' : 'false');

    fetch('/profile/generate-detections', {
      method: 'POST',
      body: formData,
      headers: { 'X-Requested-With': 'XMLHttpRequest' }
    })
    .then(function(response) {
      return response.json();
    })
    .then(function(data) {
      if (data.success && data.redirect_url) {
        window.location = data.redirect_url;
      } else if (data.error) {
        hideLoading();
        alert('Error: ' + data.error);
      }
    })
    .catch(function(error) {
      hideLoading();
      alert('Error generating detections: ' + error);
    });
  });
}
