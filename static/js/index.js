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
  var popup = document.getElementById('shikari-desc-popup');
  var hideCheckbox = document.getElementById('hide-desc-popup-checkbox');
  var dontShowCheckbox = document.getElementById('dont-show-desc-popup-checkbox');
  var dontShow = localStorage.getItem('shikariDontShowDescPopup');
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
          localStorage.setItem('shikariDontShowDescPopup', 'true');
          popup.style.display = 'none';
        } else {
          localStorage.setItem('shikariDontShowDescPopup', 'false');
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
    var techEl = document.getElementById('technique_input');
    var techVal = (techEl && techEl.value) || '';

    if (val.length > 30) {
      if (errorSpan) errorSpan.style.display = 'inline';
      if (btn) btn.disabled = true;
      return;
    } else {
      if (errorSpan) errorSpan.style.display = 'none';
    }

    var trimmed = val.trim();
    var cveTrimmed = cveVal.trim();

    // Enable the button when the group, CVE or technique field has a value
    if (btn) btn.disabled = (trimmed === '' && cveTrimmed === '' && techVal.trim() === '');

    // Enable threat briefing button only when group name is present
    var briefingBtn = document.getElementById('briefing-btn');
    if (briefingBtn) briefingBtn.disabled = (trimmed === '');
  }

  // Get CVE input reference before validate is called
  var cveInput = document.getElementById('cve_input');

  validate();

  // One of group, CVE or techniques: filling one disables the other two until it's cleared
  var techniqueField = document.getElementById('technique_input');
  var huntFields = [
    { el: input, using: 'Threat Group', placeholder: 'e.g., APT29, Scattered Spider' },
    { el: cveInput, using: 'CVE', placeholder: 'e.g., CVE-2024-1234 or CVE-2021-44228, CVE-2022-22965' },
    { el: techniqueField, using: 'ATT&CK techniques', placeholder: 'e.g., T1003, T1021.001, T1078' },
  ].filter(function (f) { return f.el; });
  function exclusive() {
    var active = huntFields.filter(function (f) { return f.el.value.trim(); })[0];
    huntFields.forEach(function (f) {
      var off = !!active && active !== f;
      f.el.disabled = off;
      f.el.placeholder = off ? 'Disabled (using ' + active.using + ')' : f.placeholder;
      f.el.style.opacity = off ? '0.5' : '1';
    });
    validate();
  }
  huntFields.forEach(function (f) { f.el.addEventListener('input', exclusive); });

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
      var lolCheckbox = document.getElementById('lol-datasets-checkbox');
      if (lolCheckbox) {
        formData.delete('lol_datasets');
        formData.append('lol_datasets', lolCheckbox.checked ? 'true' : 'false');
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

        // Profiling runs in the background now; follow the redirect to the progress page,
        // which then opens the Review page (summary, exposure map, groups) when it finishes.
        if (typeof data === 'object' && data.redirect_url) {
          window.location = data.redirect_url;
          return;
        }
        if (typeof data === 'object') {
          alert(data.error ? 'Could not start profiling: ' + data.error : 'Profiling started.');
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

  // /?report=<url> (the Threat Feed's "Analyse in Shikari"): open the Analyse tab with the URL filled in
  var reportParam = new URLSearchParams(window.location.search).get('report');
  if (blogUrlInput && reportParam && /^https?:\/\//.test(reportParam)) {
    var uploadTab = document.querySelector('.tab-button[data-tab="upload"]');
    if (uploadTab) uploadTab.click();
    blogUrlInput.value = reportParam;
    validateUpload();
  }

  // Drag and drop support
  if (dropzone) {
    dropzone.addEventListener('dragover', function (e) {
      e.preventDefault();
      e.stopPropagation();
    });

    dropzone.addEventListener('dragleave', function (e) {
      e.preventDefault();
      e.stopPropagation();
    });

    dropzone.addEventListener('drop', function (e) {
      e.preventDefault();
      e.stopPropagation();

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

      // The same AI prompt as Hunt: the chosen AI reads the report and generates detections
      function run() {
        if (hasUrl && !hasFile) {
          // Blog URL analysis
          showLoading('blog analysis');
          var blogFormData = new FormData();
          blogFormData.append('url', url.trim());
          blogFormData.append('ai_provider', document.getElementById('upload_ai_provider').value);
          blogFormData.append('ai_model', document.getElementById('upload_ai_model').value);

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
      }
      if (!window.shikariAskAi) return run();
      window.shikariAskAi({ title: 'Use AI for this report?', purpose: 'read the report and generate detections alongside the standard pipeline', run: 'process it' },
        function (providerId, modelId) {
          document.getElementById('upload_ai_provider').value = providerId;
          document.getElementById('upload_ai_model').value = modelId;
          run();
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
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-modal', 'true');
  modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:9500;display:flex;align-items:center;justify-content:center;';

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

  // No form control ever sent auto_generate, so gating on it left users with only Close
  if (data.ttps_count > 0 || data.iocs_count > 0) {
    var ttpsPending = data.ttps && data.ttps.length > 0;
    html += '<button id="proceed-generation"' + (ttpsPending ? ' disabled title="Loading techniques…"' : '') + ' style="padding:0.75em 1.5em;border:none;background:#007bff;color:white;border-radius:4px;cursor:pointer;font-size:1em;font-weight:500;">Proceed with Selected Items</button>';
  } else {
    html += '<button id="close-extraction" style="padding:0.75em 1.5em;border:none;background:#28a745;color:white;border-radius:4px;cursor:pointer;font-size:1em;font-weight:500;">Close</button>';
  }
  html += '</div>';

  modalContent.innerHTML = html;
  modal.appendChild(modalContent);
  document.body.appendChild(modal);

  // Proceed waits for the TTP checkboxes: clicking while they load would send none
  function enableProceed() {
    var btn = document.getElementById('proceed-generation');
    if (btn) { btn.disabled = false; btn.removeAttribute('title'); }
  }

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
        enableProceed();
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
        enableProceed();
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
    // The Analyse tab's options (unchecked boxes send nothing, so send each one)
    [['lol_datasets', 'upload_lol_datasets'], ['osint_enhancement', 'upload_osint_enhancement'],
     ['osint_comparison', 'upload_osint_comparison']].forEach(function (pair) {
      var box = document.getElementById(pair[1]);
      if (box) formData.append(pair[0], box.checked ? 'true' : 'false');
    });

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



// Profile → Technology stack: say when group hunts are filtered by it, with a way out
document.addEventListener('DOMContentLoaded', function () {
  var note = document.getElementById('hp-stack-note');
  if (!note) return;
  fetch('/api/profile/stack').then(function (r) { return r.ok ? r.json() : null; }).then(function (data) {
    var n = data && data.stack ? data.stack.length : 0;
    if (!n) return;
    document.getElementById('hp-stack-count').textContent = n + ' product' + (n === 1 ? '' : 's');
    note.hidden = false;
  }).catch(function () {});
});


// Recent CVEs picker: the last 30 days (shikari.intelligence.cve_feed, /api/cves/recent).
// Picking a CVE adds it to the CVE field; picking it again takes it out.
document.addEventListener('DOMContentLoaded', function () {
  var dialog = document.getElementById('cve-picker');
  var open = document.getElementById('cve-browse');
  var field = document.getElementById('cve_input');
  if (!dialog || !open || !field || typeof dialog.showModal !== 'function') return;
  var list = document.getElementById('cvp-list');
  var search = document.getElementById('cvp-search');
  var kev = document.getElementById('cvp-kev');
  var stack = document.getElementById('cvp-stack');
  var high = document.getElementById('cvp-high');
  var more = document.getElementById('cvp-more');
  var count = document.getElementById('cvp-count');
  var picked = document.getElementById('cvp-selected');
  var PAGE = 50;
  var offset = 0, ask = 0, timer = null;

  function chosen() {
    return field.value.split(',').map(function (c) { return c.trim().toUpperCase(); }).filter(Boolean);
  }

  function setChosen(ids) {
    field.value = ids.join(', ');
    field.dispatchEvent(new Event('input', { bubbles: true }));  // the group field and Generate follow it
    picked.textContent = ids.length ? ids.length + ' selected: ' + ids.join(', ') : 'Nothing selected yet';
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function badge(cls, text, title) {
    var b = el('span', 'cvp-badge ' + cls, text);
    if (title) b.title = title;
    return b;
  }

  function row(c) {
    var li = el('li', 'cvp-row');
    li.tabIndex = 0;
    li.setAttribute('role', 'checkbox');
    li.dataset.id = c.cve_id;
    li.setAttribute('aria-checked', String(chosen().indexOf(c.cve_id) >= 0));
    var tick = el('span', 'cvp-tick', '✓');
    tick.setAttribute('aria-hidden', 'true');
    var body = el('div');
    var line = el('div', 'cvp-line');
    line.appendChild(el('span', 'cvp-id', c.cve_id));
    line.appendChild(el('span', 'cvp-date', (c.published || '').slice(0, 10)));
    var cvss = c.cvss_v3 || {};
    var sev = String(cvss.severity || '').toLowerCase();
    line.appendChild(cvss.score != null
      ? badge('cvp-sev-' + (sev || 'none'), cvss.score + ' ' + sev.charAt(0).toUpperCase() + sev.slice(1), 'CVSS v3 ' + (cvss.vector || ''))
      : badge('cvp-sev-none', 'Not scored yet', 'NVD has not analysed it yet'));
    if (c.kev) {
      line.appendChild(badge('cvp-kev', 'Exploited',
        'In CISA KEV since ' + (c.kev.date_added || '?') + (c.kev.due ? '; federal patch deadline ' + c.kev.due : '')));
      if (c.kev.ransomware) line.appendChild(badge('cvp-ransom', 'Ransomware', 'Known use in ransomware campaigns'));
    }
    (c.on_stack || []).forEach(function (p) { line.appendChild(badge('cvp-stack', p, 'In your technology stack')); });
    if (c.researched) line.appendChild(badge('cvp-done-mark', 'Researched', 'Already researched: its hunt starts at once'));
    var others = (c.products || []).filter(function (p) { return (c.on_stack || []).indexOf(p) < 0; });
    if (others.length) line.appendChild(el('span', 'cvp-prod', others.join(', ')));
    body.appendChild(line);
    var desc = el('p', 'cvp-desc', c.description || '');
    desc.title = c.description || '';
    body.appendChild(desc);
    li.appendChild(tick);
    li.appendChild(body);
    return li;
  }

  function toggle(li) {
    var ids = chosen(), id = li.dataset.id, at = ids.indexOf(id);
    if (at >= 0) ids.splice(at, 1); else ids.push(id);
    li.setAttribute('aria-checked', String(at < 0));
    setChosen(ids);
  }

  function load(reset) {
    if (reset) offset = 0;
    var mine = ++ask;
    var qs = new URLSearchParams({ q: search.value.trim(), offset: String(offset), limit: String(PAGE) });
    if (kev.checked) qs.set('kev', 'true');
    if (stack.checked) qs.set('stack', 'true');
    if (high.checked) qs.set('min_score', '7');
    if (reset) count.textContent = 'Loading…';
    fetch('/api/cves/recent?' + qs).then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); }).then(function (data) {
      if (mine !== ask) return;  // a newer search has been asked for
      var chip = document.getElementById('cvp-stack-chip');
      stack.disabled = !data.has_stack;
      chip.title = data.has_stack ? '' : 'Set a technology stack in Profile to filter by it';
      if (reset) list.replaceChildren();
      (data.cves || []).forEach(function (c) { list.appendChild(row(c)); });
      offset += (data.cves || []).length;
      more.hidden = offset >= data.total;
      var st = data.status || {};
      if (!data.total && !st.last_refresh) {
        list.replaceChildren(el('li', 'cvp-empty', st.refreshing
          ? 'Collecting the last 30 days from the NVD. The first collection takes about 20 minutes.'
          : 'No CVEs collected yet: they are collected when Shikari starts.'));
        count.textContent = '';
        return;
      }
      if (!data.total) list.replaceChildren(el('li', 'cvp-empty', 'No CVE in the last ' + data.window_days + ' days matches.'));
      count.textContent = data.total.toLocaleString('en-GB') + ' CVE' + (data.total === 1 ? '' : 's') +
        (st.last_refresh ? ' · updated ' + new Date(st.last_refresh).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : '') +
        (st.refreshing ? ' · updating now' : '');
    }).catch(function () {
      if (mine === ask) count.textContent = 'Recent CVEs could not be loaded.';
    });
  }

  open.addEventListener('click', function () {
    if (field.disabled) return;
    setChosen(chosen());
    dialog.showModal();
    search.focus();
    load(true);
  });
  // The group field disables the CVE field; the link follows it
  new MutationObserver(function () { open.disabled = field.disabled; })
    .observe(field, { attributes: true, attributeFilter: ['disabled'] });

  list.addEventListener('click', function (e) {
    var li = e.target.closest('.cvp-row');
    if (li) toggle(li);
  });
  list.addEventListener('keydown', function (e) {
    var li = e.target.closest('.cvp-row');
    if (!li) return;
    if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); toggle(li); }
    if (e.key === 'ArrowDown' && li.nextElementSibling) { e.preventDefault(); li.nextElementSibling.focus(); }
    if (e.key === 'ArrowUp' && li.previousElementSibling) { e.preventDefault(); li.previousElementSibling.focus(); }
  });
  search.addEventListener('keydown', function (e) { if (e.key === 'Enter') e.preventDefault(); });  // it's inside the Hunt form
  search.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(function () { load(true); }, 250); });
  [kev, stack, high].forEach(function (box) { box.addEventListener('change', function () { load(true); }); });
  more.addEventListener('click', function () { load(false); });
  document.getElementById('cvp-done').addEventListener('click', function () { dialog.close(); field.focus(); });
  document.getElementById('cvp-close').addEventListener('click', function () { dialog.close(); });
  dialog.addEventListener('click', function (e) { if (e.target === dialog) dialog.close(); });  // the backdrop
});

// Home-page OSINT key control: toggle a saved key on/off, or add one via a modal (POST /api/osint-key),
// so a key can be managed without the Profile page. Draws the row's button to match the new state.
(function () {
  const list = document.querySelector('.hp-keys-list');
  const modal = document.getElementById('osint-key-modal');
  if (!list || !modal) return;

  const input = document.getElementById('osint-key-input');
  const errEl = document.getElementById('osint-key-err');
  const envEl = document.getElementById('osint-key-env');
  const whatEl = document.getElementById('osint-key-what');
  const saveBtn = document.getElementById('osint-key-save');
  let active = null;  // the row a modal save will act on

  async function post(payload) {
    const r = await fetch('/api/osint-key', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
    });
    return r.json();
  }

  function toggleButton(enabled) {
    const on = !!enabled;
    return `<button type="button" class="hp-key-toggle${on ? ' is-on' : ''}" role="switch" aria-checked="${on}">` +
      `<span class="hp-key-knob"></span><span class="hp-key-state">${on ? 'On' : 'Off'}</span></button>`;
  }

  function openModal(row) {
    active = row;
    envEl.textContent = row.dataset.env;
    whatEl.textContent = (row.querySelector('.hp-key-what') || {}).textContent || '';
    input.value = '';
    errEl.hidden = true;
    modal.hidden = false;
    input.focus();
  }
  function closeModal() { modal.hidden = true; active = null; }

  list.addEventListener('click', async function (e) {
    const toggle = e.target.closest('.hp-key-toggle');
    const add = e.target.closest('.hp-key-add');
    if (toggle) {
      const row = toggle.closest('.hp-key-row');
      const next = !toggle.classList.contains('is-on');
      toggle.disabled = true;
      const res = await post({ platform: row.dataset.platform, enabled: next }).catch(() => null);
      toggle.disabled = false;
      if (res && res.success) {
        toggle.classList.toggle('is-on', res.enabled);
        toggle.setAttribute('aria-checked', String(res.enabled));
        toggle.querySelector('.hp-key-state').textContent = res.enabled ? 'On' : 'Off';
      }
    } else if (add) {
      openModal(add.closest('.hp-key-row'));
    }
  });

  saveBtn.addEventListener('click', async function () {
    if (!active) return;
    const key = input.value.trim();
    if (!key) { errEl.textContent = 'Enter a key.'; errEl.hidden = false; return; }
    saveBtn.disabled = true;
    const res = await post({ platform: active.dataset.platform, key }).catch(() => null);
    saveBtn.disabled = false;
    if (res && res.success) {
      const addBtn = active.querySelector('.hp-key-add');
      if (addBtn) addBtn.outerHTML = toggleButton(res.enabled);
      closeModal();
    } else {
      errEl.textContent = (res && res.error) || 'Could not save the key.';
      errEl.hidden = false;
    }
  });

  input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); saveBtn.click(); } });
  modal.querySelector('.hp-modal-close').addEventListener('click', closeModal);
  document.getElementById('osint-key-cancel').addEventListener('click', closeModal);
  modal.addEventListener('click', e => { if (e.target === modal) closeModal(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && !modal.hidden) closeModal(); });
})();
