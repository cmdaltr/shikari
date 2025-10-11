var loadingInterval;
function showLoading(groupName) {
  var overlay = document.getElementById('loading-overlay');
  var groupSpan = document.getElementById('loading-group');
  var dots = document.getElementById('loading-dots');
  if (groupSpan) groupSpan.textContent = groupName ? ("for '" + groupName + "'") : '';
  overlay.style.display = 'flex';
  if (dots) {
    var count = 0;
    loadingInterval = setInterval(function () {
      count = (count + 1) % 4;
      dots.textContent = '.'.repeat(count);
    }, 500);
  }
}
function hideLoading() {
  document.getElementById('loading-overlay').style.display = 'none';
  if (loadingInterval) { clearInterval(loadingInterval); loadingInterval = null; }
  var dots = document.getElementById('loading-dots'); if (dots) dots.textContent = '';
  var groupSpan = document.getElementById('loading-group'); if (groupSpan) groupSpan.textContent = '';
}

document.addEventListener('DOMContentLoaded', function () {
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
    if (val.length > 30) {
      if (errorSpan) errorSpan.style.display = 'inline';
      if (btn) btn.disabled = true;
      return;
    } else {
      if (errorSpan) errorSpan.style.display = 'none';
    }
    var trimmed = val.trim();
    if (btn) btn.disabled = (trimmed === '');
  }

  validate();

  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (!input || input.value.trim() === '') {
        if (btn) btn.disabled = true;
        return false;
      }
      showLoading(input.value);

      var formData = new FormData(form);
      fetch('/generate', {
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
