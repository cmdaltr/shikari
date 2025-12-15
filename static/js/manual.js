// Client-side append/edit/draft handling for Manual Group Entry
(function () {
  var STORAGE_KEY = 'archer.manualEntries';
  var STORAGE_GROUP_KEY = 'archer.manualGroupName';
  var entries = [];

  function safeParse(json) {
    try { return JSON.parse(json); } catch (_) { return null; }
  }
  function loadEntries() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      var arr = safeParse(raw);
      entries = Array.isArray(arr) ? arr : [];
    } catch (_) { entries = []; }
  }
  function saveEntries() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(entries)); } catch (_) {}
  }
  function clearManualStorage() {
    try { localStorage.removeItem(STORAGE_KEY); } catch (_) {}
    try { localStorage.removeItem(STORAGE_GROUP_KEY); } catch (_) {}
  }

  function buildCard(entry) {
    var card = document.createElement('div');
    card.className = 'manual-entry';
    card.style.border = '1px solid #e5e7eb';
    card.style.borderRadius = '8px';
    card.style.padding = '0.75rem';
    card.style.marginBottom = '0.75rem';
    card.style.background = '#fafafa';

    if (entry.technique) {
      var head = document.createElement('div');
      head.className = 'subheading';
      head.textContent = entry.technique;
      card.appendChild(head);
    }
    if (entry.group_desc) {
      var desc = document.createElement('p');
      desc.style.margin = '0 0 .5rem 0';
      desc.textContent = entry.group_desc;
      card.appendChild(desc);
    }
    if (entry.tactics && entry.tactics.length) {
      var badgeWrap = document.createElement('div');
      badgeWrap.style.margin = '0 0 .5rem 0';
      entry.tactics.forEach(function (t) {
        var b = document.createElement('span');
        b.className = 'tactic-badge';
        b.textContent = t;
        badgeWrap.appendChild(b);
      });
      card.appendChild(badgeWrap);
    }
    if (entry.procedures && entry.procedures.length) {
      var ul = document.createElement('ul');
      ul.style.margin = '0';
      ul.style.paddingLeft = '1.1rem';
      entry.procedures.forEach(function (p) {
        var li = document.createElement('li');
        li.textContent = p;
        ul.appendChild(li);
      });
      card.appendChild(ul);
    }
    return card;
  }

  function renderAll() {
    var list = document.getElementById('technique-list');
    if (!list) return;
    list.innerHTML = '';
    entries.forEach(function (e) { list.appendChild(buildCard(e)); });
  }

  document.addEventListener('DOMContentLoaded', function () {
    loadEntries();
    renderAll();

    // Show stored group name or infer from first entry; hide description block if present
    var nameEl = document.getElementById('group-name');
    var descBlock = document.getElementById('group_desc_block');
    var nameSet = false;
    try {
      var storedName = localStorage.getItem(STORAGE_GROUP_KEY) || '';
      if (storedName) {
        if (nameEl) {
          nameEl.textContent = storedName;
          nameEl.hidden = false;
          nameEl.style.display = 'block';
        }
        if (descBlock) descBlock.style.display = 'none';
        nameSet = true;
      }
    } catch (_) {}
    if (entries.length > 0 && !nameSet) {
      if (descBlock) descBlock.style.display = 'none';
      if (nameEl && !nameEl.textContent.trim()) {
        var firstDesc = entries[0] && entries[0].group_desc;
        if (firstDesc) {
          nameEl.textContent = firstDesc;
          nameEl.hidden = false;
          nameEl.style.display = 'block';
          try { localStorage.setItem(STORAGE_GROUP_KEY, firstDesc); } catch (_) {}
        }
      }
    }

    // Append handler
    var appendBtn = document.getElementById('append-btn');
    if (appendBtn && appendBtn.dataset.bound !== '1') {
      appendBtn.dataset.bound = '1';
      appendBtn.addEventListener('click', function () {
        try {
          var groupDescEl = document.getElementById('group_desc');
          var techniqueEl = document.getElementById('technique');
          var proceduresEl = document.getElementById('procedures');
          var list = document.getElementById('technique-list');
          if (!list) return;

          var groupDesc = (groupDescEl && groupDescEl.value || '').trim();
          var technique = (techniqueEl && techniqueEl.value || '').trim();
          var proceduresRaw = (proceduresEl && proceduresEl.value) || '';
          var procedures = proceduresRaw.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
          var tactics = Array.prototype.slice.call(document.querySelectorAll('input[name="tactics"]:checked'))
            .map(function (i) { return i.value; });

          if (!technique && !groupDesc && !tactics.length && !procedures.length) return;

          var entry = { group_desc: groupDesc, technique: technique, tactics: tactics, procedures: procedures };
          entries.push(entry);
          saveEntries();
          list.appendChild(buildCard(entry));

          // After first append, hide description and set group name
          if (entries.length === 1) {
            if (descBlock) descBlock.style.display = 'none';
            if (nameEl && !nameEl.textContent.trim() && groupDesc) {
              nameEl.textContent = groupDesc;
              nameEl.hidden = false;
              nameEl.style.display = 'block';
            }
            try { if (groupDesc) localStorage.setItem(STORAGE_GROUP_KEY, groupDesc); } catch (_) {}
          }

          var msg = document.getElementById('append-message');
          if (msg) {
            msg.textContent = 'Appended (saved locally).';
            msg.style.display = 'block';
            msg.style.color = 'green';
            msg.setAttribute('role', 'status');
            clearTimeout(window.__appendMsgTimer);
            window.__appendMsgTimer = setTimeout(function () { msg.style.display = 'none'; }, 1800);
          }
        } catch (e) {
          if (window.console && console.error) console.error(e);
        }
      });
    }

    // Submit handler -> POST to /generate with FormData, handle JSON/HTML, clear storage
    var submitBtn = document.getElementById('submit-btn');
    if (submitBtn && submitBtn.dataset.bound !== '1') {
      submitBtn.dataset.bound = '1';
      submitBtn.addEventListener('click', function () {
        try {
          var msg = document.getElementById('append-message');
          if (!entries || !entries.length) {
            if (msg) {
              msg.textContent = 'Please append at least one entry before submitting.';
              msg.style.display = 'block';
              msg.style.color = 'darkred';
              msg.setAttribute('role', 'alert');
            }
            return;
          }

          // Prefer stored group name, then heading, then current/first description
          var storedName = '';
          try { storedName = localStorage.getItem(STORAGE_GROUP_KEY) || ''; } catch (_) {}
          var groupName = (storedName || ((nameEl && nameEl.textContent) || '')).trim();
          if (!groupName) {
            var gdEl = document.getElementById('group_desc');
            var currentDesc = (gdEl && gdEl.value || '').trim();
            groupName = currentDesc || (entries[0] && entries[0].group_desc) || '';
          }

          var prevSubmitText = submitBtn.textContent;
          submitBtn.disabled = true;
          if (appendBtn) appendBtn.disabled = true;
          submitBtn.textContent = 'Submitting...';

          var fd = new FormData();
          fd.append('group_name', groupName);
          fd.append('manual', '1');
          fd.append('manual_entries', JSON.stringify(entries));

          fetch('/generate', {
            method: 'POST',
            body: fd,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
          })
          .then(function (response) {
            var contentType = response.headers.get('content-type') || '';
            if (contentType.includes('application/json')) {
              return response.json().then(function (payload) { return { kind: 'json', payload: payload }; });
            }
            return response.text().then(function (payload) { return { kind: 'html', payload: payload }; });
          })
          .then(function (res) {
            if (res.kind === 'json') {
              var data = res.payload || {};
              if (data.redirect_url) {
                clearManualStorage();
                window.location = data.redirect_url;
                return;
              }
              if (msg) {
                msg.textContent = data.message || 'Unexpected response.';
                msg.style.display = 'block';
                msg.style.color = 'darkred';
                msg.setAttribute('role', 'alert');
              }
              return;
            }
            var parser = new DOMParser();
            var doc = parser.parseFromString(res.payload, 'text/html');
            var newContent = doc.getElementById('main-content');
            var oldContent = document.getElementById('main-content');
            if (newContent && oldContent) {
              oldContent.innerHTML = newContent.innerHTML;
              clearManualStorage();
            }
          })
          .catch(function (err) {
            if (msg) {
              msg.textContent = 'Submit failed: ' + err.message;
              msg.style.display = 'block';
              msg.style.color = 'darkred';
              msg.setAttribute('role', 'alert');
            }
          })
          .finally(function () {
            submitBtn.disabled = false;
            if (appendBtn) appendBtn.disabled = false;
            submitBtn.textContent = prevSubmitText || 'Submit';
          });
        } catch (e) {
          if (window.console && console.error) console.error(e);
        }
      });
    }
  });

  // Blog/Report Analysis Handler
  var analyzeBlogBtn = document.getElementById('analyze-blog-btn');
  if (analyzeBlogBtn) {
    analyzeBlogBtn.addEventListener('click', function () {
      var blogUrlInput = document.getElementById('blog_url');
      var statusDiv = document.getElementById('blog-analysis-status');

      if (!blogUrlInput || !blogUrlInput.value.trim()) {
        if (statusDiv) {
          statusDiv.textContent = 'Please enter a valid URL';
          statusDiv.style.color = 'darkred';
        }
        return;
      }

      var url = blogUrlInput.value.trim();

      // Validate URL format
      try {
        new URL(url);
      } catch (e) {
        if (statusDiv) {
          statusDiv.textContent = 'Invalid URL format. Please enter a complete URL (e.g., https://example.com/blog/post)';
          statusDiv.style.color = 'darkred';
        }
        return;
      }

      // Disable button and show loading
      analyzeBlogBtn.disabled = true;
      analyzeBlogBtn.textContent = 'Analyzing...';

      if (statusDiv) {
        statusDiv.textContent = 'Fetching and analyzing blog post...';
        statusDiv.style.color = '#0066cc';
      }

      // Send request to analyze blog
      fetch('/analyze_blog', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({ url: url })
      })
      .then(function (response) {
        return response.json();
      })
      .then(function (data) {
        if (data.success) {
          if (statusDiv) {
            statusDiv.textContent = data.message || 'Analysis complete! Techniques and procedures have been extracted.';
            statusDiv.style.color = '#28a745';
          }

          // Populate fields if data was extracted
          if (data.group_name) {
            var groupNameEl = document.getElementById('group_name');
            if (groupNameEl) {
              groupNameEl.textContent = data.group_name;
              groupNameEl.removeAttribute('hidden');
            }
          }

          if (data.group_desc) {
            var groupDescEl = document.getElementById('group_desc');
            if (groupDescEl) groupDescEl.value = data.group_desc;
          }

          if (data.technique) {
            var techniqueEl = document.getElementById('technique');
            if (techniqueEl) techniqueEl.value = data.technique;
          }

          if (data.tactics && data.tactics.length) {
            var tacticCheckboxes = document.querySelectorAll('input[name="tactics"]');
            tacticCheckboxes.forEach(function (checkbox) {
              if (data.tactics.includes(checkbox.value)) {
                checkbox.checked = true;
              }
            });
          }

          if (data.procedures) {
            var proceduresEl = document.getElementById('procedures');
            if (proceduresEl) proceduresEl.value = data.procedures;
          }

          // Scroll to the form
          window.scrollTo({ top: 0, behavior: 'smooth' });
        } else {
          if (statusDiv) {
            statusDiv.textContent = data.message || 'Analysis failed. Please try again.';
            statusDiv.style.color = 'darkred';
          }
        }
      })
      .catch(function (err) {
        if (statusDiv) {
          statusDiv.textContent = 'Error: ' + err.message;
          statusDiv.style.color = 'darkred';
        }
      })
      .finally(function () {
        analyzeBlogBtn.disabled = false;
        analyzeBlogBtn.textContent = 'Analyze Blog Post';
      });
    });
  }
})();