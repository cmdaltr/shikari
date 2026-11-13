// Client-side append/edit/draft handling for Manual Group Entry
(function () {
  var STORAGE_KEY = 'shikari.manualEntries';
  var STORAGE_GROUP_KEY = 'shikari.manualGroupName';
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
  // A reference must be a web link: anything else is refused at Append (and again by the server)
  function badReferences(lines) {
    return lines.filter(function (line) {
      if (/\s/.test(line)) return true;
      try {
        var u = new URL(line);
        return !((u.protocol === 'http:' || u.protocol === 'https:') && u.host);
      } catch (_) { return true; }
    });
  }
  function techniquePlatforms() {
    var el = document.getElementById('mn-technique-platforms');
    return (el && safeParse(el.textContent)) || {};
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
    // Entries appended before Platforms existed have none: the server uses the technique's
    if (entry.platforms && entry.platforms.length) {
      var platWrap = document.createElement('div');
      platWrap.style.margin = '0 0 .5rem 0';
      entry.platforms.forEach(function (p) {
        var b = document.createElement('span');
        b.className = 'platform-badge';
        b.textContent = p;
        platWrap.appendChild(b);
      });
      card.appendChild(platWrap);
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
    // Entries appended before Indicators existed have none: their queries come from AI or the LOL datasets
    if (entry.indicators && entry.indicators.length) {
      var indTitle = document.createElement('p');
      indTitle.className = 'mn-indicators-title';
      indTitle.textContent = 'Indicators';
      card.appendChild(indTitle);
      var inds = document.createElement('ul');
      inds.className = 'mn-indicators';
      entry.indicators.forEach(function (v) {
        var li = document.createElement('li');
        li.textContent = v;
        inds.appendChild(li);
      });
      card.appendChild(inds);
    }
    if (entry.references && entry.references.length) {
      var refs = document.createElement('ul');
      refs.className = 'mn-refs';
      entry.references.forEach(function (r) {
        var li = document.createElement('li');
        var a = document.createElement('a');
        // Only links Append accepted reach here, but an older stored entry is checked again
        if (!badReferences([r]).length) a.href = r;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = r;
        li.appendChild(a);
        refs.appendChild(li);
      });
      card.appendChild(refs);
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

    // Choosing a technique ticks its ATT&CK platforms; the user can change them before Append
    var platformsOf = techniquePlatforms();
    var techniqueSel = document.getElementById('technique');
    if (techniqueSel) {
      techniqueSel.addEventListener('change', function () {
        var tid = (techniqueSel.value.split(':')[0] || '').trim().toUpperCase();
        var own = platformsOf[tid] || [];
        document.querySelectorAll('input[name="platforms"]').forEach(function (box) {
          box.checked = own.indexOf(box.value) !== -1;
        });
      });
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
          var platforms = Array.prototype.slice.call(document.querySelectorAll('input[name="platforms"]:checked'))
            .map(function (i) { return i.value; });
          var indicatorsEl = document.getElementById('indicators');
          var indicators = ((indicatorsEl && indicatorsEl.value) || '').split('\n')
            .map(function (s) { return s.trim(); }).filter(Boolean);
          var referencesEl = document.getElementById('references');
          var references = ((referencesEl && referencesEl.value) || '').split('\n')
            .map(function (s) { return s.trim(); }).filter(Boolean);

          if (!technique && !groupDesc && !tactics.length && !procedures.length) return;

          var bad = badReferences(references);
          if (bad.length) {
            var refMsg = document.getElementById('append-message');
            if (refMsg) {
              refMsg.textContent = 'References must be http:// or https:// URLs, one per line: ' + bad.slice(0, 3).join(', ');
              refMsg.style.display = 'block';
              refMsg.style.color = 'darkred';
              refMsg.setAttribute('role', 'alert');
              clearTimeout(window.__appendMsgTimer);
            }
            return;
          }

          var entry = { group_desc: groupDesc, technique: technique, tactics: tactics, platforms: platforms,
                        procedures: procedures, indicators: indicators, references: references };
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

    // Submit handler -> POST to /manual_submit with FormData, handle JSON/HTML, clear storage
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

          // The Hunt tab's AI prompt (templates/partials/ai_prompt.html); without it, no AI
          if (window.shikariAskAi) {
            window.shikariAskAi({ title: 'Use AI for these detections?',
                                  purpose: 'generate detections alongside the standard pipeline', run: 'submit' },
                                function (providerId, modelId) { send(groupName, providerId, modelId); });
          } else {
            send(groupName, '', '');
          }
        } catch (e) {
          if (window.console && console.error) console.error(e);
        }
      });
    }

    function send(groupName, aiProvider, aiModel) {
      var msg = document.getElementById('append-message');
      try {
        var prevSubmitText = submitBtn.textContent;
        submitBtn.disabled = true;
        if (appendBtn) appendBtn.disabled = true;
        submitBtn.textContent = 'Submitting...';

        var fd = new FormData();
        fd.append('group_name', groupName);
        fd.append('group_desc', (entries[0] && entries[0].group_desc) || '');
        fd.append('technique_entries', JSON.stringify(entries));
        fd.append('ai_provider', aiProvider || '');
        fd.append('ai_model', aiModel || '');
        // Every option sent as true/false: an unticked box sends nothing, and the server's
        // defaults are the Hunt tab's (correlations, LOL and OSINT Enhancement on)
        [['auto_validate', 'mn-auto-validate'], ['lol_datasets', 'mn-lol-datasets'],
         ['osint_enhancement', 'mn-osint-enhancement'], ['osint_comparison', 'mn-osint-comparison'],
         ['run_correlation', 'mn-run-correlation']].forEach(function (pair) {
          var box = document.getElementById(pair[1]);
          if (box) fd.append(pair[0], box.checked && !box.disabled ? 'true' : 'false');
        });

        fetch('/manual_submit', {
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
    }
  });
})();