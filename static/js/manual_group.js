// Client-side append/edit/draft handling for Manual Group Entry
(function(){
  const form = document.getElementById('manual-group-form');
  const appendBtn = document.getElementById('append-btn');
  const appendMsg = document.getElementById('append-message');
  const techniqueList = document.getElementById('technique-list');

  let techniqueEntries = [];
  let editingIndex = -1; // -1 means not editing

  function uuidv4(){
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c){
      const r = Math.random()*16|0, v = c=='x'? r : (r&0x3|0x8);
      return v.toString(16);
    });
  }

  function getDraftId(){
    const name = 'draft_id=';
    const dc = document.cookie.split(';').map(s=>s.trim());
    for(const c of dc){ if(c.indexOf(name)===0) return c.substring(name.length); }
    const id = uuidv4();
    const d = new Date(); d.setFullYear(d.getFullYear()+1);
    document.cookie = `draft_id=${id}; path=/; expires=${d.toUTCString()}`;
    return id;
  }

  function getUserIdFromCookie(){
    const name = 'user_id=';
    const dc = document.cookie.split(';').map(s=>s.trim());
    for(const c of dc){ if(c.indexOf(name)===0) return c.substring(name.length); }
    return null;
  }

  function readUserId(){ if(typeof window !== 'undefined' && window.USER_ID) return window.USER_ID; return getUserIdFromCookie(); }

  async function saveDraft(){
    try{
      const payload = {draft_id: draftId, group_name: form.group_name.value || '', entries: techniqueEntries};
      const uid = readUserId(); if(uid) payload.user_id = uid;
      await fetch('/save_draft', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
    }catch(e){ /* ignore */ }
  }

  async function loadDraft(){
    try{
      const uid = readUserId();
      const qp = uid ? `?draft_id=${draftId}&user_id=${encodeURIComponent(uid)}` : `?draft_id=${draftId}`;
      const res = await fetch(`/load_draft${qp}`);
      if(res.ok){
        const data = await res.json();
        if(data && data.entries){ techniqueEntries = data.entries; renderTechniqueList(); }
      }
    }catch(e){ /* ignore */ }
  }

  function renderTechniqueList(){
    if(!techniqueEntries.length){ techniqueList.innerHTML = ''; return; }
    let html = '<h4>Appended Techniques</h4><ul style="list-style:none; padding:0;">';
    techniqueEntries.forEach((e, idx)=>{
      const badges = (e.tactics||[]).map(t=>`<span class="tactic-badge">${escapeHtml(t)}</span>`).join(' ');
      html += `<li style="padding:0.4rem 0; border-bottom:1px solid #eee; display:flex; justify-content:space-between; align-items:center;">
        <div style="flex:1;">
          <div><strong>${escapeHtml(e.technique)}</strong></div>
          <div style="font-size:0.9rem;color:#444;">${badges || '<span style="color:#888">No tactics</span>'}</div>
          <div style="font-size:0.9rem;color:#666;">Procedures: ${escapeHtml(e.procedures.replace(/\n/g, ', '))}</div>
        </div>
        <div style="margin-left:1rem; white-space:nowrap;">
          <button data-idx="${idx}" class="edit-btn">Edit</button>
        </div>
      </li>`;
    });
    html += '</ul>';
    techniqueList.innerHTML = html;

    techniqueList.querySelectorAll('.edit-btn').forEach(b=>{
      b.addEventListener('click', (ev)=>{
        const i = parseInt(ev.currentTarget.getAttribute('data-idx'));
        const item = techniqueEntries[i];
        form.technique.value = item.technique;
        form.procedures.value = item.procedures;
        form.querySelectorAll('input[name="tactics"]').forEach(cb=>cb.checked = item.tactics && item.tactics.includes(cb.value));
        editingIndex = i;
        appendMsg.style.display = 'block';
        appendMsg.style.color = 'green';
        appendMsg.textContent = 'Editing entry, click Append to save changes.';
      });
    });
  }

  function escapeHtml(s){ return String(s).replace(/[&<>\"']/g, function(m){return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[m]; }); }

  appendBtn.addEventListener('click', async function(e){
    e.preventDefault();
    const technique = form.technique.value;
    const procedures = form.procedures.value.trim();
    const tactics = Array.from(form.querySelectorAll('input[name="tactics"]:checked')).map(cb=>cb.value);
    if(!technique){
      appendMsg.style.display='block'; appendMsg.style.color='red'; appendMsg.textContent='Please select a technique before appending.'; return;
    }
    if(!procedures){
      appendMsg.style.display='block'; appendMsg.style.color='red'; appendMsg.textContent='Procedures must have content before appending.'; return;
    }
    const entry = {technique, tactics, procedures};
    if(editingIndex >= 0){ techniqueEntries[editingIndex] = entry; editingIndex = -1; }
    else { techniqueEntries.push(entry); }
    appendMsg.style.display='block'; appendMsg.style.color='green'; appendMsg.textContent='Technique saved successfully.';
    renderTechniqueList(); await saveDraft();
    form.technique.value = ''; form.procedures.value = ''; form.querySelectorAll('input[name="tactics"]').forEach(cb=>cb.checked=false);
    setTimeout(()=>{ appendMsg.style.display='none'; }, 2000);
  });

  form.addEventListener('submit', function(e){
    if(techniqueEntries.length === 0){
      e.preventDefault(); appendMsg.style.display='block'; appendMsg.style.color='red'; appendMsg.textContent='Please append at least one technique before submitting.'; return false;
    }
    const hidden = document.createElement('input');
    hidden.type='hidden'; hidden.name='technique_entries'; hidden.value=JSON.stringify(techniqueEntries);
    form.appendChild(hidden); return true;
  });

  const draftId = getDraftId();
  window.addEventListener('load', function(){ loadDraft(); });
})();