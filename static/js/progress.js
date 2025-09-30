// Poll /progress_status for updates and update the progress bars and lists
const params = new URLSearchParams(window.location.search);
const group = params.get('group_name') || '';

function pct(part, total){
  if(!total || total<=0) return 0;
  return Math.min(100, Math.round((part/total)*100));
}

async function refresh(){
  if(!group) return;
  try{
    const res = await fetch(`/progress_status?group_name=${encodeURIComponent(group)}`);
    const j = await res.json();
    if(!j.ok) return;
    const p = j.progress || {};

    // YAML progress
    const created = p.created_yaml || 0;
    const total = p.total_yaml || 10; // default guess if backend doesn't supply
    const yamlPct = pct(created, total);
    document.getElementById('yaml-progress-inner').style.width = yamlPct + '%';

    // GenAI progress
    const genaiFill = document.getElementById('genai-progress-inner');
    if(p.status === 'genai_started' || p.status === 'genai_starting'){
      genaiFill.style.width = '20%';
      genaiFill.style.background = '#2196F3';
    } else if(p.status === 'genai_complete'){
      genaiFill.style.width = '100%';
      genaiFill.style.background = '#2196F3';
    } else if(p.status === 'genai_failed'){
      genaiFill.style.background = '#f44336';
      genaiFill.style.width = '100%';
    }

    // If final state, load correlations JSON
    if(p.status === 'genai_complete'){
      const corrResp = await fetch(`/correlations/${encodeURIComponent(group)}.json`);
      if(corrResp.ok){
        const wrapper = await corrResp.json();
        const corr = wrapper.results || {};
        const vlist = document.getElementById('vendor-corr-list');
        const xlist = document.getElementById('cross-corr-list');
        vlist.innerHTML = '';
        xlist.innerHTML = '';
        (corr.vendor_correlations||[]).forEach(item=>{
          const li = document.createElement('li');
          li.textContent = `${item.vendor}: ${item.a} <-> ${item.b}`;
          vlist.appendChild(li);
        });
        (corr.cross_vendor_correlations||[]).forEach(item=>{
          const li = document.createElement('li');
          li.textContent = `${item.a_vendor}(${item.a}) <-> ${item.b_vendor}(${item.b})`;
          xlist.appendChild(li);
        });
      }
    }

  }catch(e){
    console.debug('progress poll err', e);
  }
}

setInterval(refresh, 1500);
refresh();