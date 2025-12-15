(function () {
  const container = document.getElementById("genai-correlations");
  if (!container) return;
  const content = document.getElementById("genai-correlations-content");
  const group = container.dataset.group || "smoke_test";
  const pollIntervalMs = 3000;
  let fetchedOnce = false;

  async function fetchJson(url) {
    try {
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) return null;
      return await res.json();
    } catch (e) {
      return null;
    }
  }

  function renderResults(obj) {
    if (!obj) {
      content.innerText = "No results.";
      return;
    }
    const vc = obj.vendor_correlations || [];
    const cc = obj.cross_vendor_correlations || [];
    const wrap = document.createElement("div");
    const summary = document.createElement("div");
    summary.innerHTML = `<strong>Vendor correlations:</strong> ${vc.length} &nbsp;&nbsp; <strong>Cross-vendor:</strong> ${cc.length}`;
    wrap.appendChild(summary);

    function makeList(title, arr) {
      const s = document.createElement("div");
      s.innerHTML = `<h4>${title} (${arr.length})</h4>`;
      const ul = document.createElement("ul");
      arr.forEach((it) => {
        const li = document.createElement("li");
        const members = it.members || (it.a ? [it.a, it.b] : []);
        const membersText = members.join(" | ");
        const reason = it.reason ? ` — ${it.reason}` : "";
        li.textContent = `${membersText}${reason}`;
        ul.appendChild(li);
      });
      s.appendChild(ul);
      return s;
    }

    if (vc.length) wrap.appendChild(makeList("Vendor correlations", vc));
    if (cc.length) wrap.appendChild(makeList("Cross-vendor Correlations", cc));
    content.innerHTML = "";
    content.appendChild(wrap);
  }

  async function poll() {
    const endpointCandidate = `/correlations/${group}.json`;
    let obj = await fetchJson(endpointCandidate);
    if (!obj) {
      obj = await fetchJson(`/data/correlations/${group}.json`);
    }
    if (obj) {
      fetchedOnce = true;
      renderResults(obj);
    } else if (!fetchedOnce) {
      content.innerText = "No correlations yet. Waiting...";
    }
  }

  poll();
  setInterval(poll, pollIntervalMs);
})();