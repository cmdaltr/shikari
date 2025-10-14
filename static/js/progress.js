// Poll /progress_status for updates and update the progress bars and lists
const params = new URLSearchParams(window.location.search);
const group = params.get('group_name') || '';

// Track YAML state to avoid regressions and lock at 100% once complete
let lastYamlPct = 0;
let yamlComplete = false;
// Track last created count and last reported YAML file path
let lastYamlCreated = 0;
let lastYamlFileShown = '';

// Ellipsis animation state
let ellipsisTimer = null;
let ellipsisCount = 0;
let ellipsisEl = null;

// Ensure an animated ellipsis span exists after the waiting text in the "last YAML file" line
function ensureEllipsisSpan(hostEl) {
  // Reuse existing span if already attached to the same host
  if (ellipsisEl && ellipsisEl.parentElement === hostEl) return ellipsisEl;
  // If the span exists elsewhere, remove it so we can reattach
  if (ellipsisEl && ellipsisEl.parentElement && ellipsisEl.parentElement !== hostEl) {
    try { ellipsisEl.remove(); } catch (_) {}
    ellipsisEl = null;
  }
  if (!hostEl) return null;
  const span = document.createElement('span');
  span.id = 'progress-ellipsis';
  span.style.display = 'inline-block';
  span.style.minWidth = '1.2em';
  span.textContent = ''; // start empty; will animate
  hostEl.appendChild(document.createTextNode(''));
  hostEl.appendChild(span);
  ellipsisEl = span;
  return span;
}
function startEllipsis(hostEl) {
  if (ellipsisTimer) return;
  const span = ensureEllipsisSpan(hostEl);
  if (!span) return;
  ellipsisCount = 0;
  ellipsisTimer = setInterval(function () {
    ellipsisCount = (ellipsisCount + 1) % 4;
    span.textContent = '.'.repeat(ellipsisCount);
  }, 400);
}
function stopEllipsis(removeSpan) {
  if (ellipsisTimer) {
    clearInterval(ellipsisTimer);
    ellipsisTimer = null;
  }
  if (!ellipsisEl) return;
  if (removeSpan) {
    try { ellipsisEl.remove(); } catch (_) {}
    ellipsisEl = null;
  } else {
    ellipsisEl.textContent = '...';
  }
}

function pct(part, total){
  if(!total || total<=0) return 0;
  return Math.min(100, Math.round((part/total)*100));
}

// Deep-scan helper: find last string value that looks like a YAML path
function findLastYamlStringDeep(value, acc) {
  acc = acc || [];
  if (typeof value === 'string') {
    if (/\.(ya?ml)$/i.test(value)) acc.push(value);
    return acc;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) findLastYamlStringDeep(value[i], acc);
    return acc;
  }
  if (value && typeof value === 'object') {
    for (const k in value) {
      if (!Object.prototype.hasOwnProperty.call(value, k)) continue;
      findLastYamlStringDeep(value[k], acc);
    }
    return acc;
  }
  return acc;
}

// Extract a best-guess "last file written" from server payload
function extractLastYamlFile(root, progress) {
  const j = root || {};
  const p = progress || {};
  // direct fields (expanded)
  const candidates = [
    p.last_yaml_file, p.last_yaml, p.last_yaml_filename, p.last_yaml_path, p.last_yaml_filepath, p.last_yaml_fullpath, p.last_yaml_full_path,
    p.last_written_file, p.last_output_file, p.latest_yaml, p.latest_yaml_file, p.latest_file, p.current_yaml_file, p.current_file, p.file,
    j.last_yaml_file, j.last_yaml, j.last_yaml_filename, j.last_yaml_path, j.last_yaml_filepath, j.last_yaml_fullpath, j.last_yaml_full_path,
    j.last_written_file, j.last_output_file, j.latest_yaml, j.latest_yaml_file, j.latest_file, j.current_yaml_file, j.current_file, j.file,
    (p.output && p.output.last_yaml), (j.output && j.output.last_yaml)
  ].filter(Boolean);
  const direct = candidates.find(s => typeof s === 'string' && /\.(ya?ml)$/i.test(s));
  if (direct) return String(direct);
  // arrays
  const arrays = [
    p.yaml_files, p.created_yaml_files, p.files,
    j.yaml_files, j.created_yaml_files, j.files
  ].filter(Array.isArray);
  for (const arr of arrays) {
    const lastYaml = [...arr].reverse().find(f => typeof f === 'string' && /\.(ya?ml)$/i.test(f));
    if (lastYaml) return String(lastYaml);
  }
  // deep scan anywhere in payloads
  const found = findLastYamlStringDeep([p, j]);
  if (found.length) return String(found[found.length - 1]);
  return '';
}

// Ensure there is a small line under the YAML bar to show the last file written
function getOrCreateLastFileEl(yamlFillEl) {
  // Prefer the placeholder in the HTML if present
  let el = document.getElementById('last-yaml-file');
  if (el) return el;

  // Fallback: create if missing and insert after the YAML bar
  el = document.createElement('div');
  el.id = 'last-yaml-file';
  el.style.marginTop = '6px';
  el.style.fontSize = '0.9em';
  el.style.color = '#666'; // Default color for "Waiting for first file"
  el.style.display = 'block';
  el.style.whiteSpace = 'normal';
  el.style.wordBreak = 'break-all';
  let bar = null;
  try { bar = yamlFillEl && (yamlFillEl.closest && yamlFillEl.closest('.progress-bar')) || yamlFillEl.parentElement; } catch (_) {}
  if (bar && bar.parentElement) {
    bar.insertAdjacentElement('afterend', el);
  } else {
    const container = document.getElementById('progress-content') || document.body;
    container.appendChild(el);
  }
  return el;
}

// HEAD a subset and pick the "best" candidate by size, then Last-Modified
async function pickByHead(urls) {
  const limit = Math.min(urls.length, 25);
  let best = { url: '', size: -1, ts: 0 };
  for (let i = 0; i < limit; i++) {
    const u = urls[i];
    try {
      const resp = await fetch(u, { method: 'HEAD' });
      if (!resp.ok) continue;
      const len = Number(resp.headers.get('content-length')) || 0;
      const lm = resp.headers.get('last-modified');
      const ts = lm ? Date.parse(lm) : 0;
      if (len > best.size || (len === best.size && ts > best.ts)) {
        best = { url: u, size: len, ts };
      }
    } catch (_) {}
  }
  return best.url || urls[urls.length - 1] || '';
}

// Fetch a YAML file list from an API endpoint (data-files-url) and normalize to absolute URLs
async function listYamlFilesFromApi(filesUrl) {
  const resp = await fetch(filesUrl, { headers: { 'X-Requested-With': 'XMLHttpRequest' } });
  if (!resp.ok) throw new Error('FILES_API_NOT_AVAILABLE');
  const data = await resp.json();
  const arrays = [data.files, data.entries, data.items, data.list].filter(Array.isArray);
  const out = new Set();
  arrays.forEach(arr => {
    arr.forEach(x => {
      let path = '';
      if (typeof x === 'string') path = x;
      else if (x && typeof x === 'object') path = x.path || x.file || x.name || '';
      if (path && /\.(ya?ml)$/i.test(path)) {
        if (/^https?:\/\//i.test(path) || path.startsWith('/')) out.add(path);
        else out.add(`${path}`.replace(/\/{2,}/g, '/'));
      }
    });
  });
  return Array.from(out);
}

// Replace the fetchDirectoryYamlFiles and getMostRecentQueryYaml functions with these versions
async function fetchYamlFilesInDirectory(dirPath = 'data/queries') {
  try {
    // First attempt - try to directly access the directory listing if it's enabled on the server
    try {
      const dirRes = await fetch(`/${dirPath}/`, { 
        method: 'GET',
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
      });
      
      if (dirRes.ok && dirRes.headers.get('content-type')?.includes('text/html')) {
        const html = await dirRes.text();
        // Parse HTML directory listing to extract YAML files
        const regex = new RegExp(`href="([^"]+\\.(ya?ml))"[^>]*>([^<]+)<\\/a>\\s*<\\/td>\\s*<td[^>]*>([\\d-]+\\s+[\\d:]+)`, 'gi');
        const files = [];
        let match;
        while ((match = regex.exec(html)) !== null) {
          const [_, href, __, name, dateStr] = match;
          const fullPath = `${dirPath}/${href}`.replace(/\/{2,}/g, '/');
          files.push({
            path: fullPath,
            name: name || href,
            url: `/${fullPath}`
          });
        }
        
        if (files.length > 0) {
          // Get timestamps via HEAD requests to sort by last-modified
          const fileDetails = await Promise.all(files.map(async file => {
            try {
              const headRes = await fetch(file.url, { method: 'HEAD' });
              if (headRes.ok) {
                const lastMod = headRes.headers.get('last-modified');
                return {
                  ...file,
                  modified: lastMod ? new Date(lastMod) : new Date(0),
                  size: parseInt(headRes.headers.get('content-length') || '0')
                };
              }
            } catch (_) {}
            return { ...file, modified: new Date(0), size: 0 };
          }));
          
          return fileDetails.sort((a, b) => b.modified - a.modified);
        }
      }
    } catch (e) {
      console.debug('Directory listing parse failed:', e);
    }
    
    // Second attempt - try a predictable file pattern with date-based naming
    // Assuming files might be named like YYYY-MM-DD-query.yaml or query-YYYY-MM-DD.yaml
    const today = new Date();
    const dates = [];
    
    // Generate the last 7 days of possible dates
    for (let i = 0; i < 7; i++) {
      const d = new Date(today);
      d.setDate(d.getDate() - i);
      const year = d.getFullYear();
      const month = String(d.getMonth() + 1).padStart(2, '0');
      const day = String(d.getDate()).padStart(2, '0');
      dates.push(`${year}-${month}-${day}`);
      dates.push(`${year}${month}${day}`);
    }
    
    // Try different filename patterns
    const candidates = [
      ...dates.map(date => `${dirPath}/query-${date}.yaml`),
      ...dates.map(date => `${dirPath}/${date}-query.yaml`),
      ...dates.map(date => `${dirPath}/queries-${date}.yaml`),
      ...dates.map(date => `${dirPath}/${date}-queries.yaml`),
      `${dirPath}/latest.yaml`,
      `${dirPath}/query.yaml`,
      `${dirPath}/queries.yaml`
    ];
    
    // Check each candidate with HEAD request
    const validFiles = [];
    for (const path of candidates) {
      try {
        const res = await fetch(`/${path}`, { method: 'HEAD' });
        if (res.ok) {
          const lastMod = res.headers.get('last-modified');
          validFiles.push({
            path,
            name: path.split('/').pop(),
            modified: lastMod ? new Date(lastMod) : new Date(),
            size: parseInt(res.headers.get('content-length') || '0')
          });
        }
      } catch (_) {}
    }
    
    return validFiles.sort((a, b) => b.modified - a.modified);
  } catch (e) {
    console.debug('Error fetching directory files:', e);
    return [];
  }
}

// Add variables to track latest.yaml polling
let lastYamlFileCheckTime = 0;
const YAML_FILE_CHECK_INTERVAL = 20000; // 20 seconds in milliseconds

// Simplified function to get the latest YAML file path from latest.yaml
async function getMostRecentQueryYaml() {
  try {
    // Only check for the latest.yaml file every 10 seconds
    const now = Date.now();
    if (now - lastYamlFileCheckTime < YAML_FILE_CHECK_INTERVAL) {
      return ''; // Skip checking if it's too soon
    }
    
    lastYamlFileCheckTime = now;
    
    // Try to fetch the content of latest.yaml which contains the path to the latest file
    const latestYamlRes = await fetch('/data/queries/latest.yaml');
    
    if (latestYamlRes.ok) {
      // The content of latest.yaml is the path to the actual latest YAML file
      const filePath = await latestYamlRes.text();
      console.debug('Latest file from latest.yaml:', filePath.trim());
      return filePath.trim();
    } else {
      console.debug('Could not access latest.yaml file:', latestYamlRes.status);
    }
    
    return '';
  } catch (err) {
    console.debug('Error fetching latest YAML file info:', err);
    return '';
  }
}

// Fix the syntax error in the file
async function refresh(){
  if(!group) return;
  try{
    const res = await fetch(`/progress_status?group_name=${encodeURIComponent(group)}`);
    const j = await res.json();
    const p = j.progress || j.progress_state || j || {};

    // Detection generation progress (monotonic + lock at 100% once complete)
    const created = p.created_yaml || p.yaml_created || 0;
    const total = p.total_yaml || p.yaml_total || 10;
    const currentPct = Math.min(100, Math.round((total > 0 ? (created/total)*100 : 0)));

    const serverMovedToCorrelation = (p.status === 'genai_started' || p.status === 'genai_starting' || p.status === 'genai_complete');
    if (!yamlComplete && (serverMovedToCorrelation || (total > 0 && created >= total) || currentPct >= 100)) {
      yamlComplete = true;
      console.debug('Detection generation complete, transitioning to correlation');

      // Force a final progress update to ensure backend knows detection generation is complete
      if (!serverMovedToCorrelation) {
        try {
          // Signal completion to the backend via special endpoint
          await fetch(`/complete_yaml?group_name=${encodeURIComponent(group)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
        } catch (err) {
          console.debug('Error signaling detection completion:', err);
        }
      }
    }

    const yamlFill = document.getElementById('yaml-progress') || document.querySelector('.progress-fill.yaml');
    if (yamlFill) {
      const nextPct = yamlComplete ? 100 : Math.max(lastYamlPct, currentPct);
      lastYamlPct = nextPct;
      yamlFill.style.width = nextPct + '%';
      if (nextPct >= 100) yamlFill.classList.add('complete');
    }

    // Drive the "last file" line every tick
    const lastEl = getOrCreateLastFileEl(yamlFill);
    
    // Extract file path from the server response, or try to read the latest.yaml file
    let detectedFile = extractLastYamlFile(j, p);
    let displayFile = detectedFile; // Default to the same value
    let validFileDetected = false; // Flag to track if we have a valid file

    // If no file is detected through the standard method, we'll send a request to get the latest file
    if (!detectedFile) {
      try {
        // Make a special request to the progress_status endpoint with a parameter to include the latest file
        const latestFileRes = await fetch(`/progress_status?group_name=${encodeURIComponent(group)}&include_latest_file=true`);
        if (latestFileRes.ok) {
          const latestFileData = await latestFileRes.json();
          console.debug('Latest file data:', latestFileData);
          
          // Check if we have actual content in the latest file (not empty)
          const hasContent = latestFileData && 
                            latestFileData.latest_file && 
                            latestFileData.latest_file.trim() !== '';
          
          // Only use the file info if we have actual content
          if (hasContent) {
            // Use the prettified name if available, otherwise use whatever we can get
            if (latestFileData.latest_file_pretty) {
              detectedFile = latestFileData.latest_file; // Store full path
              displayFile = latestFileData.latest_file_pretty; // Use pretty name for display
              validFileDetected = true;
            } else if (latestFileData.latest_filename) {
              detectedFile = latestFileData.latest_file;
              displayFile = latestFileData.latest_filename;
              validFileDetected = true;
            } else {
              detectedFile = latestFileData.latest_file;
              displayFile = detectedFile;
              validFileDetected = true;
            }
          }
        }
      } catch (err) {
        console.debug('Error fetching latest file info:', err);
      }
    } else {
      // We already have a file from the first method
      validFileDetected = detectedFile.trim() !== '';
    }
    
    const createdIncreased = created > lastYamlCreated;
    if (createdIncreased) lastYamlCreated = created;

    if (lastEl) {
      // YAML generation is complete, show "Complete" message
      if (yamlComplete) {
        lastEl.innerHTML = ''; // Clear existing content

        // "Complete: " in green and bold
        const completeText = document.createElement('span');
        completeText.textContent = 'Complete: ';
        completeText.style.color = '#28a745'; // Green color matching detection bar
        completeText.style.fontWeight = 'bold';
        lastEl.appendChild(completeText);

        // Show actual YAML file count (total_files) not procedure count (total_yaml)
        // One procedure can generate multiple YAML files (one per data source/index)
        const totalFiles = p.total_files || total;
        const countSpan = document.createElement('span');
        countSpan.textContent = `${totalFiles} detection files generated`;
        countSpan.style.color = '#495057'; // Default grey/black text
        lastEl.appendChild(countSpan);

        // Stop ellipsis animation if it's still running
        stopEllipsis(true);
      }
      // Still in progress, show file or waiting message
      else if (detectedFile && detectedFile.trim() !== '') {
        // We have a valid file path - display it
        if (detectedFile !== lastYamlFileShown) {
          lastYamlFileShown = String(detectedFile);
        }

        lastEl.innerHTML = ''; // Clear existing content

        // "Detection file created: " in default color
        const prefixSpan = document.createElement('span');
        prefixSpan.textContent = 'Detection file created: ';
        lastEl.appendChild(prefixSpan);

        // Filename in green, not bold
        const filenameSpan = document.createElement('span');
        filenameSpan.textContent = displayFile;
        filenameSpan.style.color = '#28a745'; // Green color matching detection bar
        lastEl.appendChild(filenameSpan);

        lastEl.title = detectedFile; // Keep full path in tooltip
        stopEllipsis(true); // Stop ellipsis animation

        console.debug('Displaying file:', displayFile);
      } else if (created >= 5) {
        // Have at least 5 files - show count (gives ellipsis more time to animate)
        lastEl.innerHTML = ''; // Clear existing content

        // "Processing: " in default color
        const prefixSpan = document.createElement('span');
        prefixSpan.textContent = 'Processing: ';
        lastEl.appendChild(prefixSpan);

        // "X of Y files" in green, not bold
        const countSpan = document.createElement('span');
        countSpan.textContent = `${created} of ${total} files`;
        countSpan.style.color = '#28a745'; // Green color matching detection bar
        lastEl.appendChild(countSpan);

        stopEllipsis(true);
      } else {
        // No valid file yet or only 1-4 files - show waiting message with animated ellipsis
        lastEl.textContent = 'Waiting for first file';
        lastEl.style.color = '#666'; // Default gray for waiting text
        lastEl.removeAttribute('title');
        startEllipsis(lastEl); // Keep ellipsis animating
      }
    }

    // Sole-vendor correlation progress - only start after detection completes
    const correlationFill = document.getElementById('genai-progress');
    if (correlationFill) {
      let correlationPct = 0;
      const correlationStatus = p.status || '';
      const correlationProcessed = p.processed || p.genai_processed || 0;
      const correlationTotal = p.total_pairs || p.genai_total || p.total_files || 0;

      // Only show correlation progress if detection generation is complete
      if (!yamlComplete) {
        // Don't start correlation until detection is done
        correlationPct = 0;
      } else if (correlationStatus === 'genai_complete' || correlationStatus === 'complete') {
        // Both genai_complete and complete mean correlation finished
        correlationPct = 100;
      } else if (correlationStatus === 'genai_processing' || correlationStatus === 'genai_started') {
        // Calculate percentage if we have totals
        if (correlationTotal > 0 && correlationProcessed > 0) {
          correlationPct = Math.min(99, Math.round((correlationProcessed / correlationTotal) * 100));
        } else if (correlationProcessed > 0) {
          // If we don't have total, show progress based on processed count
          // Cap at 99% until complete
          correlationPct = Math.min(99, Math.round(Math.log(correlationProcessed + 1) * 10));
        } else if (correlationStatus === 'genai_started') {
          correlationPct = 1; // Show minimal progress when started
        }
      } else if (correlationStatus === 'genai_starting') {
        // Just starting, show minimal progress
        correlationPct = 1;
      }

      correlationFill.style.width = correlationPct + '%';
      if (correlationPct >= 100) {
        correlationFill.classList.add('complete');
      }
    }

    // Display correlation techniques info below the correlation bar
    const correlationInfoEl = document.getElementById('last-correlation');
    if (correlationInfoEl && yamlComplete) {
      const correlationStatus = p.status || '';
      const correlationProcessed = p.processed || 0;
      const correlationTotal = p.total_pairs || 0;
      const vendorCount = p.vendor_count || 0;

      if (correlationStatus === 'genai_complete' || correlationStatus === 'complete') {
        // Correlation complete
        correlationInfoEl.innerHTML = '';

        // "Complete: " in blue and bold
        const completeText = document.createElement('span');
        completeText.textContent = 'Complete: ';
        completeText.style.color = '#007bff';
        completeText.style.fontWeight = 'bold';
        correlationInfoEl.appendChild(completeText);

        // "9979 high-fidelity correlations generated" in black (default), normal weight
        const countSpan = document.createElement('span');
        countSpan.textContent = `${vendorCount} high-fidelity correlations generated`;
        countSpan.style.color = '#495057'; // Default grey/black text
        correlationInfoEl.appendChild(countSpan);
      } else if (correlationStatus === 'genai_processing') {
        // Show progress
        correlationInfoEl.innerHTML = '';

        // "Correlating techniques: " in default color
        const prefixSpan = document.createElement('span');
        prefixSpan.textContent = 'Correlating techniques: ';
        correlationInfoEl.appendChild(prefixSpan);

        // "X of Y pairs evaluated" in blue, not bold
        const progressSpan = document.createElement('span');
        progressSpan.textContent = `${correlationProcessed} of ${correlationTotal} pairs evaluated`;
        progressSpan.style.color = '#007bff';
        correlationInfoEl.appendChild(progressSpan);
      } else if (correlationStatus === 'genai_starting' || correlationStatus === 'genai_started') {
        // Just starting
        correlationInfoEl.textContent = 'Starting correlation analysis';
        startEllipsis(correlationInfoEl);
      } else {
        // Waiting
        correlationInfoEl.textContent = 'Waiting for detection generation to complete';
      }
    }

    // Cross-vendor correlation progress - only start after sole-vendor correlation completes
    const crossVendorFill = document.getElementById('cross-vendor-progress');
    const crossVendorSection = document.getElementById('cross-vendor-section');
    if (crossVendorFill && crossVendorSection) {
      let crossVendorPct = 0;
      const correlationStatus = p.status || '';
      const crossCount = p.cross_count || 0;

      // Check if cross-vendor correlation was enabled from backend
      const isCrossVendorEnabled = p.cross_vendor_enabled === true;

      // Only show cross-vendor progress if sole-vendor correlation is complete
      const soleVendorComplete = (correlationStatus === 'genai_complete' || correlationStatus === 'complete');

      if (!isCrossVendorEnabled) {
        // Cross-vendor disabled - grey out the section
        crossVendorPct = 0;
        crossVendorSection.classList.add('disabled');
      } else {
        // Cross-vendor enabled - remove disabled class and show pink theme
        crossVendorSection.classList.remove('disabled');

        if (!soleVendorComplete) {
          // Wait for sole-vendor to complete first
          crossVendorPct = 0;
        } else if (crossCount > 0) {
          // Cross-vendor complete - show 100%
          crossVendorPct = 100;
        } else {
          // Processing (if we add cross-vendor correlation tracking in the future)
          crossVendorPct = 0;
        }
      }

      crossVendorFill.style.width = crossVendorPct + '%';
      if (crossVendorPct >= 100) {
        crossVendorFill.classList.add('complete');
      }
    }

    // Display cross-vendor correlation info below the cross-vendor bar
    const crossVendorInfoEl = document.getElementById('last-cross-vendor');
    if (crossVendorInfoEl && crossVendorSection) {
      const correlationStatus = p.status || '';
      const crossCount = p.cross_count || 0;
      const isCrossVendorEnabled = p.cross_vendor_enabled === true;
      const soleVendorComplete = (correlationStatus === 'genai_complete' || correlationStatus === 'complete');

      if (!isCrossVendorEnabled) {
        // Cross-vendor disabled
        crossVendorInfoEl.textContent = 'Cross-vendor correlation not enabled for this analysis';
        crossVendorInfoEl.style.color = '#999';
      } else if (!soleVendorComplete) {
        // Wait for sole-vendor to complete
        crossVendorInfoEl.textContent = 'Waiting for sole-vendor correlation to complete';
        crossVendorInfoEl.style.color = '#999';
      } else if (crossCount > 0) {
        // Cross-vendor complete
        crossVendorInfoEl.innerHTML = '';

        // "Complete: " in pink and bold
        const completeText = document.createElement('span');
        completeText.textContent = 'Complete: ';
        completeText.style.color = '#e91e63';
        completeText.style.fontWeight = 'bold';
        crossVendorInfoEl.appendChild(completeText);

        // "X high-fidelity correlations generated" in black (default), normal weight
        const countSpan = document.createElement('span');
        countSpan.textContent = `${crossCount} cross-vendor high-fidelity correlations generated`;
        countSpan.style.color = '#495057';
        crossVendorInfoEl.appendChild(countSpan);
      } else {
        // No cross-vendor correlations found (enabled but no results)
        crossVendorInfoEl.textContent = 'No cross-vendor correlations identified';
        crossVendorInfoEl.style.color = '#6c757d';
      }
    }

    // Correlation progress (if present)
    const corrEl = document.getElementById('correlation-progress');
    if (corrEl) {
      const corrPct = Math.min(100, Math.round((p.correlation_progress || 0) * 100));
      corrEl.style.width = corrPct + '%';
      if (corrPct >= 100) corrEl.classList.add('complete');
    }

  } catch(e) {
    console.debug('progress poll err', e);
  }
}
setInterval(refresh, 1500);
refresh();
// Remove previous DOMContentLoaded ellipsis start tied to the leady when in the "Waiting for first file" state.
// It now starts only when in the "Waiting for first file" state.Loaded', function () {
// document.addEventListener('DOMContentLoaded', function () {
//   startEllipsis();// });