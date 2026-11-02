/**
 * Detection Validation UI Controller
 *
 * Handles the client-side logic for detection validation workflow:
 * - Docker status checking
 * - Session management
 * - Progress tracking
 * - Results display
 * - Refinement application
 */

// Validation state
let validationState = {
    sessionId: null,
    status: 'idle',
    currentQuery: '',
    techniqueId: '',
    techniqueName: '',
    vendor: 'secops',
    dockerAvailable: false,
    suggestions: [],
    iteration: 0,
};

// API endpoints
const VALIDATION_API_BASE = '/api/validation';

/**
 * Initialize validation panel
 */
async function initDetectionValidation() {
    // Check Docker availability
    await checkDockerStatus();

    // Set up event listeners
    document.getElementById('vendor-select')?.addEventListener('change', (e) => {
        validationState.vendor = e.target.value;
    });

    // Auto-detect vendor from query syntax
    document.getElementById('validation-query')?.addEventListener('input', (e) => {
        const query = e.target.value;
        const detected = detectVendorFromQuery(query);
        if (detected) {
            document.getElementById('vendor-select').value = detected;
            validationState.vendor = detected;
        }
    });
}

/**
 * Check if Docker is available
 */
async function checkDockerStatus() {
    try {
        const response = await fetch(`${VALIDATION_API_BASE}/docker-status`);
        const data = await response.json();

        validationState.dockerAvailable = data.available;

        const warningEl = document.getElementById('docker-warning');
        const warningMsg = document.getElementById('docker-warning-message');
        const startBtn = document.getElementById('btn-start-validation');

        if (!data.available) {
            if (warningEl) warningEl.style.display = 'flex';
            if (warningMsg) warningMsg.textContent = data.message;
            if (startBtn) startBtn.disabled = true;
        } else {
            if (warningEl) warningEl.style.display = 'none';
            if (startBtn) startBtn.disabled = false;
        }

        return data.available;
    } catch (error) {
        console.error('Failed to check Docker status:', error);
        showDockerWarning('Could not connect to validation service.');
        return false;
    }
}

/**
 * Show Docker warning message
 */
function showDockerWarning(message) {
    const warningEl = document.getElementById('docker-warning');
    const warningMsg = document.getElementById('docker-warning-message');
    if (warningEl) warningEl.style.display = 'flex';
    if (warningMsg) warningMsg.textContent = message;

    const startBtn = document.getElementById('btn-start-validation');
    if (startBtn) startBtn.disabled = true;
}

/**
 * Detect vendor from query syntax
 */
function detectVendorFromQuery(query) {
    if (!query) return null;

    const lowerQuery = query.toLowerCase();

    // KQL patterns (MDE)
    if (lowerQuery.includes('deviceprocessevents') ||
        lowerQuery.includes('devicenetworkevents') ||
        (lowerQuery.includes('| where') && lowerQuery.includes('contains'))) {
        return 'mde';
    }

    // Google SecOps: a UDM search (or a legacy YARA-L rule)
    if ((lowerQuery.includes('rule ') && lowerQuery.includes('events:')) ||
        lowerQuery.trimStart().startsWith('// shikari_') ||
        /(^|[\s(])(\$e\d*\.)?metadata\.event_type\s*=/.test(lowerQuery) ||
        lowerQuery.includes('re.regex(')) {
        return 'secops';
    }

    // Elasticsearch patterns
    if (lowerQuery.includes('process.command_line') ||
        lowerQuery.includes('@timestamp') ||
        (lowerQuery.includes('"query"') && lowerQuery.includes('"bool"'))) {
        return 'elastic';
    }

    // SPL patterns (Splunk)
    if (lowerQuery.includes('index=') ||
        lowerQuery.includes('sourcetype=') ||
        lowerQuery.includes('| stats') ||
        lowerQuery.includes('| table')) {
        return 'splunk';
    }

    return null;
}

/**
 * Start the validation process
 */
async function startValidation() {
    const queryEl = document.getElementById('validation-query');
    const query = queryEl ? queryEl.value.trim() : '';

    if (!query) {
        alert('Please enter a detection query.');
        return;
    }

    // Get indicators from input fields
    const cmdEl = document.getElementById('indicators-cmd');
    const swEl = document.getElementById('indicators-sw');
    const cmdIndicators = cmdEl ? cmdEl.value.split('\n').filter(l => l.trim()) : [];
    const swIndicators = swEl ? swEl.value.split('\n').filter(l => l.trim()) : [];

    if (cmdIndicators.length === 0 && swIndicators.length === 0) {
        alert('Please enter at least one indicator for event generation.');
        return;
    }

    validationState.currentQuery = query;
    const vendorSelect = document.getElementById('vendor-select');
    validationState.vendor = vendorSelect ? vendorSelect.value : 'secops';

    updateValidationStatus('running', 'Starting validation...');
    showValidationProgress(true);
    hideValidationResults();

    // Disable start button, show stop button
    const startBtn = document.getElementById('btn-start-validation');
    const stopBtn = document.getElementById('btn-stop-validation');
    if (startBtn) startBtn.style.display = 'none';
    if (stopBtn) stopBtn.style.display = 'inline-flex';

    try {
        // Step 1: Create session
        updateProgressStep('step-siem', 'active');
        const sessionResponse = await fetch(`${VALIDATION_API_BASE}/sessions`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                technique_id: validationState.techniqueId || 'CUSTOM',
                technique_name: validationState.techniqueName || 'Custom Detection',
                query: query,
                vendor: validationState.vendor,
            })
        });

        const sessionData = await sessionResponse.json();
        if (!sessionData.success) throw new Error(sessionData.error || 'Failed to create session');

        validationState.sessionId = sessionData.session.session_id;
        const sessionDisplay = document.getElementById('session-id-display');
        if (sessionDisplay) sessionDisplay.textContent = validationState.sessionId.substring(0, 8);

        const sessionInfo = document.getElementById('session-info');
        if (sessionInfo) sessionInfo.style.display = 'flex';

        // Step 2: Start SIEM
        const siemResponse = await fetch(`${VALIDATION_API_BASE}/start-siem`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                session_id: validationState.sessionId,
                port_offset: 0,
            })
        });

        const siemData = await siemResponse.json();
        if (!siemData.success) throw new Error(siemData.error || 'Failed to start SIEM');

        updateProgressStep('step-siem', 'complete');

        // Step 3: Generate events
        updateProgressStep('step-events', 'active');
        const eventsResponse = await fetch(`${VALIDATION_API_BASE}/generate-events`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                session_id: validationState.sessionId,
                indicators: {
                    cmd: cmdIndicators,
                    sw: swIndicators,
                },
                malicious_count: 10,
                benign_count: 20,
            })
        });

        const eventsData = await eventsResponse.json();
        if (!eventsData.success) throw new Error(eventsData.error || 'Failed to generate events');

        updateProgressStep('step-events', 'complete');

        // Step 4: Test detection
        updateProgressStep('step-test', 'active');
        const testResponse = await fetch(`${VALIDATION_API_BASE}/test`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                session_id: validationState.sessionId,
            })
        });

        const testData = await testResponse.json();
        if (!testData.success) throw new Error(testData.error || 'Failed to test detection');

        updateProgressStep('step-test', 'complete');

        // Step 5: Get suggestions if failed
        updateProgressStep('step-results', 'active');
        validationState.iteration = testData.iteration;
        const iterationEl = document.getElementById('iteration-count');
        if (iterationEl) iterationEl.textContent = testData.iteration;

        if (!testData.result.passed) {
            const suggestionsResponse = await fetch(
                `${VALIDATION_API_BASE}/suggestions/${validationState.sessionId}`
            );
            const suggestionsData = await suggestionsResponse.json();
            if (suggestionsData.success) {
                validationState.suggestions = suggestionsData.suggestions;
            }
        }

        updateProgressStep('step-results', 'complete');

        // Show results
        showValidationResults(testData.result);

        if (testData.result.passed) {
            updateValidationStatus('success', 'Validation passed!');
        } else {
            updateValidationStatus('warning', 'Validation needs improvement');
        }

    } catch (error) {
        console.error('Validation error:', error);
        updateValidationStatus('error', `Error: ${error.message}`);
        showValidationProgress(false);
    } finally {
        if (startBtn) startBtn.style.display = 'inline-flex';
        if (stopBtn) stopBtn.style.display = 'none';
    }
}

/**
 * Stop the validation session
 */
async function stopValidation() {
    if (!validationState.sessionId) return;

    try {
        await fetch(`${VALIDATION_API_BASE}/stop/${validationState.sessionId}`, {
            method: 'POST'
        });
    } catch (error) {
        console.error('Error stopping validation:', error);
    }

    updateValidationStatus('ready', 'Validation stopped');
    showValidationProgress(false);

    const startBtn = document.getElementById('btn-start-validation');
    const stopBtn = document.getElementById('btn-stop-validation');
    if (startBtn) startBtn.style.display = 'inline-flex';
    if (stopBtn) stopBtn.style.display = 'none';
}

/**
 * Update the status display
 */
function updateValidationStatus(status, message) {
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');

    if (dot) dot.className = `status-dot ${status}`;
    if (text) text.textContent = message;
    validationState.status = status;
}

/**
 * Show/hide progress indicator
 */
function showValidationProgress(show) {
    const progressEl = document.getElementById('validation-progress');
    if (progressEl) progressEl.style.display = show ? 'block' : 'none';

    if (show) {
        // Reset all steps
        ['step-siem', 'step-events', 'step-test', 'step-results'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.className = 'step';
        });
    }
}

/**
 * Update a progress step
 */
function updateProgressStep(stepId, status) {
    const step = document.getElementById(stepId);
    if (step) step.className = `step ${status}`;
}

/**
 * Hide the results panel
 */
function hideValidationResults() {
    const resultsEl = document.getElementById('validation-results');
    if (resultsEl) resultsEl.style.display = 'none';
}

/**
 * Show the validation results
 */
function showValidationResults(result) {
    const resultsEl = document.getElementById('validation-results');
    if (resultsEl) resultsEl.style.display = 'block';

    // Update status icon and text
    const statusIcon = document.getElementById('result-status-icon');
    const statusText = document.getElementById('result-status-text');
    const saveBtn = document.getElementById('btn-save');

    if (result.passed) {
        if (statusIcon) statusIcon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
        if (statusText) {
            statusText.textContent = 'Detection Passed!';
            statusText.style.color = '#10b981';
        }
        if (saveBtn) saveBtn.style.display = 'inline-flex';
    } else {
        if (statusIcon) statusIcon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
        if (statusText) {
            statusText.textContent = 'Detection Needs Improvement';
            statusText.style.color = '#f59e0b';
        }
        if (saveBtn) saveBtn.style.display = 'none';
    }

    // Update metrics
    const metricTp = document.getElementById('metric-tp');
    const metricFn = document.getElementById('metric-fn');
    const metricFp = document.getElementById('metric-fp');
    const metricTn = document.getElementById('metric-tn');

    if (metricTp) metricTp.textContent = result.true_positives;
    if (metricFn) metricFn.textContent = result.false_negatives;
    if (metricFp) metricFp.textContent = result.false_positives;
    if (metricTn) metricTn.textContent = result.true_negatives;

    // Update scores
    const scorePrecision = document.getElementById('score-precision');
    const scoreRecall = document.getElementById('score-recall');
    const scoreF1 = document.getElementById('score-f1');

    if (scorePrecision) scorePrecision.textContent = `${Math.round(result.precision * 100)}%`;
    if (scoreRecall) scoreRecall.textContent = `${Math.round(result.recall * 100)}%`;
    if (scoreF1) scoreF1.textContent = `${Math.round(result.f1_score * 100)}%`;

    // Show suggestions if any
    if (validationState.suggestions.length > 0) {
        showValidationSuggestions(validationState.suggestions);
    } else {
        const suggestionsPanel = document.getElementById('suggestions-panel');
        if (suggestionsPanel) suggestionsPanel.style.display = 'none';
    }
}

/**
 * Display refinement suggestions
 */
function showValidationSuggestions(suggestions) {
    const panel = document.getElementById('suggestions-panel');
    const list = document.getElementById('suggestions-list');

    if (panel) panel.style.display = 'block';
    if (list) {
        list.innerHTML = '';

        suggestions.forEach((suggestion, index) => {
            const item = document.createElement('div');
            item.className = 'suggestion-item';
            item.innerHTML = `
                <div class="suggestion-header">
                    <span class="suggestion-type">${suggestion.type.replace('_', ' ')}</span>
                    <span class="suggestion-confidence">${Math.round(suggestion.confidence * 100)}% confidence</span>
                </div>
                <p class="suggestion-description">${suggestion.description}</p>
                <div class="suggestion-code">
                    <div class="code-before">
                        <label>Original:</label>
                        <code>${escapeHtmlForValidation(suggestion.original || '(none)')}</code>
                    </div>
                    <div class="code-after">
                        <label>Suggested:</label>
                        <code>${escapeHtmlForValidation(suggestion.suggested)}</code>
                    </div>
                </div>
                <p class="suggestion-explanation">${suggestion.explanation}</p>
                <button class="btn-apply-suggestion" onclick="applySuggestion(${index})">
                    Apply This Fix
                </button>
            `;
            list.appendChild(item);
        });
    }
}

/**
 * Apply a refinement suggestion
 */
async function applySuggestion(index) {
    if (!validationState.sessionId) return;

    try {
        const response = await fetch(`${VALIDATION_API_BASE}/refine`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                session_id: validationState.sessionId,
                suggestion_index: index,
            })
        });

        const data = await response.json();
        if (!data.success) throw new Error(data.error);

        // Show refined query
        const refinedPanel = document.getElementById('refined-query-panel');
        const refinedDisplay = document.getElementById('refined-query-display');

        if (refinedPanel) refinedPanel.style.display = 'block';
        if (refinedDisplay) refinedDisplay.textContent = data.new_query;
        validationState.currentQuery = data.new_query;

        // Update the main query textarea too
        const queryEl = document.getElementById('validation-query');
        if (queryEl) queryEl.value = data.new_query;

    } catch (error) {
        console.error('Failed to apply refinement:', error);
        alert(`Failed to apply refinement: ${error.message}`);
    }
}

/**
 * Test the refined query
 */
async function testRefinedQuery() {
    await rerunValidation();
}

/**
 * Re-run validation with current query
 */
async function rerunValidation() {
    if (!validationState.sessionId) {
        await startValidation();
        return;
    }

    updateValidationStatus('running', 'Re-testing detection...');

    try {
        const queryEl = document.getElementById('validation-query');
        const query = queryEl ? queryEl.value.trim() : '';

        const testResponse = await fetch(`${VALIDATION_API_BASE}/test`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                session_id: validationState.sessionId,
                query: query,
            })
        });

        const testData = await testResponse.json();
        if (!testData.success) throw new Error(testData.error);

        validationState.iteration = testData.iteration;
        const iterationEl = document.getElementById('iteration-count');
        if (iterationEl) iterationEl.textContent = testData.iteration;

        // Get new suggestions if failed
        if (!testData.result.passed) {
            const suggestionsResponse = await fetch(
                `${VALIDATION_API_BASE}/suggestions/${validationState.sessionId}`
            );
            const suggestionsData = await suggestionsResponse.json();
            if (suggestionsData.success) {
                validationState.suggestions = suggestionsData.suggestions;
            }
        } else {
            validationState.suggestions = [];
        }

        showValidationResults(testData.result);

        if (testData.result.passed) {
            updateValidationStatus('success', 'Validation passed!');
        } else {
            updateValidationStatus('warning', 'Validation needs improvement');
        }

    } catch (error) {
        console.error('Re-run error:', error);
        updateValidationStatus('error', `Error: ${error.message}`);
    }
}

/**
 * Copy refined query to clipboard
 */
function copyRefinedQuery() {
    const refinedDisplay = document.getElementById('refined-query-display');
    const query = refinedDisplay ? refinedDisplay.textContent : '';
    navigator.clipboard.writeText(query).then(() => {
        alert('Query copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

/**
 * Save the validated detection
 */
async function saveValidatedDetection() {
    alert('Saving validated detection... (Feature coming soon)');
}

/**
 * Escape HTML for safe display
 */
function escapeHtmlForValidation(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Load validation for a specific detection
 * Called from results page or library
 */
function loadDetectionValidation(techniqueId, techniqueName, query, vendor) {
    validationState.techniqueId = techniqueId;
    validationState.techniqueName = techniqueName;
    validationState.vendor = vendor;

    // Show technique section
    const techSection = document.getElementById('technique-section');
    const techIdDisplay = document.getElementById('technique-id-display');
    const techNameDisplay = document.getElementById('technique-name-display');

    if (techSection) techSection.style.display = 'block';
    if (techIdDisplay) techIdDisplay.textContent = techniqueId;
    if (techNameDisplay) techNameDisplay.textContent = techniqueName;

    // Set query and vendor
    const queryEl = document.getElementById('validation-query');
    const vendorSelect = document.getElementById('vendor-select');

    if (queryEl) queryEl.value = query;
    if (vendorSelect) vendorSelect.value = vendor;

    // Show validation panel
    const validationPanel = document.getElementById('validation-panel');
    if (validationPanel) validationPanel.style.display = 'block';
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', initDetectionValidation);
