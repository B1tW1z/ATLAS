/**
 * ATLAS Web UI Application
 * JavaScript for scan workflows and UI interactions
 */

// API Configuration
const API_BASE = '/api';

// State
let currentScanId = sessionStorage.getItem('atlas_scan_id') || null;
let selectedChecks = new Set();
let allChecks = [];
let currentUser = null;
let allScans = [];

// ========== Initialization ==========

document.addEventListener('DOMContentLoaded', async () => {
    // Check authentication first
    const isAuthenticated = await checkAuthentication();

    if (!isAuthenticated) {
        window.location.href = '/login';
        return;
    }

    initNavigation();
    checkApiStatus();
    startHeaderClock();
    loadDashboard();

    // Close user menu when clicking outside
    document.addEventListener('click', (e) => {
        const userProfile = document.getElementById('user-profile');
        if (userProfile && !userProfile.contains(e.target)) {
            userProfile.classList.remove('open');
        }
    });
});

function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        // Only handle internal navigation if data-page attribute exists
        if (!item.dataset.page) {
            return;
        }

        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            if (page) {
                showPage(page);
                // Close sidebar on mobile after navigation
                if (window.innerWidth <= 768) {
                    toggleSidebar();
                }
            }
        });
    });

    // Handle hash navigation
    if (window.location.hash) {
        const page = window.location.hash.replace('#', '');
        showPage(page);
    }
}

// Toggle sidebar for mobile
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');

    if (sidebar) {
        sidebar.classList.toggle('open');
    }
    if (overlay) {
        overlay.classList.toggle('active');
    }
}

// Live header clock
function startHeaderClock() {
    function tick() {
        const el = document.getElementById('header-clock');
        if (el) {
            const now = new Date();
            el.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
    }
    tick();
    setInterval(tick, 30000); // update every 30s
}

function showPage(pageName) {
    // Don't try to show undefined pages
    if (!pageName) return;

    // Update nav - only update items that have data-page (not external links)
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
        item.classList.toggle('active', item.dataset.page === pageName);
    });

    // Show page
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });

    const targetPage = document.getElementById(`page-${pageName}`);
    if (targetPage) {
        targetPage.classList.add('active');
    }

    // Page-specific actions
    if (pageName === 'dashboard') {
        loadDashboard();
    } else if (pageName === 'checks') {
        loadAllChecks();
    } else if (pageName === 'new-scan') {
        resetScanWizard();
    } else if (pageName === 'demo') {
        loadDemoTargets();
    } else if (pageName === 'reports') {
        loadReports();
    } else if (pageName === 'profile') {
        loadProfile();
    } else if (pageName === 'activity') {
        loadActivityFeed();
    } else if (pageName === 'scheduling') {
        loadSchedules();
    } else if (pageName === 'terminal') {
        initWebTerminal();
    }
    // Update header breadcrumb
    const pageLabels = {
        dashboard: 'Dashboard', 'new-scan': 'New Scan', checks: 'Vulnerability Checks',
        demo: 'Demo Targets', reports: 'Reports', activity: 'Activity Log',
        scheduling: 'Scheduled Scans', terminal: 'Terminal', profile: 'Profile', settings: 'Settings'
    };
    const bc = document.getElementById('header-breadcrumb');
    if (bc) bc.textContent = pageLabels[pageName] || pageName;

    window.location.hash = pageName;
}

// ========== API Helpers ==========

async function apiRequest(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'API request failed');
        }

        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

async function checkApiStatus() {
    try {
        await apiRequest('/health');
        document.querySelector('.status-dot').classList.add('connected');
        document.getElementById('api-status-text').textContent = 'Connected';
    } catch (error) {
        document.getElementById('api-status-text').textContent = 'Disconnected';
    }
}

// ========== Toast Notification System ==========

function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container');
    if (!container) { console.warn(message); return; }

    const icons = { success: '\u2713', error: '\u2715', info: '\u2139', warning: '\u26a0' };
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="this.closest('.toast').remove()">\u00d7</button>
    `;
    container.appendChild(toast);

    const timer = setTimeout(() => {
        toast.classList.add('dismissing');
        setTimeout(() => toast.remove(), 300);
    }, duration);

    toast.querySelector('.toast-close').addEventListener('click', () => clearTimeout(timer));
}

// ========== Animated Counter ==========

function animateCounter(element, target, duration = 600) {
    if (!element || target === 0) { if (element) element.textContent = target; return; }
    const start = 0;
    const startTime = performance.now();
    function update(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        element.textContent = Math.round(start + (target - start) * ease);
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

// ========== Donut Chart ==========

function renderDonutChart(severity) {
    const chart = document.getElementById('donut-chart');
    const legend = document.getElementById('chart-legend');
    const totalEl = document.getElementById('donut-total');
    if (!chart || !legend) return;

    const c = severity.critical || 0;
    const h = severity.high || 0;
    const m = severity.medium || 0;
    const l = severity.low || 0;
    const total = c + h + m + l;

    if (total === 0) {
        chart.style.background = 'var(--bg-tertiary)';
        totalEl.textContent = '0';
        legend.innerHTML = '<span style="color:var(--text-muted);font-size:0.8rem;">No findings yet</span>';
        return;
    }

    animateCounter(totalEl, total);

    const slices = [];
    let angle = 0;
    const addSlice = (val, color) => {
        if (val === 0) return;
        const deg = (val / total) * 360;
        slices.push(`${color} ${angle}deg ${angle + deg}deg`);
        angle += deg;
    };
    addSlice(c, '#ff4757');
    addSlice(h, '#ff6b6b');
    addSlice(m, '#ffd43b');
    addSlice(l, '#51cf66');

    chart.style.background = `conic-gradient(${slices.join(', ')})`;

    legend.innerHTML = [
        { label: 'Critical', cls: 'critical', val: c },
        { label: 'High', cls: 'high', val: h },
        { label: 'Medium', cls: 'medium', val: m },
        { label: 'Low', cls: 'low', val: l }
    ].map(i => `
        <div class="legend-item">
            <span class="legend-dot ${i.cls}"></span>
            <span>${i.label}</span>
            <span class="legend-count">${i.val}</span>
        </div>
    `).join('');
}

// ========== Scan Filter ==========

function filterScans() {
    const query = (document.getElementById('scan-search')?.value || '').toLowerCase().trim();
    const tbody = document.getElementById('scans-table-body');
    if (!tbody || !allScans.length) return;

    const filtered = query
        ? allScans.filter(s =>
            s.id.toLowerCase().includes(query) ||
            s.target.toLowerCase().includes(query) ||
            s.status.toLowerCase().includes(query) ||
            s.phase.toLowerCase().includes(query)
        )
        : allScans;

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No scans match your search.</td></tr>';
        return;
    }
    renderScanRows(tbody, filtered);
}

function renderScanRows(tbody, scans) {
    tbody.innerHTML = scans.map(scan => `
        <tr>
            <td><code>${scan.id}</code></td>
            <td>${truncate(scan.target, 40)}</td>
            <td><span class="status-${scan.status}">${scan.status}</span></td>
            <td>${scan.phase}</td>
            <td>${formatDate(scan.created_at)}</td>
            <td>
                <button class="btn btn-sm" onclick="viewScan('${scan.id}')">View</button>
                ${scan.status === 'paused' ?
            `<button class="btn btn-sm btn-secondary" onclick="resumeScan('${scan.id}')">Resume</button>` : ''
        }
                <button class="btn btn-sm btn-secondary" title="Export" onclick="exportScan('${scan.id}')" style="padding: 4px 8px;">\u2b07</button>
                <button class="btn btn-sm" title="Delete" onclick="deleteScan('${scan.id}')" style="padding: 4px 8px; color: var(--severity-critical); border-color: var(--severity-critical);">\u2715</button>
            </td>
        </tr>
    `).join('');
}

// ========== Dashboard ==========

async function loadDashboard() {
    const tbody = document.getElementById('scans-table-body');

    // Show skeleton loading
    tbody.innerHTML = Array(4).fill('').map(() => `
        <tr>
            <td><div class="skeleton skeleton-cell" style="width:60px"></div></td>
            <td><div class="skeleton skeleton-cell" style="width:80%"></div></td>
            <td><div class="skeleton skeleton-cell" style="width:50px"></div></td>
            <td><div class="skeleton skeleton-cell" style="width:60px"></div></td>
            <td><div class="skeleton skeleton-cell" style="width:70px"></div></td>
            <td><div class="skeleton skeleton-cell" style="width:100px"></div></td>
        </tr>
    `).join('');

    try {
        // Fetch real stats from dashboard API
        try {
            const stats = await apiRequest('/dashboard/stats');
            const sev = stats.findings_by_severity || stats.severity_breakdown || {};
            animateCounter(document.getElementById('stat-total-scans'), stats.total_scans || 0);
            animateCounter(document.getElementById('stat-critical'), sev.critical || 0);
            animateCounter(document.getElementById('stat-high'), sev.high || 0);
            animateCounter(document.getElementById('stat-medium'), sev.medium || 0);
            renderDonutChart(sev);
        } catch (e) {
            console.warn('Dashboard stats unavailable:', e);
        }

        const { scans } = await apiRequest('/scans?limit=10');
        allScans = scans;

        if (scans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6">
                        <div class="empty-state-enhanced">
                            <div class="empty-state-icon">🔍</div>
                            <h4>No scans yet</h4>
                            <p>Launch your first vulnerability assessment to see results here.</p>
                            <button class="btn btn-primary btn-sm" onclick="showPage('new-scan')">+ Start First Scan</button>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        renderScanRows(tbody, scans);

    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

// ========== Scan Wizard ==========

function resetScanWizard() {
    currentScanId = null;
    sessionStorage.removeItem('atlas_scan_id');
    selectedChecks.clear();
    document.getElementById('target-input').value = '';
    goToStep(1);
}

function goToStep(stepNum) {
    // Update indicators
    document.querySelectorAll('.step').forEach((step, idx) => {
        step.classList.remove('active', 'completed');
        if (idx + 1 < stepNum) step.classList.add('completed');
        if (idx + 1 === stepNum) step.classList.add('active');
    });

    // Show step content
    document.querySelectorAll('.wizard-step').forEach(step => {
        step.classList.remove('active');
    });

    const stepNames = ['target', 'recon', 'selection', 'execution', 'results'];
    const stepEl = document.getElementById(`step-${stepNames[stepNum - 1]}`);
    if (stepEl) {
        stepEl.classList.add('active');
    }
}

async function startScan() {
    const target = document.getElementById('target-input').value.trim();
    const wordlist = document.getElementById('wordlist-input').value.trim();

    if (!target) {
        showToast('Please enter a target URL or IP address', 'warning');
        return;
    }

    showLoading('Initializing scan...');

    try {
        // Create scan payload
        const payload = { target };
        if (wordlist) {
            payload.wordlist = wordlist;
        }

        // Create scan
        const scan = await apiRequest('/scans', {
            method: 'POST',
            body: JSON.stringify(payload)
        });

        currentScanId = scan.id;
        sessionStorage.setItem('atlas_scan_id', scan.id);

        // Move to recon step
        goToStep(2);
        hideLoading();

        // Start reconnaissance
        await runReconnaissance();

    } catch (error) {
        hideLoading();
        showToast('Failed to start scan: ' + error.message, 'error');
    }
}

async function runReconnaissance() {
    const progressFill = document.getElementById('recon-progress');
    const statusText = document.getElementById('recon-status');

    // Animate progress
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress = Math.min(progress + 2, 90);
        progressFill.style.width = `${progress}%`;
    }, 500);

    try {
        statusText.textContent = 'Scanning ports and services...';

        // Fire-and-forget: kick off recon in background
        fetch(`${API_BASE}/scans/${currentScanId}/recon`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }).catch(() => { });

        // Poll scan status until recon completes (120s timeout)
        const results = await pollScanPhase('SELECTION', statusText, [
            'Scanning ports and services...',
            'Enumerating service versions...',
            'Fingerprinting target...',
            'Analyzing discovered services...'
        ], 90); // 90 attempts × 2s = 180s timeout

        clearInterval(progressInterval);
        progressFill.style.width = '100%';
        statusText.textContent = 'Reconnaissance complete!';

        // Display results
        if (results && results.recon) {
            displayReconResults(results.recon);
        } else {
            try {
                const scanData = await apiRequest(`/scans/${currentScanId}`);
                displayReconResults({
                    host: scanData.target,
                    ports: [],
                    services: {},
                    fingerprint: null
                });
            } catch (e) {
                displayReconResults({ host: '', ports: [], services: {}, fingerprint: null });
            }
        }

    } catch (error) {
        clearInterval(progressInterval);

        if (error.message.includes('scan_error')) {
            // Backend reported an actual error during recon
            progressFill.style.width = '100%';
            progressFill.style.background = 'var(--severity-critical, #ff4757)';
            statusText.innerHTML = `
                <span style="color: var(--severity-critical, #ff4757)">✕ Reconnaissance failed</span>
                <br><small style="opacity:0.7">The scan encountered an error. The target may be unreachable or invalid.</small>
                <br><button class="btn btn-sm" style="margin-top:8px" onclick="skipToCheckSelection()">Skip → Select Checks Manually</button>
            `;
        } else if (error.message.includes('timed out')) {
            progressFill.style.width = '100%';
            progressFill.style.background = 'var(--severity-medium, #f39c12)';
            statusText.innerHTML = `
                <span style="color: var(--severity-medium, #f39c12)">⏱ Reconnaissance timed out</span>
                <br><small style="opacity:0.7">Target may be unreachable or scanning is still running in background.</small>
                <br><button class="btn btn-sm" style="margin-top:8px" onclick="skipToCheckSelection()">Skip → Select Checks Manually</button>
            `;
        } else {
            statusText.textContent = 'Reconnaissance failed: ' + error.message;
        }
    }
}

/**
 * Skip recon and go straight to check selection.
 */
async function skipToCheckSelection() {
    goToStep(3);
    await loadApplicableChecks();
}

/**
 * Poll scan status until a target phase is reached.
 * @param {string} targetPhase - Phase to wait for (uppercase)
 * @param {HTMLElement} statusEl - Status text element to update
 * @param {string[]} messages - Cycling status messages
 * @param {number} maxAttempts - Max poll attempts (default 15 = 30s)
 * @returns {object} Progress data
 */
async function pollScanPhase(targetPhase, statusEl, messages, maxAttempts = 15) {
    let attempt = 0;
    let msgIdx = 0;

    while (attempt < maxAttempts) {
        await new Promise(r => setTimeout(r, 2000));
        attempt++;

        // Show elapsed time alongside status messages
        const elapsed = attempt * 2;
        if (messages && messages.length > 0 && attempt % 3 === 0) {
            msgIdx = (msgIdx + 1) % messages.length;
        }
        if (statusEl && messages && messages.length > 0) {
            statusEl.textContent = `${messages[msgIdx]} (${elapsed}s)`;
        }

        try {
            const progress = await apiRequest(`/scans/${currentScanId}`);

            const phaseOrder = ['IDLE', 'INITIALIZING', 'RECON', 'SELECTION', 'TESTING', 'REPORTING', 'COMPLETED', 'ERROR'];
            const currentIdx = phaseOrder.indexOf(progress.phase);
            const targetIdx = phaseOrder.indexOf(targetPhase);

            if (progress.phase === 'ERROR') {
                throw new Error('scan_error — reconnaissance failed on the backend');
            }

            if (currentIdx >= targetIdx) {
                return progress;
            }
        } catch (e) {
            if (e.message.includes('scan_error')) {
                throw e; // Re-throw scan errors
            }
            console.debug('Poll attempt failed, retrying...', e);
        }
    }

    throw new Error('Request timed out — target may be unreachable');
}

function displayReconResults(results) {
    const resultsCard = document.getElementById('recon-results-card');
    const servicesList = document.getElementById('services-list');
    const fingerprintBadge = document.getElementById('fingerprint-badge');

    // Show fingerprint if detected
    if (results.fingerprint) {
        fingerprintBadge.textContent = `Target Identified: ${results.fingerprint}`;
        fingerprintBadge.style.display = 'inline-block';
    } else {
        fingerprintBadge.style.display = 'none';
    }

    // Display services
    const services = results.services || {};
    const ports = Object.keys(services);

    if (ports.length === 0) {
        servicesList.innerHTML = '<p class="empty-state">No open ports detected</p>';
    } else {
        servicesList.innerHTML = ports.map(port => {
            const svc = services[port];
            return `
                <div class="service-item">
                    <div class="service-port">Port ${port}</div>
                    <div class="service-name">${svc.service || 'unknown'} ${svc.version || ''}</div>
                </div>
            `;
        }).join('');
    }

    resultsCard.style.display = 'block';
}

async function proceedToSelection() {
    goToStep(3);
    await loadApplicableChecks();
}

async function loadApplicableChecks() {
    try {
        const { checks } = await apiRequest('/checks');
        allChecks = checks;

        displayChecksForSelection(checks);

    } catch (error) {
        console.error('Failed to load checks:', error);
    }
}

function displayChecksForSelection(checks) {
    const container = document.getElementById('checks-list');

    // Group by category
    const byCategory = {};
    checks.forEach(check => {
        if (!byCategory[check.category]) {
            byCategory[check.category] = [];
        }
        byCategory[check.category].push(check);
    });

    container.innerHTML = Object.entries(byCategory).map(([category, categoryChecks]) => `
        <div class="check-category">
            <div class="category-header">${category}</div>
            ${categoryChecks.map(check => `
                <label class="check-item">
                    <input type="checkbox" 
                           value="${check.id}" 
                           onchange="toggleCheck('${check.id}')"
                           ${selectedChecks.has(check.id) ? 'checked' : ''}>
                    <div class="check-info">
                        <div class="check-name">${check.name}</div>
                        <div class="check-description">${check.description}</div>
                    </div>
                    <span class="severity-badge severity-${check.severity}">${check.severity}</span>
                </label>
            `).join('')}
        </div>
    `).join('');

    updateSelectionCount();
}

function toggleCheck(checkId) {
    if (selectedChecks.has(checkId)) {
        selectedChecks.delete(checkId);
    } else {
        selectedChecks.add(checkId);
    }
    updateSelectionCount();
}

function selectAllChecks() {
    allChecks.forEach(check => selectedChecks.add(check.id));
    document.querySelectorAll('.check-item input').forEach(cb => cb.checked = true);
    updateSelectionCount();
}

function deselectAllChecks() {
    selectedChecks.clear();
    document.querySelectorAll('.check-item input').forEach(cb => cb.checked = false);
    updateSelectionCount();
}

function updateSelectionCount() {
    document.getElementById('selected-count').textContent = selectedChecks.size;
}

async function executeChecks() {
    if (selectedChecks.size === 0) {
        showToast('Please select at least one check to execute', 'warning');
        return;
    }

    goToStep(4);

    const execProgress = document.getElementById('exec-progress');
    const execCurrent = document.getElementById('exec-current');
    const execTotal = document.getElementById('exec-total');
    const execLog = document.getElementById('execution-log');

    execTotal.textContent = selectedChecks.size;
    execCurrent.textContent = '0';
    execLog.innerHTML = '';

    try {
        // Select checks
        await apiRequest(`/scans/${currentScanId}/select`, {
            method: 'POST',
            body: JSON.stringify({ check_ids: Array.from(selectedChecks) })
        });

        addLogEntry('Checks selected, starting execution...', 'info');

        // Fire-and-forget: kick off execution in background
        fetch(`${API_BASE}/scans/${currentScanId}/execute`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }).catch(() => { });

        // Poll for completion with live progress updates
        const totalChecks = selectedChecks.size;
        let lastCompleted = 0;
        const checkNames = Array.from(selectedChecks);

        const maxPollAttempts = 30; // 30 * 2s = 60s max
        let pollAttempt = 0;

        while (pollAttempt < maxPollAttempts) {
            await new Promise(r => setTimeout(r, 2000));
            pollAttempt++;

            try {
                const progress = await apiRequest(`/scans/${currentScanId}`);

                const completed = progress.completed_checks || 0;
                const pct = totalChecks > 0 ? Math.round((completed / totalChecks) * 100) : 0;

                execProgress.style.width = `${pct}%`;
                execCurrent.textContent = completed;

                // Log newly completed checks
                if (completed > lastCompleted) {
                    for (let i = lastCompleted; i < completed && i < checkNames.length; i++) {
                        addLogEntry(`✓ Completed: ${checkNames[i]}`, 'success');
                    }
                    lastCompleted = completed;
                }

                if (progress.current_check) {
                    addLogEntry(`Running: ${progress.current_check}...`, 'info');
                }

                // Check if execution is complete (phase moved to reporting/complete)
                const phaseOrder = ['IDLE', 'INITIALIZING', 'RECON', 'SELECTION', 'TESTING', 'REPORTING', 'COMPLETED', 'ERROR'];
                const phaseIdx = phaseOrder.indexOf(progress.phase);
                if (phaseIdx >= phaseOrder.indexOf('REPORTING')) {
                    // Execution done — fetch findings
                    execProgress.style.width = '100%';
                    execCurrent.textContent = totalChecks;

                    // Fetch the actual findings from the scan
                    let findings = [];
                    try {
                        const report = await apiRequest(`/reports/${currentScanId}/findings`);
                        findings = report.findings || [];
                    } catch (e) {
                        // Fallback: findings_count from progress
                        addLogEntry(`Completed with ${progress.findings_count || 0} findings`, 'info');
                    }

                    addLogEntry(`Execution complete. Found ${findings.length} vulnerabilities.`,
                        findings.length > 0 ? 'error' : 'success');

                    setTimeout(() => {
                        displayResults(findings);
                    }, 1000);
                    return;
                }
            } catch (e) {
                console.debug('Execution poll failed, retrying...', e);
            }
        }

        addLogEntry('⏱ Execution timed out — checks may still be running in the background. Try viewing this scan from the Dashboard later.', 'error');

    } catch (error) {
        addLogEntry('Execution failed: ' + error.message, 'error');
    }
}

function addLogEntry(message, type = 'info') {
    const log = document.getElementById('execution-log');
    const entry = document.createElement('div');
    entry.className = `log-item ${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
}

function displayResults(findings) {
    goToStep(5);

    // Count by severity
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => {
        counts[f.severity] = (counts[f.severity] || 0) + 1;
    });

    document.getElementById('result-critical').textContent = counts.critical;
    document.getElementById('result-high').textContent = counts.high;
    document.getElementById('result-medium').textContent = counts.medium;
    document.getElementById('result-low').textContent = counts.low;
    document.getElementById('result-info').textContent = counts.info;

    // Display findings
    const container = document.getElementById('findings-list');

    if (findings.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="color: var(--severity-low);">
                ✓ No vulnerabilities found!
            </div>
        `;
        return;
    }

    container.innerHTML = findings.map(finding => `
        <div class="finding-card ${finding.severity}">
            <div class="finding-header">
                <div class="finding-title">${finding.title}</div>
                <span class="severity-badge severity-${finding.severity}">${finding.severity}</span>
            </div>
            <div class="finding-section">
                <div class="finding-section-title">Description</div>
                <p>${finding.description}</p>
            </div>
            ${finding.evidence ? `
                <div class="finding-section">
                    <div class="finding-section-title">Evidence</div>
                    <div class="finding-evidence">${escapeHtml(finding.evidence)}</div>
                </div>
            ` : ''}
            ${finding.remediation ? `
                <div class="finding-section">
                    <div class="finding-section-title">Remediation</div>
                    <p>${finding.remediation}</p>
                </div>
            ` : ''}
        </div>
    `).join('');
}

async function downloadReport() {
    try {
        // Generate report
        await apiRequest(`/reports/${currentScanId}/generate`, {
            method: 'POST',
            body: JSON.stringify({ format: 'html' })
        });

        // Download
        window.open(`${API_BASE}/reports/${currentScanId}/download?format=html`, '_blank');

    } catch (error) {
        showToast('Failed to generate report: ' + error.message, 'error');
    }
}

// ========== Reports Page ==========

async function loadReports() {
    try {
        // Fetch reports list (we'll use the scans list effectively for now as reports correspond to scans)
        const { scans } = await apiRequest('/scans?limit=50');
        const container = document.querySelector('#page-reports .card');

        if (scans.length === 0) {
            container.innerHTML = '<p class="empty-state">No scans found.</p>';
            return;
        }

        container.innerHTML = `
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Scan ID</th>
                            <th>Target</th>
                            <th>Date</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${scans.map(scan => `
                            <tr>
                                <td><code>${scan.id}</code></td>
                                <td>${truncate(scan.target, 50)}</td>
                                <td>${formatDate(scan.created_at)}</td>
                                <td><span class="status-${scan.status}">${scan.status}</span></td>
                                <td>
                                    <button class="btn btn-sm" onclick="downloadReportId('${scan.id}')">Download</button>
                                    <button class="btn btn-sm btn-secondary delete-btn" data-role="admin" style="color: var(--severity-critical); border-color: var(--severity-critical);" onclick="deleteReport('${scan.id}')">Delete</button>
                                </td>
                            </tr>
                        `).join('')}
                </tbody>
                </table>
            </div>
        `;

        // Re-apply role visibility for dynamically loaded content
        if (currentUser) {
            applyRoleVisibility(currentUser.role);
        }
    } catch (error) {
        console.error('Failed to load reports:', error);
    }
}

async function downloadReportId(scanId) {
    try {
        await apiRequest(`/reports/${scanId}/generate`, {
            method: 'POST',
            body: JSON.stringify({ format: 'html' })
        });
        window.open(`${API_BASE}/reports/${scanId}/download?format=html`, '_blank');
    } catch (error) {
        showToast('Failed to generate report', 'error');
    }
}

async function deleteReport(scanId) {
    if (!confirm('Are you sure you want to delete this report?')) return;

    try {
        await apiRequest(`/reports/${scanId}`, { method: 'DELETE' });
        loadReports(); // Reload list
    } catch (error) {
        showToast('Failed to delete report: ' + error.message, 'error');
    }
}

// ========== All Checks Page ==========

async function loadAllChecks() {
    try {
        const data = await apiRequest('/checks/categories');

        const summary = document.getElementById('checks-summary');
        summary.innerHTML = `
            <p>Total: <strong>${data.total}</strong> vulnerability checks available</p>
        `;

        const { checks } = await apiRequest('/checks');

        // Group by category
        const byCategory = {};
        checks.forEach(check => {
            if (!byCategory[check.category]) byCategory[check.category] = [];
            byCategory[check.category].push(check);
        });

        const container = document.getElementById('all-checks-list');
        container.innerHTML = Object.entries(byCategory).map(([cat, catChecks]) => `
            <div class="check-category">
                <div class="category-header">${cat} (${catChecks.length})</div>
                ${catChecks.map(c => `
                    <div class="check-item" style="cursor: default;">
                        <div class="check-info">
                            <div class="check-name">${c.name}</div>
                            <div class="check-description">${c.description}</div>
                            ${c.owasp_category ? `<small style="color: var(--text-muted);">${c.owasp_category}</small>` : ''}
                        </div>
                        <span class="severity-badge severity-${c.severity}">${c.severity}</span>
                    </div>
                `).join('')}
            </div>
        `).join('');

    } catch (error) {
        console.error('Failed to load checks:', error);
    }
}

// ========== Demo Targets Page ==========

async function loadDemoTargets() {
    try {
        const data = await apiRequest('/presets');

        const container = document.getElementById('presets-grid');

        container.innerHTML = data.presets.map(preset => `
            <div class="preset-card">
                <div class="preset-header">
                    <div class="preset-title">${preset.name}</div>
                    <span class="preset-category">${preset.category}</span>
                </div>
                
                <p class="preset-description">${preset.description}</p>
                
                <div class="preset-stats">
                    <div class="stat">
                        <strong>${preset.vulnerability_count}</strong> Vulnerabilities
                    </div>
                </div>
                
                <div class="preset-tags">
                    ${preset.tags.map(tag => `<span class="preset-tag">${tag}</span>`).join('')}
                </div>
                
                <div style="margin-top: auto; display: flex; gap: 12px;">
                    <a href="${preset.github_url}" target="_blank" class="btn btn-sm btn-secondary">
                        GitHub
                    </a>
                    <button class="btn btn-sm btn-primary" style="flex: 1;" onclick="startPresetScan('${preset.id}', '${preset.default_url}')">
                        Launch Demo
                    </button>
                </div>
            </div>
        `).join('');

    } catch (error) {
        console.error('Failed to load presets:', error);
    }
}

async function startPresetScan(presetId, defaultUrl) {
    // Presets with interactive simulations
    const simulatablePresets = ['iotgoat', 'vulnbank'];
    if (simulatablePresets.includes(presetId)) {
        await launchPresetSimulation(presetId);
        return;
    }

    // Other presets: original behavior
    const url = prompt(`Enter target URL for ${presetId}:`, defaultUrl);
    if (!url) return;

    showPage('new-scan');
    document.getElementById('target-input').value = url;

    // Auto-start
    await startScan();
}


// ========== IoTGoat Demo Simulation ==========

let simData = null;
let simCurrentStep = -1;
let simCompletedSteps = new Set();
let simIsAnimating = false;

const PRESET_SIM_META = {
    iotgoat: {
        label: 'OWASP IoTGoat',
        ip: '192.168.1.1',
        termTitle: 'iotgoatuser@IoTGoat:~',
        icon: '📡'
    },
    vulnbank: {
        label: 'VulnBank',
        ip: '127.0.0.1:5000',
        termTitle: 'pentester@kali:~/vulnbank',
        icon: '🏦'
    }
};

async function launchPresetSimulation(presetId) {
    const meta = PRESET_SIM_META[presetId] || { label: presetId, ip: 'localhost', termTitle: 'user@host:~', icon: '🔍' };
    showLoading(`Initializing ${meta.label} simulation...`);
    try {
        simData = await apiRequest(`/presets/${presetId}/simulate`, { method: 'POST' });
        simCurrentStep = -1;
        simCompletedSteps = new Set();
        simIsAnimating = false;

        showPage('iotgoat-demo');
        hideLoading();

        // Update page header dynamically
        const titleEl = document.querySelector('#page-iotgoat-demo .page-header h2');
        if (titleEl) titleEl.textContent = `${meta.label} — Live Simulation`;
        const deviceName = document.querySelector('.sim-device-name');
        if (deviceName) deviceName.textContent = meta.label;
        const ipBadge = document.querySelector('.sim-ip-badge');
        if (ipBadge) ipBadge.textContent = meta.ip;
        const termTitle = document.querySelector('.sim-terminal-title');
        if (termTitle) termTitle.textContent = meta.termTitle;

        renderSimStepList();
        updateSimProgress();

        // Auto-start first step
        runSimulationStep(0);
    } catch (error) {
        hideLoading();
        showToast(`Failed to load ${meta.label} simulation: ` + error.message, 'error');
    }
}

function renderSimStepList() {
    const list = document.getElementById('sim-step-list');
    list.innerHTML = simData.steps.map((step, idx) => `
        <div class="sim-step-item ${idx === simCurrentStep ? 'active' : ''} ${simCompletedSteps.has(idx) ? 'completed' : ''}"
             data-step="${idx}" onclick="runSimulationStep(${idx})">
            <div class="sim-step-item-num">${String(step.id).padStart(2, '0')}</div>
            <div class="sim-step-item-info">
                <div class="sim-step-item-title">${step.title}</div>
                <div class="sim-step-item-cat">${step.owasp_category}</div>
            </div>
            <div class="sim-step-item-status">
                ${simCompletedSteps.has(idx) ? '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#00ff88" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>' : ''}
            </div>
        </div>
    `).join('');
}

function updateSimProgress() {
    const done = simCompletedSteps.size;
    const total = simData.steps.length;
    document.getElementById('sim-steps-done').textContent = done;
    document.getElementById('sim-steps-total').textContent = total;
    document.getElementById('sim-progress-fill').style.width = `${(done / total) * 100}%`;

    // Show complete button if all done
    const completeBtn = document.getElementById('sim-complete-btn');
    if (done === total) {
        completeBtn.style.display = 'block';
    }
}

async function runSimulationStep(stepIndex) {
    if (simIsAnimating) return;
    if (stepIndex < 0 || stepIndex >= simData.steps.length) return;

    simCurrentStep = stepIndex;
    const step = simData.steps[stepIndex];

    // Update step header
    document.getElementById('sim-step-number').textContent = String(step.id).padStart(2, '0');
    document.getElementById('sim-step-title').textContent = step.title;
    document.getElementById('sim-owasp-badge').textContent = step.owasp_category;
    document.getElementById('sim-step-desc').textContent = step.description;

    // Hide findings and nav for now
    document.getElementById('sim-findings-panel').style.display = 'none';
    document.getElementById('sim-step-nav').style.display = 'none';

    // Highlight active step in navigator
    renderSimStepList();

    // Clear terminal
    const termBody = document.getElementById('sim-terminal-body');
    termBody.innerHTML = '';

    // Animate terminal commands
    simIsAnimating = true;

    for (const cmd of step.commands) {
        await animateTerminalCommand(termBody, cmd.prompt, cmd.output, cmd.delay || 1000);
    }

    simIsAnimating = false;

    // Mark step as completed
    simCompletedSteps.add(stepIndex);
    updateSimProgress();
    renderSimStepList();

    // Show findings
    showSimFindings(step.findings);

    // Show navigation
    const navDiv = document.getElementById('sim-step-nav');
    navDiv.style.display = 'flex';
    document.getElementById('sim-prev-btn').disabled = stepIndex === 0;
    document.getElementById('sim-next-btn').textContent =
        stepIndex === simData.steps.length - 1 ? 'View Summary ✓' : 'Next Challenge →';
}

function animateTerminalCommand(container, prompt, output, delay) {
    return new Promise(resolve => {
        // Remove old cursor
        const oldCursor = container.querySelector('.sim-terminal-cursor');
        if (oldCursor) oldCursor.remove();

        // Add prompt line with typing effect
        const promptLine = document.createElement('div');
        promptLine.className = 'sim-terminal-line prompt';
        container.appendChild(promptLine);

        // Type out the prompt
        let promptText = prompt;
        let charIdx = 0;
        const typeSpeed = 15;

        const typeInterval = setInterval(() => {
            if (charIdx < promptText.length) {
                promptLine.textContent = promptText.substring(0, charIdx + 1);
                charIdx++;
                container.scrollTop = container.scrollHeight;
            } else {
                clearInterval(typeInterval);

                // After prompt finishes, show "processing" pause then output
                setTimeout(() => {
                    // Add output lines
                    const lines = output.split('\n');
                    lines.forEach(line => {
                        const outputLine = document.createElement('div');
                        outputLine.className = 'sim-terminal-line output';
                        // Highlight warnings/alerts in red
                        if (line.includes('[!]') || line.includes('FOUND') || line.includes('SUCCESS') || line.includes('succeeded')) {
                            outputLine.className += ' highlight';
                        }
                        outputLine.textContent = line;
                        container.appendChild(outputLine);
                    });

                    // Add blank line separator
                    const spacer = document.createElement('div');
                    spacer.className = 'sim-terminal-line';
                    spacer.innerHTML = '&nbsp;';
                    container.appendChild(spacer);

                    // Add cursor
                    const cursor = document.createElement('div');
                    cursor.className = 'sim-terminal-cursor';
                    cursor.textContent = '█';
                    container.appendChild(cursor);

                    container.scrollTop = container.scrollHeight;
                    resolve();
                }, delay);
            }
        }, typeSpeed);
    });
}

function showSimFindings(findings) {
    const panel = document.getElementById('sim-findings-panel');
    const list = document.getElementById('sim-findings-list');

    list.innerHTML = findings.map(f => `
        <div class="sim-finding-card severity-${f.severity}">
            <div class="sim-finding-header">
                <span class="sim-finding-title">${escapeHtml(f.title)}</span>
                <span class="severity-badge severity-${f.severity}">${f.severity}</span>
            </div>
            <p class="sim-finding-desc">${escapeHtml(f.description)}</p>
            <div class="sim-finding-details">
                <div class="sim-finding-section">
                    <strong>Evidence</strong>
                    <pre>${escapeHtml(f.evidence)}</pre>
                </div>
                <div class="sim-finding-section">
                    <strong>Remediation</strong>
                    <p>${escapeHtml(f.remediation)}</p>
                </div>
                <div class="sim-finding-meta">
                    <span class="sim-meta-badge">${f.cwe}</span>
                    <span class="sim-meta-badge">OWASP IoT ${f.owasp_iot}</span>
                </div>
            </div>
        </div>
    `).join('');

    panel.style.display = 'block';
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function navigateSimStep(direction) {
    const nextIndex = simCurrentStep + direction;
    if (nextIndex < 0) return;

    if (nextIndex >= simData.steps.length) {
        showSimulationSummary();
        return;
    }
    runSimulationStep(nextIndex);
}

function showSimulationSummary() {
    // Collect all findings
    const allFindings = [];
    simData.steps.forEach(step => {
        step.findings.forEach(f => allFindings.push(f));
    });

    const counts = { critical: 0, high: 0, medium: 0 };
    allFindings.forEach(f => {
        if (counts[f.severity] !== undefined) counts[f.severity]++;
    });

    document.getElementById('sim-sum-critical').textContent = counts.critical;
    document.getElementById('sim-sum-high').textContent = counts.high;
    document.getElementById('sim-sum-medium').textContent = counts.medium;

    // Render all findings
    const container = document.getElementById('sim-summary-findings');
    container.innerHTML = allFindings.map(f => `
        <div class="sim-summary-finding-item">
            <span class="severity-badge severity-${f.severity}">${f.severity}</span>
            <span>${escapeHtml(f.title)}</span>
            <span class="sim-meta-badge">${f.cwe}</span>
        </div>
    `).join('');

    document.getElementById('sim-summary-overlay').style.display = 'flex';
}

function closeSimulationSummary() {
    document.getElementById('sim-summary-overlay').style.display = 'none';
}

// ========== Utilities ==========

function showLoading(text = 'Loading...') {
    document.getElementById('loading-text').textContent = text;
    document.getElementById('loading-overlay').classList.add('active');
}

function hideLoading() {
    document.getElementById('loading-overlay').classList.remove('active');
}

function truncate(str, len) {
    return str.length > len ? str.substring(0, len) + '...' : str;
}

function formatDate(dateStr) {
    if (!dateStr) return '—';
    // Backend sends UTC isoformat without 'Z' — append it so JS treats as UTC
    let s = String(dateStr);
    if (!s.endsWith('Z') && !s.includes('+') && !s.includes('-', 10)) {
        s += 'Z';
    }
    const d = new Date(s);
    if (isNaN(d)) return dateStr; // fallback if unparseable
    return d.toLocaleString('en-IN', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function viewScan(scanId) {
    try {
        showLoading('Loading scan...');
        currentScanId = scanId;
        sessionStorage.setItem('atlas_scan_id', scanId);

        const progress = await apiRequest(`/scans/${scanId}`);
        hideLoading();

        showPage('new-scan');

        // Map scan phase to wizard step
        const phaseToStep = {
            'IDLE': 1,
            'INITIALIZING': 1,
            'RECON': 2,
            'SELECTION': 3,
            'TESTING': 4,
            'REPORTING': 5,
            'COMPLETED': 5,
            'ERROR': 1
        };

        const step = phaseToStep[progress.phase] || 1;

        // Set the target input
        document.getElementById('target-input').value = progress.target || '';

        if (step === 1) {
            goToStep(1);
        } else if (step === 2) {
            goToStep(2);
            // Recon is in progress, poll for it
            await runReconnaissance();
        } else if (step >= 3) {
            // Recon done, go to selection
            goToStep(3);
            await loadApplicableChecks();

            if (step >= 4 && progress.findings_count > 0) {
                // Already has results, jump to results
                try {
                    const report = await apiRequest(`/reports/${scanId}/findings`);
                    displayResults(report.findings || []);
                } catch (e) {
                    goToStep(3); // Fallback to selection
                }
            }
        }
    } catch (error) {
        hideLoading();
        showToast('Failed to load scan: ' + error.message, 'error');
    }
}

async function resumeScan(scanId) {
    try {
        await apiRequest(`/scans/${scanId}/resume`, { method: 'POST' });
        loadDashboard();
    } catch (error) {
        showToast('Failed to resume scan: ' + error.message, 'error');
    }
}

// ========== Authentication & User Profile ==========

/**
 * Check if user is authenticated and load user profile
 */
async function checkAuthentication() {
    // First try to get user from localStorage
    const storedUser = localStorage.getItem('atlas_user');
    if (storedUser) {
        try {
            currentUser = JSON.parse(storedUser);
            updateUserProfile(currentUser);
            applyRoleVisibility(currentUser.role);
        } catch (e) {
            console.error('Failed to parse stored user:', e);
        }
    }

    // Then verify with server (but don't block if it fails)
    try {
        const response = await fetch('/api/auth/verify', {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('atlas_token') || ''}`
            },
            credentials: 'include'  // Include cookies
        });

        if (response.ok) {
            const data = await response.json();
            currentUser = data.user;

            // Store updated user data
            localStorage.setItem('atlas_user', JSON.stringify(currentUser));

            // Update user profile UI
            updateUserProfile(currentUser);

            // Apply role-based visibility
            applyRoleVisibility(currentUser.role);

            return true;
        }
    } catch (error) {
        console.error('Auth verify failed:', error);
    }

    // If we have a stored user, allow access (for demo purposes)
    if (currentUser) {
        return true;
    }

    // No authentication, return false
    return false;
}

/**
 * Update user profile section in sidebar
 */
function updateUserProfile(user) {
    const avatarEl = document.getElementById('user-avatar');
    const nameEl = document.getElementById('user-name');
    const roleBadgeEl = document.getElementById('user-role-badge');

    if (avatarEl && user.name) {
        // Get initials
        const initials = user.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
        avatarEl.textContent = initials;
    }

    if (nameEl) {
        nameEl.textContent = user.name || user.username || 'User';
    }

    if (roleBadgeEl) {
        // Map roles to display text
        const roleMap = {
            'admin': 'Administrator',
            'analyst': 'Analyst',
            'pentester': 'Pen Tester',
            'user': 'Security User'
        };
        const roleText = roleMap[user.role] || 'Pen Tester';
        roleBadgeEl.textContent = roleText;
        roleBadgeEl.classList.remove('admin', 'pentester', 'analyst');
        roleBadgeEl.classList.add(user.role === 'admin' ? 'admin' : 'pentester');
    }
}

/**
 * Toggle user dropdown menu
 */
function toggleUserMenu() {
    const userProfile = document.getElementById('user-profile');
    if (!userProfile) return;
    const isOpen = userProfile.classList.toggle('open');
    if (isOpen) {
        // Close when clicking anywhere outside
        setTimeout(() => {
            function closeOnOutsideClick(e) {
                if (!userProfile.contains(e.target)) {
                    userProfile.classList.remove('open');
                    document.removeEventListener('click', closeOnOutsideClick, true);
                }
            }
            document.addEventListener('click', closeOnOutsideClick, true);
        }, 0);
    }
}

/**
 * Apply role-based visibility to UI elements
 * data-role can be: "admin", "pentester", "analyst", or comma-separated list like "pentester,admin"
 */
function applyRoleVisibility(role) {
    document.querySelectorAll('[data-role]').forEach(el => {
        const allowedRoles = el.dataset.role.split(',').map(r => r.trim());

        if (allowedRoles.includes(role)) {
            // User has permission - show element
            el.classList.remove('hidden');
        } else {
            // User doesn't have permission - hide element
            el.classList.add('hidden');
        }
    });
}

/**
 * Handle user logout
 */
async function handleLogout() {
    try {
        await fetch('/api/auth/logout', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('atlas_token') || ''}`
            }
        });
    } catch (error) {
        console.error('Logout error:', error);
    }

    // Clear local storage
    localStorage.removeItem('atlas_token');
    localStorage.removeItem('atlas_user');

    // Redirect to login
    window.location.href = '/login';
}

/**
 * Load user profile data into profile page
 */
function loadProfile() {
    if (!currentUser) return;

    // Update Avatar
    const avatarEl = document.getElementById('profile-page-avatar');
    if (avatarEl && currentUser.name) {
        avatarEl.textContent = currentUser.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
    }

    // Update Text Fields
    const fields = {
        'profile-page-name': currentUser.name,
        'profile-page-username': currentUser.username,
        'profile-page-email': currentUser.email || 'No email provided',
        'profile-page-joined': currentUser.created_at ? formatDate(currentUser.created_at) : 'Feb 2026'
    };

    for (const [id, value] of Object.entries(fields)) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    // Update Role Badge
    const roleBadge = document.getElementById('profile-page-role');
    if (roleBadge && currentUser.role) {
        roleBadge.textContent = currentUser.role.charAt(0).toUpperCase() + currentUser.role.slice(1);
        roleBadge.className = 'user-role-badge ' + (currentUser.role === 'admin' ? 'admin' : 'pentester');
    }

    // Pre-fill edit forms
    const editName = document.getElementById('edit-name');
    const editEmail = document.getElementById('edit-email');
    if (editName) editName.value = currentUser.name || '';
    if (editEmail) editEmail.value = currentUser.email || '';
}

// ========== Scan Actions (Delete / Export / Cancel) ==========

async function deleteScan(scanId) {
    if (!confirm(`Delete scan ${scanId} and all associated data? This cannot be undone.`)) return;
    try {
        await apiRequest(`/scans/${scanId}`, { method: 'DELETE' });
        showToast('Scan deleted successfully', 'success');
        loadDashboard();
    } catch (error) {
        showToast('Failed to delete scan: ' + error.message, 'error');
    }
}

async function exportScan(scanId) {
    try {
        const data = await apiRequest(`/scans/${scanId}/export`);
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `atlas-scan-${scanId}.json`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (error) {
        showToast('Failed to export scan: ' + error.message, 'error');
    }
}

async function cancelScan(scanId) {
    if (!confirm('Cancel this running scan?')) return;
    try {
        await apiRequest(`/scans/${scanId}/cancel`, { method: 'POST' });
        loadDashboard();
    } catch (error) {
        showToast('Failed to cancel scan: ' + error.message, 'error');
    }
}

// ========== Activity Log ==========

async function loadActivityFeed() {
    const container = document.getElementById('activity-feed');
    // Skeleton loading
    container.innerHTML = Array(5).fill('').map(() => `
        <div class="activity-item">
            <div class="skeleton" style="width:10px;height:10px;border-radius:50%;margin-top:5px;"></div>
            <div class="activity-content">
                <div class="skeleton skeleton-line w-75"></div>
                <div class="skeleton skeleton-line w-30" style="margin-top:6px;"></div>
            </div>
        </div>
    `).join('');

    try {
        const data = await apiRequest('/activity?limit=50');
        const events = data.events || [];

        if (events.length === 0) {
            container.innerHTML = `
                <div class="empty-state-enhanced">
                    <div class="empty-state-icon">📋</div>
                    <h4>No activity yet</h4>
                    <p>Events will appear here as you run scans.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = events.map((ev, idx) => {
            const dotClass = ['scan_created', 'scan_completed', 'scan_cancelled', 'finding_discovered', 'error'].includes(ev.event_type)
                ? ev.event_type : 'default';
            return `
                <div class="activity-item" style="animation-delay: ${idx * 0.04}s;">
                    <div class="activity-dot ${dotClass}"></div>
                    <div class="activity-content">
                        <div class="activity-message">${escapeHtml(ev.message)}</div>
                        <div class="activity-meta">
                            ${ev.scan_id ? `<code>${ev.scan_id}</code> · ` : ''}
                            ${formatDate(ev.timestamp)}
                        </div>
                    </div>
                </div>
            `;
        }).join('');

    } catch (error) {
        container.innerHTML = '<p class="empty-state">Failed to load activity feed.</p>';
        console.error('Activity feed error:', error);
    }
}

// ========== Scheduled Scans ==========

async function loadSchedules() {
    const tbody = document.getElementById('schedules-table-body');
    try {
        const data = await apiRequest('/scheduler');
        const schedules = data.schedules || [];

        if (schedules.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6">
                        <div class="empty-state-enhanced">
                            <div class="empty-state-icon">⏰</div>
                            <h4>No scheduled scans</h4>
                            <p>Create a recurring scan using the form above.</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = schedules.map(s => `
            <tr>
                <td><code>${s.id}</code></td>
                <td>${truncate(s.target, 35)}</td>
                <td><code>${s.cron_expr}</code></td>
                <td>
                    <label class="toggle-switch" style="transform: scale(0.8);">
                        <input type="checkbox" ${s.enabled ? 'checked' : ''} onchange="toggleSchedule('${s.id}', this.checked)">
                        <span class="slider"></span>
                    </label>
                </td>
                <td>${s.last_run ? formatDate(s.last_run) : 'Never'}</td>
                <td>
                    <button class="btn btn-sm" onclick="deleteSchedule('${s.id}')" 
                        style="color: var(--severity-critical); border-color: var(--severity-critical);">
                        Delete
                    </button>
                </td>
            </tr>
        `).join('');

    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Failed to load schedules.</td></tr>';
        console.error('Schedules error:', error);
    }
}

async function createScheduledScan() {
    const target = document.getElementById('schedule-target').value.trim();
    const cron = document.getElementById('schedule-cron').value;

    if (!target) {
        showToast('Please enter a target URL', 'warning');
        return;
    }

    try {
        await apiRequest('/scheduler', {
            method: 'POST',
            body: JSON.stringify({ target, cron_expr: cron })
        });
        showToast('Schedule created successfully', 'success');
        document.getElementById('schedule-target').value = '';
        loadSchedules();
    } catch (error) {
        showToast('Failed to create schedule: ' + error.message, 'error');
    }
}

async function toggleSchedule(scheduleId, enabled) {
    try {
        await apiRequest(`/scheduler/${scheduleId}`, {
            method: 'PUT',
            body: JSON.stringify({ enabled })
        });
    } catch (error) {
        showToast('Failed to update schedule: ' + error.message, 'error');
        loadSchedules();
    }
}

async function deleteSchedule(scheduleId) {
    if (!confirm('Delete this scheduled scan?')) return;
    try {
        await apiRequest(`/scheduler/${scheduleId}`, { method: 'DELETE' });
        showToast('Schedule deleted', 'success');
        loadSchedules();
    } catch (error) {
        showToast('Failed to delete schedule: ' + error.message, 'error');
    }
}

// ========== Profile Edit & Password Change ==========

async function saveProfileChanges() {
    const name = document.getElementById('edit-name').value.trim();
    const email = document.getElementById('edit-email').value.trim();
    const msgEl = document.getElementById('profile-edit-msg');

    if (!name && !email) {
        msgEl.innerHTML = '<span style="color: #ff6b6b;">Please fill in at least one field.</span>';
        return;
    }

    try {
        const body = {};
        if (name) body.name = name;
        if (email) body.email = email;

        const result = await apiRequest('/auth/profile', {
            method: 'PUT',
            body: JSON.stringify(body)
        });

        // Update local user data
        if (result.user) {
            currentUser = { ...currentUser, ...result.user };
            localStorage.setItem('atlas_user', JSON.stringify(currentUser));
            updateUserProfile(currentUser);
            loadProfile();
        }

        msgEl.innerHTML = '<span style="color: #00ff88;">✓ Profile updated successfully!</span>';
        setTimeout(() => { msgEl.innerHTML = ''; }, 3000);

    } catch (error) {
        msgEl.innerHTML = `<span style="color: #ff6b6b;">Error: ${error.message}</span>`;
    }
}

async function changeUserPassword() {
    const currentPw = document.getElementById('current-password').value;
    const newPw = document.getElementById('new-password').value;
    const msgEl = document.getElementById('password-change-msg');

    if (!currentPw || !newPw) {
        msgEl.innerHTML = '<span style="color: #ff6b6b;">Please fill in both fields.</span>';
        return;
    }

    if (newPw.length < 8) {
        msgEl.innerHTML = '<span style="color: #ff6b6b;">New password must be at least 8 characters.</span>';
        return;
    }

    try {
        await apiRequest('/auth/password', {
            method: 'PUT',
            body: JSON.stringify({ current_password: currentPw, new_password: newPw })
        });

        document.getElementById('current-password').value = '';
        document.getElementById('new-password').value = '';
        msgEl.innerHTML = '<span style="color: #00ff88;">✓ Password changed successfully!</span>';
        setTimeout(() => { msgEl.innerHTML = ''; }, 3000);

    } catch (error) {
        msgEl.innerHTML = `<span style="color: #ff6b6b;">Error: ${error.message}</span>`;
    }
}
// ========== Real Web Terminal (xterm.js + WebSocket) ==========

const WebTerminal = {
    term: null,
    fitAddon: null,
    ws: null,
    initialized: false,
    _sessionTimer: null,
    _reconnectAttempts: 0,
    _maxReconnectAttempts: 5,

    _initRetries: 0,

    init() {
        if (this.initialized && this.term) {
            // Already initialized — just re-fit
            setTimeout(() => this.fit(), 100);
            return;
        }

        // Guard: xterm.js may not be loaded yet (deferred scripts)
        if (typeof Terminal === 'undefined' || typeof FitAddon === 'undefined') {
            if (this._initRetries < 10) {
                this._initRetries++;
                setTimeout(() => this.init(), 200);
            } else {
                console.error('xterm.js failed to load');
            }
            return;
        }
        this._initRetries = 0;

        const container = document.getElementById('xterm-container');
        if (!container) return;

        // Clear any previous content
        container.innerHTML = '';

        // Create xterm.js instance
        this.term = new Terminal({
            cursorBlink: true,
            cursorStyle: 'bar',
            fontSize: 14,
            fontFamily: '"Fira Code", "Cascadia Code", "JetBrains Mono", monospace',
            theme: {
                background: '#000000',
                foreground: '#a0aec0',
                cursor: '#00ff88',
                cursorAccent: '#000000',
                selectionBackground: 'rgba(0, 255, 136, 0.2)',
                selectionForeground: '#ffffff',
                black: '#0a0e1a',
                red: '#ff4757',
                green: '#00ff88',
                yellow: '#ffd43b',
                blue: '#00d4ff',
                magenta: '#b794f6',
                cyan: '#00d4ff',
                white: '#e2e8f0',
                brightBlack: '#4a5568',
                brightRed: '#ff6b81',
                brightGreen: '#2ed573',
                brightYellow: '#fffa65',
                brightBlue: '#70a1ff',
                brightMagenta: '#d6a4ff',
                brightCyan: '#7bed9f',
                brightWhite: '#ffffff',
            },
            allowProposedApi: true,
            scrollback: 5000,
            convertEol: true,
        });

        // Load addons
        this.fitAddon = new FitAddon.FitAddon();
        this.term.loadAddon(this.fitAddon);

        if (typeof WebLinksAddon !== 'undefined') {
            this.term.loadAddon(new WebLinksAddon.WebLinksAddon());
        }

        // Open terminal in container
        this.term.open(container);

        // Fit to container
        setTimeout(() => this.fit(), 50);

        // Handle user input — send to WebSocket
        this.term.onData((data) => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(data);
            }
        });

        // Handle resize
        this.term.onResize(({ cols, rows }) => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ type: 'resize', cols, rows }));
            }
        });

        // Watch for container resize
        const resizeObserver = new ResizeObserver(() => this.fit());
        resizeObserver.observe(container);

        // Connect WebSocket
        this.connect();

        this.initialized = true;
    },

    fit() {
        if (this.fitAddon && this.term) {
            try {
                this.fitAddon.fit();
            } catch (e) {
                // Ignore fit errors during transitions
            }
        }
    },

    connect() {
        const token = localStorage.getItem('atlas_token');
        if (!token) {
            this.term.writeln('\r\n\x1b[31m[ERROR] Not authenticated. Please log in first.\x1b[0m\r\n');
            this.updateStatus('ERROR', 'red');
            return;
        }

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/api/terminal/ws?token=${encodeURIComponent(token)}`;

        this.updateStatus('CONNECTING', 'yellow');

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            this._reconnectAttempts = 0;
            this.updateStatus('CONNECTED', 'green');

            // Send initial resize
            setTimeout(() => {
                this.fit();
                if (this.term) {
                    this.ws.send(JSON.stringify({
                        type: 'resize',
                        cols: this.term.cols,
                        rows: this.term.rows,
                    }));
                }
            }, 100);
        };

        this.ws.onmessage = (event) => {
            if (this.term) {
                this.term.write(event.data);
            }
        };

        this.ws.onclose = (event) => {
            if (event.code === 4003) {
                this.term.writeln('\r\n\x1b[31m[ACCESS DENIED] Terminal requires pentester or admin role.\x1b[0m\r\n');
                this.updateStatus('DENIED', 'red');
                return;
            }

            this.updateStatus('DISCONNECTED', 'red');

            // Auto-reconnect with backoff
            if (this._reconnectAttempts < this._maxReconnectAttempts) {
                this._reconnectAttempts++;
                const delay = Math.min(1000 * Math.pow(2, this._reconnectAttempts), 10000);
                this.term.writeln(`\r\n\x1b[33m[DISCONNECTED] Reconnecting in ${delay / 1000}s... (attempt ${this._reconnectAttempts}/${this._maxReconnectAttempts})\x1b[0m`);
                setTimeout(() => this.connect(), delay);
            } else {
                this.term.writeln('\r\n\x1b[31m[DISCONNECTED] Max reconnect attempts reached. Refresh the page.\x1b[0m\r\n');
            }
        };

        this.ws.onerror = () => {
            this.updateStatus('ERROR', 'red');
        };
    },

    updateStatus(text, color) {
        const el = document.getElementById('ws-status');
        if (el) {
            el.textContent = text;
            // Update the indicator dot color
            el.style.setProperty('--status-color', color === 'green' ? '#00ff88' : color === 'yellow' ? '#ffd43b' : '#ff4757');
        }
    },

    clear() {
        if (this.term) {
            this.term.clear();
        }
    },

    destroy() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        if (this._sessionTimer) {
            clearInterval(this._sessionTimer);
            this._sessionTimer = null;
        }
        // Don't dispose term — keep it alive for re-navigation
    }
};

function initWebTerminal() {
    WebTerminal.init();

    // Update title with actual username
    const titleEl = document.getElementById('web-term-title');
    if (currentUser && titleEl) {
        const user = currentUser.username || 'pentester';
        titleEl.textContent = `${user}@atlas ~ bash`;
    }

    // Session timer
    if (!WebTerminal._sessionTimer) {
        const startTime = Date.now();
        WebTerminal._sessionTimer = setInterval(() => {
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            const mins = Math.floor(elapsed / 60);
            const secs = String(elapsed % 60).padStart(2, '0');
            const el = document.getElementById('web-term-session-time');
            if (el) el.textContent = `SESSION: ${mins}:${secs}`;
        }, 1000);
    }

    // Focus the terminal
    setTimeout(() => WebTerminal.term?.focus(), 200);
}

function webTermClear() {
    WebTerminal.clear();
}

function webTermFullscreen() {
    const wrapper = document.getElementById('web-terminal-wrapper');
    if (wrapper) {
        wrapper.classList.toggle('fullscreen');
        // Re-fit after transition
        setTimeout(() => WebTerminal.fit(), 300);
    }
}

