/**
 * ATLAS Web UI Application
 * JavaScript for scan workflows and UI interactions
 */

// API Configuration
const API_BASE = '/api';

// State
let currentScanId = null;
let selectedChecks = new Set();
let allChecks = [];
let currentUser = null;

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

    // Initialize sidebar state
    initSidebarState();

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

// Toggle sidebar collapse (Desktop)
function toggleSidebarCollapse() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        sidebar.classList.toggle('collapsed');
        // Save preference
        const isCollapsed = sidebar.classList.contains('collapsed');
        localStorage.setItem('sidebarCollapsed', isCollapsed);
    }
}

// Initialize sidebar state
function initSidebarState() {
    const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    const sidebar = document.getElementById('sidebar');
    if (isCollapsed && sidebar) {
        sidebar.classList.add('collapsed');
    }
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
    }

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

// ========== Dashboard ==========

async function loadDashboard() {
    try {
        const { scans } = await apiRequest('/scans?limit=10');

        document.getElementById('stat-total-scans').textContent = scans.length;

        const tbody = document.getElementById('scans-table-body');

        if (scans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">No scans yet. Start your first scan!</td>
                </tr>
            `;
            return;
        }

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
                </td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

// ========== Scan Wizard ==========

function resetScanWizard() {
    currentScanId = null;
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
        alert('Please enter a target URL or IP address');
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

        // Move to recon step
        goToStep(2);
        hideLoading();

        // Start reconnaissance
        await runReconnaissance();

    } catch (error) {
        hideLoading();
        alert('Failed to start scan: ' + error.message);
    }
}

async function runReconnaissance() {
    const progressFill = document.getElementById('recon-progress');
    const statusText = document.getElementById('recon-status');

    // Animate progress
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress = Math.min(progress + 5, 90);
        progressFill.style.width = `${progress}%`;
    }, 200);

    try {
        statusText.textContent = 'Scanning ports and services...';

        const results = await apiRequest(`/scans/${currentScanId}/recon`, {
            method: 'POST'
        });

        clearInterval(progressInterval);
        progressFill.style.width = '100%';
        statusText.textContent = 'Reconnaissance complete!';

        // Display results
        displayReconResults(results);

    } catch (error) {
        clearInterval(progressInterval);
        statusText.textContent = 'Reconnaissance failed: ' + error.message;
    }
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
        alert('Please select at least one check to execute');
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

        // Execute checks
        const { findings, total } = await apiRequest(`/scans/${currentScanId}/execute`, {
            method: 'POST'
        });

        execProgress.style.width = '100%';
        execCurrent.textContent = selectedChecks.size;

        addLogEntry(`Execution complete. Found ${findings.length} vulnerabilities.`,
            findings.length > 0 ? 'error' : 'success');

        // Show results after short delay
        setTimeout(() => {
            displayResults(findings);
        }, 1000);

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
        alert('Failed to generate report: ' + error.message);
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
        alert('Failed to generate report');
    }
}

async function deleteReport(scanId) {
    if (!confirm('Are you sure you want to delete this report?')) return;

    try {
        await apiRequest(`/reports/${scanId}`, { method: 'DELETE' });
        loadReports(); // Reload list
    } catch (error) {
        alert('Failed to delete report: ' + error.message);
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
        alert(`Failed to load ${meta.label} simulation: ` + error.message);
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
    return new Date(dateStr).toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function viewScan(scanId) {
    // TODO: Implement scan details view
    alert('View scan details: ' + scanId);
}

async function resumeScan(scanId) {
    try {
        await apiRequest(`/scans/${scanId}/resume`, { method: 'POST' });
        loadDashboard();
    } catch (error) {
        alert('Failed to resume scan: ' + error.message);
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
    if (userProfile) {
        userProfile.classList.toggle('open');
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

    // Attach event listeners for buttons if not already attached
    // (Simple implementation: re-attaching is fine or check attribute)
    document.querySelectorAll('.settings-card button').forEach(btn => {
        btn.onclick = () => alert('This feature is coming soon!');
    });
}
