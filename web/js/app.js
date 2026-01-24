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

// ========== Initialization ==========

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    checkApiStatus();
    loadDashboard();
});

function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            showPage(page);
        });
    });

    // Handle hash navigation
    if (window.location.hash) {
        const page = window.location.hash.replace('#', '');
        showPage(page);
    }
}

function showPage(pageName) {
    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
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

    if (!target) {
        alert('Please enter a target URL or IP address');
        return;
    }

    showLoading('Initializing scan...');

    try {
        // Create scan
        const scan = await apiRequest('/scans', {
            method: 'POST',
            body: JSON.stringify({ target })
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
        fingerprintBadge.textContent = `🎯 Target Identified: ${results.fingerprint}`;
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
    // Determine target URL
    const url = prompt(`Enter target URL for ${presetId}:`, defaultUrl);
    if (!url) return;

    showPage('new-scan');
    document.getElementById('target-input').value = url;

    // Auto-start
    await startScan();
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
