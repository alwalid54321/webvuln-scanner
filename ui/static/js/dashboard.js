/**
 * Web Vulnerability Scanner - Dashboard JavaScript
 * Handles UI interactions, WebSocket communication, and data visualization
 */

// Socket.IO connection
const socket = io();
let startTime = null;
let timerInterval = null;
let severityChart = null;
let findings = [];

// DOM Elements
const statusIndicator = document.getElementById('status-indicator');
const statusDot = statusIndicator.querySelector('.status-dot');
const statusText = statusIndicator.querySelector('.status-text');

const startButton = document.getElementById('start-scan');
const pauseButton = document.getElementById('pause-scan');
const stopButton = document.getElementById('stop-scan');
const testConnectivityButton = document.getElementById('test-connectivity');

const targetUrlInput = document.getElementById('target-url');
const scanDepthInput = document.getElementById('scan-depth');
const scanDelayInput = document.getElementById('scan-delay');
const scanTimeoutInput = document.getElementById('scan-timeout');
const scanThreadsInput = document.getElementById('scan-threads');

const statUrls = document.getElementById('stat-urls');
const statFindings = document.getElementById('stat-findings');
const statDuration = document.getElementById('stat-duration');
const statUrlsPerSec = document.getElementById('stat-urls-per-sec');

const scanProgress = document.getElementById('scan-progress');
const progressPercentage = document.getElementById('progress-percentage');

const severityFilter = document.getElementById('severity-filter');
const searchInput = document.getElementById('search-findings');
const findingsTableBody = document.getElementById('findings-table-body');

const findingsModal = document.getElementById('finding-details-modal');
const modalClose = document.querySelector('.close-modal');
const modalTitle = document.getElementById('modal-title');
const modalBody = document.getElementById('finding-details');

// Plugin checkboxes
const pluginSql = document.getElementById('plugin-sql');
const pluginXss = document.getElementById('plugin-xss');
const pluginTraversal = document.getElementById('plugin-traversal');
const pluginRedirect = document.getElementById('plugin-redirect');
const pluginHeaders = document.getElementById('plugin-headers');

/**
 * Initialize the dashboard
 */
function initDashboard() {
    // Create chart
    createSeverityChart();
    
    // Socket event listeners
    setupSocketListeners();
    
    // UI event listeners
    setupUIListeners();
    
    // Load initial data
    loadInitialData();
}

/**
 * Set up Socket.IO event listeners
 */
function setupSocketListeners() {
    // Connection established
    socket.on('connect', () => {
        console.log('Connected to server');
    });
    
    // Connection lost
    socket.on('disconnect', () => {
        console.log('Disconnected from server');
        updateStatus('disconnected');
    });
    
    // Status update
    socket.on('status_update', (data) => {
        updateDashboardStatus(data);
    });
    
    // New finding received
    socket.on('new_finding', (finding) => {
        addFinding(finding);
        updateChart();
    });
    
    // All findings update
    socket.on('findings_update', (data) => {
        findings = data;
        renderFindings();
        updateChart();
    });
    
    // Progress update
    socket.on('progress_update', (data) => {
        updateProgress(data);
    });
}

/**
 * Set up UI event listeners
 */
function setupUIListeners() {
    // Start scan button
    startButton.addEventListener('click', () => {
        const targetUrl = targetUrlInput.value.trim();
        if (!targetUrl || !isValidUrl(targetUrl)) {
            alert('Please enter a valid URL');
            return;
        }
        
        const activePlugins = getActivePlugins();
        if (activePlugins.length === 0) {
            alert('Please select at least one plugin');
            return;
        }
        
        startScan(targetUrl);
    });
    
    // Pause scan button
    pauseButton.addEventListener('click', () => {
        if (pauseButton.textContent === 'Pause') {
            socket.emit('pause_scan');
        } else {
            socket.emit('resume_scan');
        }
    });
    
    // Stop scan button
    stopButton.addEventListener('click', () => {
        if (confirm('Are you sure you want to stop the current scan?')) {
            socket.emit('stop_scan');
        }
    });
    
    // Test connectivity button
    testConnectivityButton.addEventListener('click', () => {
        const targetUrl = targetUrlInput.value.trim();
        if (!targetUrl || !isValidUrl(targetUrl)) {
            alert('Please enter a valid URL');
            return;
        }
        
        testConnectivity(targetUrl);
    });
    
    // Severity filter
    severityFilter.addEventListener('change', filterFindings);
    
    // Search input
    searchInput.addEventListener('input', filterFindings);
    
    // Modal close
    modalClose.addEventListener('click', () => {
        findingsModal.style.display = 'none';
    });
    
    // Close modal when clicking outside
    window.addEventListener('click', (e) => {
        if (e.target === findingsModal) {
            findingsModal.style.display = 'none';
        }
    });
}

/**
 * Load initial data from the server
 */
function loadInitialData() {
    // Fetch current status
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            updateDashboardStatus(data);
        })
        .catch(error => console.error('Error fetching status:', error));
    
    // Fetch findings
    fetch('/api/findings')
        .then(response => response.json())
        .then(data => {
            findings = data;
            renderFindings();
            updateChart();
        })
        .catch(error => console.error('Error fetching findings:', error));
}

/**
 * Start a new scan
 * @param {string} targetUrl - The URL to scan
 */
function startScan(targetUrl) {
    const scanConfig = {
        target_url: targetUrl,
        max_depth: parseInt(scanDepthInput.value, 10),
        delay: parseFloat(scanDelayInput.value),
        timeout: parseInt(scanTimeoutInput.value, 10),
        threads: parseInt(scanThreadsInput.value, 10),
        plugins: getActivePlugins()
    };
    
    socket.emit('start_scan', scanConfig, (response) => {
        if (response.success) {
            startTime = new Date();
            startTimer();
            updateStatus('running');
            toggleControlButtons(true);
            findings = [];
            renderFindings();
            updateChart();
        } else {
            alert(`Failed to start scan: ${response.message}`);
        }
    });
}

/**
 * Test connectivity to target URL
 * @param {string} targetUrl - The URL to test
 */
function testConnectivity(targetUrl) {
    // Disable the test button and show loading state
    testConnectivityButton.disabled = true;
    testConnectivityButton.textContent = 'Testing...';
    
    // Emit connectivity test request
    socket.emit('test_connectivity', { target_url: targetUrl }, (response) => {
        // Re-enable the button
        testConnectivityButton.disabled = false;
        testConnectivityButton.textContent = 'Test Connectivity';
        
        if (response.success) {
            alert(`✅ Connectivity Test Successful!\n\nTarget: ${targetUrl}\nResponse Time: ${response.response_time}ms\nStatus: ${response.status_code}\n\nTarget is ready for scanning.`);
        } else {
            alert(`❌ Connectivity Test Failed!\n\nTarget: ${targetUrl}\nError: ${response.error}\n\nSuggestions:\n• Check if the URL is correct\n• Try increasing timeout settings\n• Verify network connectivity\n• Check if target blocks automated requests`);
        }
    });
}

/**
 * Get active plugins based on checkbox selection
 * @returns {Array} - List of active plugin names
 */
function getActivePlugins() {
    const plugins = [];
    if (pluginSql.checked) plugins.push('sql_injection');
    if (pluginXss.checked) plugins.push('xss');
    if (pluginTraversal.checked) plugins.push('directory_traversal');
    if (pluginRedirect.checked) plugins.push('open_redirect');
    if (pluginHeaders.checked) plugins.push('security_headers');
    return plugins;
}

/**
 * Update dashboard status display
 * @param {Object} data - Status data
 */
function updateDashboardStatus(data) {
    if (data.is_running) {
        updateStatus('running');
        toggleControlButtons(true);
        
        if (!startTime && data.start_time) {
            startTime = new Date(data.start_time * 1000);
            startTimer();
        }
    } else {
        updateStatus('idle');
        toggleControlButtons(false);
        stopTimer();
    }
    
    // Update statistics
    statUrls.textContent = data.scanned_urls || 0;
    statFindings.textContent = data.findings_count || 0;
    
    // Calculate URLs per second
    if (startTime) {
        const elapsedSeconds = (new Date() - startTime) / 1000;
        if (elapsedSeconds > 0) {
            const urlsPerSec = (data.scanned_urls / elapsedSeconds).toFixed(1);
            statUrlsPerSec.textContent = urlsPerSec;
        }
    }
    
    // Update target URL input if different
    if (data.target_url && data.target_url !== targetUrlInput.value) {
        targetUrlInput.value = data.target_url;
    }
    
    // Update progress if total URLs is available
    if (data.total_urls > 0) {
        updateProgress({
            total: data.total_urls,
            current: data.scanned_urls,
            percentage: (data.scanned_urls / data.total_urls * 100)
        });
    }
}

/**
 * Update scan progress display
 * @param {Object} data - Progress data
 */
function updateProgress(data) {
    const percentage = Math.min(100, Math.max(0, data.percentage)).toFixed(1);
    scanProgress.style.width = `${percentage}%`;
    progressPercentage.textContent = `${percentage}%`;
    
    statUrls.textContent = data.current || 0;
    
    // If we have a current URL, we could show it somewhere
    // if (data.url) {
    //     document.getElementById('current-url').textContent = data.url;
    // }
}

/**
 * Update status indicator
 * @param {string} status - Status value (running, paused, idle, disconnected)
 */
function updateStatus(status) {
    statusDot.className = 'status-dot';
    
    switch (status) {
        case 'running':
            statusDot.classList.add('running');
            statusText.textContent = 'Running';
            pauseButton.textContent = 'Pause';
            break;
        case 'paused':
            statusDot.classList.add('paused');
            statusText.textContent = 'Paused';
            pauseButton.textContent = 'Resume';
            break;
        case 'idle':
            statusText.textContent = 'Idle';
            break;
        case 'disconnected':
            statusText.textContent = 'Disconnected';
            break;
    }
}

/**
 * Toggle control buttons based on scan status
 * @param {boolean} isRunning - Whether scan is running
 */
function toggleControlButtons(isRunning) {
    startButton.disabled = isRunning;
    pauseButton.disabled = !isRunning;
    stopButton.disabled = !isRunning;
    
    // Disable inputs during scan
    targetUrlInput.disabled = isRunning;
    scanDepthInput.disabled = isRunning;
    scanDelayInput.disabled = isRunning;
    
    // Disable plugin toggles during scan
    pluginSql.disabled = isRunning;
    pluginXss.disabled = isRunning;
    pluginTraversal.disabled = isRunning;
    pluginRedirect.disabled = isRunning;
    pluginHeaders.disabled = isRunning;
}

/**
 * Start the scan timer
 */
function startTimer() {
    stopTimer();
    startTime = startTime || new Date();
    
    timerInterval = setInterval(() => {
        const elapsed = new Date() - startTime;
        const seconds = Math.floor((elapsed / 1000) % 60);
        const minutes = Math.floor((elapsed / (1000 * 60)) % 60);
        const hours = Math.floor(elapsed / (1000 * 60 * 60));
        
        let timeString = '';
        if (hours > 0) {
            timeString = `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
        } else {
            timeString = `${pad(minutes)}:${pad(seconds)}`;
        }
        
        statDuration.textContent = timeString;
    }, 1000);
}

/**
 * Stop the scan timer
 */
function stopTimer() {
    if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
    }
}

/**
 * Pad a number with leading zero if needed
 * @param {number} num - Number to pad
 * @returns {string} - Padded number string
 */
function pad(num) {
    return num.toString().padStart(2, '0');
}

/**
 * Create the severity distribution chart
 */
function createSeverityChart() {
    const ctx = document.getElementById('severity-chart').getContext('2d');
    
    severityChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                label: 'Findings by Severity',
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(231, 76, 60, 0.8)',   // Critical - Red
                    'rgba(230, 126, 34, 0.8)',  // High - Orange
                    'rgba(241, 196, 15, 0.8)',  // Medium - Yellow
                    'rgba(52, 152, 219, 0.8)',  // Low - Blue
                    'rgba(127, 140, 141, 0.8)'  // Info - Gray
                ],
                borderColor: [
                    'rgb(231, 76, 60)',
                    'rgb(230, 126, 34)',
                    'rgb(241, 196, 15)',
                    'rgb(52, 152, 219)',
                    'rgb(127, 140, 141)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Update the severity chart with current findings
 */
function updateChart() {
    if (!severityChart) return;
    
    const severityCounts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'INFO': 0
    };
    
    findings.forEach(finding => {
        if (finding.severity && severityCounts.hasOwnProperty(finding.severity)) {
            severityCounts[finding.severity]++;
        }
    });
    
    severityChart.data.datasets[0].data = [
        severityCounts.CRITICAL,
        severityCounts.HIGH,
        severityCounts.MEDIUM,
        severityCounts.LOW,
        severityCounts.INFO
    ];
    
    severityChart.update();
}

/**
 * Add a new finding to the list
 * @param {Object} finding - Finding data
 */
function addFinding(finding) {
    findings.unshift(finding);  // Add to beginning of array
    renderFindings();
}

/**
 * Render findings in the table
 */
function renderFindings() {
    // Apply filters
    const filteredFindings = filterFindingsData();
    
    // Clear table
    findingsTableBody.innerHTML = '';
    
    // Add findings
    if (filteredFindings.length === 0) {
        findingsTableBody.innerHTML = `
            <tr>
                <td colspan="6" class="no-findings">No findings to display</td>
            </tr>
        `;
        return;
    }
    
    filteredFindings.forEach((finding, index) => {
        const row = document.createElement('tr');
        
        // Truncate URL if too long
        const url = finding.url;
        const displayUrl = url.length > 50 ? url.substring(0, 47) + '...' : url;
        
        row.innerHTML = `
            <td>${index + 1}</td>
            <td>
                <span class="severity-badge severity-${finding.severity || 'INFO'}">
                    ${finding.severity || 'INFO'}
                </span>
            </td>
            <td>${escapeHtml(finding.title || 'Untitled')}</td>
            <td title="${escapeHtml(url)}">${escapeHtml(displayUrl)}</td>
            <td>${escapeHtml(finding.plugin_name || '')}</td>
            <td class="actions">
                <button class="action-btn view-details" title="View Details">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                        <circle cx="12" cy="12" r="3"></circle>
                    </svg>
                </button>
            </td>
        `;
        
        // Add event listener to view button
        const viewButton = row.querySelector('.view-details');
        viewButton.addEventListener('click', () => {
            showFindingDetails(finding);
        });
        
        findingsTableBody.appendChild(row);
    });
}

/**
 * Filter findings based on user input
 */
function filterFindings() {
    renderFindings();
}

/**
 * Filter the findings data based on current filter settings
 * @returns {Array} - Filtered findings
 */
function filterFindingsData() {
    const severityValue = severityFilter.value.toUpperCase();
    const searchValue = searchInput.value.toLowerCase();
    
    return findings.filter(finding => {
        // Filter by severity
        if (severityValue && finding.severity !== severityValue) {
            return false;
        }
        
        // Filter by search term
        if (searchValue) {
            const searchFields = [
                finding.title || '',
                finding.url || '',
                finding.plugin_name || '',
                finding.description || '',
                finding.evidence || ''
            ];
            
            return searchFields.some(field => 
                field.toLowerCase().includes(searchValue)
            );
        }
        
        return true;
    });
}

/**
 * Show finding details in modal
 * @param {Object} finding - Finding data
 */
function showFindingDetails(finding) {
    modalTitle.textContent = finding.title || 'Finding Details';
    
    const content = `
        <div class="finding-detail-section">
            <h3>Overview</h3>
            <p><strong>Severity:</strong> <span class="severity-badge severity-${finding.severity || 'INFO'}">${finding.severity || 'INFO'}</span></p>
            <p><strong>URL:</strong> ${escapeHtml(finding.url || '')}</p>
            <p><strong>Plugin:</strong> ${escapeHtml(finding.plugin_name || '')}</p>
            ${finding.cwe_id ? `<p><strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html" target="_blank">${finding.cwe_id}</a></p>` : ''}
        </div>
        
        <div class="finding-detail-section">
            <h3>Description</h3>
            <p>${escapeHtml(finding.description || 'No description available.')}</p>
        </div>
        
        ${finding.evidence ? `
        <div class="finding-detail-section">
            <h3>Evidence</h3>
            <div class="finding-evidence">${escapeHtml(finding.evidence)}</div>
        </div>
        ` : ''}
        
        ${finding.remediation ? `
        <div class="finding-detail-section">
            <h3>Remediation</h3>
            <p>${escapeHtml(finding.remediation)}</p>
        </div>
        ` : ''}
        
        <div class="finding-detail-section">
            <h3>Request / Response</h3>
            ${finding.request ? `
            <h4>Request</h4>
            <div class="finding-evidence">${escapeHtml(finding.request)}</div>
            ` : ''}
            
            ${finding.response ? `
            <h4>Response</h4>
            <div class="finding-evidence">${escapeHtml(finding.response.length > 500 ? finding.response.substring(0, 500) + '...' : finding.response)}</div>
            ` : ''}
        </div>
    `;
    
    modalBody.innerHTML = content;
    findingsModal.style.display = 'flex';
}

/**
 * Validate URL format
 * @param {string} url - URL to validate
 * @returns {boolean} - Whether URL is valid
 */
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Escape HTML special characters
 * @param {string} unsafe - String to escape
 * @returns {string} - Escaped string
 */
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', initDashboard);
