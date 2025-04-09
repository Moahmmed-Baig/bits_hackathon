/**
 * Dashboard JavaScript
 * Provides functionality for the dashboard page
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Handle scan progress updates if there's an active scan
    initScanProgressUpdates();
});

/**
 * Initialize scan progress updates for active scans
 */
function initScanProgressUpdates() {
    const scanProgressElement = document.getElementById('scanProgress');
    
    if (!scanProgressElement) {
        return; // No active scan section on page
    }
    
    const scanIdElement = document.getElementById('scanId');
    
    if (!scanIdElement) {
        return; // No scan ID element found
    }
    
    const scanId = scanIdElement.textContent.trim();
    
    if (!scanId) {
        return; // No scan ID available
    }
    
    const progressBar = document.getElementById('scanProgressBar');
    const urlsScanned = document.getElementById('urlsScanned');
    const breachesDetected = document.getElementById('breachesDetected');
    
    if (!progressBar || !urlsScanned || !breachesDetected) {
        return; // Missing required elements
    }
    
    // Function to update scan progress
    function updateScanProgress() {
        // Don't show loading screen for background status checks
        fetch(`/api/scan/status/${scanId}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    // Default to 10 targets if not provided
                    const targetsCount = data.targets_count || 10;
                    // Calculate progress percentage (maximum 99% until completed)
                    const progress = Math.min((data.urls_scanned / Math.max(1, targetsCount)) * 100, 99);
                    
                    // Update progress bar
                    progressBar.style.width = `${progress}%`;
                    progressBar.setAttribute('aria-valuenow', progress);
                    
                    // Update scanned counts
                    urlsScanned.textContent = data.urls_scanned;
                    breachesDetected.textContent = data.breaches_detected;
                    
                    if (data.status === 'completed') {
                        // Scan completed, update UI
                        progressBar.style.width = '100%';
                        progressBar.classList.remove('progress-bar-animated', 'progress-bar-striped');
                        progressBar.classList.add('bg-success');
                        
                        // Show loading screen before page reload
                        if (typeof showLoading === 'function') {
                            showLoading();
                        }
                        
                        // Reload page after a delay to show the completed state
                        setTimeout(() => {
                            window.location.reload();
                        }, 2000);
                    } else if (data.status === 'failed') {
                        // Scan failed, update UI
                        progressBar.classList.remove('progress-bar-animated', 'progress-bar-striped');
                        progressBar.classList.add('bg-danger');
                        
                        // Show loading screen before page reload
                        if (typeof showLoading === 'function') {
                            showLoading();
                        }
                        
                        // Reload page after a delay
                        setTimeout(() => {
                            window.location.reload();
                        }, 2000);
                    } else {
                        // Scan still in progress, continue polling
                        setTimeout(updateScanProgress, 3000);
                    }
                } else {
                    console.error('Error fetching scan status:', data.error);
                    // Try again after a delay
                    setTimeout(updateScanProgress, 5000);
                }
            })
            .catch(error => {
                console.error('Error fetching scan status:', error);
                // Try again after a longer delay on error
                setTimeout(updateScanProgress, 8000);
            });
    }
    
    // Start polling for updates
    updateScanProgress();
}
