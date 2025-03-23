/**
 * Scan JavaScript
 * Provides functionality for scan detail and breach detail pages
 */

document.addEventListener('DOMContentLoaded', function() {
    // Handle breach status updates
    initBreachStatusButtons();
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl, {
            html: true,
            trigger: 'focus'
        });
    });
    
    // Initialize scan status updates if on scan detail page
    initScanDetailUpdates();
});

/**
 * Initialize breach status update buttons
 */
function initBreachStatusButtons() {
    const statusButtons = document.querySelectorAll('.breach-status-btn');
    
    statusButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            event.preventDefault();
            
            const breachId = this.getAttribute('data-breach-id');
            const status = this.getAttribute('data-status');
            
            if (!breachId || !status) {
                console.error('Missing breach ID or status');
                return;
            }
            
            updateBreachStatus(breachId, status, this);
        });
    });
}

/**
 * Update a breach status
 * @param {string} breachId - The ID of the breach to update
 * @param {string} status - The new status
 * @param {HTMLElement} buttonElement - The button element that was clicked
 */
function updateBreachStatus(breachId, status, buttonElement) {
    // Create form data
    const formData = new FormData();
    formData.append('status', status);
    
    // Update button state
    const originalText = buttonElement.innerHTML;
    buttonElement.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
    buttonElement.disabled = true;
    
    // Don't show full loading screen for status updates, just the button spinner
    // This is a small operation that should be quick
    
    // Send the update request
    fetch(`/api/breach/${breachId}/status`, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // Update UI to show the new status
            const statusBadge = document.querySelector(`.breach-status-badge[data-breach-id="${breachId}"]`);
            if (statusBadge) {
                // Remove all status classes
                statusBadge.classList.remove('bg-primary', 'bg-info', 'bg-danger', 'bg-success');
                
                // Add appropriate class based on status
                if (status === 'new') {
                    statusBadge.classList.add('bg-primary');
                    statusBadge.textContent = 'New';
                } else if (status === 'reviewed') {
                    statusBadge.classList.add('bg-info');
                    statusBadge.textContent = 'Reviewed';
                } else if (status === 'confirmed') {
                    statusBadge.classList.add('bg-danger');
                    statusBadge.textContent = 'Confirmed';
                } else if (status === 'false_positive') {
                    statusBadge.classList.add('bg-success');
                    statusBadge.textContent = 'False Positive';
                }
            }
            
            // Show success message
            const alertElement = document.createElement('div');
            alertElement.className = 'alert alert-success alert-dismissible fade show mt-3';
            alertElement.innerHTML = `
                Status updated successfully to <strong>${status.replace('_', ' ')}</strong>.
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            `;
            
            // Insert alert before the content section
            const contentSection = document.querySelector('.breach-content') || document.querySelector('.card');
            if (contentSection && contentSection.parentNode) {
                contentSection.parentNode.insertBefore(alertElement, contentSection);
            } else {
                document.querySelector('main').prepend(alertElement);
            }
            
            // Disable other status buttons if they exist
            const otherButtons = document.querySelectorAll(`.breach-status-btn[data-breach-id="${breachId}"]`);
            otherButtons.forEach(btn => {
                if (btn.getAttribute('data-status') === status) {
                    btn.classList.remove('btn-outline-secondary');
                    btn.classList.add('btn-success');
                    btn.innerHTML = `<i class="fas fa-check me-1"></i> ${status.replace('_', ' ').charAt(0).toUpperCase() + status.replace('_', ' ').slice(1)}`;
                } else {
                    btn.disabled = false;
                    btn.innerHTML = btn.getAttribute('data-status').replace('_', ' ').charAt(0).toUpperCase() + btn.getAttribute('data-status').replace('_', ' ').slice(1);
                }
            });
        } else {
            // Show error message
            const alertElement = document.createElement('div');
            alertElement.className = 'alert alert-danger alert-dismissible fade show mt-3';
            alertElement.innerHTML = `
                Error updating status: ${data.error || 'Unknown error'}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            `;
            
            // Insert alert before the content section
            const contentSection = document.querySelector('.breach-content') || document.querySelector('.card');
            if (contentSection && contentSection.parentNode) {
                contentSection.parentNode.insertBefore(alertElement, contentSection);
            } else {
                document.querySelector('main').prepend(alertElement);
            }
            
            // Reset button state
            buttonElement.innerHTML = originalText;
            buttonElement.disabled = false;
        }
    })
    .catch(error => {
        console.error('Error updating breach status:', error);
        
        // Show error message
        const alertElement = document.createElement('div');
        alertElement.className = 'alert alert-danger alert-dismissible fade show mt-3';
        alertElement.innerHTML = `
            Network error updating status. Please try again.
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Insert alert before the content section
        const contentSection = document.querySelector('.breach-content') || document.querySelector('.card');
        if (contentSection && contentSection.parentNode) {
            contentSection.parentNode.insertBefore(alertElement, contentSection);
        } else {
            document.querySelector('main').prepend(alertElement);
        }
        
        // Reset button state
        buttonElement.innerHTML = originalText;
        buttonElement.disabled = false;
    });
}

/**
 * Initialize scan detail page updates
 */
function initScanDetailUpdates() {
    const scanStatusElement = document.getElementById('scanStatus');
    
    if (!scanStatusElement) {
        return; // Not on scan detail page
    }
    
    const scanIdElement = document.getElementById('scanId');
    
    if (!scanIdElement) {
        return; // No scan ID element found
    }
    
    const scanId = scanIdElement.textContent.trim();
    
    if (!scanId) {
        return; // No scan ID available
    }
    
    const currentStatus = scanStatusElement.textContent.trim().toLowerCase();
    
    // Only poll for updates if scan is in progress
    if (currentStatus === 'in progress') {
        // Function to update scan status
        function updateScanStatus() {
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
                        if (data.status !== 'in_progress') {
                            // Show loading screen before page reload
                            if (typeof showLoading === 'function') {
                                showLoading();
                            }
                            
                            // Scan completed or failed, reload page
                            window.location.reload();
                        } else {
                            // Scan still in progress, update UI if needed
                            const urlsScannedElement = document.getElementById('urlsScanned');
                            const breachesDetectedElement = document.getElementById('breachesDetected');
                            
                            if (urlsScannedElement) {
                                urlsScannedElement.textContent = data.urls_scanned;
                            }
                            
                            if (breachesDetectedElement) {
                                breachesDetectedElement.textContent = data.breaches_detected;
                            }
                            
                            // Continue polling
                            setTimeout(updateScanStatus, 3000);
                        }
                    } else {
                        console.error('Error fetching scan status:', data.error);
                        // Try again after a delay
                        setTimeout(updateScanStatus, 5000);
                    }
                })
                .catch(error => {
                    console.error('Error fetching scan status:', error);
                    // Try again after a longer delay on error
                    setTimeout(updateScanStatus, 8000);
                });
        }
        
        // Start polling for updates
        updateScanStatus();
    }
}
