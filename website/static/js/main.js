// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('Website JavaScript loaded');
    
    // Initialize all components
    initializeGlobalListeners();
    initializePageSpecificFeatures();
    setupAnimations();
    
    // Check for flash messages and auto-dismiss
    setupFlashMessages();
    
    // Setup analytics if needed
    setupAnalytics();
});

// Initialize global event listeners
function initializeGlobalListeners() {
    console.log('Setting up global listeners');
    
    // Logout confirmation for all logout links
    const logoutLinks = document.querySelectorAll('a[href*="logout"], .btn-logout');
    logoutLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to logout?')) {
                e.preventDefault();
            }
        });
    });
    
    // Admin panel logout
    const adminLogout = document.querySelector('.logout a');
    if (adminLogout) {
        adminLogout.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to logout from admin panel?')) {
                e.preventDefault();
            }
        });
    }
    
    // Form submission handling
    const forms = document.querySelectorAll('form:not(.no-js)');
    forms.forEach(form => {
        form.addEventListener('submit', handleFormSubmit);
    });
    
    // External link handling (open in new tab)
    const externalLinks = document.querySelectorAll('a[href^="http"]:not([href*="' + window.location.hostname + '"])');
    externalLinks.forEach(link => {
        link.setAttribute('target', '_blank');
        link.setAttribute('rel', 'noopener noreferrer');
    });
    
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            const targetId = this.getAttribute('href');
            if (targetId !== '#') {
                e.preventDefault();
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    targetElement.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            }
        });
    });
}

// Initialize page-specific features
function initializePageSpecificFeatures() {
    const path = window.location.pathname;
    
    if (path.includes('/admin')) {
        initializeAdminPage();
    } else if (path.includes('/verify')) {
        // Already handled by verify.js
        console.log('Verify page - external JS loaded');
    } else if (path === '/' || path === '/index.html') {
        initializeHomePage();
    } else if (path.includes('/feedback')) {
        initializeFeedbackPage();
    }
}

// Admin page initialization
function initializeAdminPage() {
    console.log('Initializing admin page features');
    
    // Table row highlighting
    const tableRows = document.querySelectorAll('.admin-table tbody tr');
    tableRows.forEach(row => {
        row.addEventListener('mouseenter', function() {
            this.style.backgroundColor = '#f5f5f5';
        });
        row.addEventListener('mouseleave', function() {
            this.style.backgroundColor = '';
        });
    });
    
    // Action button hover effects
    const actionButtons = document.querySelectorAll('.btn-action, .action-btn');
    actionButtons.forEach(button => {
        button.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px)';
        });
        button.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
    
    // Confirm destructive actions
    const destructiveButtons = document.querySelectorAll('.btn-unban, [data-action="delete"]');
    destructiveButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to perform this action?')) {
                e.preventDefault();
            }
        });
    });
    
    // Auto-refresh dashboard stats
    if (window.location.pathname.includes('/dashboard')) {
        // Refresh stats every 60 seconds
        setInterval(refreshDashboardStats, 60000);
    }
}

// Home page initialization
function initializeHomePage() {
    console.log('Initializing home page features');
    
    // Animate stats counters
    const statNumbers = document.querySelectorAll('.stat-number');
    if (statNumbers.length > 0) {
        animateCounters();
        
        // Refresh stats every 30 seconds
        setInterval(animateCounters, 30000);
    }
    
    // Feature cards animation
    const featureCards = document.querySelectorAll('.feature-card');
    featureCards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });
    
    // CTA button animation
    const ctaButton = document.querySelector('.cta-button');
    if (ctaButton) {
        ctaButton.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.05)';
        });
        ctaButton.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1)';
        });
    }
}

// Feedback page initialization
function initializeFeedbackPage() {
    console.log('Initializing feedback page');
    
    // Contact option animations
    const contactOptions = document.querySelectorAll('.contact-option');
    contactOptions.forEach((option, index) => {
        option.style.opacity = '0';
        option.style.transform = 'translateX(-20px)';
        
        setTimeout(() => {
            option.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            option.style.opacity = '1';
            option.style.transform = 'translateX(0)';
        }, index * 200);
    });
}

// Setup animations
function setupAnimations() {
    // Add CSS for animations
    const style = document.createElement('style');
    style.textContent = `
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }
        
        .slide-up {
            animation: slideUp 0.5s ease-out;
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        @keyframes slideUp {
            from { 
                opacity: 0;
                transform: translateY(20px);
            }
            to { 
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(102, 126, 234, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(102, 126, 234, 0); }
            100% { box-shadow: 0 0 0 0 rgba(102, 126, 234, 0); }
        }
    `;
    document.head.appendChild(style);
}

// Setup flash messages
function setupFlashMessages() {
    const flashMessages = document.querySelectorAll('.alert, .flash-message, [role="alert"]');
    flashMessages.forEach(message => {
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            message.style.opacity = '0';
            message.style.transition = 'opacity 0.5s ease';
            setTimeout(() => {
                if (message.parentNode) {
                    message.parentNode.removeChild(message);
                }
            }, 500);
        }, 5000);
        
        // Add close button if not present
        if (!message.querySelector('.close-btn')) {
            const closeBtn = document.createElement('button');
            closeBtn.className = 'close-btn';
            closeBtn.innerHTML = '&times;';
            closeBtn.style.cssText = `
                position: absolute;
                right: 10px;
                top: 50%;
                transform: translateY(-50%);
                background: none;
                border: none;
                font-size: 1.5rem;
                cursor: pointer;
                color: inherit;
                opacity: 0.7;
            `;
            closeBtn.addEventListener('click', function() {
                this.parentElement.style.opacity = '0';
                setTimeout(() => {
                    if (this.parentElement.parentNode) {
                        this.parentElement.parentNode.removeChild(this.parentElement);
                    }
                }, 500);
            });
            message.style.position = 'relative';
            message.style.paddingRight = '40px';
            message.appendChild(closeBtn);
        }
    });
}

// Setup basic analytics
function setupAnalytics() {
    // Track page views (you can replace with your analytics service)
    console.log('Page view:', {
        path: window.location.pathname,
        referrer: document.referrer,
        timestamp: new Date().toISOString()
    });
    
    // Track outbound links
    document.addEventListener('click', function(e) {
        const link = e.target.closest('a');
        if (link && link.href && !link.href.includes(window.location.hostname)) {
            console.log('Outbound link click:', link.href);
        }
    });
}

// Handle form submissions
function handleFormSubmit(e) {
    const form = e.target;
    const submitButton = form.querySelector('button[type="submit"], input[type="submit"]');
    
    if (submitButton) {
        // Show loading state
        const originalText = submitButton.innerHTML || submitButton.value;
        submitButton.disabled = true;
        submitButton.style.opacity = '0.7';
        
        if (submitButton.tagName === 'BUTTON') {
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        } else {
            submitButton.value = 'Processing...';
        }
        
        // Store original text for restoration
        submitButton.setAttribute('data-original-text', originalText);
        
        // Re-enable button after 30 seconds if still disabled (failsafe)
        setTimeout(() => {
            if (submitButton.disabled) {
                submitButton.disabled = false;
                submitButton.style.opacity = '1';
                if (submitButton.tagName === 'BUTTON') {
                    submitButton.innerHTML = originalText;
                } else {
                    submitButton.value = originalText;
                }
                console.warn('Form submission timeout - button re-enabled');
            }
        }, 30000);
    }
}

// Animate counters on home page
function animateCounters() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Update user count
                const usersCount = document.getElementById('users-count');
                if (usersCount && data.data.verified_users) {
                    animateCounter(usersCount, data.data.verified_users);
                }
                
                // Update security events
                const securityEvents = document.getElementById('security-events');
                if (securityEvents && data.data.security_events_today) {
                    animateCounter(securityEvents, data.data.security_events_today);
                }
                
                // Update uptime if element exists
                const uptimeElement = document.getElementById('uptime');
                if (uptimeElement && data.data.uptime) {
                    const days = Math.floor(data.data.uptime / 86400);
                    uptimeElement.textContent = `${days}+`;
                }
            }
        })
        .catch(error => {
            console.error('Failed to fetch stats:', error);
        });
}

// Animate a single counter
function animateCounter(element, target) {
    const current = parseInt(element.textContent) || 0;
    const increment = target > current ? 1 : -1;
    const duration = 1000; // ms
    const stepTime = Math.abs(Math.floor(duration / (target - current)));
    
    let currentValue = current;
    
    const timer = setInterval(() => {
        currentValue += increment;
        element.textContent = currentValue;
        
        if (currentValue === target) {
            clearInterval(timer);
        }
    }, stepTime);
}

// Refresh dashboard stats (admin only)
function refreshDashboardStats() {
    if (window.location.pathname.includes('/admin/dashboard')) {
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Update stats cards
                    const statElements = {
                        'total_users': data.data.total_users,
                        'verified_users': data.data.verified_users,
                        'today_verifications': data.data.today_verifications,
                        'total_bans': data.data.total_bans
                    };
                    
                    for (const [key, value] of Object.entries(statElements)) {
                        const element = document.querySelector(`[data-stat="${key}"]`);
                        if (element) {
                            const current = parseInt(element.textContent) || 0;
                            if (current !== value) {
                                animateCounter(element, value);
                            }
                        }
                    }
                }
            })
            .catch(error => {
                console.error('Failed to refresh dashboard stats:', error);
            });
    }
}

// Error handler for uncaught errors
window.addEventListener('error', function(e) {
    console.error('Uncaught error:', e.error);
    
    // Don't show error to user for minor errors
    if (e.error.message && e.error.message.includes('ResizeObserver')) {
        return; // Ignore ResizeObserver errors
    }
});

// Add helper for copying to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text)
        .then(() => {
            // Show success message
            const message = document.createElement('div');
            message.textContent = 'Copied to clipboard!';
            message.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: #27ae60;
                color: white;
                padding: 10px 20px;
                border-radius: 5px;
                z-index: 10000;
                animation: slideInRight 0.3s ease;
            `;
            document.body.appendChild(message);
            
            setTimeout(() => {
                message.style.opacity = '0';
                message.style.transition = 'opacity 0.3s ease';
                setTimeout(() => {
                    if (message.parentNode) {
                        message.parentNode.removeChild(message);
                    }
                }, 300);
            }, 2000);
        })
        .catch(err => {
            console.error('Failed to copy:', err);
        });
}

// Expose utility functions globally (only if needed)
window.utils = {
    copyToClipboard,
    animateCounter,
    showAlert: function(message, type = 'info') {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.textContent = message;
        alert.style.cssText = `
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            padding: 15px 30px;
            border-radius: 5px;
            background: ${type === 'success' ? '#27ae60' : type === 'error' ? '#e74c3c' : '#3498db'};
            color: white;
            z-index: 10000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        `;
        document.body.appendChild(alert);
        
        setTimeout(() => {
            alert.remove();
        }, 5000);
    }
};