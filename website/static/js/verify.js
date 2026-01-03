// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('Verification system initialized');
    
    // Setup debug toggle if it exists
    const debugToggle = document.querySelector('.debug-toggle');
    if (debugToggle) {
        debugToggle.addEventListener('click', toggleDebug);
    }
    
    // Setup verification button if user is logged in and not verified
    const startVerificationBtn = document.getElementById('startVerification');
    if (startVerificationBtn) {
        console.log('Start Verification button found, setting up click handler');
        startVerificationBtn.addEventListener('click', startVerification);
    } else {
        console.log('Start Verification button not found or user already verified');
    }
    
    // Setup logout confirmation
    const logoutBtn = document.querySelector('.btn-logout');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to logout?')) {
                e.preventDefault();
            }
        });
    }
    
    // Setup Discord login button (if exists)
    const discordLoginBtn = document.querySelector('.btn-discord');
    if (discordLoginBtn) {
        discordLoginBtn.addEventListener('click', function() {
            console.log('Discord login initiated');
            // Show loading state
            this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Redirecting to Discord...';
            this.style.opacity = '0.7';
        });
    }
    
    // Check initial state
    checkVerificationState();
});

// Toggle debug information
function toggleDebug() {
    const debugInfo = document.getElementById('debugInfo');
    if (debugInfo) {
        debugInfo.style.display = debugInfo.style.display === 'none' ? 'block' : 'none';
    }
}

// Check verification state on page load
function checkVerificationState() {
    const appData = document.getElementById('app-data');
    if (!appData) return;
    
    const HAS_DISCORD_USER = appData.dataset.hasDiscordUser === 'true';
    const IS_VERIFIED = appData.dataset.isVerified === 'true';
    
    console.log('Initial state:', { HAS_DISCORD_USER, IS_VERIFIED });
    
    // If user is verified, update UI
    if (IS_VERIFIED) {
        showResult('success', '✅ Already Verified', 
            'You are already verified! Return to Discord to access all channels.');
    }
}

// Main verification function
async function startVerification() {
    console.log('Starting verification process...');
    
    const appData = document.getElementById('app-data');
    if (!appData) {
        showError('Application data not found. Please refresh the page.');
        return;
    }
    
    const CSRF_TOKEN = appData.dataset.csrfToken;
    const btn = document.getElementById('startVerification');
    const resultDiv = document.getElementById('verificationResult');
    const errorDiv = document.getElementById('errorDetails');
    
    // Reset previous results
    if (errorDiv) errorDiv.style.display = 'none';
    if (resultDiv) resultDiv.innerHTML = '';
    
    // Validate CSRF token
    if (!CSRF_TOKEN || CSRF_TOKEN.length < 10) {
        showError('Missing CSRF token. Please refresh the page and try again.');
        return;
    }
    
    // Disable button and show loading
    btn.disabled = true;
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verifying...';
    
    try {
        console.log('Making verification request...');
        
        const response = await fetch("/api/verify", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": CSRF_TOKEN
            },
            body: JSON.stringify({}),
            credentials: 'include' // Include cookies for session
        });
        
        console.log('Response status:', response.status);
        
        const responseData = await response.json();
        console.log('Response data:', responseData);
        
        if (response.ok && responseData.success) {
            // Success - user verified
            showResult("success", "✅ Verification Successful!", 
                "Your Discord account has been verified! The bot will give you the Verified role shortly. Reloading page...");
            
            // Update session flag in hidden data
            appData.dataset.isVerified = 'true';
            
            // Update UI to show verified state
            setTimeout(() => {
                window.location.reload();
            }, 2000);
            
        } else if (responseData.already_verified) {
            // Already verified
            showResult("info", "Already Verified", 
                "You are already verified! Return to Discord to access all channels.");
            
            appData.dataset.isVerified = 'true';
            
        } else if (responseData.requires_oauth) {
            // Need Discord login
            showResult("error", "Login Required", 
                `<p>Please login with Discord first.</p>
                 <a href="/auth/discord" class="btn-discord">
                    <i class="fab fa-discord"></i> Login with Discord
                 </a>`);
            
        } else if (response.status === 403) {
            // IP banned or blocked
            showResult("error", "Access Denied", 
                "Your IP address has been blocked from verification. Please contact an administrator.");
            
        } else {
            // Other error
            const errorMsg = responseData.error || "Verification failed. Please try again.";
            showError(errorMsg);
            
            // If session might be expired, suggest login
            if (responseData.error && (
                responseData.error.includes('session') || 
                responseData.error.includes('login') ||
                responseData.error.includes('Discord'))) {
                setTimeout(() => {
                    window.location.href = '/auth/discord';
                }, 3000);
            }
        }
        
    } catch (error) {
        console.error('Network error:', error);
        showError('Network error. Please check your internet connection and try again.');
        
        // Network error - show retry option
        setTimeout(() => {
            btn.innerHTML = '<i class="fas fa-redo"></i> Try Again';
            btn.disabled = false;
            btn.onclick = startVerification; // Reattach handler
        }, 3000);
        
    } finally {
        // Only reset button if not already handled
        if (btn.disabled) {
            setTimeout(() => {
                btn.disabled = false;
                btn.innerHTML = originalText;
            }, 5000);
        }
    }
}

// Show result message
function showResult(type, title, message) {
    const resultDiv = document.getElementById('verificationResult');
    if (!resultDiv) return;
    
    const colors = {
        success: '#d4edda',
        error: '#f8d7da',
        info: '#d1ecf1',
        warning: '#fff3cd'
    };
    
    const borderColors = {
        success: '#28a745',
        error: '#dc3545',
        info: '#17a2b8',
        warning: '#ffc107'
    };
    
    const textColors = {
        success: '#155724',
        error: '#721c24',
        info: '#0c5460',
        warning: '#856404'
    };
    
    resultDiv.innerHTML = `
        <div class="result-message" style="
            padding: 15px; 
            border-radius: 8px; 
            background: ${colors[type] || '#f8f9fa'}; 
            border-left: 4px solid ${borderColors[type] || '#007bff'};
            color: ${textColors[type] || '#212529'}; 
            margin: 10px 0;
            animation: fadeIn 0.3s ease-in;">
            <h4 style="margin: 0 0 10px 0; display: flex; align-items: center; gap: 8px;">
                ${title}
            </h4>
            <div style="margin: 0;">${message}</div>
        </div>
    `;
    
    // Add CSS animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    `;
    if (!document.querySelector('#fade-in-style')) {
        style.id = 'fade-in-style';
        document.head.appendChild(style);
    }
    
    // Scroll to result
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Show error details
function showError(message) {
    const errorDiv = document.getElementById('errorDetails');
    if (errorDiv) {
        errorDiv.innerHTML = `
            <div style="display: flex; align-items: flex-start; gap: 10px;">
                <i class="fas fa-exclamation-triangle" style="color: #dc3545;"></i>
                <div>
                    <strong>Error Details:</strong>
                    <p style="margin: 5px 0 0 0;">${message}</p>
                </div>
            </div>
        `;
        errorDiv.style.display = 'block';
        errorDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
}

// Helper function to update button state
function updateButtonState(button, isLoading, text = '') {
    if (isLoading) {
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + (text || 'Loading...');
        button.style.opacity = '0.7';
    } else {
        button.disabled = false;
        button.innerHTML = text || button.getAttribute('data-original-text') || 'Start Verification';
        button.style.opacity = '1';
    }
}

// Add event listener for Enter key on verification button
document.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        const startBtn = document.getElementById('startVerification');
        const focusedElement = document.activeElement;
        
        // If Enter is pressed and focus is on verification button, trigger click
        if (startBtn && focusedElement === startBtn) {
            startVerification();
        }
    }
});