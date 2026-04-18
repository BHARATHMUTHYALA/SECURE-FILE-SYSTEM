/**
 * SecureFS Frontend JavaScript
 * Handles password strength, 2FA, rate limiting, and other UI interactions
 */

// ============ PASSWORD STRENGTH METER ============

/**
 * Check password strength using backend API
 */
async function checkPasswordStrength(password) {
  if (!password || password.length === 0) {
    updateStrengthMeter({ score: 0, feedback: [] });
    return;
  }

  try {
    const response = await fetch('/api/auth/check-password-strength', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });

    if (response.ok) {
      const data = await response.json();
      updateStrengthMeter(data.data);
    }
  } catch (error) {
    console.error('Password strength check failed:', error);
  }
}

/**
 * Update the password strength meter UI
 */
function updateStrengthMeter(strengthData) {
  const fillElement = document.getElementById('password-strength-fill');
  const feedbackElement = document.getElementById('password-strength-feedback');
  
  if (!fillElement || !feedbackElement) return;

  const { score, feedback } = strengthData;
  
  // Update progress bar
  const percentage = (score / 4) * 100;
  fillElement.style.width = `${percentage}%`;
  
  // Update color based on score
  fillElement.className = 'strength-fill';
  if (score <= 1) {
    fillElement.classList.add('danger');
  } else if (score === 2) {
    fillElement.classList.add('warning');
  } else if (score === 3) {
    fillElement.classList.add('good');
  } else {
    fillElement.classList.add('excellent');
  }
  
  // Update feedback text
  const strengthLabels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
  const strengthLabel = strengthLabels[score] || 'Unknown';
  
  let feedbackHTML = `<strong>${strengthLabel}</strong>`;
  if (feedback && feedback.length > 0) {
    feedbackHTML += '<ul class="feedback-list">';
    feedback.forEach(item => {
      feedbackHTML += `<li>${item}</li>`;
    });
    feedbackHTML += '</ul>';
  }
  
  feedbackElement.innerHTML = feedbackHTML;
}

/**
 * Initialize password strength meter on password inputs
 */
function initPasswordStrengthMeter(passwordInputId, containerId) {
  const passwordInput = document.getElementById(passwordInputId);
  const container = document.getElementById(containerId);
  
  if (!passwordInput || !container) return;
  
  // Create strength meter HTML
  const meterHTML = `
    <div class="password-strength-meter">
      <div class="strength-bar">
        <div class="strength-fill" id="password-strength-fill"></div>
      </div>
      <div class="strength-feedback" id="password-strength-feedback"></div>
    </div>
  `;
  
  // Insert after password input
  passwordInput.parentNode.insertAdjacentHTML('afterend', meterHTML);
  
  // Add event listener
  let debounceTimer;
  passwordInput.addEventListener('input', (e) => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      checkPasswordStrength(e.target.value);
    }, 300);
  });
}

// ============ TWO-FACTOR AUTHENTICATION ============

let twoFASetupData = null;

/**
 * Open 2FA setup modal
 */
async function openTwoFASetup() {
  try {
    const response = await fetch('/api/auth/2fa/setup', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });

    if (!response.ok) {
      throw new Error('Failed to setup 2FA');
    }

    const data = await response.json();
    twoFASetupData = data.data;
    
    // Show modal
    const modal = document.getElementById('twofa-setup-modal');
    modal.classList.add('active');
    
    // Display QR code
    const qrContainer = document.getElementById('qr-code-container');
    qrContainer.innerHTML = `
      <div class="qr-code-display">
        <img src="${twoFASetupData.qrCodeURL}" alt="2FA QR Code" style="max-width: 250px; margin: 0 auto; display: block;">
      </div>
    `;
    
    // Display secret
    document.getElementById('twofa-secret').textContent = twoFASetupData.secret;
    
    // Show step 1
    document.getElementById('twofa-step-1').style.display = 'block';
    document.getElementById('twofa-step-2').style.display = 'block';
    document.getElementById('twofa-backup-codes').style.display = 'none';
    
  } catch (error) {
    console.error('2FA setup error:', error);
    showToast('Failed to setup 2FA: ' + error.message, 'error');
  }
}

/**
 * Verify 2FA code and enable 2FA
 */
async function verifyTwoFA() {
  const code = document.getElementById('twofa-verify-code').value.trim();
  
  if (!code || code.length !== 6) {
    showToast('Please enter a 6-digit code', 'error');
    return;
  }
  
  try {
    const response = await fetch('/api/auth/2fa/verify', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ 
        token: code
      })
    });

    if (!response.ok) {
      throw new Error('Invalid verification code');
    }

    const data = await response.json();
    
    // Show backup codes
    document.getElementById('twofa-step-1').style.display = 'none';
    document.getElementById('twofa-step-2').style.display = 'none';
    document.getElementById('twofa-backup-codes').style.display = 'block';
    
    const backupCodesList = document.getElementById('backup-codes-list');
    backupCodesList.innerHTML = twoFASetupData.backupCodes.map(code => 
      `<div class="backup-code">${code}</div>`
    ).join('');
    
    showToast('2FA enabled successfully!', 'success');
    
    // Refresh security page
    setTimeout(() => {
      closeTwoFASetup();
      if (typeof loadSecurityPage === 'function') {
        loadSecurityPage();
      }
    }, 3000);
    
  } catch (error) {
    console.error('2FA verification error:', error);
    showToast('Verification failed: ' + error.message, 'error');
  }
}

/**
 * Close 2FA setup modal
 */
function closeTwoFASetup() {
  const modal = document.getElementById('twofa-setup-modal');
  modal.classList.remove('active');
  document.getElementById('twofa-verify-code').value = '';
  twoFASetupData = null;
}

/**
 * Disable 2FA
 */
async function disableTwoFA() {
  if (!confirm('Are you sure you want to disable Two-Factor Authentication? This will make your account less secure.')) {
    return;
  }
  
  const password = prompt('Enter your password to confirm:');
  if (!password) return;
  
  const token = prompt('Enter your current 2FA code:');
  if (!token) return;
  
  try {
    const response = await fetch('/api/auth/2fa/disable', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ password, token })
    });

    if (!response.ok) {
      throw new Error('Failed to disable 2FA');
    }

    showToast('2FA disabled successfully', 'success');
    
    // Refresh security page
    if (typeof loadSecurityPage === 'function') {
      loadSecurityPage();
    }
    
  } catch (error) {
    console.error('2FA disable error:', error);
    showToast('Failed to disable 2FA: ' + error.message, 'error');
  }
}

/**
 * Regenerate backup codes
 */
async function regenerateBackupCodes() {
  if (!confirm('Regenerate backup codes? Your old backup codes will no longer work.')) {
    return;
  }
  
  const password = prompt('Enter your password to confirm:');
  if (!password) return;
  
  try {
    const response = await fetch('/api/auth/2fa/regenerate-backup-codes', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ password })
    });

    if (!response.ok) {
      throw new Error('Failed to regenerate backup codes');
    }

    const data = await response.json();
    
    // Show backup codes in modal
    const modal = document.getElementById('backup-codes-modal');
    modal.classList.add('active');
    
    const backupCodesList = document.getElementById('regenerated-backup-codes-list');
    backupCodesList.innerHTML = data.data.backupCodes.map(code => 
      `<div class="backup-code">${code}</div>`
    ).join('');
    
    showToast('Backup codes regenerated successfully', 'success');
    
  } catch (error) {
    console.error('Backup codes regeneration error:', error);
    showToast('Failed to regenerate backup codes: ' + error.message, 'error');
  }
}

/**
 * Copy backup codes to clipboard
 */
function copyBackupCodes() {
  const codes = Array.from(document.querySelectorAll('.backup-code'))
    .map(el => el.textContent)
    .join('\n');
  
  navigator.clipboard.writeText(codes).then(() => {
    showToast('Backup codes copied to clipboard', 'success');
  }).catch(err => {
    console.error('Failed to copy:', err);
    showToast('Failed to copy backup codes', 'error');
  });
}

/**
 * Show 2FA login modal
 */
function showTwoFALoginModal() {
  const modal = document.getElementById('twofa-login-modal');
  modal.classList.add('active');
  document.getElementById('twofa-login-code').value = '';
  document.getElementById('twofa-login-code').focus();
}

/**
 * Verify 2FA code during login
 */
async function verifyTwoFALogin() {
  const code = document.getElementById('twofa-login-code').value.trim();
  const useBackupCode = document.getElementById('use-backup-code-checkbox')?.checked || false;
  
  if (!code) {
    showToast('Please enter a code', 'error');
    return;
  }
  
  try {
    const endpoint = useBackupCode ? '/api/auth/2fa/verify-backup-code' : '/api/auth/2fa/verify-login';
    
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('tempToken')}`
      },
      body: JSON.stringify({ token: code })
    });

    if (!response.ok) {
      throw new Error('Invalid code');
    }

    const data = await response.json();
    
    // Store the real token
    localStorage.setItem('token', data.data.token);
    localStorage.removeItem('tempToken');
    
    // Close modal and show app
    closeTwoFALoginModal();
    showToast('Login successful!', 'success');
    
    // Redirect or reload
    if (typeof showApp === 'function') {
      showApp();
    } else {
      window.location.reload();
    }
    
  } catch (error) {
    console.error('2FA login verification error:', error);
    showToast('Verification failed: ' + error.message, 'error');
  }
}

/**
 * Close 2FA login modal
 */
function closeTwoFALoginModal() {
  const modal = document.getElementById('twofa-login-modal');
  modal.classList.remove('active');
}

/**
 * Toggle between TOTP and backup code input
 */
function toggleBackupCodeInput() {
  const checkbox = document.getElementById('use-backup-code-checkbox');
  const codeInput = document.getElementById('twofa-login-code');
  
  if (checkbox.checked) {
    codeInput.placeholder = 'Enter backup code';
    codeInput.maxLength = 10;
  } else {
    codeInput.placeholder = 'Enter 6-digit code';
    codeInput.maxLength = 6;
  }
  
  codeInput.value = '';
  codeInput.focus();
}

// ============ RATE LIMITING FEEDBACK ============

/**
 * Enhanced fetch wrapper with rate limit handling
 */
async function fetchWithRateLimitHandling(url, options = {}) {
  try {
    const response = await fetch(url, options);
    
    // Check for rate limiting
    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After') || '60';
      const resetTime = response.headers.get('X-RateLimit-Reset');
      
      let message = `Too many requests. Please try again in ${retryAfter} seconds.`;
      
      if (resetTime) {
        const resetDate = new Date(parseInt(resetTime) * 1000);
        const now = new Date();
        const secondsUntilReset = Math.ceil((resetDate - now) / 1000);
        message = `Rate limit exceeded. Please wait ${secondsUntilReset} seconds before trying again.`;
      }
      
      showToast(message, 'warning');
      
      // Log rate limit info for debugging
      console.warn('Rate Limit Info:', {
        limit: response.headers.get('X-RateLimit-Limit'),
        remaining: response.headers.get('X-RateLimit-Remaining'),
        reset: response.headers.get('X-RateLimit-Reset'),
        retryAfter: retryAfter
      });
      
      throw new Error('Rate limit exceeded');
    }
    
    return response;
    
  } catch (error) {
    if (error.message !== 'Rate limit exceeded') {
      console.error('Fetch error:', error);
    }
    throw error;
  }
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
  // Create toast container if it doesn't exist
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  
  // Create toast element
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  const icon = {
    success: 'fa-check-circle',
    error: 'fa-exclamation-circle',
    warning: 'fa-exclamation-triangle',
    info: 'fa-info-circle'
  }[type] || 'fa-info-circle';
  
  toast.innerHTML = `
    <i class="fas ${icon}"></i>
    <span>${message}</span>
  `;
  
  container.appendChild(toast);
  
  // Auto remove after 5 seconds
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => {
      container.removeChild(toast);
    }, 300);
  }, 5000);
}

// ============ INITIALIZATION ============

document.addEventListener('DOMContentLoaded', function() {
  console.log('SecureFS script.js loaded');
  
  // Initialize password strength meter on auth page
  const authPassword = document.getElementById('auth-password');
  if (authPassword) {
    // Check if we're on registration mode
    const authToggle = document.getElementById('auth-toggle');
    if (authToggle) {
      authToggle.addEventListener('click', function() {
        // Delay to let the form update
        setTimeout(() => {
          const usernameGroup = document.getElementById('username-group');
          if (usernameGroup && !usernameGroup.classList.contains('hidden')) {
            // Registration mode - add password strength meter
            if (!document.getElementById('password-strength-fill')) {
              initPasswordStrengthMeter('auth-password', 'auth-form');
            }
          } else {
            // Login mode - remove password strength meter
            const meter = document.querySelector('.password-strength-meter');
            if (meter) {
              meter.remove();
            }
          }
        }, 100);
      });
    }
  }
});

/**
 * Load security page and render 2FA status
 */
async function loadSecurityPage() {
  try {
    // Fetch user data to get 2FA status
    const response = await fetch('/api/auth/me', {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });
    
    if (!response.ok) {
      throw new Error('Failed to load user data');
    }
    
    const data = await response.json();
    const user = data.data;
    
    // Render 2FA status
    renderTwoFAStatus(user.twoFactorEnabled);
    
  } catch (error) {
    console.error('Failed to load security page:', error);
    // Show error state instead of infinite loading
    const container = document.getElementById('twofa-status-container');
    if (container) {
      container.innerHTML = `
        <div class="alert alert-danger">
          <i class="fas fa-exclamation-triangle"></i>
          <span>Failed to load 2FA status. Please refresh the page.</span>
        </div>
        <button class="btn btn-primary" onclick="loadSecurityPage()" style="margin-top: 12px;">
          <i class="fas fa-rotate"></i> Retry
        </button>
      `;
    }
  }
}

/**
 * Render 2FA status in security settings
 */
function renderTwoFAStatus(enabled) {
  const container = document.getElementById('twofa-status-container');
  if (!container) return;
  
  if (enabled) {
    container.innerHTML = `
      <div class="twofa-status enabled">
        <i class="fas fa-shield-check"></i>
        <span>Two-Factor Authentication is <strong>Enabled</strong></span>
      </div>
      <div style="margin-top: 16px; display: flex; gap: 10px;">
        <button class="btn btn-danger" onclick="disableTwoFA()">
          <i class="fas fa-shield-xmark"></i> Disable 2FA
        </button>
        <button class="btn btn-ghost" onclick="regenerateBackupCodes()">
          <i class="fas fa-rotate"></i> Regenerate Backup Codes
        </button>
      </div>
    `;
  } else {
    container.innerHTML = `
      <div class="twofa-status disabled">
        <i class="fas fa-shield-xmark"></i>
        <span>Two-Factor Authentication is <strong>Disabled</strong></span>
      </div>
      <p style="color: var(--text-muted); margin-top: 12px; font-size: 14px;">
        Add an extra layer of security to your account by requiring a code from your phone in addition to your password.
      </p>
      <button class="btn btn-primary" onclick="openTwoFASetup()" style="margin-top: 16px;">
        <i class="fas fa-shield-plus"></i> Enable 2FA
      </button>
    `;
  }
}

/**
 * Handle API errors globally
 */
async function handleAPIError(response) {
  const data = await response.json().catch(() => ({ error: 'Unknown error' }));
  
  switch (response.status) {
    case 401:
      localStorage.removeItem('token');
      window.location.href = '/';
      showToast('Session expired. Please log in again.', 'error');
      break;
    case 403:
      showToast('You don\'t have permission to perform this action.', 'error');
      break;
    case 404:
      showToast('Resource not found. It may have been deleted.', 'error');
      break;
    case 429:
      handleRateLimitError(response);
      break;
    case 500:
      showToast('Server error. Please try again later.', 'error');
      break;
    default:
      showToast(data.error || 'An error occurred', 'error');
  }
}

/**
 * Handle rate limit errors
 */
function handleRateLimitError(response) {
  const retryAfter = response.headers.get('Retry-After') || '60';
  const resetTime = response.headers.get('X-RateLimit-Reset');
  
  let message = `Too many requests. Please try again in ${retryAfter} seconds.`;
  
  if (resetTime) {
    const resetDate = new Date(parseInt(resetTime) * 1000);
    const now = new Date();
    const secondsUntilReset = Math.ceil((resetDate - now) / 1000);
    message = `Rate limit exceeded. Please wait ${secondsUntilReset} seconds before trying again.`;
  }
  
  showToast(message, 'warning');
  
  // Log rate limit info for debugging
  console.warn('Rate Limit Info:', {
    limit: response.headers.get('X-RateLimit-Limit'),
    remaining: response.headers.get('X-RateLimit-Remaining'),
    reset: response.headers.get('X-RateLimit-Reset'),
    retryAfter: retryAfter
  });
}

/**
 * Set button loading state
 */
function setButtonLoading(button, loading) {
  if (loading) {
    button.disabled = true;
    button.dataset.originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
  } else {
    button.disabled = false;
    button.innerHTML = button.dataset.originalText || button.innerHTML;
  }
}

/**
 * Feature detection
 */
function checkBrowserSupport() {
  if (!window.crypto || !window.crypto.subtle) {
    showToast('Your browser does not support encryption features. Please upgrade.', 'error');
    return false;
  }
  
  if (!window.fetch) {
    showToast('Your browser is not supported. Please upgrade.', 'error');
    return false;
  }
  
  return true;
}

// Check browser support on load
document.addEventListener('DOMContentLoaded', function() {
  checkBrowserSupport();
});

// Export functions for use in other scripts
window.SecureFS = {
  checkPasswordStrength,
  initPasswordStrengthMeter,
  openTwoFASetup,
  verifyTwoFA,
  closeTwoFASetup,
  disableTwoFA,
  regenerateBackupCodes,
  copyBackupCodes,
  showTwoFALoginModal,
  verifyTwoFALogin,
  closeTwoFALoginModal,
  toggleBackupCodeInput,
  fetchWithRateLimitHandling,
  showToast,
  loadSecurityPage,
  renderTwoFAStatus,
  handleAPIError,
  handleRateLimitError,
  setButtonLoading
};
