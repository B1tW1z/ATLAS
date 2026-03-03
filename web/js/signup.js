/**
 * ATLAS Signup Page JavaScript
 * 
 * Handles signup form validation, password strength, and form submission.
 */

const SignupManager = {
    /**
     * Initialize signup page functionality
     */
    init() {
        this.bindEvents();
    },

    /**
     * Bind event listeners
     */
    bindEvents() {
        const signupForm = document.getElementById('signup-form');
        if (signupForm) {
            signupForm.addEventListener('submit', (e) => this.handleSignup(e));
        }

        const passwordToggle = document.getElementById('password-toggle');
        if (passwordToggle) {
            passwordToggle.addEventListener('click', () => this.togglePassword());
        }

        const passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.addEventListener('input', () => this.checkPasswordStrength());
        }

        const confirmPasswordInput = document.getElementById('confirm-password');
        if (confirmPasswordInput) {
            confirmPasswordInput.addEventListener('input', () => this.checkPasswordMatch());
        }

        const googleBtn = document.getElementById('google-signup-btn');
        if (googleBtn) {
            googleBtn.addEventListener('click', () => this.handleGoogleSignup());
        }

        const microsoftBtn = document.getElementById('microsoft-signup-btn');
        if (microsoftBtn) {
            microsoftBtn.addEventListener('click', () => this.handleMicrosoftSignup());
        }

        const githubBtn = document.getElementById('github-signup-btn');
        if (githubBtn) {
            githubBtn.addEventListener('click', () => this.handleGithubSignup());
        }

        // Terms and conditions scroll detection
        const termsContainer = document.getElementById('terms-container');
        if (termsContainer) {
            termsContainer.addEventListener('scroll', () => this.handleTermsScroll());
        }

        // Terms checkbox change - update button state
        const termsCheckbox = document.getElementById('terms-accept');
        if (termsCheckbox) {
            termsCheckbox.addEventListener('change', () => this.updateSubmitButton());
        }
    },

    /**
     * Handle terms scroll - enable checkbox when scrolled to bottom
     */
    handleTermsScroll() {
        const termsContainer = document.getElementById('terms-container');
        const termsCheckbox = document.getElementById('terms-accept');
        const termsHint = document.getElementById('terms-hint');

        if (!termsContainer || !termsCheckbox) return;

        // Check if scrolled near the bottom (within 10px)
        const isAtBottom = termsContainer.scrollHeight - termsContainer.scrollTop <= termsContainer.clientHeight + 10;

        if (isAtBottom) {
            termsCheckbox.disabled = false;
            if (termsHint) {
                termsHint.classList.add('hidden');
            }
        }
    },

    /**
     * Update submit button state based on terms acceptance
     */
    updateSubmitButton() {
        const termsCheckbox = document.getElementById('terms-accept');
        const signupBtn = document.getElementById('signup-btn');

        if (!termsCheckbox || !signupBtn) return;

        signupBtn.disabled = !termsCheckbox.checked;
    },

    /**
     * Toggle password visibility
     */
    togglePassword() {
        const passwordInput = document.getElementById('password');
        const eyeIcon = document.getElementById('eye-icon');

        if (!passwordInput || !eyeIcon) return;

        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            eyeIcon.innerHTML = `
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                    d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
            `;
        } else {
            passwordInput.type = 'password';
            eyeIcon.innerHTML = `
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                    d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                    d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
            `;
        }
    },

    /**
     * Check password strength
     */
    checkPasswordStrength() {
        const password = document.getElementById('password').value;
        const strengthDiv = document.getElementById('password-strength');

        if (!strengthDiv) return;

        let strength = 0;
        let feedback = '';

        if (password.length >= 8) strength++;
        if (password.length >= 12) strength++;
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
        if (/\d/.test(password)) strength++;
        if (/[^a-zA-Z0-9]/.test(password)) strength++;

        if (password.length === 0) {
            strengthDiv.innerHTML = '';
            strengthDiv.className = 'password-strength';
        } else if (strength < 2) {
            feedback = 'Weak';
            strengthDiv.className = 'password-strength weak';
        } else if (strength < 4) {
            feedback = 'Medium';
            strengthDiv.className = 'password-strength medium';
        } else {
            feedback = 'Strong';
            strengthDiv.className = 'password-strength strong';
        }

        if (feedback) {
            strengthDiv.innerHTML = `<span class="strength-bar"></span><span class="strength-text">${feedback}</span>`;
        }

        // Also check password match if confirm field has value
        this.checkPasswordMatch();
    },

    /**
     * Check if passwords match
     */
    checkPasswordMatch() {
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        const matchDiv = document.getElementById('password-match');

        if (!matchDiv) return;

        if (confirmPassword.length === 0) {
            matchDiv.textContent = '';
            matchDiv.className = 'input-hint password-match';
        } else if (password === confirmPassword) {
            matchDiv.textContent = '✓ Passwords match';
            matchDiv.className = 'input-hint password-match match';
        } else {
            matchDiv.textContent = '✗ Passwords do not match';
            matchDiv.className = 'input-hint password-match no-match';
        }
    },

    /**
     * Handle signup form submission
     */
    async handleSignup(e) {
        e.preventDefault();

        const signupBtn = document.getElementById('signup-btn');
        const errorDiv = document.getElementById('signup-error');
        const successDiv = document.getElementById('signup-success');

        const name = document.getElementById('name').value.trim();
        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        const userType = document.getElementById('user-type').value;
        const termsAccepted = document.getElementById('terms-accept').checked;

        // Client-side validation
        if (password !== confirmPassword) {
            this.showError(errorDiv, 'Passwords do not match');
            return;
        }

        if (password.length < 8) {
            this.showError(errorDiv, 'Password must be at least 8 characters');
            return;
        }

        if (!userType) {
            this.showError(errorDiv, 'Please select your user type');
            return;
        }

        if (!termsAccepted) {
            this.showError(errorDiv, 'You must accept the Terms and Conditions');
            return;
        }

        // Disable button
        signupBtn.disabled = true;
        signupBtn.textContent = 'Creating account...';
        errorDiv.classList.remove('show');
        successDiv.classList.remove('show');

        try {
            const response = await fetch('/api/auth/signup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ name, username, email, password, role: userType })
            });

            const data = await response.json();

            if (response.ok) {
                this.showSuccess(successDiv, 'Account created successfully! Redirecting...');
                // Store token if provided
                if (data.token) {
                    localStorage.setItem('atlas_token', data.token);
                }
                if (data.user) {
                    localStorage.setItem('atlas_user', JSON.stringify(data.user));
                }
                // Redirect to dashboard after short delay
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1500);
            } else {
                this.showError(errorDiv, data.detail || 'Signup failed. Please try again.');
            }
        } catch (error) {
            console.error('Signup error:', error);
            this.showError(errorDiv, 'Connection error. Please try again.');
        } finally {
            signupBtn.disabled = false;
            signupBtn.textContent = 'Create Account';
        }
    },

    /**
     * Handle Google signup
     */
    async handleGoogleSignup() {
        const errorDiv = document.getElementById('signup-error');
        const successDiv = document.getElementById('signup-success');

        // Show loading modal for demo
        this.showLoadingModal('Connecting to Google...', 'google');

        // Pause for demo/presentation (2 seconds)
        await new Promise(resolve => setTimeout(resolve, 2000));

        try {
            this.updateLoadingModal('Authenticating with Google...');

            const response = await fetch('/api/auth/google', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            const data = await response.json();

            if (response.ok) {
                this.updateLoadingModal('Authentication successful!');
                await new Promise(resolve => setTimeout(resolve, 1000));

                if (data.token) {
                    localStorage.setItem('atlas_token', data.token);
                }
                if (data.user) {
                    localStorage.setItem('atlas_user', JSON.stringify(data.user));
                }

                this.hideLoadingModal();
                this.showSuccess(successDiv, 'Google sign-in successful! Redirecting...');
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            } else {
                this.hideLoadingModal();
                this.showError(errorDiv, data.detail || 'Google sign-up failed');
            }
        } catch (error) {
            this.hideLoadingModal();
            console.error('Google signup error:', error);
            this.showError(errorDiv, 'Google sign-up is not configured yet');
        }
    },

    /**
     * Show loading modal
     */
    showLoadingModal(message, provider) {
        // Remove existing modal if any
        this.hideLoadingModal();

        const modal = document.createElement('div');
        modal.id = 'oauth-loading-modal';
        modal.className = 'oauth-loading-modal';
        modal.innerHTML = `
            <div class="oauth-loading-content">
                <div class="oauth-loading-spinner"></div>
                <p class="oauth-loading-text">${message}</p>
                <p class="oauth-loading-provider">Please wait while we connect your ${provider} account</p>
            </div>
        `;
        document.body.appendChild(modal);

        // Trigger animation
        requestAnimationFrame(() => modal.classList.add('show'));
    },

    /**
     * Update loading modal message
     */
    updateLoadingModal(message) {
        const textEl = document.querySelector('.oauth-loading-text');
        if (textEl) {
            textEl.textContent = message;
        }
    },

    /**
     * Hide loading modal
     */
    hideLoadingModal() {
        const modal = document.getElementById('oauth-loading-modal');
        if (modal) {
            modal.classList.remove('show');
            setTimeout(() => modal.remove(), 300);
        }
    },

    /**
     * Handle Microsoft signup
     */
    async handleMicrosoftSignup() {
        const errorDiv = document.getElementById('signup-error');
        const successDiv = document.getElementById('signup-success');

        try {
            const response = await fetch('/api/auth/microsoft', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            const data = await response.json();

            if (response.ok) {
                if (data.token) {
                    localStorage.setItem('atlas_token', data.token);
                }
                if (data.user) {
                    localStorage.setItem('atlas_user', JSON.stringify(data.user));
                }
                this.showSuccess(successDiv, 'Microsoft sign-in successful! Redirecting...');
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            } else {
                this.showError(errorDiv, data.detail || 'Microsoft sign-up failed');
            }
        } catch (error) {
            console.error('Microsoft signup error:', error);
            this.showError(errorDiv, 'Microsoft sign-up is not configured yet');
        }
    },

    /**
     * Handle GitHub signup
     */
    async handleGithubSignup() {
        const errorDiv = document.getElementById('signup-error');
        const successDiv = document.getElementById('signup-success');

        try {
            const response = await fetch('/api/auth/github', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            const data = await response.json();

            if (response.ok) {
                if (data.token) {
                    localStorage.setItem('atlas_token', data.token);
                }
                if (data.user) {
                    localStorage.setItem('atlas_user', JSON.stringify(data.user));
                }
                this.showSuccess(successDiv, 'GitHub sign-in successful! Redirecting...');
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            } else {
                this.showError(errorDiv, data.detail || 'GitHub sign-up failed');
            }
        } catch (error) {
            console.error('GitHub signup error:', error);
            this.showError(errorDiv, 'GitHub sign-up is not configured yet');
        }
    },

    /**
     * Show error message
     */
    showError(errorDiv, message) {
        errorDiv.textContent = message;
        errorDiv.classList.add('show');
    },

    /**
     * Show success message
     */
    showSuccess(successDiv, message) {
        successDiv.textContent = message;
        successDiv.classList.add('show');
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    SignupManager.init();
});
