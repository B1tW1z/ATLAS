/**
 * ATLAS Login Page JavaScript
 * 
 * Handles login form submission, password toggle, and session management.
 */

const LoginManager = {
    /**
     * Initialize login page functionality
     */
    init() {
        this.bindEvents();
        this.checkExistingSession();
    },

    /**
     * Bind event listeners
     */
    bindEvents() {
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        const passwordToggle = document.getElementById('password-toggle');
        if (passwordToggle) {
            passwordToggle.addEventListener('click', () => this.togglePassword());
        }

        const googleBtn = document.getElementById('google-login-btn');
        if (googleBtn) {
            googleBtn.addEventListener('click', () => this.handleGoogleLogin());
        }

        const microsoftBtn = document.getElementById('microsoft-login-btn');
        if (microsoftBtn) {
            microsoftBtn.addEventListener('click', () => this.handleMicrosoftLogin());
        }

        const githubBtn = document.getElementById('github-login-btn');
        if (githubBtn) {
            githubBtn.addEventListener('click', () => this.handleGithubLogin());
        }
    },

    /**
     * Handle Google login
     */
    async handleGoogleLogin() {
        const errorDiv = document.getElementById('login-error');

        // For demo: simulate Google login with a demo user
        try {
            const response = await fetch('/api/auth/google', {
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
                window.location.href = '/';
            } else {
                this.showError(errorDiv, data.detail || 'Google sign-in failed');
            }
        } catch (error) {
            this.showError(errorDiv, 'Google sign-in is not configured yet');
        }
    },

    /**
     * Handle Microsoft login
     */
    async handleMicrosoftLogin() {
        const errorDiv = document.getElementById('login-error');

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
                window.location.href = '/';
            } else {
                this.showError(errorDiv, data.detail || 'Microsoft sign-in failed');
            }
        } catch (error) {
            this.showError(errorDiv, 'Microsoft sign-in is not configured yet');
        }
    },

    /**
     * Handle GitHub login
     */
    async handleGithubLogin() {
        const errorDiv = document.getElementById('login-error');

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
                window.location.href = '/';
            } else {
                this.showError(errorDiv, data.detail || 'GitHub sign-in failed');
            }
        } catch (error) {
            this.showError(errorDiv, 'GitHub sign-in is not configured yet');
        }
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
     * Handle login form submission
     */
    async handleLogin(e) {
        e.preventDefault();

        const loginBtn = document.getElementById('login-btn');
        const errorDiv = document.getElementById('login-error');

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const remember = document.getElementById('remember')?.checked || false;

        // Disable button and show loading state
        loginBtn.disabled = true;
        loginBtn.textContent = 'Logging in...';
        errorDiv.classList.remove('show');

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password, remember })
            });

            const data = await response.json();

            if (response.ok) {
                // Store token
                if (data.token) {
                    localStorage.setItem('atlas_token', data.token);
                }
                if (data.user) {
                    localStorage.setItem('atlas_user', JSON.stringify(data.user));
                }
                // Redirect to dashboard
                window.location.href = '/';
            } else {
                this.showError(errorDiv, data.detail || 'Invalid username or password');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showError(errorDiv, 'Connection error. Please try again.');
        } finally {
            loginBtn.disabled = false;
            loginBtn.textContent = 'Login';
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
     * Check if user is already logged in
     */
    async checkExistingSession() {
        const token = localStorage.getItem('atlas_token');
        if (!token) return;

        try {
            const response = await fetch('/api/auth/verify', {
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (response.ok) {
                window.location.href = '/';
            } else {
                // Token invalid, clear storage
                localStorage.removeItem('atlas_token');
                localStorage.removeItem('atlas_user');
            }
        } catch (error) {
            // Connection error, let user try to login
            console.error('Session verification error:', error);
        }
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    LoginManager.init();
});
