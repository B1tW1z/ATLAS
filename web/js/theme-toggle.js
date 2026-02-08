/**
 * ATLAS Theme Toggle - Shared across all pages
 * Handles theme switching with localStorage persistence
 */

// Initialize theme on page load (runs immediately)
(function () {
    const savedTheme = localStorage.getItem('atlas_theme');
    if (savedTheme === 'cyberpunk') {
        document.body.classList.add('cyberpunk-theme');
    }
})();

/**
 * Toggle between original and cyberpunk themes
 */
function toggleTheme() {
    const isCyberpunk = document.body.classList.toggle('cyberpunk-theme');
    localStorage.setItem('atlas_theme', isCyberpunk ? 'cyberpunk' : 'default');

    // Update button text if exists
    const toggleText = document.getElementById('theme-toggle-text');
    if (toggleText) {
        toggleText.textContent = isCyberpunk ? 'Classic Mode' : 'Cyberpunk Mode';
    }
}

// Update toggle text on DOM load
document.addEventListener('DOMContentLoaded', function () {
    const savedTheme = localStorage.getItem('atlas_theme');
    const toggleText = document.getElementById('theme-toggle-text');
    if (toggleText && savedTheme === 'cyberpunk') {
        toggleText.textContent = 'Classic Mode';
    }
});
