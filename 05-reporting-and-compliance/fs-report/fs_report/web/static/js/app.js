/**
 * Finite State Report Kit — Alpine.js Components
 *
 * Components:
 * - prerunForm: Adaptive pre-run configuration form
 * - progressStream: SSE-powered live progress display
 * - recipeSelector: Recipe checkbox management
 * - toastManager: Toast notification system (defined inline in _toast.html)
 */

// Theme toggle
function toggleTheme() {
    var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('fs-theme', next);
}

// Global htmx event listener for toast notifications
document.addEventListener('htmx:afterRequest', function(event) {
    if (event.detail.successful) {
        // Handled by individual elements via @htmx:after-request
    }
});
