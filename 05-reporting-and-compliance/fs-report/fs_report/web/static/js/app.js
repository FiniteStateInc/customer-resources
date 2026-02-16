/**
 * Finite State Report Kit — Alpine.js Components
 *
 * Components:
 * - prerunForm: Adaptive pre-run configuration form
 * - progressStream: SSE-powered live progress display
 * - recipeSelector: Recipe checkbox management
 * - toastManager: Toast notification system (defined inline in _toast.html)
 */

// Global htmx event listener for toast notifications
document.addEventListener('htmx:afterRequest', function(event) {
    if (event.detail.successful) {
        // Handled by individual elements via @htmx:after-request
    }
});
