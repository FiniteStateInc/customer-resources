/* ===================================================================
 * Runs index page (/runs) — refresh chrome after an HTMX body swap.
 *
 * The page is server-rendered; the only interactivity is the manual Refresh
 * button (hx-get /api/runs/list → swaps #runs-body). After each swap we:
 *   - re-run lucide.createIcons() (swapped markup isn't processed by the
 *     deferred lucide pass → raw <i data-lucide=...> placeholders otherwise), and
 *   - update the "{N} run(s)" eyebrow count, which lives in .page-head OUTSIDE
 *     the swap target, so it would otherwise go stale.
 * Mirrors reports-page.js's _updateEyebrow + afterSwap wiring (one mechanism,
 * consistent across the two list pages — PR #131 multi-review). (R-PR130/131.)
 * =================================================================== */

(function () {
  "use strict";

  /* Update the "{N} run(s)" eyebrow to the refreshed row count. Keyed off the
     stable #runs-count id (robust if another .eyebrow is ever added). */
  function _updateEyebrow(body) {
    var eyebrow = document.getElementById("runs-count");
    if (!eyebrow) return;
    var n = body.querySelectorAll(".runrow").length;
    eyebrow.textContent = n + (n === 1 ? " run" : " runs");
  }

  document.body.addEventListener("htmx:afterSwap", function (e) {
    if (!e.target || e.target.id !== "runs-body") return;
    _updateEyebrow(e.target);
    if (window.lucide) window.lucide.createIcons();
  });
})();
