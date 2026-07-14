/* ============================================================
 * fs-report Phase 2 — reports-page.js
 *
 * Standalone Report History page (/reports) behavior:
 *   - Search: filters .rep rows by case-insensitive substring on row text.
 *   - Category chips (All / Executive / Investigation / Remediation /
 *     Compliance / Exploitability Evidence): toggle .rep rows by data-rf.
 *     Search + category COMPOSE —
 *     a row is visible only if it passes both. Both kept in module state so
 *     they survive body swaps.
 *   - Date headers (.rep-date) hide when every row until the next header is
 *     hidden (no lingering empty "Yesterday").
 *   - After a Refresh swap of #reports-body: re-apply the active filter and
 *     re-create lucide icons. Chip/search handlers bind to .page-head (OUTSIDE
 *     #reports-body) so they survive swaps.
 *   - Refresh errors for /api/reports/list → a toast, leaving rows in place.
 *
 * No auto-refresh (reports are static) — Refresh is manual only.
 * This file loads ONLY on /reports (via the page's {% block scripts %}), but
 * every step is guarded on the relevant DOM existing — defensive by design.
 *
 * Vanilla ES5-style IIFE — no framework, no build step.
 * ============================================================ */
(function () {
  'use strict';

  var _activeFilter = 'all'; /* all | executive | investigation | remediation | compliance | exploitability-evidence */
  var _query = '';
  var _inited = false;

  /* ── Apply search + category filter to every .rep row, then hide empty
        date headers. ── */
  function _applyFilter() {
    var body = document.getElementById('reports-body');
    if (!body) return;
    var rows = body.querySelectorAll('.rep');
    var i;
    for (i = 0; i < rows.length; i++) {
      var row = rows[i];
      var rf = row.getAttribute('data-rf') || '';
      var catOk = _activeFilter === 'all' || rf === _activeFilter;
      var textOk = true;
      if (_query) {
        var t = (row.textContent || '').toLowerCase();
        textOk = t.indexOf(_query) >= 0;
      }
      row.style.display = (catOk && textOk) ? '' : 'none';
    }
    _syncDateHeaders(body);
  }

  /* ── Hide a .rep-date header when all rows under it (until the next
        header) are hidden. ── */
  function _syncDateHeaders(body) {
    var children = body.children;
    var i, j;
    for (i = 0; i < children.length; i++) {
      var el = children[i];
      if (!el.classList || !el.classList.contains('rep-date')) continue;
      var anyVisible = false;
      for (j = i + 1; j < children.length; j++) {
        var sib = children[j];
        if (sib.classList && sib.classList.contains('rep-date')) break;
        if (sib.classList && sib.classList.contains('rep') &&
            sib.style.display !== 'none') {
          anyVisible = true;
          break;
        }
      }
      el.style.display = anyVisible ? '' : 'none';
    }
  }

  /* ── Wire the search input (in .page-head, OUTSIDE #reports-body). ── */
  function _wireSearch() {
    var input = document.querySelector('.page-head .search input');
    if (!input) return;
    input.addEventListener('input', function () {
      _query = (this.value || '').toLowerCase();
      _applyFilter();
    });
  }

  /* ── Wire category chips (delegated on .chips, OUTSIDE #reports-body). ── */
  function _wireChips() {
    var chipBar = document.querySelector('.page-head .chips');
    if (!chipBar) return;
    chipBar.addEventListener('click', function (e) {
      var chip = e.target.closest ? e.target.closest('.chip') : null;
      if (!chip || !chipBar.contains(chip)) return;
      var rf = chip.getAttribute('data-rf');
      if (!rf) return;
      var chips = chipBar.querySelectorAll('.chip');
      for (var i = 0; i < chips.length; i++) {
        chips[i].classList.remove('on');
      }
      chip.classList.add('on');
      _activeFilter = rf;
      _applyFilter();
    });
  }

  /* ── Update the "{N} generated" eyebrow to the refreshed row count. ── */
  function _updateEyebrow(body) {
    var eyebrow = document.querySelector('.page-head .eyebrow');
    if (!eyebrow) return;
    var n = body.querySelectorAll('.rep').length;
    eyebrow.textContent = n + ' generated';
  }

  /* ── Re-apply filter + re-create icons + refresh count after each body swap. ── */
  function _wireAfterSwap() {
    var body = document.getElementById('reports-body');
    if (!body) return;
    body.addEventListener('htmx:afterSwap', function () {
      _updateEyebrow(body);
      _applyFilter();
      if (window.lucide) lucide.createIcons();
    });
  }

  /* ── Surface refresh failures instead of silently leaving stale rows. ── */
  function _wireErrors() {
    function onErr(e) {
      var cfg = e && e.detail && e.detail.requestConfig;
      var path = cfg && cfg.path;
      /* Only react to our own refresh request; ignore unrelated/path-less
         failures so we don't show a misleading toast. */
      if (!path || path.indexOf('/api/reports/list') === -1) return;
      if (window.__showToast) {
        window.__showToast('Refresh failed — showing last data');
      }
    }
    document.body.addEventListener('htmx:responseError', onErr);
    document.body.addEventListener('htmx:sendError', onErr);
  }

  /* ── Init (guarded against double-run). ── */
  function _init() {
    if (_inited) return;
    if (!document.getElementById('reports-body')) return; /* only on /reports */
    _inited = true;

    _wireSearch();
    _wireChips();
    _wireAfterSwap();
    _wireErrors();
  }

  document.addEventListener('DOMContentLoaded', _init);
})();
