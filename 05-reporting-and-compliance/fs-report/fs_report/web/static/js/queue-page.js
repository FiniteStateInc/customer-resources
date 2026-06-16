/* ============================================================
 * fs-report Phase 2 — queue-page.js
 *
 * Standalone Scan Queue page (/queue) behavior:
 *   - Filter chips (All / Processing / Stuck / Done) toggle .qg rows by
 *     data-flag; the active filter is tracked so it survives body swaps.
 *   - Auto-refresh: 180 000 ms interval, visibility-gated (≤200 req/hr).
 *   - After each HTMX swap of #queue-body: re-apply the active filter and
 *     re-create lucide icons in the fresh markup.
 *
 * This file loads ONLY on /queue (via the page's {% block scripts %}), but
 * every step is guarded on the relevant DOM existing — defensive by design.
 *
 * Vanilla ES5-style IIFE — no framework, no build step.
 * ============================================================ */
(function () {
  'use strict';

  var REFRESH_MS = 300000;
  var _poller = null;
  var _activeFilter = 'all'; /* one of: all | running | stuck | done */
  var _inited = false;

  /* ── Apply the active filter to every .qg row in #queue-body ── */
  function _applyFilter() {
    var body = document.getElementById('queue-body');
    if (!body) return;
    var rows = body.querySelectorAll('.qg');
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var show;
      if (_activeFilter === 'running') {
        show = row.getAttribute('data-has-running') === '1';
      } else if (_activeFilter === 'stuck') {
        show = row.getAttribute('data-has-stuck') === '1';
      } else if (_activeFilter === 'done') {
        show = row.getAttribute('data-all-done') === '1';
      } else {
        show = true; /* 'all' */
      }
      row.style.display = show ? '' : 'none';
    }
  }

  /* ── Wire filter chips (delegated on .chips, OUTSIDE #queue-body) ── */
  function _wireChips() {
    var chipBar = document.querySelector('.page-head .chips');
    if (!chipBar) return;
    chipBar.addEventListener('click', function (e) {
      var chip = e.target.closest ? e.target.closest('.chip') : null;
      if (!chip || !chipBar.contains(chip)) return;
      var qf = chip.getAttribute('data-qf');
      if (!qf) return;
      /* Set .on on the clicked chip, clear siblings. */
      var chips = chipBar.querySelectorAll('.chip');
      for (var i = 0; i < chips.length; i++) {
        chips[i].classList.remove('on');
      }
      chip.classList.add('on');
      _activeFilter = qf;
      _applyFilter();
    });
  }

  /* ── Auto-refresh poller (visibility-gated) ── */
  function _refresh() {
    try {
      var body = document.getElementById('queue-body');
      if (body && window.htmx) {
        htmx.ajax('GET', '/api/queue/full', {
          target: '#queue-body',
          swap: 'innerHTML'
        });
      }
    } catch (e) { /* ignore — next tick will retry */ }
  }

  function _startPoller() {
    if (_poller !== null) return; /* already running */
    _poller = setInterval(function () {
      if (document.hidden) return; /* skip while tab is hidden */
      _refresh();
    }, REFRESH_MS);
  }

  function _stopPoller() {
    if (_poller !== null) {
      clearInterval(_poller);
      _poller = null;
    }
  }

  /* ── Stamp the status-bar "last sync" with the current time ── */
  function _stampSync() {
    var syncEl = document.querySelector('[data-cc="sync"]');
    if (syncEl) syncEl.textContent = new Date().toTimeString().slice(0, 8);
  }

  /* ── Re-apply filter + re-create icons after each body swap ── */
  function _wireAfterSwap() {
    var body = document.getElementById('queue-body');
    if (!body) return;
    body.addEventListener('htmx:afterSwap', function () {
      _applyFilter();
      if (window.lucide) lucide.createIcons();
      /* The queue's own refresh is the freshest data on /queue, so the
         footer "last sync" should track it (not only the projects fetch). */
      _stampSync();
    });
  }

  /* ── Surface refresh failures instead of silently leaving stale rows ── */
  function _wireErrors() {
    function onErr(e) {
      var cfg = e && e.detail && e.detail.requestConfig;
      var path = cfg && cfg.path;
      if (path && path.indexOf('/api/queue/full') === -1) return; /* not ours */
      if (window.__showToast) {
        window.__showToast('Queue refresh failed — showing last data');
      }
    }
    document.body.addEventListener('htmx:responseError', onErr);
    document.body.addEventListener('htmx:sendError', onErr);
  }

  /* ── Visibility handling: stop while hidden, restart + catch up ── */
  function _wireVisibility() {
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        _stopPoller();
      } else {
        _startPoller();
        _refresh(); /* one immediate refresh on refocus */
      }
    });
  }

  /* ── Init (guarded against double-run) ── */
  function _init() {
    if (_inited) return;
    /* Only act on the queue page. */
    if (!document.getElementById('queue-body')) return;
    _inited = true;

    _wireChips();
    _wireAfterSwap();
    _wireErrors();
    _wireVisibility();
    _startPoller();
    /* The body is server-rendered fresh at page load, so stamp "last sync"
       now rather than waiting up to 3 min for the first auto-refresh. */
    _stampSync();
  }

  document.addEventListener('DOMContentLoaded', _init);
})();
