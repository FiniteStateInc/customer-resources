/**
 * command-center.js — Command Center page wiring.
 *
 * Responsibilities:
 *   CROSS-PAGE (runs on every shell page — always):
 *     - Live projects fetch → window.__CC.projects + palette __refreshPaletteProjects
 *       + status-bar [data-cc="projects"] count + status-bar [data-cc="sync"] stamp.
 *     - Live folders fetch → window.__CC.folders + palette __refreshPaletteFolders
 *       (folder is a first-class ⌘K target — folder-targeting design §5).
 *     - Wire configure modal: window.__openConfigure, window.__closeCfgModal.
 *     - Expose window.__showToast.
 *
 *   COCKPIT-ONLY (gated: only when #running-container exists in the DOM):
 *     - Fetch /api/cc/overview and populate KPI band, scan-health ring,
 *       throughput sparkline, connection pill, and status-bar spans.
 *     - Wire run bar: #rb-run, #rb-pin, report select, and a SINGLE
 *       initScopeDropdowns cascade over #rb-folder/#rb-project/#rb-version
 *       (the cascade — not fetchProjects — populates + binds those selects).
 *     - Wire page buttons: #cc-refresh, #cc-new.
 *     - Wire launcher: filter chips, sort chips, card clicks.
 *     - Handle ?configure=<recipe> on page load.
 *     - Running-reports poller (_rrPoller, 2.5 s) and queue poller
 *       (_queuePoller, 180 s), including the visibilitychange handler
 *       that drives them.
 *
 * Deferred (C5): Full pre-run form modal for configure-type recipes is NOT
 *   implemented here. When ?configure=<recipe> is detected the recipe is
 *   pre-selected in #rb-report and the run bar is scrolled into view with a
 *   brief toast. The full prerun-form modal integration is deferred to a
 *   future task.
 *
 * Depends on fast-run.js (window.__openFR, window.__setScope) and
 * window.__CC (set by _cc_shell.html inline script).
 *
 * ES5-style IIFE — no build step required.
 */
(function () {
  'use strict';

  /* ── Helpers ──────────────────────────────────────────────────── */
  function el(id) { return document.getElementById(id); }
  function qs(sel) { return document.querySelector(sel); }
  function qsa(sel) { return document.querySelectorAll(sel); }

  /* CARD-BACK ID SCOPING (PR #117 review r3 — ROOT-CAUSE fix).
     The card-back fragment emits FIXED global ids (cardcfg-bv-project,
     cardcfg-ft, …). Two earlier rounds tried to make duplicate ids impossible
     by clearing the other back before the new one wires — but a flip
     transition (or a stale deferred unload) can briefly leave TWO backs in the
     DOM, and document.getElementById would then bind the wrong card.

     The fix: every card-back element lookup is SCOPED to that card's own
     `.wf-back` subtree — `back.querySelector('#cardcfg-…')` here, and
     `initVersionPicker({ root: back, … })` (Element.querySelector matches only
     descendants). So even if a second back coexists with the same ids, each
     card's wiring binds ITS OWN elements. Correctness no longer depends on
     when the other back is cleared — coexisting backs are functionally
     harmless. (Duplicate ids are technically invalid HTML; scoped lookups make
     them harmless, and single-active-back keeps at most one flipped.)

     SINGLE ACTIVE BACK is now kept purely for UX (one flipped card at a time +
     one Esc handler): opening a card collapses any other open back. The
     deferred unload (innerHTML='', data-loaded reset) is DOM hygiene only — it
     is NO LONGER load-bearing for correctness, so it must not grow more timing
     logic. Re-flipping a previously-opened card re-fetches its fragment; losing
     unsaved edits when flipping away is acceptable (like closing a modal). */
  var _openCard = null;

  var CC = window.__CC || {};
  var MOTION = !document.body.classList.contains('no-motion');
  var _inited = false;

  /* ── Count-up animation (KPI numbers) ───────────────────────── */
  function animateCount(elem, target) {
    if (!MOTION) { elem.textContent = target.toLocaleString(); return; }
    var dur = 1100, t0 = performance.now();
    function tick(now) {
      var p = Math.min(1, (now - t0) / dur);
      var e = 1 - Math.pow(1 - p, 3);
      elem.textContent = Math.round(target * e).toLocaleString();
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  /* ── Delta text helper ───────────────────────────────────────── */
  /* count is the current-window count, used to distinguish "new activity"
     (delta null because prior was 0 but cur > 0) from "both zero" (show —). */
  function deltaText(pct, count) {
    if (pct === null || pct === undefined) {
      return (count && count > 0) ? 'new' : '—';
    }
    if (pct > 0) return '▲ +' + pct + '% vs prior 30d';
    if (pct < 0) return '▼ ' + pct + '% vs prior 30d';
    return '— flat vs prior 30d';
  }

  /* ── Show a brief toast message ──────────────────────────────── */
  function showToast(msg) {
    var t = document.createElement('div');
    t.style.cssText = [
      'position:fixed', 'bottom:54px', 'left:50%', 'transform:translateX(-50%)',
      'background:var(--surface-2,#2a2a3a)', 'color:var(--ink,#e0e0e0)',
      'padding:8px 18px', 'border-radius:6px', 'font-size:13px',
      'box-shadow:0 2px 12px rgba(0,0,0,.4)', 'z-index:9999',
      'pointer-events:none', 'opacity:1', 'transition:opacity .4s'
    ].join(';');
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function () { t.style.opacity = '0'; }, 2200);
    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 2700);
  }

  /* Expose toast for fast-run.js (and any other caller) — cross-page */
  window.__showToast = showToast;

  /* ── Populate KPI from overview JSON ─────────────────────────── */
  function populateKPI(data) {
    /* Platform cell */
    var platformEl = qs('[data-cc="platform"]');
    var platformSub = qs('[data-cc="platform-sub"]');
    var p = (data.platform || '').toLowerCase();  /* hoisted: used by both platformEl and platformSub */
    if (platformEl) {
      var pLabel = p === 'operational' ? 'Operational'
                 : p === 'degraded'    ? 'Degraded'
                 : p === 'unreachable' ? 'Unreachable'
                 : data.platform || '—';
      platformEl.textContent = pLabel;
      platformEl.style.color = p === 'operational' ? 'var(--sev-low)'
                              : p === 'degraded'    ? 'var(--sev-medium)'
                              : 'var(--sev-high)';
    }
    if (platformSub) {
      platformSub.textContent = p === 'operational' ? 'all scan services healthy' : '';
    }

    /* Scans 30d */
    var scansEl = qs('[data-cc="scans"]');
    var scansDelta = qs('[data-cc="scans-delta"]');
    if (data.scans_30d) {
      if (scansEl) {
        scansEl.setAttribute('data-count', data.scans_30d.count || 0);
        animateCount(scansEl, data.scans_30d.count || 0);
      }
      if (scansDelta) {
        var dt = deltaText(data.scans_30d.delta_pct, data.scans_30d.count);
        scansDelta.textContent = dt;
        scansDelta.className = 'kdelta' + (
          data.scans_30d.delta_pct > 0 ? ' up' : data.scans_30d.delta_pct < 0 ? ' down' : ''
        );
      }
    }

    /* Reports 30d */
    var reportsEl = qs('[data-cc="reports"]');
    var reportsDelta = qs('[data-cc="reports-delta"]');
    if (data.reports_30d) {
      if (reportsEl) {
        reportsEl.setAttribute('data-count', data.reports_30d.count || 0);
        animateCount(reportsEl, data.reports_30d.count || 0);
      }
      if (reportsDelta) {
        var rdt = deltaText(data.reports_30d.delta_pct, data.reports_30d.count);
        reportsDelta.textContent = rdt;
        reportsDelta.className = 'kdelta' + (
          data.reports_30d.delta_pct > 0 ? ' up' : data.reports_30d.delta_pct < 0 ? ' down' : ''
        );
      }
    }

    /* Active users 30d */
    var usersEl = qs('[data-cc="users"]');
    var usersSub = qs('[data-cc="users-sub"]');
    if (data.active_users_30d && usersEl) {
      usersEl.setAttribute('data-count', data.active_users_30d.count || 0);
      animateCount(usersEl, data.active_users_30d.count || 0);
    }
    if (usersSub) usersSub.textContent = 'distinct scan authors';
  }

  /* ── Draw the scan-health ring ───────────────────────────────── */
  function drawRing(data) {
    var health = data.scan_health || {};
    var rate = health.success_rate;
    var grade = health.grade || '—';
    var tags = health.tags || [];

    var ring = el('ring');
    var gradeEl = qs('[data-cc="grade"]');
    var rateEl = qs('[data-cc="rate"]');
    var tagsEl = qs('[data-cc="tags"]');

    if (gradeEl) gradeEl.textContent = grade;
    if (rateEl) {
      rateEl.textContent = rate !== null && rate !== undefined
        ? Math.round(rate * 100) + '% success'
        : '—';
    }
    if (tagsEl) {
      tagsEl.innerHTML = '';
      tags.forEach(function (tag) {
        var span = document.createElement('span');
        span.className = 'ptag';
        span.textContent = tag;
        tagsEl.appendChild(span);
      });
    }

    if (ring && rate !== null && rate !== undefined) {
      var C = 465;
      var target = Math.round(C * (1 - rate));
      if (!MOTION) {
        ring.style.transition = 'none';
        ring.style.strokeDashoffset = target;
        return;
      }
      /* Reset to empty WITHOUT a transition so it jumps instantly, force a
         reflow to commit that, then animate to the target. Without the
         transition:none + reflow, a re-draw (e.g. Refresh) has no value change
         to animate and the ring snaps instead of doing the 1.4s draw-in. */
      ring.style.transition = 'none';
      ring.style.strokeDashoffset = C; /* start empty (instant) */
      void ring.getBoundingClientRect(); /* force reflow */
      requestAnimationFrame(function () {
        ring.style.transition = 'stroke-dashoffset 1.4s cubic-bezier(0.16,1,0.3,1)';
        ring.style.strokeDashoffset = target;
      });
    }
  }

  /* ── Disconnected / error state ──────────────────────────────── */
  function showDisconnected(status) {
    var hints = {
      rate_limited:  'Rate-limited — retrying',
      unreachable:   'API unreachable',
      unconfigured:  'Not connected',
    };
    var hint = hints[status] || 'Not connected';
    var platformEl = qs('[data-cc="platform"]');
    if (platformEl) { platformEl.textContent = 'Offline'; platformEl.style.color = 'var(--ink-mute)'; }
    var connPill = qs('.conn-pill');
    if (connPill) connPill.style.opacity = '.5';
    /* Optional: surface hint in platform-sub */
    var sub = qs('[data-cc="platform-sub"]');
    if (sub) sub.textContent = hint;
  }

  /* ── Fetch overview and populate ─────────────────────────────── */
  function fetchOverview() {
    fetch('/api/cc/overview')
      .then(function (resp) { return resp.json(); })
      .then(function (data) {
        if (!data.connected) {
          showDisconnected(data.status || 'unreachable');
          return;
        }
        populateKPI(data);
        drawRing(data);
        /* Update status bar sync time (cockpit path) */
        var syncEl = qs('[data-cc="sync"]');
        if (syncEl) {
          var now = new Date();
          syncEl.textContent = now.toTimeString().slice(0, 8);
        }
        /* Surface meta.capped hint on the KPI band */
        if (data.meta && data.meta.capped) {
          var cappedMsg = 'based on recent scans (data capped at ' + (data.meta.pages_fetched || '?') + ' pages)';
          var kpiBand = qs('.kpi-band');
          if (kpiBand) kpiBand.title = cappedMsg;
        }
      })
      .catch(function () {
        showDisconnected('unreachable');
      });
  }

  /* ── Run bar wiring ───────────────────────────────────────────── */
  function wireRunBar() {
    var rbRun     = el('rb-run');
    var rbPin     = el('rb-pin');
    var rbFolder  = el('rb-folder');
    var rbProject = el('rb-project');
    var rbVersion = el('rb-version');
    var rbReport  = el('rb-report');
    var rbPinned  = el('rb-pinned');

    /* SINGLE CASCADE OWNER (Task 13).  The run bar's Folder → Project → Version
       selects are populated AND bound by ONE initScopeDropdowns instance — the
       run bar no longer fetches/populates/binds #rb-project or #rb-version
       itself (that logic moved out of fetchProjects()/the old change handlers
       to avoid double-binding + racing).  The cascade restores the seeded
       data-value (pinned_folder / pinned_project / pinned_version) and pushes
       every effective scope through onChange → __setScope so the scope gate and
       launch payload always read the live Folder/Project/Version. */
    if (typeof initScopeDropdowns === 'function' && rbProject && rbVersion) {
      initScopeDropdowns({
        folderId:         'rb-folder',
        projectId:        'rb-project',
        versionId:        'rb-version',
        folderEmptyLabel: 'Any folder',
        projectEmptyLabel: 'All projects',
        onChange: function (s) {
          if (window.__setScope) window.__setScope(s.project, s.version, s.folder);
        },
      });
    } else if (window.__setScope && CC.pinned) {
      /* Defensive fallback: if the cascade helper is unavailable, still seed
         scope from the pinned values so the gate isn't empty. */
      window.__setScope(CC.pinned.project || '', CC.pinned.version || '', CC.pinned.folder || '');
    }

    /* Folder run-bar sync race (Finding 6b). The cascade's onChange only fires
       AFTER the async filterProjects() refetch completes, so a folder pick
       followed by an IMMEDIATE ⌘K / R-key / card-body launch (which read the
       stored SCOPE, not the live run bar) could still carry the PRE-change
       folder. The cascade clears project/version synchronously on a folder
       change (see _scope_dropdowns.html), so push the live scope through
       __setScope right away — before the deferred onChange — so SCOPE.folder is
       fresh the instant the folder changes. The later onChange re-pushes the
       same (now resolved) scope harmlessly. The run-bar Run button still reads
       the live values directly, so it's unaffected either way. */
    if (rbFolder && window.__setScope) {
      rbFolder.addEventListener('change', function () {
        window.__setScope(
          rbProject ? rbProject.value.trim() : '',
          rbVersion ? rbVersion.value.trim() : '',
          rbFolder.value.trim()
        );
      });
    }

    /* B9 #17: Period control — visible only when the selected report is a
       period recipe (recipe.applicability.show_period, mirroring PERIOD_RECIPES
       server-side). The value rides /api/run as the already-supported `period`
       override; blank means "use the recipe default". */
    var rbPeriodGroup = el('rb-period-group');
    var rbPeriod      = el('rb-period');
    function _reportShowsPeriod(name) {
      if (!name) return false;
      var list = (window.__CC && window.__CC.recipes) || [];
      var key = String(name).toLowerCase();
      for (var i = 0; i < list.length; i++) {
        if (list[i] && String(list[i].name).toLowerCase() === key) {
          return !!(list[i].applicability && list[i].applicability.show_period);
        }
      }
      return false;
    }
    function _syncPeriod() {
      if (!rbPeriodGroup || !rbReport) return;
      if (_reportShowsPeriod(rbReport.value)) rbPeriodGroup.removeAttribute('hidden');
      else rbPeriodGroup.setAttribute('hidden', '');
    }
    if (rbReport) rbReport.addEventListener('change', _syncPeriod);
    _syncPeriod();

    /* Run button */
    if (rbRun) {
      rbRun.addEventListener('click', function () {
        var folder  = rbFolder  ? rbFolder.value.trim()  : '';
        var project = rbProject ? rbProject.value.trim() : '';
        var version = rbVersion ? rbVersion.value.trim() : '';
        var report  = rbReport  ? rbReport.value.trim()  : '';
        if (!report) return;
        /* Only carry a period when the control is actually showing for this
           report — a stale value from a previously-selected period recipe must
           not leak onto a non-period run. */
        var period = (rbPeriodGroup && !rbPeriodGroup.hasAttribute('hidden') && rbPeriod)
          ? rbPeriod.value.trim() : '';
        if (window.__setScope) window.__setScope(project, version, folder);
        if (window.__openFR) window.__openFR(report, { project: project, version: version, folder: folder, period: period });
      });
    }

    /* Pin button — run-bar only, so it stays in the cockpit-gated wiring.
       Folder is pinned too (§4): a folder-only selection (no project) round-trips
       so the R-key / palette / cross-page launches can seed SCOPE.folder. */
    if (rbPin) {
      rbPin.addEventListener('click', function () {
        var folder  = rbFolder  ? rbFolder.value.trim()  : '';
        var project = rbProject ? rbProject.value.trim() : '';
        var version = rbVersion ? rbVersion.value.trim() : '';
        var report  = rbReport  ? rbReport.value  : '';
        _postPin(report, project, version, folder, {
          rbPinned: rbPinned,
          okToast: 'Pinned: ' + (report || '—'),
          failToast: 'Pin failed — check connection',
        });
      });
    }
  }

  /* × Unpin — delegated so it works for the run-bar readout button (which is
     re-created on every successful pin, cockpit only) AND the sidebar button
     (which renders on EVERY shell page when a pin is set).  Wired from the
     cross-page init so the sidebar × works off-dashboard too; _postPin is at
     module scope and null-safes the absent run-bar readout off-dashboard.
     POSTing empty pinned_* to /api/cc/pin clears the pin (no separate
     endpoint).  Registered exactly once (cross-page init runs once per page). */
  function wireUnpin() {
    document.addEventListener('click', function (e) {
      var btn = e.target && e.target.closest ? e.target.closest('[data-cc="unpin"]') : null;
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      _postPin('', '', '', '', {
        rbPinned: el('rb-pinned'),  /* null off-dashboard — _postPin guards it */
        okToast: 'Unpinned',
        failToast: 'Unpin failed — check connection',
      });
    });

    /* #21: per-row Stop on the Running Reports monitor. Delegated (one listener)
       so it covers poller-refreshed rows without rebinding. Registered in the
       CAPTURE phase (the `true` 3rd arg) so it pre-empts the row's inline
       navigate-onclick: a canvas row's onclick is a BUBBLE-phase handler, so a
       document-level BUBBLE listener would fire too late (the row already
       navigated). Capturing at document runs first; stopPropagation then
       prevents the row navigation entirely. The backend POST
       /api/run/{id}/cancel only sets cancel_event; the run finishes at the next
       cancellable chunk and the poller settles the row to "cancelled" — we give
       immediate feedback (disable + cancelling title) meanwhile, and set the
       expectation that the current step finishes first. */
    document.addEventListener('click', _onRunStopClick, true);
  }

  function _onRunStopClick(e) {
    var btn = e.target && e.target.closest ? e.target.closest('.run-stop') : null;
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();
    if (btn.disabled) return;
    var rid = btn.getAttribute('data-run-id');
    if (!rid) return;
    btn.disabled = true;
    btn.title = 'Cancelling…';
    fetch('/api/run/' + encodeURIComponent(rid) + '/cancel', {
      method: 'POST',
      headers: { 'X-FS-Session': _nonce() },
    })
      .then(function (r) {
        if (!r.ok) {
          btn.disabled = false;
          btn.title = 'Stop run';
          showToast("Couldn't stop the run");
        } else {
          showToast('Cancelling — the current step must finish first…');
        }
      })
      .catch(function () {
        btn.disabled = false;
        btn.title = 'Stop run';
        showToast("Couldn't stop the run — check connection");
      });
  }

  /* Shared pin/unpin POST + DOM sync.  Posting empty pinned_* clears the pin.
     Rebuilds the run-bar readout (with an × unpin control when pinned), updates
     the sidebar pinned display + its × visibility, and keeps window.__CC.pinned
     fresh so the keyboard shortcut R is never stale.

     Folder-targeting (§4): a folder-only pin (folder set, no project) still
     renders a scope readout (Lucide folder icon + folder name) and keeps the
     unpin control visible. ``folder`` carries the folder ID; the run bar can't
     know the folder's display name client-side, so the readout falls back to the
     ID until the next render resolves the name (server-side, shell_context). */
  function _postPin(report, project, version, folder, opts) {
    opts = opts || {};
    var fd = new FormData();
    fd.append('pinned_report',  report);
    fd.append('pinned_project', project);
    fd.append('pinned_version', version);
    fd.append('pinned_folder',  folder || '');
    fetch('/api/cc/pin', {
      method: 'POST',
      headers: { 'X-FS-Session': _nonce() },
      body: fd,
    })
    .then(function (r) {
      /* Gate on HTTP status: a 403 (CSRF) or 5xx must NOT clear the pin or
         toast success.  Reject so the .catch path shows the failure toast and
         leaves the UI + window.__CC.pinned untouched. */
      if (!r.ok) {
        return Promise.reject(new Error('pin request failed: ' + r.status));
      }
      return r.json();
    })
    .then(function (body) {
      /* Anything pinned? report, project, OR folder all count. */
      var anyPinned = !!(body.pinned_report || body.pinned_project || body.pinned_folder);
      var rbPinned = opts.rbPinned || el('rb-pinned');
      if (rbPinned) {
        if (anyPinned) {
          /* Build readout without innerHTML interpolation of dynamic values */
          rbPinned.innerHTML = '<i data-lucide="pin"></i> Pinned: <b class="pin-report"></b><span class="pin-scope"></span>'
            + '<button type="button" class="rb-unpin" data-cc="unpin" title="Unpin" aria-label="Unpin"><i data-lucide="x"></i></button>';
          var pinReportEl = rbPinned.querySelector('.pin-report');
          var pinScopeEl  = rbPinned.querySelector('.pin-scope');
          if (pinReportEl) pinReportEl.textContent = body.pinned_report || '—';
          if (pinScopeEl && body.pinned_project) {
            pinScopeEl.textContent = ' · ' + body.pinned_project + (body.pinned_version ? ' @ ' + body.pinned_version : '');
          } else if (pinScopeEl && body.pinned_folder) {
            /* Folder-only pin: show the folder target. No display name is known
               client-side (pinned_folder is the ID), so fall back to the ID; the
               next shell render resolves + renders the name (shell_context §4). */
            var fLabel = (window.__CC && window.__CC.pinned && window.__CC.pinned.folderName) || body.pinned_folder;
            pinScopeEl.innerHTML = ' · <i data-lucide="folder"></i> ';
            pinScopeEl.appendChild(document.createTextNode(fLabel));
          } else if (pinScopeEl) {
            pinScopeEl.textContent = '';
          }
          if (window.lucide) lucide.createIcons();
        } else {
          rbPinned.innerHTML = '';
        }
      }
      /* Keep window.__CC.pinned in sync so keyboard shortcut R is not stale.
         Preserve folderName (resolved server-side at render) when the folder ID
         is unchanged so the readout label survives a re-pin. */
      var syncCC = window.__CC || {};
      var prevPinned = syncCC.pinned || {};
      var keepFolderName = (prevPinned.folder && prevPinned.folder === body.pinned_folder)
        ? (prevPinned.folderName || '') : '';
      syncCC.pinned = {
        report:     body.pinned_report  || '',
        project:    body.pinned_project || '',
        version:    body.pinned_version || '',
        folder:     body.pinned_folder  || '',
        folderName: keepFolderName
      };
      window.__CC = syncCC;
      /* Update sidebar "Pinned scope" live without a reload. A folder-only pin
         shows the folder readout (icon + name|id) and hides the project/version. */
      var sideFolder  = qs('[data-cc="pin-folder"]');
      var sideProject = qs('[data-cc="pin-project"]');
      var sideVersion = qs('[data-cc="pin-version"]');
      if (sideFolder) {
        if (body.pinned_folder) {
          var sLabel = keepFolderName || body.pinned_folder;
          sideFolder.innerHTML = '<i data-lucide="folder"></i> ';
          sideFolder.appendChild(document.createTextNode(sLabel));
          sideFolder.hidden = false;
        } else {
          sideFolder.hidden = true;
        }
      }
      if (sideProject) {
        if (body.pinned_project) {
          sideProject.textContent = body.pinned_project;
          sideProject.hidden = false;
        } else if (body.pinned_folder) {
          /* Folder-only: suppress the "—" project placeholder. */
          sideProject.textContent = '';
          sideProject.hidden = true;
        } else {
          sideProject.textContent = '—';
          sideProject.hidden = false;
        }
      }
      if (sideVersion) {
        if (body.pinned_folder && !body.pinned_project) {
          sideVersion.hidden = true;
        } else {
          sideVersion.textContent = body.pinned_version || 'latest';
          sideVersion.hidden = false;
        }
      }
      /* Show/hide the sidebar × based on whether anything is pinned now */
      var sideUnpin = qs('.sidebar [data-cc="unpin"]');
      if (sideUnpin) sideUnpin.hidden = !anyPinned;
      if (window.lucide) lucide.createIcons();
      if (opts.okToast) showToast(opts.okToast);
    })
    .catch(function () { if (opts.failToast) showToast(opts.failToast); });
  }

  /* ── Page-level button wiring ────────────────────────────────── */
  function wirePageButtons() {
    var ccRefresh = el('cc-refresh');
    var ccNew = el('cc-new');

    if (ccRefresh) {
      ccRefresh.addEventListener('click', function () {
        fetchOverview();
        /* One forced queue fetch into the container — bypasses the memo for
         * live data and avoids the double-fetch/stale-overwrite race of
         * triggering 'load' (cached) and clicking #q-refresh (forced) at once.
         * Works even when the panel is in an error/empty state (no button). */
        var qContainer = el('scan-queue-container');
        if (qContainer && window.htmx) {
          htmx.ajax('GET', '/api/queue?force=1', {
            target: '#scan-queue-container',
            swap: 'innerHTML'
          });
        }
        /* Also refresh Running Reports panel */
        if (window.__refreshRunning) window.__refreshRunning();
      });
    }

    if (ccNew) {
      ccNew.addEventListener('click', function () {
        var launcher = el('launcher');
        if (launcher) launcher.scrollIntoView({ behavior: 'smooth' });
      });
    }
  }

  /* ── Launcher: filter + sort chips ───────────────────────────── */
  function wireLauncher() {
    var grid = el('wf-grid');
    if (!grid) return;
    var cards = grid.querySelectorAll('.wf-card');

    /* Filter chips */
    var filterChips = qsa('.chip[data-filter]');
    filterChips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        filterChips.forEach(function (c) { c.classList.remove('on'); });
        chip.classList.add('on');
        var f = chip.getAttribute('data-filter');
        cards.forEach(function (card) {
          var cat = card.getAttribute('data-cat') || '';
          card.style.display = (f === 'all' || cat === f) ? '' : 'none';
        });
      });
    });

    /* Sort chips */
    var sortChips = qsa('#wf-sort .sc');
    sortChips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        sortChips.forEach(function (c) { c.classList.remove('on'); });
        chip.classList.add('on');
        var sortBy = chip.getAttribute('data-sort');
        var cardArr = Array.prototype.slice.call(cards);
        if (sortBy === 'name') {
          cardArr.sort(function (a, b) {
            var na = (a.querySelector('h3') || {}).textContent || '';
            var nb = (b.querySelector('h3') || {}).textContent || '';
            return na.localeCompare(nb);
          });
        }
        /* For 'recent' we restore the original DOM (server) order.  There is
           no real recency signal — the server renders the cards sorted by
           (nav_category, name), so this simply restores that category-grouped
           + alphabetical default order. */
        cardArr.forEach(function (card) { grid.appendChild(card); });
      });
    });

    /* Card interactions: gear → flip-to-configure; body → the §4 ladder.
       Note: the Comparison card is now a plain <a> link (no data-comparison),
       so no special routing is needed here. */
    cards.forEach(function (card) {
      card.addEventListener('click', function (e) {
        var recipe = card.getAttribute('data-recipe');
        if (!recipe) return;

        /* ── Comparison (saved meta-compare) → always the prerun modal. ──
           Axis compounds carry run-only inputs — finding-types + Left/Right
           scope override (Decision 11) — that ONLY the prerun modal collects.
           The per-card config back-face is CVE-oriented (its needs-setup toast
           literally says "Add a CVE…") and never renders those fields, so route
           BOTH the gear and the card body straight to __openConfigure, ahead of
           the gear/needs-setup ladder below.  Clicks inside an (unused) back
           face are ignored defensively. */
        if (card.getAttribute('data-kind') === 'comparison') {
          if (e.target && e.target.closest && e.target.closest('.wf-back')) return;
          e.stopPropagation();
          if (window.__openConfigure) {
            window.__openConfigure(recipe, _runBarScope());
          } else {
            location.href = '/?configure=' + encodeURIComponent(recipe);
          }
          return;
        }

        /* ── Gear click → flip to configure (lazy-load the back). ──
           Use closest('.wf-gear') because the click target may be the gear's
           inner Lucide <svg>, not the <button> itself; stopPropagation so the
           gear never falls through to the card-body run. */
        var gear = e.target && e.target.closest ? e.target.closest('.wf-gear') : null;
        if (gear) {
          e.stopPropagation();
          _flipCardToConfigure(card, recipe);
          return;
        }

        /* Ignore clicks on anything inside the back face (tabs, inputs,
           Save/Reset buttons) — those are wired separately and must not
           re-trigger a run. */
        if (e.target && e.target.closest && e.target.closest('.wf-back')) return;

        /* ── Card-body click ladder (§4 rule 2). ── */
        /* 1. needs-setup → auto-flip to configure (+ one-time toast). */
        if (card.getAttribute('data-needs-setup') === '1') {
          _flipCardToConfigure(card, recipe);
          if (!card.__nsToast) {
            card.__nsToast = true;
            showToast('Add a CVE to run this report.');
          }
          return;
        }
        /* 2. scope-req unmet by the run bar → toast the hint, don't fire.
           On-card path: read the card's own data-scope-req (load-bearing per
           spec §4) and pass it to the gate, so the card is self-contained;
           the OFF-card __openFR path keeps using the window.__CC.scopeReq map
           (§10) since it has no element. */
        var hint = window.__scopeGateHint
          ? window.__scopeGateHint(recipe, _runBarScope(), card.getAttribute('data-scope-req') || '')
          : '';
        if (hint) { showToast(hint); return; }
        /* 3. else → run (existing run path). */
        /* Double-launch guard: rapid card-body clicks fired duplicate runs.
           Ignore further run-clicks on THIS card within the cooldown, and add a
           brief "launching" class for immediate feedback.  Scoped to the
           card-body path only — gear/flip, the comparison card, and the run-bar
           Run button are untouched. */
        var now = Date.now();
        if (card.__lastLaunch && (now - card.__lastLaunch) < 2000) return;
        card.__lastLaunch = now;
        card.classList.add('launching');
        setTimeout(function () { card.classList.remove('launching'); }, 2000);
        /* Pass the LIVE run-bar scope (project/version/folder) into __openFR,
           consistent with Save & Run. The scope gate above already reads
           _runBarScope(); relying on the stored SCOPE staying in sync here was a
           fragile split (a folder pick's deferred onChange could leave SCOPE
           stale at click time). project-wins is applied inside __openFR when both
           project and folder are set. */
        if (window.__openFR) {
          var cbScope = _runBarScope();
          window.__openFR(recipe, {
            project: cbScope.project,
            version: cbScope.version,
            folder: cbScope.folder,
          });
        }
      });
    });
  }

  /* ── Current run-bar scope (for the client-side scope gate) ───── */
  function _runBarScope() {
    var rbF = el('rb-folder');
    var rbP = el('rb-project');
    var rbV = el('rb-version');
    return {
      project: rbP ? rbP.value : '',
      version: rbV ? rbV.value : '',
      folder: rbF ? rbF.value : '',
    };
  }

  /* ════════════════════════════════════════════════════════════════
   * Per-report card config — gear / flip / tabs / save (design §10).
   * Lazy-loads the GET /api/cc/card-config fragment into the card's
   * .wf-back, wires its tabs / version pickers / finding-types rebuild /
   * Save / Save&Run / Reset, manages back-face a11y (inert + focus), and
   * keeps window.__CC.needsSetup + the card's data-needs-setup in sync.
   * ════════════════════════════════════════════════════════════════ */

  /* CSRF nonce from the fs-csrf meta (window.NONCE is bootstrapped from it). */
  function _nonce() {
    if (window.NONCE) return window.NONCE;
    var m = qs('meta[name="fs-csrf"]');
    return m ? m.content : '';
  }

  /* Make the populated back face inert + a11y-hidden when not flipped. */
  function _setBackInert(back, inert) {
    if (!back) return;
    if (inert) {
      back.setAttribute('aria-hidden', 'true');
      try { back.inert = true; } catch (e) { /* older engines */ }
      back.setAttribute('inert', '');
    } else {
      back.removeAttribute('aria-hidden');
      try { back.inert = false; } catch (e) { /* ignore */ }
      back.removeAttribute('inert');
    }
  }

  /* Switch the active tab on a card back: toggle BOTH the .wf-tab
     aria-selected state AND the matching .wf-cfg-panel .active / [hidden]. */
  function _wireCardTabs(back) {
    var tabs = back.querySelectorAll('.wf-tab');
    var panels = back.querySelectorAll('.wf-cfg-panel');
    function activate(name) {
      tabs.forEach(function (t) {
        t.setAttribute('aria-selected', t.getAttribute('data-tab') === name ? 'true' : 'false');
      });
      panels.forEach(function (p) {
        var on = p.getAttribute('data-tabpanel') === name;
        p.classList.toggle('active', on);
        if (on) p.removeAttribute('hidden'); else p.setAttribute('hidden', '');
      });
    }
    tabs.forEach(function (t) {
      t.addEventListener('click', function () { activate(t.getAttribute('data-tab')); });
    });
    /* On render, activate the FIRST present tab and sync its panel. The Report
       tab is gated away entirely for recipes with no report-specific options
       (report-config-card-gating §5d), and the Advanced panel always starts
       hidden — so never assume Report exists; activate whichever tab button is
       first in the DOM so the active tab never points at a hidden/empty panel. */
    if (tabs.length) {
      activate(tabs[0].getAttribute('data-tab'));
    }
  }

  /* Rebuild the hidden finding_types field from the ft_cb checkbox group on
     change (mirrors the modal's _wireCfgSubmit + settings-page.js). */
  function _wireCardFindingTypes(back) {
    var hidden = back.querySelector('#cardcfg-ft');
    if (!hidden) return;
    var boxes = back.querySelectorAll('input[name="ft_cb"]');
    function sync() {
      var vals = [];
      back.querySelectorAll('input[name="ft_cb"]:checked').forEach(function (cb) {
        vals.push(cb.value);
      });
      /* Allow clearing all types: empty string is valid (server inherits). */
      hidden.value = vals.join(',');
    }
    boxes.forEach(function (cb) { cb.addEventListener('change', sync); });
  }

  /* Bind the baseline/current version pickers using the shared
     initVersionPicker helper (defined in _scope_dropdowns.html, included on
     the dashboard page). Mirrors how _openCfgModal binds initScopeDropdowns
     post-load — without this the picker selects are inert markup. */
  /* Comparison-mode toggle (Version Comparison): "All versions" ON makes the
     baseline/current pair INERT (dimmed + non-interactive; B11 #19a — was
     hidden, which made the pickers undiscoverable) and CLEARS it (→ empty pair →
     all versions); OFF activates it (specific-pair mode). Pure UX over the
     engine's empty-vs-set-pair semantics — no persisted field. apply() runs once
     on bind to set the initial inert state matching the server-rendered toggle;
     it can't wipe a saved pair because the toggle is checked ONLY when no saved
     pair exists (template `{% if not _vc_pair %}`). Shared by the card back and
     the configure modal. */
  function _wireVcModeToggle(root, toggleId, pairSelector, inputIds) {
    var tog = root.querySelector('#' + toggleId);
    var pair = root.querySelector(pairSelector);
    if (!tog || !pair) return;
    /* B11 #19a discoverability: keep the baseline/current pickers VISIBLE but
       INERT when "All versions" is on (this previously hid the block entirely,
       so it read as "no version picker"). The pair stays in the layout, dimmed
       (.vc-pair-inert) + non-interactive (the `inert` attr — no tab stops, no
       clicks), so users can SEE the controls exist and learn that turning the
       toggle off activates them. Switching to all-versions still clears the
       pair → empty pair → the engine's all-versions changelog. */
    function apply() {
      var allVersions = tog.checked;
      pair.classList.toggle('vc-pair-inert', allVersions);
      pair.inert = allVersions;
      if (allVersions) {
        inputIds.forEach(function (id) {
          var inp = root.querySelector('#' + id);
          if (inp) {
            inp.value = '';
            inp.dispatchEvent(new Event('input', { bubbles: true }));
          }
        });
      }
    }
    tog.addEventListener('change', apply);
    apply(); /* set the initial inert state (was carried by the server `hidden`) */
  }

  function _wireCardVersionPickers(back) {
    if (typeof initVersionPicker !== 'function') return;
    if (!back.querySelector('#cardcfg-bv')) return; /* not a version recipe */
    /* Pass the card's OWN back as `root` so initVersionPicker resolves the
       cardcfg-* ids within THIS card's subtree (Element.querySelector scopes to
       descendants).  The card-back fragment uses fixed global ids; scoping the
       lookups here makes a second back coexisting in the DOM (during a flip
       transition, or a stale deferred unload) functionally harmless — the
       picker always binds this card's selects, never another card's. */
    /* Default both pickers to the pinned project (live read) so a version
       recipe opens with it pre-selected; maybePreselect no-ops when the field
       already carries a saved version ID. */
    var pinnedProj = (window.__CC && window.__CC.pinned && window.__CC.pinned.project) || '';
    initVersionPicker({
      root: back,
      projectSelId: 'cardcfg-bv-project',
      versionSelId: 'cardcfg-bv-version',
      inputId: 'cardcfg-bv',
      presetProject: pinnedProj,
    });
    initVersionPicker({
      root: back,
      projectSelId: 'cardcfg-cv-project',
      versionSelId: 'cardcfg-cv-version',
      inputId: 'cardcfg-cv',
      presetProject: pinnedProj,
    });
    _wireVcModeToggle(back, 'cardcfg-vc-all', '.cardcfg-vc-pair', [
      'cardcfg-bv',
      'cardcfg-cv',
    ]);
  }

  /* Live deployment-notes char counter (matches the modal/settings page). */
  function _wireCardCharCounter(back) {
    var ta = back.querySelector('#cardcfg-deploy-notes');
    var count = back.querySelector('#cardcfg-deploy-notes-count');
    if (!ta || !count) return;
    ta.addEventListener('input', function () {
      count.textContent = String(ta.value.length);
    });
  }

  /* Shared card-config serialiser used by BOTH the card-back Save and the
     modal "Save as default" paths so the same user action persists the same
     /api/cc/card-config body (spec §6).  Critically it INCLUDES empty fields
     (the bare `params.append(fe.name, fe.value)` else-branch) so clearing a
     field — e.g. emptying "Period" — sends `period=`, which the backend
     `_build_override` treats as "inherit" and clears the stored override.  A
     serialiser that dropped empties (the modal's old `else if (fe.value)`)
     would silently leave the old override in place.  finding_types is rebuilt
     from the checked ft_cb boxes; `ftHiddenId` is the hidden field's id on the
     given form (`cardcfg-ft` for the card, `pre-ft` for the modal).
     The backend allowlist (_STR_KEYS/_INT_KEYS/_BOOL_KEYS) drops any field
     name not in the card-config set, so extra form fields are harmless. */
  function _serializeCardCfgForm(form, ftHiddenId) {
    var params = new URLSearchParams();
    if (!form) return params;
    var els = form.elements;
    for (var i = 0; i < els.length; i++) {
      var fe = els[i];
      if (!fe.name) continue;
      if (fe.type === 'checkbox') {
        if (fe.name === 'ft_cb') continue; /* handled via hidden finding_types */
        if (fe.name === 'st_cb') continue; /* handled via hidden scan_types */
        if (fe.name === 'ss_cb') continue; /* handled via hidden scan_statuses */
        if (fe.name === 'as_cb') continue; /* SP2: handled via hidden autotriage_status */
        params.append(fe.name, fe.checked ? 'true' : 'false');
      } else if (fe.id === ftHiddenId) {
        var vals = [];
        form.querySelectorAll('input[name="ft_cb"]:checked').forEach(function (cb) {
          vals.push(cb.value);
        });
        params.append('finding_types', vals.join(','));
      } else if (fe.id === 'cardcfg-scan-types') {
        /* Rebuild scan_types from checked st_cb boxes at serialize time,
           matching the finding_types rebuild above (symmetry + removes any
           change-event timing dependency on _wireCardScanCheckboxes). */
        var stVals = [];
        form.querySelectorAll('input[name="st_cb"]:checked').forEach(function (cb) {
          stVals.push(cb.value);
        });
        params.append('scan_types', stVals.join(','));
      } else if (fe.id === 'cardcfg-scan-statuses') {
        /* Rebuild scan_statuses from checked ss_cb boxes at serialize time. */
        var ssVals = [];
        form.querySelectorAll('input[name="ss_cb"]:checked').forEach(function (cb) {
          ssVals.push(cb.value);
        });
        params.append('scan_statuses', ssVals.join(','));
      } else if (fe.id === 'cardcfg-autotriage-status') {
        /* SP2: rebuild autotriage_status from checked as_cb boxes at serialize
           time (mirrors scan_types/scan_statuses). */
        var asVals = [];
        form.querySelectorAll('input[name="as_cb"]:checked').forEach(function (cb) {
          asVals.push(cb.value);
        });
        params.append('autotriage_status', asVals.join(','));
      } else {
        params.append(fe.name, fe.value);
      }
    }
    return params;
  }

  /* Serialise the card back form into URLSearchParams (include-empties),
     rebuilding finding_types from the checked ft_cb boxes. */
  function _serializeCardForm(back) {
    return _serializeCardCfgForm(back.querySelector('.cardcfg-form'), 'cardcfg-ft');
  }

  /* Show / clear the inline error banner on a card back. */
  function _cardError(back, msg) {
    var box = back.querySelector('.cardcfg-error');
    if (!box) return;
    if (msg) { box.textContent = msg; box.style.display = ''; }
    else { box.textContent = ''; box.style.display = 'none'; }
  }

  /* Reflect a recomputed needs_setup across the card attr + the off-card
     client Set so every launch path honors it with no reload (§10). */
  function _applyNeedsSetup(card, recipe, needsSetup) {
    card.setAttribute('data-needs-setup', needsSetup ? '1' : '0');
    var ns = window.__CC && window.__CC.needsSetup;
    if (ns && typeof ns.add === 'function') {
      if (needsSetup) ns.add(recipe.toLowerCase());
      else ns.delete(recipe.toLowerCase());
    }
  }

  /* POST the card back to /api/cc/card-config. Returns a Promise resolving to
     { ok, body } — on a 400 (missing required), ok is false and body carries
     the error so the caller can surface it inline and block any run. */
  function _saveCardConfig(back) {
    var params = _serializeCardForm(back);
    return fetch('/api/cc/card-config', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-FS-Session': _nonce(),
      },
      body: params.toString(),
    }).then(function (resp) {
      return resp.json().then(function (body) {
        return { ok: resp.ok, body: body || {} };
      }, function () {
        return { ok: resp.ok, body: {} };
      });
    });
  }

  /* Collapse the currently-open card's back (if any) before another card opens
     — single-active-back UX (one flipped card + one Esc handler). This routes
     the previous card through _hideCardBack (flip back, drop Esc, defer-unload
     its back). It is NOT required for correctness: scoped card-back lookups
     make a briefly-coexisting back with duplicate ids harmless. No-op when
     there is no open card or the open card IS the one being opened. */
  function _collapseOtherOpenBack(keepCard) {
    if (!_openCard || _openCard === keepCard) return;
    var prev = _openCard;
    var prevBack = prev.querySelector('.wf-back[data-cardback]');
    _hideCardBack(prev, prevBack);       // remove .flipped, drop Esc handler, re-inert, unload back, clear _openCard
  }

  /* Flip a card to a lazy-loaded back: fetch + wire the fragment on first open;
     a re-flip of an already-loaded card just toggles .flipped.  Before opening,
     collapse + clear any OTHER open card's back so only one fixed-id fragment is
     ever in the document (Fix 2/4).

     Generalized from the original per-recipe `_flipCardToConfigure` (PR #117)
     so the synthetic Comparison card can reuse the SAME flip + single-active-
     back + in-flight-guard + inert/focus machinery, differing only in the
     fetch URL and the back-wiring function:
       fetchUrl  — the GET endpoint returning the fragment HTML.
       wireFn(card, back) — wires the freshly-injected back (tabs / pickers /
                            Save / Reset / close).  Called post-inject, pre-flip.
       errLabel  — used in the load-failure toast. */
  function _lazyFlipBack(card, fetchUrl, wireFn, errLabel) {
    var back = card.querySelector('.wf-back[data-cardback]');
    if (!back) return;

    /* Enforce single-active-back: collapse + clear any other open card first. */
    _collapseOtherOpenBack(card);

    /* Already loaded: a re-flip is just a CSS toggle — no fetch, no guard. */
    if (back.getAttribute('data-loaded') === '1') {
      _showCardBack(card, back);
      return;
    }

    /* In-flight guard: data-loaded is still unset until the first GET
       resolves, so a rapid second gear click would otherwise fire a second
       GET whose .then would re-run wireFn (double-binding the back's
       button/Esc listeners and leaking the first card.__escHandler).  Bail
       while a load is pending; clear the flag in BOTH .then and .catch. */
    if (card.__cfgLoading) return;
    card.__cfgLoading = true;

    fetch(fetchUrl, {
      headers: { 'X-FS-Session': _nonce() },
    })
      .then(function (resp) {
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        return resp.text();
      })
      .then(function (html) {
        card.__cfgLoading = false;
        back.innerHTML = html;
        back.setAttribute('data-loaded', '1');
        /* Default the freshly-populated back to inert until we flip + focus
           into it (so its inputs aren't tabbable while the front shows). */
        _setBackInert(back, true);
        wireFn(card, back);
        if (window.lucide) lucide.createIcons();
        _showCardBack(card, back);
      })
      .catch(function () {
        card.__cfgLoading = false;
        showToast('Could not load config for ' + errLabel);
      });
  }

  /* Per-recipe card config: lazy-flip to the /api/cc/card-config back.  Thin
     wrapper over _lazyFlipBack so the #117 behavior is unchanged. */
  function _flipCardToConfigure(card, recipe) {
    _lazyFlipBack(
      card,
      '/api/cc/card-config?recipe=' + encodeURIComponent(recipe),
      function (c, back) { _wireCardBack(c, back, recipe); },
      recipe
    );
  }

  /* Rebuild the hidden scan_types / scan_statuses fields from the st_cb / ss_cb
     checkbox groups on change (mirrors _wireCardFindingTypes). Always-rendered on
     the Advanced tab — guard for element absence. */
  function _wireCardScanCheckboxes(back) {
    var stHidden = back.querySelector('#cardcfg-scan-types');
    var ssHidden = back.querySelector('#cardcfg-scan-statuses');

    if (stHidden) {
      var stBoxes = back.querySelectorAll('input[name="st_cb"]');
      function syncSt() {
        var vals = [];
        back.querySelectorAll('input[name="st_cb"]:checked').forEach(function (cb) {
          vals.push(cb.value);
        });
        stHidden.value = vals.join(',');
      }
      stBoxes.forEach(function (cb) { cb.addEventListener('change', syncSt); });
    }

    if (ssHidden) {
      var ssBoxes = back.querySelectorAll('input[name="ss_cb"]');
      function syncSs() {
        var vals = [];
        back.querySelectorAll('input[name="ss_cb"]:checked').forEach(function (cb) {
          vals.push(cb.value);
        });
        ssHidden.value = vals.join(',');
      }
      ssBoxes.forEach(function (cb) { cb.addEventListener('change', syncSs); });
    }
  }

  /* Enforce period↔custom-date-range mutual exclusivity client-side so the
     server never 400s: when BOTH #cardcfg-start and #cardcfg-end have values,
     clear #cardcfg-period; when #cardcfg-period has a value, clear start/end.
     Guard for element absence (not every recipe shows the date range). */
  function _wireCardDateMode(back) {
    var periodInp = back.querySelector('#cardcfg-period');
    var startInp  = back.querySelector('#cardcfg-start');
    var endInp    = back.querySelector('#cardcfg-end');
    if (!periodInp || !startInp || !endInp) return;

    function onRangeChange() {
      if (startInp.value && endInp.value) {
        periodInp.value = '';
      }
    }
    function onPeriodChange() {
      if (periodInp.value) {
        startInp.value = '';
        endInp.value = '';
      }
    }

    startInp.addEventListener('input', onRangeChange);
    startInp.addEventListener('change', onRangeChange);
    endInp.addEventListener('input', onRangeChange);
    endInp.addEventListener('change', onRangeChange);
    periodInp.addEventListener('input', onPeriodChange);
    periodInp.addEventListener('change', onPeriodChange);
  }

  /* Wire a freshly-injected card back: tabs, version pickers, finding-types,
     char counter, scan checkboxes, date-mode exclusivity, close, and Save /
     Save&Run / Reset. */
  function _wireCardBack(card, back, recipe) {
    _wireCardTabs(back);
    _wireCardFindingTypes(back);
    _wireCardVersionPickers(back);
    _wireCardCharCounter(back);
    _wireCardScanCheckboxes(back);
    if (window.__fsWireUploads) window.__fsWireUploads(back); /* SP3 */
    _wireCardDateMode(back);

    /* Close / flip-back */
    var closeBtn = back.querySelector('.cardcfg-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', function () { _hideCardBack(card, back); });
    }

    /* Save */
    var saveBtn = back.querySelector('.cardcfg-save');
    if (saveBtn) {
      saveBtn.addEventListener('click', function () {
        _doCardSave(card, back, recipe, false, saveBtn);
      });
    }
    /* Save & Run */
    var saveRunBtn = back.querySelector('.cardcfg-save-run');
    if (saveRunBtn) {
      saveRunBtn.addEventListener('click', function () {
        _doCardSave(card, back, recipe, true, saveRunBtn);
      });
    }
    /* Reset to Settings defaults */
    var resetBtn = back.querySelector('.cardcfg-reset');
    if (resetBtn) {
      resetBtn.addEventListener('click', function () {
        _doCardReset(card, back, recipe, resetBtn);
      });
    }
  }

  /* Save (and optionally run). A failed validation (400) blocks the run and
     surfaces the inline error, staying flipped. For Save & Run the config is
     PERSISTED first, then the scope gate (§8/§13) is applied to the *launch
     only*: a scope-unmet requires_project* recipe persists but does not launch
     (toast), matching the body-click. */
  function _doCardSave(card, back, recipe, withRun, btn) {
    _cardError(back, '');

    /* Disable the clicked button in-flight so a double-click can't fire two
       /api/cc/card-config POSTs (+ two __openFR launches → duplicate runs);
       re-enabled in every terminal branch below, including before any
       flip-back so it's sane the next time the back is shown. */
    if (btn) btn.disabled = true;

    _saveCardConfig(back).then(function (res) {
      if (!res.ok) {
        /* 400 (missing required) — stay flipped, show inline error, no run. */
        _cardError(back, (res.body && res.body.error) || 'Could not save — check required fields.');
        if (btn) btn.disabled = false;
        return;
      }
      _applyNeedsSetup(card, recipe, !!(res.body && res.body.needs_setup));

      if (withRun) {
        /* Scope gate applies to the launch only — the save already persisted.
           On-card path: pass the card's own data-scope-req (§4). */
        var hint = window.__scopeGateHint
          ? window.__scopeGateHint(recipe, _runBarScope(), card.getAttribute('data-scope-req') || '')
          : '';
        if (hint) {
          /* Persisted, but the run can't proceed — toast and stay flipped so
             the user can pick a project in the run bar. */
          showToast(hint);
          if (btn) btn.disabled = false;
          return;
        }
        showToast('Saved — running ' + recipe);
        var sc = _runBarScope();
        /* SP2: carry the card-back dry-run toggle (transient, not persisted by
           the save above) so Save & Run can preview instead of writing. */
        var dryBox = back.querySelector('#cardcfg-dry-run');
        if (window.__openFR) {
          window.__openFR(recipe, {
            project: sc.project,
            version: sc.version,
            /* Carry the live folder so a folder-only Save & Run targets the
               folder (Finding 6a). _runBarScope() already returns the live
               #rb-folder value; project wins in __openFR when both are set. */
            folder: sc.folder,
            dry_run: !!(dryBox && dryBox.checked),
          });
        }
      } else {
        showToast('Saved: ' + recipe);
      }
      /* Flipping back to the front — re-enable so the button is sane the next
         time this back face is shown (it is reused, not re-created). */
      if (btn) btn.disabled = false;
      _hideCardBack(card, back);
    }).catch(function () {
      _cardError(back, 'Save failed — check connection.');
      if (btn) btn.disabled = false;
    });
  }

  /* Reset: clear the recipe's overrides, refetch the back so fields show the
     inherited globals, update live state, toast. */
  function _doCardReset(card, back, recipe, btn) {
    _cardError(back, '');

    /* Disable the Reset button in-flight so a double-click can't fire two
       reset POSTs racing the re-fetch.  The success path replaces the whole
       back via innerHTML (re-wiring a fresh Reset button), so this exact
       button only needs re-enabling on the error / catch branches that keep
       the current DOM. */
    if (btn) btn.disabled = true;

    var params = new URLSearchParams();
    params.set('recipe', recipe);
    fetch('/api/cc/card-config/reset', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-FS-Session': _nonce(),
      },
      body: params.toString(),
    })
      .then(function (resp) {
        return resp.json().then(function (body) {
          return { ok: resp.ok, body: body || {} };
        }, function () { return { ok: resp.ok, body: {} }; });
      })
      .then(function (res) {
        if (!res.ok) { _cardError(back, 'Reset failed.'); if (btn) btn.disabled = false; return; }
        _applyNeedsSetup(card, recipe, !!(res.body && res.body.needs_setup));
        /* Re-fetch the back so every field re-renders with inherited globals. */
        return fetch('/api/cc/card-config?recipe=' + encodeURIComponent(recipe), {
          headers: { 'X-FS-Session': _nonce() },
        })
          .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })
          .then(function (html) {
            back.innerHTML = html;
            back.setAttribute('data-loaded', '1');
            /* Card stays flipped through a Reset; the back must remain
               non-inert + keep focus, so clear inert before re-wiring.  The
               old Reset button is gone with the innerHTML swap; _wireCardBack
               binds a fresh, enabled one. */
            _setBackInert(back, false);
            _wireCardBack(card, back, recipe);
            if (window.lucide) lucide.createIcons();
            _focusInBack(back);
            showToast('Reset to Settings defaults');
          });
      })
      .catch(function () { _cardError(back, 'Reset failed — check connection.'); if (btn) btn.disabled = false; });
  }

  /* Move focus into the back (first focusable / the close button). */
  function _focusInBack(back) {
    var target = back.querySelector('.cardcfg-close') ||
      back.querySelector('button, [href], input, select, textarea');
    if (target && typeof target.focus === 'function') {
      try { target.focus(); } catch (e) { /* ignore */ }
    }
  }

  /* Flip the card to its back: clear inert, add .flipped, remember the
     previously-focused element, move focus into the back, register Esc. */
  function _showCardBack(card, back) {
    var current = document.activeElement;
    card.__restoreFocus = (current && card.contains(current)) ? current : (card.querySelector('.wf-gear') || null);
    _setBackInert(back, false);
    card.classList.add('flipped');
    _openCard = card;   /* single-active-back: this is now the open card */
    _focusInBack(back);
    card.__escHandler = function (e) {
      if (e.key === 'Escape') _hideCardBack(card, back);
    };
    document.addEventListener('keydown', card.__escHandler);
  }

  /* Unload a card's back: drop its fragment (innerHTML='') and reset
     data-loaded. DOM hygiene only — keeping at most one back's markup in the
     document. Correctness does NOT depend on this firing before another back
     wires: all card-back lookups are scoped to their own `.wf-back` subtree
     (see the _openCard note), so a stale or coexisting back with duplicate ids
     is harmless. Re-flipping a previously-configured card re-fetches its
     fragment — the same trade-off the round-1 collapse path already accepted. */
  function _unloadBack(back) {
    if (!back) return;
    back.innerHTML = '';
    back.removeAttribute('data-loaded');
  }

  /* Flip back to the front: remove .flipped, re-inert the back, restore the
     front focus, drop the Esc handler, then UNLOAD the back (DOM hygiene — its
     ids leave the document). Every close path (Esc, close button, flip-away via
     _collapseOtherOpenBack, save-then-close) funnels through here. The unload
     timing below is purely cosmetic (avoid blanking the still-visible back
     mid-flip); correctness rests on scoped card-back lookups, not on when this
     fires (see the _openCard note).

     The back is backface-visibility:hidden and rotates away on flip-back, so
     it is not visible past 90° of the .5s rotation — but clearing innerHTML
     synchronously would blank it during the first, still-visible half of the
     spin. So we defer the unload to the flip-back transitionend (with a timeout
     fallback in case the event is missed), guarded so a re-flip before it fires
     cancels the unload. Under body.no-motion the back is visibility:hidden the
     instant .flipped is removed, so we unload immediately. */
  function _hideCardBack(card, back) {
    card.classList.remove('flipped');
    _setBackInert(back, true);
    if (card.__escHandler) {
      document.removeEventListener('keydown', card.__escHandler);
      card.__escHandler = null;
    }
    if (_openCard === card) _openCard = null;   /* single-active-back bookkeeping */
    var restore = card.__restoreFocus || card.querySelector('.wf-gear');
    if (restore && typeof restore.focus === 'function') {
      try { restore.focus(); } catch (e) { /* ignore */ }
    }
    card.__restoreFocus = null;

    /* Unload the back so its cardcfg-* ids leave the document. */
    if (!MOTION) {
      _unloadBack(back);                  /* instant swap — no visible flip to wait on */
      return;
    }
    var inner = card.querySelector('.wf-inner');
    /* Bump a token so a re-flip (which clears it) cancels a pending unload. */
    var token = (card.__unloadToken || 0) + 1;
    card.__unloadToken = token;
    var done = function () {
      if (inner) inner.removeEventListener('transitionend', onEnd);
      /* Only unload if still closed AND no newer flip superseded us. */
      if (card.__unloadToken === token && !card.classList.contains('flipped')) {
        _unloadBack(back);
      }
    };
    var onEnd = function (e) {
      /* Only the .wf-inner transform finishing the flip-back counts. */
      if (e.target === inner && e.propertyName === 'transform') done();
    };
    if (inner) inner.addEventListener('transitionend', onEnd);
    /* Fallback in case transitionend is missed (interrupted/dropped); .5s
       transition → 600ms is comfortably past completion. */
    setTimeout(done, 600);
  }

  /* ── C5: ?configure=<recipe> handling ───────────────────────── */
  function handleConfigure() {
    var configure = CC.configure;
    if (!configure) {
      /* Also try reading from URL directly */
      try {
        var params = new URLSearchParams(window.location.search);
        configure = params.get('configure') || '';
      } catch (e) { /* ignore */ }
    }
    if (!configure) return;

    /* Open the configure modal — ends the redirect-loop trap */
    if (window.__openConfigure) {
      window.__openConfigure(configure);
    } else {
      /* Fallback: pre-select in run-bar (should not normally be reached) */
      var rbReport = el('rb-report');
      if (rbReport) {
        var opts = rbReport.options;
        for (var i = 0; i < opts.length; i++) {
          if (opts[i].value.toLowerCase() === configure.toLowerCase()) {
            rbReport.selectedIndex = i;
            break;
          }
        }
      }
      var runbar = qs('.runbar');
      if (runbar) runbar.scrollIntoView({ behavior: 'smooth', block: 'center' });
      showToast('Set scope below, then Run');
    }
  }

  /* ── Configure modal (prerun form in a centered modal) ─────── */

  /**
   * Open the configure modal and load the prerun form via HTMX.
   * Exposed globally as window.__openConfigure(recipe, opts).
   *
   * @param {string} recipe  Recipe label
   * @param {object} [opts]  Optional { project, version, folder } to pre-fill scope
   *
   * Scope pre-fill: after the prerun fragment loads (which includes
   * _scope_dropdowns.html and defines initScopeDropdowns), we set
   * data-value on #pre-folder, #pre-project, #pre-version and then
   * call initScopeDropdowns — exactly as settings.html does. The
   * function reads data-value to restore the selection after the API
   * calls complete (cascade: folder → project → version).
   */
  /* Task D (T2): the centered configure-MODAL context.  _openPrerun is
     container-parameterized via a ctx object so the SAME fetch → _afterLoad →
     _wireCfgSubmit pipeline drives both the modal AND the Builder's inline run
     drawer.  This is the default ctx; __openConfigure (the thin wrapper below)
     passes it so every existing modal caller is byte-for-byte unchanged. */
  function _modalCtx() {
    return {
      target: el('cfg-modal'),          // htmx swap target + query root (same el)
      targetSel: '#cfg-modal',          // htmx selector for the swap target
      suppressSaveDefault: false,       // the modal keeps "Save as default"
      open: function () {
        var cfgOv = el('cfg-ov');
        var cfgModal = el('cfg-modal');
        if (cfgOv) { cfgOv.classList.add('open'); cfgOv.onclick = _closeCfgModal; }
        if (cfgModal) cfgModal.classList.add('open');
        document.addEventListener('keydown', _cfgEscHandler);
      },
      close: _closeCfgModal,
    };
  }

  /**
   * Open the configure prerun form into a target container (modal or inline).
   * Drives the shared fetch → _afterLoad → _wireCfgSubmit pipeline.
   *
   * @param {string} recipe  Recipe label
   * @param {object} [opts]  Optional { project, version, folder } to pre-fill scope
   * @param {object} ctx     Container context — see _modalCtx() / _inlineCtx().
   *
   * Scope pre-fill: after the prerun fragment loads (which includes
   * _scope_dropdowns.html and defines initScopeDropdowns), we set
   * data-value on #pre-folder, #pre-project, #pre-version and then
   * call initScopeDropdowns — exactly as settings.html does. The
   * function reads data-value to restore the selection after the API
   * calls complete (cascade: folder → project → version).
   */
  function _openPrerun(recipe, opts, ctx) {
    var container = ctx && ctx.target;
    if (!container) return;

    opts = opts || {};
    /* When a caller (palette ⌥↵, ?configure= deep link) doesn't pass scope,
       default to the current run-bar selection so the modal pre-fills what the
       user already picked. Explicit opts (e.g. Recent Activity "Run again",
       and the Builder inline run passing _currentScopeOverride()) win.  The
       run bar lives only on the dashboard; on other pages these are absent and
       the lookups simply no-op. */
    var rbF = el('rb-folder');
    var rbP = el('rb-project');
    var rbV = el('rb-version');
    if (!opts.folder  && rbF && rbF.value) opts.folder  = rbF.value;
    if (!opts.project && rbP && rbP.value) opts.project = rbP.value;
    if (!opts.version && rbV && rbV.value) opts.version = rbV.value;

    function _afterLoad() {
      _wireCfgSubmit(recipe, ctx);
      if (window.__fsWireUploads) window.__fsWireUploads(container); /* SP3 */
      if (window.lucide) lucide.createIcons();
      /* Suppress the "Save as default" affordance for the inline (compound)
         target — it's meaningless for a compound bundle (Task D T2).  The
         fragment renders it for single recipes; hide it here for inline. */
      if (ctx.suppressSaveDefault) {
        var saveRow = container.querySelector('.prerun-save-default');
        if (saveRow) saveRow.style.display = 'none';
      }
      /* Pre-fill scope using _scope_dropdowns.html's initScopeDropdowns.
         Set data-value on each select so loadAll() restores the values
         after the async API calls complete. */
      var folderSel  = container.querySelector('#pre-folder');
      var projectSel = container.querySelector('#pre-project');
      var versionSel = container.querySelector('#pre-version');
      if (opts.folder  && folderSel)  folderSel.setAttribute('data-value',  opts.folder);
      if (opts.project && projectSel) projectSel.setAttribute('data-value', opts.project);
      if (opts.version && versionSel) versionSel.setAttribute('data-value', opts.version);
      /* initScopeDropdowns is defined inside the prerun fragment
         (via {% include "_scope_dropdowns.html" %}).  Call it to
         populate the dropdowns and restore the pre-filled values.  The pre-*
         ids are unique to the fragment, so this cascade never collides with the
         Builder rail's own g-* cascade (different element ids). */
      if (typeof initScopeDropdowns === 'function') {
        initScopeDropdowns({
          projectId: 'pre-project',
          folderId:  'pre-folder',
          versionId: 'pre-version',
          cvoId:     'pre-cvo',
        });
      }
      /* Bind the baseline/current version pickers too (Version Comparison) —
         the same helper the card back uses.  Without this the modal's pickers
         render as inert markup, leaving only the paste-ID text fallback. */
      if (typeof initVersionPicker === 'function' && container.querySelector('#pre-bv')) {
        var pinnedProj = (window.__CC && window.__CC.pinned && window.__CC.pinned.project) || '';
        initVersionPicker({ projectSelId: 'pre-bv-project', versionSelId: 'pre-bv-version', inputId: 'pre-bv', presetProject: pinnedProj });
        initVersionPicker({ projectSelId: 'pre-cv-project', versionSelId: 'pre-cv-version', inputId: 'pre-cv', presetProject: pinnedProj });
        _wireVcModeToggle(container, 'pre-vc-all', '.pre-vc-pair', ['pre-bv', 'pre-cv']);
      }
    }

    /* Load the prerun fragment via HTMX.  Re-injected fresh on each open
       (innerHTML replace) so submit handlers never stack across re-opens. */
    if (window.htmx) {
      htmx.ajax('POST', '/api/run/prerun', {
        target:  ctx.targetSel,
        swap:    'innerHTML',
        values:  { recipes: recipe },
      }).then(_afterLoad);
    } else {
      /* Fallback: plain fetch if HTMX not available */
      var fd = new FormData();
      fd.append('recipes', recipe);
      var nonceMeta = qs('meta[name="fs-csrf"]');
      var nonce = nonceMeta ? nonceMeta.content : '';
      fetch('/api/run/prerun', {
        method: 'POST',
        headers: { 'X-FS-Session': nonce },
        body: fd,
      }).then(function (r) { return r.text(); }).then(function (html) {
        container.innerHTML = html;
        _afterLoad();
      }).catch(function () { showToast('Could not load configure form'); });
    }

    ctx.open();
  }

  /* Default-modal wrapper: every existing caller (dashboard card, palette,
     ?configure= deep link, Recent Activity "Run again", fast-run) reaches the
     centered modal through here unchanged. */
  function _openCfgModal(recipe, opts) {
    _openPrerun(recipe, opts, _modalCtx());
  }

  function _closeCfgModal() {
    var cfgOv    = el('cfg-ov');
    var cfgModal = el('cfg-modal');
    if (cfgOv)    { cfgOv.classList.remove('open');    cfgOv.onclick = null; }
    if (cfgModal) { cfgModal.classList.remove('open'); }
    document.removeEventListener('keydown', _cfgEscHandler);
  }

  function _cfgEscHandler(e) {
    if (e.key === 'Escape') _closeCfgModal();
  }

  /* Task D (T2): inline-run drawer context (Builder compound/comparison).
     The drawer's content host is the htmx swap target AND query root; open/close
     toggle an Alpine open-flag via the registered hooks (set by __openInlineRun).
     "Save as default" is suppressed (meaningless for a compound). */
  var _inlineDrawer = { openFn: null, closeFn: null };
  function _inlineCtx(targetSel) {
    var host = qs(targetSel);
    return {
      target: host,
      targetSel: targetSel,
      suppressSaveDefault: true,
      open: function () {
        if (typeof _inlineDrawer.openFn === 'function') _inlineDrawer.openFn();
      },
      close: function () {
        if (typeof _inlineDrawer.closeFn === 'function') _inlineDrawer.closeFn();
      },
    };
  }

  /**
   * Open the prerun form INLINE as a right-side drawer (Builder compound /
   * comparison run surface).  Same pipeline as the modal; only the container +
   * open/close differ.  The Builder registers open/close hooks via
   * window.__registerInlineRunDrawer before calling this.
   *
   * @param {string} recipe    Recipe (compound/comparison) name
   * @param {object} [opts]     { project, folder, version } scope pre-fill
   * @param {string} targetSel  CSS selector for the drawer's content host
   */
  function _openInlineRun(recipe, opts, targetSel) {
    targetSel = targetSel || '#cpd-run-panel';
    _openPrerun(recipe, opts, _inlineCtx(targetSel));
  }

  /* The Builder registers its drawer open/close (Alpine flag flips) here so the
     inline ctx can drive them without command-center.js knowing about Alpine. */
  window.__registerInlineRunDrawer = function (openFn, closeFn) {
    _inlineDrawer.openFn = openFn;
    _inlineDrawer.closeFn = closeFn;
  };

  /** Wire the prerun form submit once it is loaded into the target container.
   *  Task D (T2): container-aware — `cfgModal` is the ctx's target (the modal
   *  #cfg-modal OR the inline drawer host) and close routes through ctx.close,
   *  so the same submit machinery serves both surfaces.  ctx defaults to the
   *  modal so any legacy single-arg call still wires the modal unchanged. */
  function _wireCfgSubmit(recipe, ctx) {
    ctx = ctx || _modalCtx();
    var cfgModal = ctx.target;
    if (!cfgModal) return;
    var _close = ctx.close || _closeCfgModal;

    /* Wire .prerun-close buttons */
    var closeBtns = cfgModal.querySelectorAll('.prerun-close');
    closeBtns.forEach(function (btn) {
      btn.addEventListener('click', _close);
    });

    /* Wire the Run button */
    var btnRun = cfgModal.querySelector('#btn-run-submit');
    if (!btnRun) return;

    /* Period↔custom-date-range mutual exclusivity: mirrors _wireCardDateMode. */
    (function () {
      var periodInp = cfgModal.querySelector('#pre-period');
      var startInp  = cfgModal.querySelector('#pre-start');
      var endInp    = cfgModal.querySelector('#pre-end');
      if (!periodInp || !startInp || !endInp) return;
      function onModalRangeChange() {
        if (startInp.value && endInp.value) {
          periodInp.value = '';
        }
      }
      function onModalPeriodChange() {
        if (periodInp.value) {
          startInp.value = '';
          endInp.value = '';
        }
      }
      startInp.addEventListener('input', onModalRangeChange);
      startInp.addEventListener('change', onModalRangeChange);
      endInp.addEventListener('input', onModalRangeChange);
      endInp.addEventListener('change', onModalRangeChange);
      periodInp.addEventListener('input', onModalPeriodChange);
      periodInp.addEventListener('change', onModalPeriodChange);
    })();

    /* Keep the hidden scan_types/scan_statuses fields live as the user toggles
       the st_cb/ss_cb boxes — mirrors _wireCardScanCheckboxes.  The /api/run
       submit rebuilds them from the checked boxes directly, but the "Save as
       default" path serialises via _serializeCardCfgForm which reads the hidden
       fields, so they must reflect the current selection (not the stale prefill). */
    (function () {
      [
        { boxName: 'st_cb', hiddenId: 'pre-scan-types' },
        { boxName: 'ss_cb', hiddenId: 'pre-scan-statuses' },
        { boxName: 'as_cb', hiddenId: 'pre-autotriage-status' }, /* SP2 */
      ].forEach(function (g) {
        var hidden = cfgModal.querySelector('#' + g.hiddenId);
        if (!hidden) return;
        function sync() {
          var vals = [];
          cfgModal
            .querySelectorAll('input[name="' + g.boxName + '"]:checked')
            .forEach(function (cb) { vals.push(cb.value); });
          hidden.value = vals.join(',');
        }
        cfgModal
          .querySelectorAll('input[name="' + g.boxName + '"]')
          .forEach(function (cb) { cb.addEventListener('change', sync); });
      });
    })();

    /* Inline error helper for the modal (mirrors the card back). */
    function _modalError(msg) {
      var box = cfgModal.querySelector('#prerun-error');
      if (!box) return;
      if (msg) { box.textContent = msg; box.style.display = ''; }
      else { box.textContent = ''; box.style.display = 'none'; }
    }

    btnRun.addEventListener('click', function () {
      var form = cfgModal.querySelector('#prerun-submit-form');
      if (!form) return;
      _modalError('');

      /* Serialise form */
      var params = new URLSearchParams();
      var els = form.elements;
      for (var i = 0; i < els.length; i++) {
        var fe = els[i];
        if (!fe.name) continue;
        if (fe.type === 'checkbox') {
          if (fe.name === 'ft_cb') {
            /* finding types checkboxes — skip, handled via hidden #pre-ft */
          } else if (fe.name === 'st_cb') {
            /* scan types checkboxes — skip, handled via hidden #pre-scan-types */
          } else if (fe.name === 'ss_cb') {
            /* scan statuses checkboxes — skip, handled via hidden #pre-scan-statuses */
          } else if (fe.name === 'as_cb') {
            /* SP2 autotriage statuses — skip, handled via hidden #pre-autotriage-status */
          } else {
            params.append(fe.name, fe.checked ? 'true' : 'false');
          }
        } else if (fe.id === 'pre-ft') {
          /* Rebuild finding_types from checked ft_cb checkboxes */
          var ftBoxes = form.querySelectorAll('input[name="ft_cb"]:checked');
          var ftVals = [];
          ftBoxes.forEach(function (cb) { ftVals.push(cb.value); });
          params.append('finding_types', ftVals.join(',') || 'cve');
        } else if (fe.id === 'pre-scan-types') {
          /* Rebuild scan_types from checked st_cb checkboxes */
          var stBoxes = form.querySelectorAll('input[name="st_cb"]:checked');
          var stVals = [];
          stBoxes.forEach(function (cb) { stVals.push(cb.value); });
          params.append('scan_types', stVals.join(','));
        } else if (fe.id === 'pre-scan-statuses') {
          /* Rebuild scan_statuses from checked ss_cb checkboxes */
          var ssBoxes = form.querySelectorAll('input[name="ss_cb"]:checked');
          var ssVals = [];
          ssBoxes.forEach(function (cb) { ssVals.push(cb.value); });
          params.append('scan_statuses', ssVals.join(','));
        } else if (fe.id === 'pre-autotriage-status') {
          /* SP2: rebuild autotriage_status from checked as_cb checkboxes */
          var asBoxes = form.querySelectorAll('input[name="as_cb"]:checked');
          var asVals = [];
          asBoxes.forEach(function (cb) { asVals.push(cb.value); });
          params.append('autotriage_status', asVals.join(','));
        } else {
          /* Send EVERY rendered field, INCLUDING empty/cleared ones (PR #117
             review r6).  The modal is authoritative only for the fields it
             actually renders; start_run uses the SET of override-allowlist keys
             PRESENT in this form to decide which saved per-card overrides to
             suppress.  A cleared text field must therefore arrive as
             present-but-empty (`component_filter=`) so its key is in that set —
             suppressing the saved override AND, being empty, not re-adding a
             value → the field falls through to the engine/global default (the
             clear is honored).  Dropping empties here (the old `else if
             (fe.value)`) would make a cleared field ABSENT, so start_run could
             not tell "cleared in the modal" from "the modal never rendered it"
             and would resurrect the saved override.  Fields the modal did NOT
             render (e.g. product_type on a non-show_deployment_context recipe)
             stay absent and keep their saved override. */
          params.append(fe.name, fe.value);
        }
      }

      /* Mark this as an AUTHORITATIVE launch (PR #117 review r5, narrowed r6).
         The modal pre-fills every field it RENDERS from EFFECTIVE values (saved
         per-card override ∪ global, via _EffectiveStateView), so its submit
         carries the saved override values for those fields.  This marker tells
         start_run that the modal is authoritative ONLY for the override keys
         this form actually carries (present, including present-but-empty from
         the include-empties serialisation above): for a present key the form
         value wins and the saved override is suppressed (so a CLEARED field
         falls through to the engine/global default instead of being resurrected
         from the override).  A field the modal did NOT render (e.g.
         product_type on a non-show_deployment_context recipe that nonetheless
         has a saved per-card override via the card AI tab) is ABSENT from the
         form, so start_run KEEPS its saved override — the r6 regression fix.
         Minimal
         launches (__openFR: recipes + scope only) carry NO marker and still get
         the full override merged, so explicit one-off run params win.
         Control-only: not in start_run's override allowlist, so it never
         reaches the run config. */
      params.append('_authoritative', '1');

      var nonce = _nonce();

      /* ── Single-recipe per-card awareness (§10). ──
         The hidden #prerun-submit-form recipes field carries the comma-joined
         names; a single recipe (no comma) is the only one that validates the
         required card input and can "Save as default". */
      var recipesField = form.querySelector('input[name="recipes"]');
      var recipesVal = recipesField ? recipesField.value : '';
      var isSingle = recipesVal && recipesVal.indexOf(',') === -1;
      var saveBox = form.querySelector('#pre-save-default');
      var cveInput = form.querySelector('#pre-cve');
      var componentInput = form.querySelector('#pre-component');

      if (isSingle) {
        /* 1. Validate the required card input — requires_cve → cve_filter, and
           requires_component → component_filter (B4 #25) — regardless of the
           checkbox, so we never launch a doomed run the engine preflight would
           only reject later. */
        var requiresCve = saveBox && saveBox.getAttribute('data-requires-cve') === '1';
        if (requiresCve && (!cveInput || !cveInput.value.trim())) {
          _modalError('CVE ID(s) required to run this report.');
          if (cveInput) { try { cveInput.focus(); } catch (e) { /* ignore */ } }
          return;
        }
        var requiresComponent =
          saveBox && saveBox.getAttribute('data-requires-component') === '1';
        if (requiresComponent && (!componentInput || !componentInput.value.trim())) {
          _modalError('A component is required to run this report.');
          if (componentInput) { try { componentInput.focus(); } catch (e) { /* ignore */ } }
          return;
        }
      }

      /* Disable the Run button while submitting */
      btnRun.disabled = true;
      btnRun.textContent = 'Starting…';

      function _launch() {
        /* __sp2PostRun satisfies the SP2 confirm gate (real autotriage write ->
           native confirm -> retry) and, for a dry-run autotriage launch, polls
           the preview + offers apply-for-real. */
        var reEnable = function () {
          btnRun.disabled = false;
          btnRun.textContent = 'Run';
        };
        window.__sp2PostRun(params, nonce, {
          onError: function (body) {
            _modalError('Run failed: ' + (body.error || 'unknown error'));
            reEnable();
          },
        })
        .then(function (body) {
          if (!body) {
            /* error toasted via onError, or user cancelled the confirm */
            reEnable();
            return;
          }
          if (body.run_id) {
            /* Close the surface (modal or inline drawer), show toast, refresh
               Running Reports.  No navigation here — a COMPOUND run is already
               being routed to /run/{id} by __sp2PostRun (fast-run.js); a plain
               single-recipe run stays put. (Task D T2: container-aware close.) */
            _close();
            var label = recipe || 'report';
            if (window.__showToast) window.__showToast('Started: ' + label);
            if (window.__refreshRunning) window.__refreshRunning();
          } else {
            _modalError('Run failed: ' + (body.error || 'unknown error'));
            reEnable();
          }
        })
        .catch(function (err) {
          _modalError('Submit failed: ' + (err.message || 'network error'));
          reEnable();
        });
      }

      /* 2. "Save as default" (single recipe, checkbox on) persists the form
         via the card-config path FIRST.  A failed validation (400) BLOCKS the
         run and surfaces the error — never launch past a failed save. */
      if (isSingle && saveBox && saveBox.checked) {
        /* Persist via the SAME include-empties serialisation as the card-back
           Save (NOT the /api/run `params` above, which drops empty fields via
           `else if (fe.value)`).  Otherwise clearing a field here + ticking
           "Save as default" would silently leave the old override in place
           because the cleared field never reached the backend.  Only the
           card-config save body uses this; the /api/run `params` are
           unchanged. */
        var cfgParams = _serializeCardCfgForm(form, 'pre-ft');
        cfgParams.set('recipe', recipesVal);
        fetch('/api/cc/card-config', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-FS-Session': nonce,
          },
          body: cfgParams.toString(),
        })
        .then(function (resp) {
          return resp.json().then(function (b) {
            return { ok: resp.ok, body: b || {} };
          }, function () { return { ok: resp.ok, body: {} }; });
        })
        .then(function (res) {
          if (!res.ok) {
            _modalError((res.body && res.body.error) || 'Could not save default — check required fields.');
            btnRun.disabled = false;
            btnRun.textContent = 'Run';
            return;
          }
          /* 3. On success, sync the off-card needsSetup set so a later launch
             of this recipe doesn't re-prompt, then run. */
          var ns = window.__CC && window.__CC.needsSetup;
          if (ns && typeof ns.add === 'function') {
            if (res.body && res.body.needs_setup) ns.add(recipesVal.toLowerCase());
            else ns.delete(recipesVal.toLowerCase());
          }
          /* Keep the corresponding card's data-needs-setup in sync too. */
          var card = qs('.wf-card[data-recipe="' + recipesVal + '"]');
          if (card) card.setAttribute('data-needs-setup', (res.body && res.body.needs_setup) ? '1' : '0');
          _launch();
        })
        .catch(function () {
          _modalError('Save default failed — check connection.');
          btnRun.disabled = false;
          btnRun.textContent = 'Run';
        });
        return;
      }

      _launch();
    });
  }

  /* Expose globally so fast-run.js and palette.js can call it — cross-page */
  window.__openConfigure  = _openCfgModal;
  window.__closeCfgModal  = _closeCfgModal;
  /* Task D (T2): Builder inline-run drawer entry point (compound/comparison). */
  window.__openInlineRun  = _openInlineRun;

  /* Expose monitor refresh for fast-run.js (immediate re-render after run start).
   * Also (re)starts the runs poller if it was stopped (e.g. after idle self-stop),
   * so a run the user just launched resumes fast 2.5 s polling immediately.
   * Cockpit-only: no-ops on pages without the monitor (e.g. /queue) so a run
   * launched from the palette there doesn't spin a poller against absent DOM. */
  window.__refreshRunning = function () {
    if (!document.getElementById('running-container')) return;
    if (window.htmx) {
      htmx.ajax('GET', '/api/running', { target: '#running-container', swap: 'innerHTML' });
    }
    /* Restart the runs poller in case it self-stopped while idle */
    _startRunningPoller();
  };

  /* ── Projects fetch — cross-page, single source of truth ───────
     Populates the CROSS-PAGE consumers that exist on every shell page
     (run bar or not):
       1. window.__CC.projects + palette refresh (⌘K target list)
       2. [data-cc="projects"] status-bar count
       3. [data-cc="sync"] status-bar last-sync time
     Exposes window.__CC.__projectNameToId (kept for any name→id consumer).

     NOTE (Task 13 — single cascade owner): this NO LONGER populates or binds
     the run bar's #rb-project / #rb-version selects.  On the dashboard those are
     owned exclusively by the run bar's initScopeDropdowns cascade (wireRunBar),
     which fetches its own projects + folders + versions and binds the change
     listeners.  Having fetchProjects() also stamp #rb-project would double-bind
     and race the cascade, so the run-bar population was removed — only the
     cross-page side-effects above remain here. */
  function fetchProjects() {
    /* GET — CSRF middleware only guards POST/PUT/DELETE, no nonce needed */
    fetch('/fsapi/public/v0/projects?limit=10000&archived=false&excluded=false')
      .then(function (resp) {
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        return resp.json();
      })
      .then(function (body) {
        var list = Array.isArray(body) ? body
                 : (body.items && Array.isArray(body.items)) ? body.items
                 : (body.data  && Array.isArray(body.data))  ? body.data
                 : null;
        if (!list) throw new Error('no list');

        /* Sort by name */
        list.sort(function (a, b) {
          return (a.name || '').localeCompare(b.name || '');
        });

        /* Build name → id map (kept for any name→id consumer) */
        var nameToId = {};
        list.forEach(function (p) { if (p.name && p.id) nameToId[p.name] = p.id; });
        var syncCC = window.__CC || {};
        syncCC.__projectNameToId = nameToId;
        window.__CC = syncCC;

        var names = list.filter(function (p) { return p && p.name; })
                        .map(function (p) { return p.name; });

        /* 1. window.__CC.projects + palette — cross-page (skip push if empty,
           but still stamp count + sync below so empty portfolios aren't stuck
           showing "—" on /queue). */
        if (names.length) {
          if (window.__refreshPaletteProjects) window.__refreshPaletteProjects(names);
          else { var cc2 = window.__CC || {}; cc2.projects = names; window.__CC = cc2; }
        }

        /* 2. Status-bar count — cross-page */
        var projectsEl = qs('[data-cc="projects"]');
        if (projectsEl) projectsEl.textContent = names.length;

        /* 3. Status-bar last-sync stamp — cross-page (so /queue shows sync time too) */
        var syncEl = qs('[data-cc="sync"]');
        if (syncEl) {
          var now = new Date();
          syncEl.textContent = now.toTimeString().slice(0, 8);
        }
      })
      .catch(function () {
        /* Best-effort: API not configured or network error — nothing to do for
           the run bar (the cascade surfaces its own load failure); the
           status-bar count simply stays at its server-rendered placeholder. */
      });
  }

  /* fetchFolders — best-effort cross-page folder load for the ⌘K palette.
     Folder is a first-class selectable target (folder-targeting design §5), so
     the palette needs folders on EVERY shell page (not just the dashboard,
     where the run-bar cascade fetches its own folders).  Mirrors fetchProjects:
     GET /fsapi/public/v0/folders, feed window.__CC.folders + the palette via
     __refreshPaletteFolders.  Folder option value = folder ID, label = name. */
  function fetchFolders() {
    /* GET — CSRF middleware only guards POST/PUT/DELETE, no nonce needed */
    fetch('/fsapi/public/v0/folders?limit=10000')
      .then(function (resp) {
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        return resp.json();
      })
      .then(function (body) {
        var list = Array.isArray(body) ? body
                 : (body.items && Array.isArray(body.items)) ? body.items
                 : (body.data  && Array.isArray(body.data))  ? body.data
                 : null;
        if (!list) throw new Error('no list');

        /* Keep only folders with an id; carry id + name + parentFolderId (the
           palette keys by ID for scope, renders the name as the label, and
           _buildFolderTree indents by parentFolderId — dropping it here would
           flatten the palette tree to a root-level list after a cross-page
           refresh). Carry both the API camelCase field and the snake_case
           alias so the tree builder (which checks parentFolderId || parent_id)
           survives whichever the API returns. */
        var folders = list
          .filter(function (f) { return f && f.id !== undefined && f.id !== null; })
          .map(function (f) {
            var pid = (f.parentFolderId != null) ? f.parentFolderId
                    : (f.parent_id != null)       ? f.parent_id
                    : null;
            return {
              id: String(f.id),
              name: f.name || String(f.id),
              parentFolderId: (pid != null) ? String(pid) : null,
              parent_id: (pid != null) ? String(pid) : null,
            };
          });

        /* Sort by name for a stable palette ordering */
        folders.sort(function (a, b) {
          return (a.name || '').localeCompare(b.name || '');
        });

        if (window.__refreshPaletteFolders) {
          window.__refreshPaletteFolders(folders);
        } else {
          var cc = window.__CC || {};
          cc.folders = folders;
          window.__CC = cc;
        }
      })
      .catch(function () {
        /* Best-effort: API not configured or network error — the palette simply
           has no Folder items (it still works for projects/recipes/views). */
      });
  }

  /* ── Idle request-budget polling policy ─────────────────────────
   *
   * RUNS POLLER (_rrPoller, 2.5 s):
   *   Polls /api/runs/active — this is LOCAL/in-memory, no platform call.
   *   Runs ONLY while ≥1 run has status==='running' AND the tab is visible.
   *   After each tick: if zero running runs remain, clearInterval → self-stop.
   *   __refreshRunning() restarts it (and fires an immediate HTMX re-render),
   *   so a run the user launches resumes fast polling instantly.
   *   On page init the poller starts once; if nothing is running it stops after
   *   the first tick (≈ 0 local requests while idle).
   *   Tradeoff: externally-started runs (CLI / other tab) only appear after a
   *   manual refresh; the user's own launches appear instantly via __refreshRunning.
   *
   * QUEUE POLLER (_queuePoller, 180 s):
   *   Refreshes #scan-queue-container via HTMX → GET /api/queue.
   *   /api/queue is platform-facing (memoized, ≤6 pages). The poller omits
   *   ?force to stay within the idle budget; the manual #cc-refresh / panel
   *   Refresh use ?force=1 to bypass the memo for a live fetch.
   *   hx-trigger on the element is "load delay:500ms" (initial load only).
   *   JS drives the 3-min periodic refresh so it can pause when tab is hidden.
   *
   * VISIBILITY GATING (COCKPIT ONLY):
   *   These pollers and their visibilitychange handler are ONLY active on the
   *   cockpit page (where #running-container exists). On /queue and other shell
   *   pages these are never started and the handler is never registered.
   *
   * IDLE REQUEST BUDGET:
   *   visible + nothing running : ~20 requests/hr (queue poll only, 3-min interval)
   *   tab hidden                : 0 requests/hr
   *   active run in progress    : ~24/min local + ~20/hr queue ≈ well under 1000/hr/IP limit
   *
   * NEVER triggers a full HTMX re-render during a run (that caused "breathing" flicker).
   * Each tick: remove vanished rows, patch/transition existing rows in-place.
   * New runs are NOT added by the poller — they appear via __refreshRunning.
   * Exception: if the panel shows only the empty-state but the API has active runs,
   * __refreshRunning is called once so the first row appears without a manual click.
   * ──────────────────────────────────────────────────────────────── */
  var _rrPoller = null;
  var _queuePoller = null;

  /* Toggle a workflow row's sparkline segment classes from a completed count.
   * When `finished` is true every segment is `.done`. Class-only — operates on
   * the segments the TEMPLATE rendered (no markup rebuild → no drift). */
  function _wfSetSegs(row, completed, total, finished) {
    var segs = row.querySelectorAll('.wf-spark .seg');
    for (var i = 0; i < segs.length; i++) {
      var cls = 'seg';
      if (finished || i < completed) cls += ' done';
      else if (i === completed) cls += ' now';
      else cls += ' pending';
      segs[i].className = cls;
    }
  }

  /* Apply the terminal status badge to a row's top bar (shared by the workflow
   * and legacy finished transitions). Removes the elapsed span + any prior
   * badge first so it matches the server template exactly. */
  function _applyFinishedBadge(rowTop, res) {
    if (!rowTop) return;
    var elEl = rowTop.querySelector('.run-elapsed');
    if (elEl) rowTop.removeChild(elEl);
    var oldBadge = rowTop.querySelector('.run-err-badge, .run-cancel-badge, .qdone-badge');
    if (oldBadge) rowTop.removeChild(oldBadge);
    var badge = document.createElement('span');
    badge.style.marginLeft = 'auto';
    if (res === 'error') { badge.className = 'run-err-badge'; badge.textContent = '✕ failed'; }
    else if (res === 'cancelled') { badge.className = 'run-cancel-badge'; badge.textContent = '— cancelled'; }
    else if (res === 'success') { badge.className = 'qdone-badge'; badge.textContent = '✓ done'; }
    else { badge.className = 'run-cancel-badge'; badge.textContent = '— finished'; }
    rowTop.appendChild(badge);
  }

  function _startRunningPoller() {
    if (_rrPoller !== null) return; /* already running */

    function _poll() {
      if (document.hidden) return; /* skip while tab is hidden */
      fetch('/api/runs/active')
        .then(function (resp) {
          if (!resp.ok) throw new Error('HTTP ' + resp.status);
          return resp.json();
        })
        .then(function (data) {
          if (!Array.isArray(data)) return;

          /* Build id → run map from API response */
          var apiById = {};
          data.forEach(function (r) { apiById[r.run_id] = r; });

          /* ── 1. Remove rows that are no longer in the active window ── */
          var domRows = document.querySelectorAll('#running-reports [data-run-id]');
          for (var i = 0; i < domRows.length; i++) {
            var rid = domRows[i].getAttribute('data-run-id');
            if (!apiById[rid]) {
              domRows[i].parentNode.removeChild(domRows[i]);
            }
          }

          /* ── 2. Patch / transition existing rows ── */
          data.forEach(function (run) {
            var row = document.querySelector('#running-reports [data-run-id="' + run.run_id + '"]');
            if (!row) return; /* new run — not added by the poller */

            /* Skip rows that have already been fully transitioned to done */
            if (row.getAttribute('data-done') === '1') return;

            var prog = run.progress;

            if (run.status === 'running') {
              if (run.kind === 'workflow') {
                /* Workflow: advance the segment sparkline + label (class/text
                   only on the template-rendered .seg nodes). Guard on a real
                   progress object so a row with missing progress keeps its
                   server-rendered label (never "step X of 0"). */
                if (prog && prog.total) {
                  var wfc = prog.completed || 0;
                  _wfSetSegs(row, wfc, prog.total, false);
                  var wfLabel = row.querySelector('.wf-spark-label');
                  if (wfLabel) wfLabel.textContent = 'step ' + wfc + ' of ' + prog.total;
                }
              } else if (prog && prog.total > 1) {
                /* Determinate: update fill width */
                var fill = row.querySelector('.run-fill');
                if (fill) {
                  var pct = Math.round(prog.completed / prog.total * 100);
                  fill.style.width = pct + '%';
                }
                /* Update status text */
                var statusText = row.querySelector('.run-status-text');
                if (statusText) {
                  statusText.textContent = 'recipe ' + prog.completed + '/' + prog.total;
                }
              }
              /* For single-recipe (total <= 1): leave the sweep bar alone */

              /* Update elapsed */
              var elapsedEl = row.querySelector('.run-elapsed');
              if (elapsedEl) {
                var e = run.elapsed || 0;
                elapsedEl.textContent = e >= 60 ? Math.floor(e / 60) + 'm' : e + 's';
              }
            } else {
              /* ── Finished run: transition the row in-place ── */
              var res = run.result; /* 'success' | 'error' | 'cancelled' | null */

              if (run.kind === 'workflow') {
                /* Workflow: class/label toggles only — fill the sparkline,
                   tint by result, shimmer once, keep the .wf-spark nodes. The
                   template's /run/{id} onclick stays for success/cancelled; an
                   ERROR row is repointed to the run log (the fast failure path,
                   matching ad-hoc error rows). No bar rebuild. */
                var wfTot = (prog && prog.total) || 0;
                _wfSetSegs(row, wfTot, wfTot, true);
                var spark = row.querySelector('.wf-spark');
                if (spark) {
                  var tint = res === 'success' ? 'success'
                    : res === 'error' ? 'error'
                    : res === 'cancelled' ? 'cancelled' : 'neutral';
                  spark.classList.add('wf-spark--' + tint);
                  spark.classList.add('wf-spark--shimmer');
                }
                var wfFinLabel = row.querySelector('.wf-spark-label');
                if (wfFinLabel && wfTot) wfFinLabel.textContent = wfTot + ' steps';
                if (res === 'error') {
                  /* Workflow error reopens the canvas (fix ④) — consistent with
                     the server template's is_canvas branch + the compound branch.
                     The canvas toolbar keeps the raw log one click away. */
                  row.onclick = (function (id) {
                    return function () { location.href = '/run/' + id; };
                  })(run.run_id);
                }
                _applyFinishedBadge(row.querySelector('.run-row-top'), res);
                row.setAttribute('data-done', '1');
              } else {
              /* Replace progress bar in-place */
              var bar = row.querySelector('.run-bar');
              if (bar) {
                /* Remove sweep animation if present */
                var sweep = bar.querySelector('.run-sweep');
                if (sweep) bar.removeChild(sweep);
                /* Remove any existing fill */
                var oldFill = bar.querySelector('.run-fill');
                if (oldFill) bar.removeChild(oldFill);

                var newFill = document.createElement('i');
                newFill.style.width = '100%';
                if (res === 'error') {
                  bar.className = 'run-bar run-bar-err';
                  newFill.className = 'run-fill run-fill-err';
                } else if (res === 'success') {
                  bar.className = 'run-bar run-bar-done';
                  newFill.className = 'run-fill run-fill-done';
                } else {
                  /* cancelled or null/unknown — muted bar (matches template:
                     run-bar-done at opacity:.4 + run-fill-done) */
                  bar.className = 'run-bar run-bar-done';
                  bar.style.opacity = '.4';
                  newFill.className = 'run-fill run-fill-done';
                }
                bar.appendChild(newFill);
              }

              /* Update / replace the run-row-top right-hand badge.
               * Badge and clickability must exactly match what the server
               * template renders so poller-updated rows are identical to
               * HTMX-rendered rows.
               *   success + report_url → green ✓ done  (clickable → report)
               *   error               → red ✕ failed  (clickable → log)
               *   cancelled           → muted — cancelled (not clickable)
               *   null / unknown      → neutral — finished (not clickable)
               */
              var rowTop = row.querySelector('.run-row-top');
              if (rowTop) {
                /* Remove elapsed element (no longer needed) */
                var elEl = rowTop.querySelector('.run-elapsed');
                if (elEl) rowTop.removeChild(elEl);
                /* Remove the per-row Stop control — the run is over (#21), so a
                   poller-finished row matches the server template (no Stop). */
                var stopBtn = rowTop.querySelector('.run-stop');
                if (stopBtn) rowTop.removeChild(stopBtn);
                /* Remove any existing badge to avoid duplicates */
                var oldBadge = rowTop.querySelector(
                  '.run-err-badge, .run-cancel-badge, .qdone-badge'
                );
                if (oldBadge) rowTop.removeChild(oldBadge);

                var badge = document.createElement('span');
                badge.style.marginLeft = 'auto';
                if (res === 'error') {
                  badge.className = 'run-err-badge';
                  badge.textContent = '✕ failed';
                } else if (res === 'cancelled') {
                  badge.className = 'run-cancel-badge';
                  badge.textContent = '— cancelled';
                } else if (res === 'success') {
                  badge.className = 'qdone-badge';
                  badge.textContent = '✓ done';
                } else {
                  /* null / unknown result — same muted badge as cancelled
                     (matches template: run-cancel-badge + text "— finished") */
                  badge.className = 'run-cancel-badge';
                  badge.textContent = '— finished';
                }
                rowTop.appendChild(badge);
              }

              /* Remove status text line (running… / recipe N/M) */
              var stEl = row.querySelector('.run-status-text');
              if (stEl && stEl.parentNode) stEl.parentNode.removeChild(stEl);

              /* Make row clickable — only for success (with report_url) and error.
               * cancelled / null / unknown are NOT made clickable (neutral state). */
              if (run.kind === 'compound') {
                /* Compound: reopen the fan-in Run canvas (parity with the server
                   template's is_canvas branch + spec §9) — NOT the combined
                   report. Clickable in EVERY terminal state INCLUDING error
                   (fix ④): the canvas renders the terminal error + deliverable
                   error message, and its toolbar keeps the raw log one click
                   away. */
                row.style.cursor = 'pointer';
                row.className = (row.className + ' run-row-link').trim();
                row.onclick = function () { location.href = '/run/' + run.run_id; };
              } else if (res === 'success' && run.report_url) {
                row.style.cursor = 'pointer';
                row.className = (row.className + ' run-row-link').trim();
                row.onclick = function () { location.href = run.report_url; };
              } else if (res === 'error') {
                row.style.cursor = 'pointer';
                row.className = (row.className + ' run-row-link').trim();
                row.onclick = function () { location.href = '/run/' + run.run_id + '/log'; };
              }

              /* Mark as done so we don't re-apply the transition */
              row.setAttribute('data-done', '1');
              }
            }
          });

          /* ── 3. Empty-state: if no data-run-id rows remain but panel has none,
                  insert a minimal placeholder. ── */
          var remaining = document.querySelectorAll('#running-reports [data-run-id]');
          var panel = document.getElementById('running-reports');
          if (panel && remaining.length === 0) {
            if (!panel.querySelector('.run-empty')) {
              var emptyDiv = document.createElement('div');
              emptyDiv.className = 'run-empty';
              emptyDiv.innerHTML =
                '<span style="color:var(--ink-mute);font-size:12px">No reports running</span>' +
                '<span style="color:var(--ink-faint);font-size:11px;margin-top:3px">Launch one from the report cards below.</span>';
              panel.appendChild(emptyDiv);
            }
          } else if (panel) {
            /* Remove placeholder once rows exist */
            var ep = panel.querySelector('.run-empty');
            if (ep) ep.parentNode.removeChild(ep);
          }

          /* ── 4. First-run bootstrap: if no rows in DOM but API has active
                  runs, trigger a one-shot full render so the panel populates
                  without the user having to click Refresh. ── */
          var domAfter = document.querySelectorAll('#running-reports [data-run-id]');
          if (domAfter.length === 0 && data.length > 0 && window.__refreshRunning) {
            window.__refreshRunning();
          }

          /* ── 5. Update headline KPI metric counts in-place ── */
          var runningCount = 0, doneCount = 0, failedCount = 0;
          data.forEach(function (r) {
            if (r.status === 'running') runningCount++;
            else if (r.result === 'success') doneCount++;
            else if (r.result === 'error') failedCount++;
          });
          var rrRunningEl = qs('[data-cc="rr-running"]');
          var rrDoneEl    = qs('[data-cc="rr-done"]');
          var rrFailedEl  = qs('[data-cc="rr-failed"]');
          if (rrRunningEl) rrRunningEl.textContent = runningCount;
          if (rrDoneEl)    rrDoneEl.textContent    = doneCount;
          if (rrFailedEl)  rrFailedEl.textContent  = failedCount;

          /* ── 6. Self-stop: if no run has status=running, halt the poller ── */
          if (runningCount === 0) {
            clearInterval(_rrPoller);
            _rrPoller = null;
          }
        })
        .catch(function () {
          /* Network/parse error — leave current rows, try again next tick */
        });
    }

    _rrPoller = setInterval(_poll, 2500);
    _poll(); /* immediate in-place tick so (re)start catches up without waiting 2.5s */
  }

  /* ── Scan-queue JS poller (180 s, visibility-gated, COCKPIT ONLY) */
  function _startQueuePoller() {
    if (_queuePoller !== null) return; /* already running */
    _queuePoller = setInterval(function () {
      if (document.hidden) return; /* skip while tab is hidden */
      try {
        var qc = document.getElementById('scan-queue-container');
        if (qc && window.htmx) {
          htmx.ajax('GET', '/api/queue', { target: '#scan-queue-container', swap: 'innerHTML' });
        }
      } catch (e) { /* ignore — next tick will retry */ }
    }, 300000);
  }

  /* ── Cross-page init — always runs on every shell page ──────── */
  /* ── SP3 §7: Apply VEX file — one-shot destructive apply ─────────
   * Upload a vex_recommendations.json (kind=recs, auto-wired by uploads.js) →
   * dry-run preview (/api/vex/apply-file {dry_run:true}) → render summary →
   * "Apply for real" ({confirm:true}). The endpoint canonicalizes + confines
   * the path to ~/.fs-report/uploads/recs/ and requires confirm for a real
   * write (server-enforced); this is the client. Dashboard-only (no-ops if the
   * trigger/modal are absent). */
  function wireApplyVexFile() {
    var trigger = el('cc-apply-vex');
    var modal   = el('vexfile-modal');
    var ov      = el('vexfile-ov');
    if (!trigger || !modal || !ov) return; /* not on this page */

    var pathEl     = el('vexfile-path');
    var previewBtn = el('vexfile-preview');
    var applyBtn   = el('vexfile-apply');
    var summaryEl  = el('vexfile-summary');
    var errorEl    = el('vexfile-error');
    var overrideEl = el('vexfile-vex-override');
    var closeBtn   = el('vexfile-close');

    function _path() { return ((pathEl && pathEl.value) || '').trim(); }
    function _showError(msg) {
      if (!errorEl) return;
      errorEl.textContent = msg || '';
      errorEl.style.display = msg ? 'block' : 'none';
    }
    function _clearSummary() {
      if (summaryEl) { summaryEl.innerHTML = ''; summaryEl.style.display = 'none'; }
    }
    function _syncPreview() {
      if (previewBtn) previewBtn.disabled = !_path();
    }
    /* The dry-run preview is only valid for the exact inputs it was computed
       with.  Invalidate it (disable Apply + drop the stale summary) whenever
       those inputs change or a re-preview fails — so a real write can never run
       on counts the user didn't actually preview. */
    function _invalidatePreview() {
      _clearSummary();
      if (applyBtn) applyBtn.disabled = true;
    }
    /* Reset the modal to a clean slate (on open AND close) so a reopened dialog
       never presents a prior session's path / summary / button state. */
    function _resetAll() {
      if (pathEl) pathEl.value = '';
      var input = modal.querySelector('.fs-upload-input');
      if (input) input.value = '';
      var nameSpan = modal.querySelector('.fs-upload-name');
      if (nameSpan) { nameSpan.textContent = 'none'; nameSpan.title = ''; }
      if (overrideEl) overrideEl.checked = false;
      _clearSummary();
      _showError('');
      if (applyBtn) { applyBtn.disabled = true; applyBtn.textContent = 'Apply for real'; }
      if (previewBtn) { previewBtn.disabled = true; previewBtn.textContent = 'Preview (dry run)'; }
    }

    function escHandler(e) { if (e.key === 'Escape') _close(); }
    function _open() {
      _resetAll();
      ov.classList.add('open');
      modal.classList.add('open');
      document.addEventListener('keydown', escHandler);
      if (window.lucide) lucide.createIcons();
    }
    function _close() {
      ov.classList.remove('open');
      modal.classList.remove('open');
      document.removeEventListener('keydown', escHandler);
      _resetAll();
    }

    /* Build the summary readout WITHOUT innerHTML interpolation of dynamic
       values (codebase convention) — textContent for every count. */
    function _renderSummary(summary, dryRun) {
      if (!summaryEl) return;
      summaryEl.innerHTML = '';
      var head = document.createElement('div');
      head.className = 'vexfile-summary-head';
      head.textContent = dryRun ? 'Dry-run preview' : 'Applied';
      summaryEl.appendChild(head);
      var rows = [
        ['Total', summary.total],
        [dryRun ? 'Would write' : 'Written', summary.succeeded],
        ['Failed', summary.failed],
        ['Skipped (invalid)', summary.skipped_invalid],
        ['Skipped (existing)', summary.skipped_existing],
      ];
      rows.forEach(function (r) {
        var row = document.createElement('div');
        row.className = 'vexfile-summary-row';
        var k = document.createElement('span'); k.textContent = r[0];
        var v = document.createElement('b'); v.textContent = String(r[1] == null ? 0 : r[1]);
        row.appendChild(k); row.appendChild(v);
        summaryEl.appendChild(row);
      });
      var by = summary.by_status || {};
      Object.keys(by).forEach(function (st) {
        var row = document.createElement('div');
        row.className = 'vexfile-summary-row sub';
        var k = document.createElement('span'); k.textContent = st;
        var v = document.createElement('b'); v.textContent = String(by[st]);
        row.appendChild(k); row.appendChild(v);
        summaryEl.appendChild(row);
      });
      summaryEl.style.display = 'block';
    }

    function _post(body) {
      return fetch('/api/vex/apply-file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-FS-Session': _nonce() },
        body: JSON.stringify(body),
      }).then(function (r) {
        return r.json().then(
          function (b) { return { ok: r.ok, b: b || {} }; },
          function () { return { ok: r.ok, b: {} }; }
        );
      });
    }

    /* recs upload done (uploads.js set #vexfile-path) — reset the flow:
       preview enabled, apply disabled until a successful preview, summary
       cleared. The clear affordance dispatches with an empty path. */
    modal.addEventListener('fs-upload-done', function (e) {
      if (!e.detail || e.detail.kind !== 'recs') return;
      _showError('');
      _clearSummary();
      if (applyBtn) applyBtn.disabled = true;
      _syncPreview();
    });

    /* A fresh file pick supersedes any prior upload: clear the stored path
       SYNCHRONOUSLY (uploads.js re-populates it only if THIS upload succeeds),
       so a failed/aborted re-upload can't leave the previously-uploaded file
       previewable/applyable — a destructive endpoint must never act on a file
       the user didn't just select. uploads.js dispatches no event on failure. */
    var recsInput = modal.querySelector('.fs-upload-input');
    if (recsInput) recsInput.addEventListener('change', function () {
      if (pathEl) pathEl.value = '';
      _showError('');
      _invalidatePreview();
      _syncPreview();
    });

    if (previewBtn) previewBtn.addEventListener('click', function () {
      var path = _path();
      if (!path) return;
      _showError('');
      /* A fresh preview supersedes any prior one: invalidate immediately so
         Apply can't fire on the previous preview's counts while this dry-run is
         still in flight (re-enabled only when THIS preview succeeds). */
      _invalidatePreview();
      previewBtn.disabled = true;
      previewBtn.textContent = 'Previewing…';
      _post({ path: path, dry_run: true, vex_override: !!(overrideEl && overrideEl.checked) })
        .then(function (res) {
          previewBtn.disabled = false;
          previewBtn.textContent = 'Preview (dry run)';
          if (!res.ok || !res.b.summary) {
            _invalidatePreview();
            _showError((res.b && res.b.error) || 'Preview failed');
            return;
          }
          _renderSummary(res.b.summary, true);
          if (applyBtn) applyBtn.disabled = false;
        })
        .catch(function () {
          previewBtn.disabled = false;
          previewBtn.textContent = 'Preview (dry run)';
          _showError('Preview failed: network error');
        });
    });

    if (applyBtn) applyBtn.addEventListener('click', function () {
      var path = _path();
      if (!path) return;
      if (!window.confirm('This writes VEX statuses to the platform and cannot be undone. Apply for real?')) return;
      _showError('');
      applyBtn.disabled = true;
      applyBtn.textContent = 'Applying…';
      _post({ path: path, dry_run: false, confirm: true, vex_override: !!(overrideEl && overrideEl.checked) })
        .then(function (res) {
          applyBtn.textContent = 'Apply for real';
          if (!res.ok || !res.b.summary) {
            applyBtn.disabled = false;
            _showError((res.b && res.b.error) || 'Apply failed');
            return;
          }
          _renderSummary(res.b.summary, false);
          showToast('VEX applied: ' + (res.b.summary.succeeded || 0) + ' written');
          /* One-shot: Apply stays disabled until a new upload + preview. */
        })
        .catch(function () {
          applyBtn.disabled = false;
          applyBtn.textContent = 'Apply for real';
          _showError('Apply failed: network error');
        });
    });

    if (overrideEl) overrideEl.addEventListener('change', function () {
      /* vex_override changed after a preview → the displayed dry-run summary no
         longer matches what Apply would write; force a re-preview. */
      if ((applyBtn && !applyBtn.disabled) || (summaryEl && summaryEl.style.display !== 'none')) {
        _invalidatePreview();
        _showError('Inputs changed — preview again before applying.');
      }
    });

    trigger.addEventListener('click', _open);
    ov.addEventListener('click', _close);
    if (closeBtn) closeBtn.addEventListener('click', _close);
  }

  function _initCrossPage() {
    fetchProjects();
    /* Folder is a first-class palette target — populate ⌘K folder items on
       every shell page (the run-bar cascade only covers the dashboard). */
    fetchFolders();
    /* Sidebar × unpin renders on every shell page when a pin is set, so its
       delegated click listener must be wired cross-page (the run bar — and
       thus wireRunBar — is dashboard-only).  Registered once per page here. */
    wireUnpin();
    /* Configure modal and toast are already exposed above as globals */
    if (window.lucide) lucide.createIcons();
  }

  /* ── Cockpit init — only when #running-container is in the DOM ─ */
  function _initCockpit() {
    fetchOverview();
    wireRunBar();
    wirePageButtons();
    wireApplyVexFile();
    wireLauncher();
    handleConfigure();
    _startRunningPoller();
    _startQueuePoller();

    /* ── Visibility-change handler: pause all polling when hidden ──
     * Registered ONLY on the cockpit page — /queue and other shell pages
     * have their own visibility handling in queue-page.js.
     * Covering the gated block ensures NO /api/cc/* calls fire on /queue
     * even on tab-refocus. */
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        /* Tab backgrounded — clear both timers; 0 requests while hidden */
        if (_rrPoller !== null) { clearInterval(_rrPoller); _rrPoller = null; }
        if (_queuePoller !== null) { clearInterval(_queuePoller); _queuePoller = null; }
      } else {
        /* Tab foregrounded — restart both pollers and catch up immediately */
        _startQueuePoller();
        try {
          var qc = document.getElementById('scan-queue-container');
          if (qc && window.htmx) {
            htmx.ajax('GET', '/api/queue', { target: '#scan-queue-container', swap: 'innerHTML' });
          }
        } catch (e) { /* ignore */ }
        /* Restart the runs poller; it fires an immediate IN-PLACE tick itself,
           so in-flight runs catch up without a full re-render ("breathing").
           __refreshRunning (full HTMX swap) is reserved for actual Run launches. */
        _startRunningPoller();
      }
    });
  }

  /* ── Init (guarded against double-run) ──────────────────────── */
  function _init() {
    if (_inited) return;
    _inited = true;

    /* Cross-page init — always */
    _initCrossPage();

    /* Cockpit-specific init — only when cockpit DOM is present */
    if (!document.getElementById('running-container')) { return; }
    _initCockpit();
  }

  /* ── DOMContentLoaded init ───────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', _init);

  /* Immediate init if DOM already loaded (script loaded after DOMContentLoaded) */
  if (document.readyState === 'interactive' || document.readyState === 'complete') {
    _init();
  }

})();
