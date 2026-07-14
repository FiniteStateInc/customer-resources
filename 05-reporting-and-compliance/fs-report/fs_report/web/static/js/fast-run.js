/**
 * fast-run.js — Fire-and-forget run launcher.
 *
 * Owns: scope state, run launch (POST /api/run), toast feedback.
 * Progress is shown in the Running Reports monitor — no modal opened.
 * Configure-type recipes still open the #cfg-modal (collect params first).
 *
 * Exposes on window:
 *   __openFR(recipe, opts)  — one-click run (or configure-redirect for multi-field recipes)
 *   __setScope(project, version, folder) — store current scope
 *   __setPinned(recipe)     — store pinned recipe label
 *
 * Called by palette.js (which loads before this file).
 *
 * ES5-style IIFE — no build step required.
 */
(function () {
  /* ── Scope state ─────────────────────────────────────────────── */
  var SCOPE = { project: '', version: '', folder: '' };

  /* Seed scope from the pinned bootstrap. Non-dashboard shell pages (/queue,
   * /reports, /settings) have NO run bar but DO bootstrap the pinned
   * project/version/folder at CC.pinned (see _cc_shell.html), so palette/R-key
   * launches on any page carry the pinned scope and a requires_project /
   * requires_project_or_folder recipe isn't dead-ended by the scope gate. The
   * run bar still drives __setScope on change (dashboard path unaffected), so
   * once it fires its live values win. The old CC.scope bootstrap is retired
   * (nothing emits it — folder-targeting design round-2): scope flows via the
   * run-bar cascade onChange (dashboard) and CC.pinned (every other page).
   * CC.pinned.folder may be absent until pinned_folder is wired (a later task);
   * guard for it ('' fallback). */
  var CC = window.__CC || {};
  if (CC.pinned) {
    if (!SCOPE.project) SCOPE.project = CC.pinned.project || '';
    if (!SCOPE.version) SCOPE.version = CC.pinned.version || '';
    if (!SCOPE.folder)  SCOPE.folder  = CC.pinned.folder  || '';
  }

  /* ── Gate helpers (shared with command-center.js card-body / Save&Run) ──
   *
   * The two launch gates from the card-config design §4 / §10, driven by the
   * window.__CC client maps the shell bootstraps:
   *   1. needs-setup  — recipe ∈ window.__CC.needsSetup (a Set of lowercase
   *      names). The off-card surface is the configure MODAL (no card to flip).
   *   2. scope-req    — window.__CC.scopeReq[name] is "project" /
   *      "project_or_folder" and the supplied scope doesn't satisfy it.
   * These are exposed on window so the card body / Save&Run apply the SAME
   * rule with the SAME maps, and so a Save/Reset that mutates the maps is
   * honored everywhere with no reload.
   */

  /** True iff `recipe` is a saved meta-compare (axis compound).
   *
   * Comparisons carry run-only inputs — finding-types + Left/Right scope
   * override (Decision 11) — that only the prerun modal collects, so EVERY
   * off-card launch surface (run bar, palette) must route them through
   * __openConfigure rather than firing a bare /api/run with global defaults.
   * Sourced from the bootstrapped window.__CC.recipes list (each entry carries
   * a `kind` of "comparison" | "compound" | null). */
  window.__isComparison = function (recipe) {
    if (!recipe) return false;
    var list = (window.__CC && window.__CC.recipes) || [];
    var key = String(recipe).toLowerCase();
    for (var i = 0; i < list.length; i++) {
      if (list[i] && String(list[i].name).toLowerCase() === key) {
        return list[i].kind === 'comparison';
      }
    }
    return false;
  };

  /** True iff the recipe currently needs setup (in window.__CC.needsSetup). */
  window.__needsSetup = function (recipe) {
    if (!recipe) return false;
    var ns = window.__CC && window.__CC.needsSetup;
    var key = recipe.toLowerCase();
    if (ns && typeof ns.has === 'function') return ns.has(key);
    /* Defensive: tolerate a plain array (e.g. test/embed contexts). */
    if (Array.isArray(ns)) {
      for (var i = 0; i < ns.length; i++) {
        if (String(ns[i]).toLowerCase() === key) return true;
      }
    }
    return false;
  };

  /**
   * Resolve the recipe's scope requirement ("project" | "project_or_folder" |
   * "") and, if unmet by the given { project, folder } scope, return the toast
   * hint string. Returns '' (falsy) when the scope gate is satisfied / absent.
   *
   * @param {string} recipe       Recipe display name.
   * @param {object} scope        { project, folder } run-bar scope.
   * @param {string} [scopeReqVal] Optional explicit requirement, supplied by
   *   the ON-card path from the card's own data-scope-req attribute (spec §4)
   *   so the card is self-contained.  When omitted/undefined (the OFF-card
   *   __openFR path, where there is no element), fall back to the
   *   window.__CC.scopeReq map keyed by recipe name (spec §10).
   */
  window.__scopeGateHint = function (recipe, scope, scopeReqVal) {
    if (!recipe) return '';
    var req;
    if (scopeReqVal !== undefined) {
      req = scopeReqVal || '';
    } else {
      var map = (window.__CC && window.__CC.scopeReq) || {};
      req = map[recipe.toLowerCase()] || '';
    }
    if (!req) return '';
    scope = scope || {};
    var hasProject = !!(scope.project && String(scope.project).trim());
    var hasFolder = !!(scope.folder && String(scope.folder).trim());
    /* Context-aware suffix: a run bar only exists on the dashboard. Launches
       also come from the palette / R-key / non-dashboard shell pages where
       there is NO run bar, so "...in the run bar" would point at nothing.
       Detect the run bar (any of its scope selects) and drop the suffix when
       it's absent so the hint stays actionable everywhere. */
    var hasRunBar = !!(typeof document !== 'undefined' && document.getElementById &&
      (document.getElementById('rb-project') || document.getElementById('rb-folder')));
    var where = hasRunBar ? ' in the run bar' : '';
    if (req === 'project' && !hasProject) {
      return 'Select a project' + where + ' to run ' + recipe;
    }
    if (req === 'project_or_folder' && !hasProject && !hasFolder) {
      return 'Select a project or folder' + where + ' to run ' + recipe;
    }
    return '';
  };

  /* ── Public API ──────────────────────────────────────────────── */

  /**
   * Store the current project/version/folder scope.
   * Called by palette.js when a project item is activated (before a one-click run).
   */
  window.__setScope = function (project, version, folder) {
    SCOPE.project = project || '';
    SCOPE.version = (version !== undefined) ? version : '';
    SCOPE.folder  = (folder  !== undefined) ? folder  : '';
  };

  /** Read the live scope (project/version/folder) — the same scope a launch
   * would carry (run-bar onChange / palette / pinned bootstrap all flow through
   * __setScope + the CC.pinned seed). Exposed so the command palette can show
   * "what am I scoped to" honestly (#14), mirroring compute_effective_scope's
   * precedence (project > folder > portfolio) on the read side. */
  window.__getScope = function () {
    return { project: SCOPE.project, version: SCOPE.version, folder: SCOPE.folder };
  };

  /**
   * Store the pinned recipe label.
   * Called by the run-bar or parent page initialisation.
   */
  window.__setPinned = function (recipe) {
    var CC = window.__CC || {};
    CC.pinned = recipe;
    window.__CC = CC;
  };

  /**
   * Launch a report run (fire-and-forget into the Running Reports monitor),
   * applying the SAME two gates as the card body (card-config design §10):
   *   1. recipe needs setup → open the configure MODAL (off-card setup
   *      surface; there is no card to flip on the run bar / palette).
   *   2. else recipe's scope-req unmet by the run-bar scope → toast the hint,
   *      do NOT fire.
   *   3. else → run.
   * The palette's Alt+Enter (activate(true) → __openConfigure) stays an
   * explicit always-modal gesture; it does NOT route through here.
   *
   * @param {string} recipe  Recipe label (display name, e.g. "Triage Prioritization")
   * @param {object} [opts]  Optional { project, version, folder } overrides; falls back to SCOPE
   */
  window.__openFR = function (recipe, opts) {
    if (!recipe) return;

    opts = opts || {};
    var project = (opts.project !== undefined) ? opts.project : SCOPE.project;
    var version = (opts.version !== undefined) ? opts.version : SCOPE.version;
    var folder  = (opts.folder  !== undefined) ? opts.folder  : SCOPE.folder;
    /* B9 #17: optional period override (run bar's Period control for period
       recipes). Quick-run only; not stored in SCOPE. Other callers omit it. */
    var period  = (opts.period  !== undefined) ? opts.period  : '';

    /* ── Gate 0: comparison → always the configure modal ──────── */
    /* A saved meta-compare must collect its run-only finding-types + L/R
       override (Decision 11); never fall through to a bare /api/run. */
    if (window.__isComparison(recipe)) {
      if (window.__openConfigure) {
        window.__openConfigure(recipe, opts);
      } else {
        location.href = '/?configure=' + encodeURIComponent(recipe);
      }
      return;
    }

    /* ── Gate 1: needs-setup → open the configure modal ───────── */
    if (window.__needsSetup(recipe)) {
      if (window.__openConfigure) {
        /* Pass opts so the modal pre-fills project/version/folder. */
        window.__openConfigure(recipe, opts);
      } else {
        /* Fallback: legacy redirect only if __openConfigure is somehow absent */
        location.href = '/?configure=' + encodeURIComponent(recipe);
      }
      return;
    }

    /* ── Gate 2: scope-req unmet → toast the hint, don't fire ──── */
    var scopeHint = window.__scopeGateHint(recipe, { project: project, folder: folder });
    if (scopeHint) {
      _showToast(scopeHint);
      return;
    }

    /* ── POST /api/run (fire-and-forget) ─────────────────────── */
    /* Folder-targeting precedence — project wins (design §2/§3): the folder ID
       is carried ONLY when no project is set (folder-only → recursive
       folder-tree target). Trim so the client agrees with the server:
       _build_engine_config treats a whitespace-only project as "unset" and does
       NOT suppress the folder. */
    var projectVal = String(project || '').trim();
    var versionVal = String(version || '').trim();
    var folderVal = (!projectVal && String(folder || '').trim())
      ? String(folder).trim()
      : '';
    var params = new URLSearchParams();
    params.set('recipes', recipe);
    /* B9 #17: period override (only set when non-empty — blank inherits the
       recipe default; `period` is already an accepted /api/run str override). */
    var periodVal = String(period || '').trim();
    if (periodVal) params.set('period', periodVal);
    /* #27 present-key contract — gated on the RUN BAR being present. When a run
       bar exists, it is the explicit, complete live scope selector, so we send
       all three scope keys PRESENT (empty = an explicit "all projects / all
       folders" selection) and the server CLEARS any stale inherited state scope.
       On pages with NO run bar (/queue, /reports, /settings) the scope comes
       from the pinned-Settings bootstrap (CC.pinned), which the page can't fully
       re-express (e.g. CC.pinned.folder may be unset) — so we OMIT unset keys
       and let the server INHERIT the pinned state scope, instead of wrongly
       clearing a Settings scope the bootstrap didn't echo. */
    var hasRunBar = !!(document.getElementById('rb-project') ||
                       document.getElementById('rb-folder'));
    if (hasRunBar) {
      params.set('project_filter', projectVal);
      params.set('version_filter', versionVal);
      params.set('folder_filter', folderVal);
    } else {
      if (projectVal) params.set('project_filter', projectVal);
      if (versionVal) params.set('version_filter', versionVal);
      if (folderVal)  params.set('folder_filter', folderVal);
    }
    /* SP2: carry a transient dry-run preview request (e.g. from the card-back
       Save & Run dry-run toggle). autotriage itself rides as a saved per-card
       override merged server-side; dry_run is never persisted. */
    if (opts.dry_run) params.set('dry_run', 'true');

    var nonceMeta = document.querySelector('meta[name="fs-csrf"]');
    var nonce     = nonceMeta ? nonceMeta.content : '';

    /* Delegates to __sp2PostRun, which satisfies the SP2 confirm gate (a saved
       per-card autotriage override on a minimal launch -> server 400
       needs_confirm -> native confirm -> retry). */
    __sp2PostRun(params, nonce, {
      onError: function (body) {
        _showToast('Run failed: ' + (body.error || 'error'));
      },
    })
    .then(function (body) {
      if (!body) return; /* error or user-cancelled confirm — already handled */
      if (!body.run_id) {
        _showToast('Run failed: no run_id from server');
        return;
      }
      /* Show brief feedback toast */
      _showToast('Started: ' + recipe);
      /* Trigger an immediate monitor refresh so the run appears right away */
      if (window.__refreshRunning) {
        window.__refreshRunning();
      } else if (window.htmx) {
        htmx.ajax('GET', '/api/running', { target: '#running-container', swap: 'innerHTML' });
      }
    })
    .catch(function (err) {
      _showToast('Run failed: ' + (err.message || 'Network error'));
    });
  };

  /* ── SP2: destructive VEX-write apply — shared launch + preview ──── */

  /** POST /api/run, transparently satisfying the server's confirm gate.
   *
   * The server returns 400 {needs_confirm:true} for a REAL (non-dry-run)
   * autotriage write that lacks confirm — including minimal/quick launches that
   * merge a saved per-card autotriage override. We surface a native confirm and
   * retry once with confirm=true. `params` is a URLSearchParams. Resolves with
   * the parsed body on success, or null (error/cancel; caller already toasted
   * via onError or the rejection is swallowed). */
  function __sp2PostRun(params, nonce, opts) {
    opts = opts || {};
    function go() {
      return fetch('/api/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-FS-Session': nonce,
        },
        body: params.toString(),
      }).then(function (resp) {
        if (resp.status === 400) {
          return resp.json().then(function (body) {
            if (body && body.needs_confirm) {
              var msg = body.error || 'This will write VEX to the platform. Proceed?';
              if (window.confirm(msg)) {
                params.set('confirm', 'true');
                return go(); /* retry once, now acknowledged */
              }
              return null; /* user cancelled */
            }
            if (opts.onError) opts.onError(body || {});
            return null;
          }, function () {
            if (opts.onError) opts.onError({ error: 'HTTP 400' });
            return null;
          });
        }
        if (!resp.ok) {
          return resp.json().then(
            function (body) { if (opts.onError) opts.onError(body || {}); return null; },
            function () { if (opts.onError) opts.onError({ error: 'HTTP ' + resp.status }); return null; }
          );
        }
        return resp.json().then(function (body) {
          /* Pass 4: a COMPOUND launch navigates to the live Run canvas so the
             fan-in is watched live (spec §2/§9). The server-returned kind is the
             authoritative signal. This is the shared chokepoint for every launch
             vector (card / run-bar / palette via __openFR, and the configure modal
             which calls __sp2PostRun directly), so the branch lives here — not in a
             per-vector handler. Plain report runs fall through unchanged. */
          if (body && body.kind === 'compound' && body.run_id) {
            window.location.href = '/run/' + encodeURIComponent(body.run_id);
            return body;
          }
          if (body && body.run_id && _isDryAutotriage(params)) {
            __sp2PollPreview(body.run_id, nonce);
          }
          return body;
        });
      });
    }
    return go();
  }
  window.__sp2PostRun = __sp2PostRun;

  function _isDryAutotriage(params) {
    var truthy = { 'true': 1, 'on': 1, '1': 1, 'yes': 1 };
    return !!truthy[String(params.get('autotriage') || '').toLowerCase()] &&
           !!truthy[String(params.get('dry_run') || '').toLowerCase()];
  }

  /** After a dry-run autotriage launch, poll the run's VEX preview and offer to
   * apply for real. Surfaces the planned writes as a confirm dialog (the cockpit
   * launches are fire-and-forget with no SSE consumer). */
  function __sp2PollPreview(runId, nonce, tries) {
    tries = tries || 0;
    if (tries > 40) return; /* ~60s budget; give up quietly */
    fetch('/api/run/' + encodeURIComponent(runId) + '/vex-preview')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !data.summary) {
          setTimeout(function () { __sp2PollPreview(runId, nonce, tries + 1); }, 1500);
          return;
        }
        var s = data.summary;
        var by = s.by_status || {};
        var lines = Object.keys(by).map(function (k) { return '  ' + by[k] + ' → ' + k; });
        var msg = 'VEX dry-run preview: ' + (s.total || 0) + ' finding(s) would be written'
          + (lines.length ? ':\n' + lines.join('\n') : '')
          + '\n\nApply these VEX statuses to the platform for real? This cannot be undone.';
        if (window.confirm(msg)) {
          fetch('/api/run/' + encodeURIComponent(runId) + '/vex-apply', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-FS-Session': nonce },
            body: JSON.stringify({ confirm: true }),
          }).then(function (r) { return r.json().then(function (b) { return { ok: r.ok, b: b }; }); })
            .then(function (res) {
              if (res.ok && res.b && res.b.summary) {
                _showToast('VEX applied: ' + (res.b.summary.succeeded || 0) + ' written');
              } else {
                _showToast('VEX apply failed: ' + ((res.b && res.b.error) || 'error'));
              }
            })
            .catch(function () { _showToast('VEX apply failed: network error'); });
        }
      })
      .catch(function () { /* preview unavailable; stop quietly */ });
  }
  window.__sp2PollPreview = __sp2PollPreview;

  /* ── Internal helpers ─────────────────────────────────────────── */

  /** Show a brief toast message (delegates to window.__showToast if available). */
  function _showToast(msg) {
    if (window.__showToast) {
      window.__showToast(msg);
      return;
    }
    /* Minimal inline fallback for contexts where command-center.js is not loaded */
    var t = document.createElement('div');
    t.style.cssText = [
      'position:fixed', 'bottom:54px', 'left:50%', 'transform:translateX(-50%)',
      /* Fixed dark pill in BOTH themes — must not use theme vars (--ink flips
         to near-black in light mode → unreadable text on the dark pill). */
      'background:#2a2a3a', 'color:#e8eaed',
      'padding:8px 18px', 'border-radius:6px', 'font-size:13px',
      'box-shadow:0 2px 12px rgba(0,0,0,.4)', 'z-index:9999',
      'pointer-events:none', 'opacity:1', 'transition:opacity .4s'
    ].join(';');
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function () { t.style.opacity = '0'; }, 2200);
    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 2700);
  }

})();
