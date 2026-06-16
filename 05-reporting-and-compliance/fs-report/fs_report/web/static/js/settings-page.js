/* ============================================================
 * fs-report Phase 2 — settings-page.js
 *
 * Standalone Settings page (/settings) behavior on the Command Center shell.
 * Reuses existing endpoints + shared components; no new write machinery.
 *
 *   - Toggles: a .sw element flips .on + its bound hidden checkbox.
 *   - finding_types: any checkbox change rewrites hidden #cfg-ft to the
 *     comma-joined checked values — INCLUDING "" when none are checked (so an
 *     all-unchecked selection is savable; we never early-return on zero).
 *   - Save (#settings-save): build FormData from #settings-form, POST to
 *     /api/settings with the X-FS-Session nonce, CHECK response.ok → toast.
 *     Disabled while in-flight. Scope selects already carry their persisted
 *     value as a pre-selected <option> (§4.8) so Save can't blank them offline.
 *   - Browse: initDirBrowser('cfg-output','cfg-output-browse').
 *   - Cascade: initScopeDropdowns({folderId,projectId,versionId,cvoId}).
 *   - Logo: populate select from GET /api/logos; upload via POST /api/logos/upload.
 *   - Cache clear: per-cache DELETE (with nonce) then refresh stats via
 *     GET /api/settings/cache and re-render the rows; lucide.createIcons() after.
 *   - Deployment-notes live char counter.
 *
 * window.NONCE is bootstrapped from the fs-csrf meta by an inline script in the
 * template BEFORE this file loads (so initDirBrowser / initScopeDropdowns can
 * populate X-FS-Session). We read it here too, defensively.
 *
 * Vanilla ES5-style IIFE — no framework, no build step. Guarded on the
 * relevant DOM existing so it no-ops on other pages.
 * ============================================================ */
(function () {
  'use strict';

  var _inited = false;

  function nonce() {
    if (window.NONCE) return window.NONCE;
    var m = document.querySelector('meta[name="fs-csrf"]');
    return m ? m.content : '';
  }

  function toast(msg) {
    if (window.__showToast) window.__showToast(msg);
  }

  /* ── Toggles: .sw[data-sw="<checkboxId>"] flips .on + the hidden box. ── */
  function _wireToggles() {
    var sws = document.querySelectorAll('.sw[data-sw]');
    for (var i = 0; i < sws.length; i++) {
      (function (sw) {
        sw.addEventListener('click', function () {
          var box = document.getElementById(sw.getAttribute('data-sw'));
          var on = !sw.classList.contains('on');
          sw.classList.toggle('on', on);
          if (box) {
            box.checked = on;
            /* fire change so dependent logic (e.g. CVO → version disable) runs */
            box.dispatchEvent(new Event('change', { bubbles: true }));
          }
        });
      })(sws[i]);
    }
  }

  /* ── finding_types: rewrite hidden field on any checkbox change. ── */
  function _syncFindingTypes() {
    var hidden = document.getElementById('cfg-ft');
    if (!hidden) return;
    var cbs = document.querySelectorAll('input[name="cfg_ft_cb"]:checked');
    var vals = [];
    for (var i = 0; i < cbs.length; i++) vals.push(cbs[i].value);
    /* Allow clearing all types: empty string is a valid value, never skipped. */
    hidden.value = vals.join(',');
  }

  function _wireFindingTypes() {
    var cbs = document.querySelectorAll('input[name="cfg_ft_cb"]');
    for (var i = 0; i < cbs.length; i++) {
      cbs[i].addEventListener('change', _syncFindingTypes);
    }
  }

  /* ── Save: POST the whole form, check response.ok. ── */
  function _save() {
    var btn = document.getElementById('settings-save');
    var form = document.getElementById('settings-form');
    if (!form) return;
    _syncFindingTypes();
    if (btn) btn.disabled = true;
    fetch('/api/settings', {
      method: 'POST',
      headers: { 'X-FS-Session': nonce() },
      body: new FormData(form)
    })
      .then(function (r) {
        toast(r.ok ? 'Settings saved' : 'Save failed (' + r.status + ')');
      })
      .catch(function () {
        toast('Save failed');
      })
      .then(function () {
        if (btn) btn.disabled = false;
      });
  }

  function _wireSave() {
    var btn = document.getElementById('settings-save');
    var form = document.getElementById('settings-form');
    if (!btn || !form) return;
    btn.addEventListener('click', _save);
    /* Enter in a text field submits the form → save. The button is type=button
       and outside the form, so without this Enter would do nothing. */
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      _save();
    });
  }

  /* ── Logo: populate select + handle upload. ── */
  function _wireLogo() {
    var sel = document.getElementById('cfg-logo-select');
    var hidden = document.getElementById('cfg-logo');
    var upload = document.getElementById('cfg-logo-upload');
    if (!sel || !hidden) return;
    var currentLogo = hidden.value || '';

    function loadLogos(selectValue) {
      fetch('/api/logos', { headers: { 'X-FS-Session': nonce() } })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          sel.innerHTML = '<option value="">(default Finite State logo)</option>';
          (data.logos || []).forEach(function (name) {
            var o = document.createElement('option');
            o.value = name;
            o.textContent = name;
            if (name === (selectValue || currentLogo)) o.selected = true;
            sel.appendChild(o);
          });
        })
        .catch(function () { /* offline — keep the default option */ });
    }

    sel.addEventListener('change', function () {
      hidden.value = sel.value;
    });

    if (upload) {
      upload.addEventListener('change', function () {
        var file = upload.files[0];
        if (!file) return;
        if (file.size > 512000) {
          toast('File too large (max 500KB)');
          return;
        }
        var fd = new FormData();
        fd.append('file', file);
        fetch('/api/logos/upload', {
          method: 'POST',
          headers: { 'X-FS-Session': nonce() },
          body: fd
        })
          .then(function (r) { return r.json(); })
          .then(function (data) {
            if (data.error) {
              toast(data.error);
            } else {
              toast('Logo uploaded');
              loadLogos(data.filename);
              hidden.value = data.filename;
            }
          })
          .catch(function () { toast('Upload failed'); });
        upload.value = '';
      });
    }

    loadLogos();
  }

  /* ── Cache clear + refresh. ── */
  function _renderCacheRows(d) {
    var host = document.getElementById('cache-rows');
    if (!host) return;
    /* If the cache dir became unreadable since load, don't paint
       "undefined MB" rows — leave the existing rows in place. */
    if (d && d.available === false) return;
    var domainNote = (d.domain_dbs && d.domain_dbs.length)
      ? ' · ' + d.domain_dbs.length + ' domain' + (d.domain_dbs.length !== 1 ? 's' : '')
      : '';
    var rows = [
      { key: 'api', name: 'API', stat: d.api_size_mb + ' MB · ' + d.api_entries + ' entries' + domainNote },
      { key: 'nvd', name: 'NVD', stat: d.nvd_size_mb + ' MB · ' + d.nvd_entries + ' entries' },
      { key: 'ai', name: 'AI', stat: d.ai_size_mb + ' MB · ' + d.ai_entries + ' entries' }
    ];
    var html = '';
    rows.forEach(function (r) {
      html += '<div class="cache-row"><div class="cache-meta">' +
        '<span class="cache-name">' + r.name + '</span>' +
        '<span class="cache-stat">' + r.stat + '</span></div>' +
        '<button type="button" class="btn btn-ghost btn-clear" data-cache="' + r.key + '">' +
        '<i data-lucide="trash-2"></i> Clear</button></div>';
    });
    host.innerHTML = html;
    if (window.lucide) lucide.createIcons();
  }

  function _refreshCache() {
    return fetch('/api/settings/cache', { headers: { 'X-FS-Session': nonce() } })
      .then(function (r) { return r.json(); })
      .then(_renderCacheRows)
      .catch(function () { /* leave stale rows */ });
  }

  function _wireCacheClear() {
    var host = document.getElementById('cache-rows');
    if (!host) return;
    host.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('.btn-clear') : null;
      if (!btn || !host.contains(btn)) return;
      var key = btn.getAttribute('data-cache');
      if (!key) return;
      if (!window.confirm('Clear the ' + key.toUpperCase() + ' cache?')) return;
      btn.disabled = true;
      fetch('/api/settings/cache/' + key, {
        method: 'DELETE',
        headers: { 'X-FS-Session': nonce() }
      })
        .then(function (r) {
          toast(r.ok ? key.toUpperCase() + ' cache cleared' : 'Clear failed (' + r.status + ')');
          return _refreshCache();
        })
        .catch(function () {
          toast('Clear failed');
        })
        .then(function () {
          /* Always re-enable — never strand the button if the stats refresh
             fails or returns unavailable (the DELETE may have succeeded). */
          btn.disabled = false;
        });
    });
  }

  /* ── Deployment-notes char counter. ── */
  function _wireCounter() {
    var ta = document.getElementById('cfg-deploy-notes');
    var counter = document.getElementById('cfg-deploy-notes-count');
    if (!ta || !counter) return;
    ta.addEventListener('input', function () {
      counter.textContent = ta.value.length;
    });
  }

  function _init() {
    if (_inited) return;
    if (!document.getElementById('settings-form')) return; /* only on /settings */
    _inited = true;

    _wireToggles();
    _wireFindingTypes();
    _wireSave();
    _wireLogo();
    _wireCacheClear();
    _wireCounter();

    /* Shared components (window.NONCE already bootstrapped in the template). */
    if (typeof initDirBrowser === 'function') {
      initDirBrowser('cfg-output', 'cfg-output-browse');
    }
    if (typeof initScopeDropdowns === 'function') {
      initScopeDropdowns({
        folderId: 'cfg-folder',
        projectId: 'cfg-project',
        versionId: 'cfg-version',
        cvoId: 'cfg-cvo'
      });
    }
  }

  document.addEventListener('DOMContentLoaded', _init);
})();
